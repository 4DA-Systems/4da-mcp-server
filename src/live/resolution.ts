// SPDX-License-Identifier: Apache-2.0
/**
 * Dependency resolution that knows when it has gone stale.
 *
 * Measured 2026-09-10: three `node ./mcp-4da-server/dist/index.js` processes
 * were live and two had started before the pull that brought hono 4.13.5.
 * `vulnerability_scan` from one of them reported hono 4.13.3 (the lockfile
 * value when it started) with `_meta.cached: false`. The live layer resolved
 * versions once at init and never again, and `cached` described only the OSV
 * lookup, so nothing in the answer could reveal that it was stale.
 *
 * A group records every file its resolution depended on as a stat signature:
 * each lockfile candidate (present or absent, so one appearing or vanishing
 * counts), the manifest when the resolver fell back to it, and for npm the
 * node_modules install state. Signatures are taken BEFORE reading, so a write
 * that lands mid-read still registers as a change. `resolveGroup` depends
 * only on its inputs and the filesystem, so the SAME resolution can be re-run
 * when a signature moves. Stat calls only: no timers, no watchers.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { oversize, tooLargeText } from "./bounded-read.js";
import { anySignatureChanged, signatureMap, signatureMtime, type FileSignature } from "./file-signature.js";
import { checkInstallState } from "./install-state.js";
import { lockfileCandidates, manifestCandidate, resolveVersionSource } from "./lockfile-parsers.js";
import { mapEcosystem, resolveAuditVersionsFrom, resolveVersionsFrom } from "./version-resolver.js";
import { parsePyprojectDependencies } from "../project-manifests.js";
import { readTextFile } from "./text-file.js";
import type { InstallDriftRecord, ResolutionSourceRecord, ResolvedDependency } from "./types.js";
import type { LockfileProblem, UncheckableDependency, UnpinnedRequirements } from "./lockfile-types.js";
import type { PrivateIndexEntry } from "./private-packages.js";

/** The inputs of one resolution, kept so the same resolution can be re-run. */
export interface ResolutionGroup {
  dir: string;
  language: string;
  deps: string[];
  devDeps: string[];
  targets: Record<string, string>;
}

export interface GroupResolution {
  group: ResolutionGroup;
  /** Direct dependencies (dependency health, upgrade planning). */
  resolved: ResolvedDependency[];
  /** The full lockfile set plus drift entries (vulnerability scanning). */
  audit: ResolvedDependency[];
  drift: InstallDriftRecord[];
  /** The (first) file the versions were read from, or null when the group resolved from nothing. */
  source: ResolutionSourceRecord | null;
  /** Every file read, `source` first (Python merges its lockfiles and requirement files). */
  sources: ResolutionSourceRecord[];
  /**
   * Set when no lockfile pins this group's versions: the manifest, how many
   * of its dependencies are declared ranges (not sent to OSV), and how many
   * are exact pins (checked as declared; what they depend on is resolved
   * nowhere, so the transitive tree was not checked).
   */
  unresolved: { manifest: string; ranges: number; pinned: number } | null;
  /** Dependencies installed from git, a URL or a local archive: listed, never matched as registry releases. */
  uncheckable: UncheckableDependency[];
  /** Packages the lockfile installs from a private registry or index (or git, Cargo): never sent anywhere. */
  privateIndex: PrivateIndexEntry[];
  /** PyPI: `--extra-index-url` indexes beside pypi.org, by file. */
  extraIndexes: Array<{ file: string; index: string }>;
  /** PyPI: requirements with no pinned version anywhere in this directory, by the file that lists them. */
  unpinned: UnpinnedRequirements[];
  /** Lockfiles present in this directory that could not be read, with the reason. */
  problems: LockfileProblem[];
  signatures: Map<string, FileSignature>;
  resolvedAt: string;
}

export function resolveGroup(group: ResolutionGroup): GroupResolution {
  const resolvedAt = new Date().toISOString();
  const ecosystem = mapEcosystem(group.language);
  const manifest = manifestCandidate(group.dir, ecosystem);
  const signatures = signatureMap([
    ...lockfileCandidates(group.dir, ecosystem),
    ...(manifest ? [manifest] : []),
  ]);

  // A lockfile or manifest over the size cap is not read (bounded-read.ts): the group resolves to
  // nothing and says why, so its dependencies are reported as not checked. Its signature is kept,
  // so the group is resolved again once the file changes.
  const tooLarge: LockfileProblem[] = [...signatures.keys()].flatMap((file) => {
    const size = oversize(file);
    return size === null ? [] : [{ file, error: tooLargeText(size), ecosystem }];
  });
  if (tooLarge.length > 0) {
    return {
      group,
      resolved: [],
      audit: [],
      drift: [],
      source: null,
      sources: [],
      unresolved: null,
      problems: tooLarge,
      // Nothing was read, so nothing is known to be uncheckable or unpinned: the problem says it was not checked.
      uncheckable: [],
      privateIndex: [],
      extraIndexes: [],
      unpinned: [],
      signatures,
      resolvedAt,
    };
  }

  const read = resolveVersionSource(group.dir, ecosystem);
  const readFiles = read.source ? [read.source, ...(read.extraSources ?? [])] : [];
  // The manifest only matters when the resolver fell back to it; editing a
  // script in package.json must not throw away a scan of an unchanged lockfile.
  if (manifest && !readFiles.includes(manifest)) signatures.delete(manifest);

  // Ruby and PHP: the lockfile (and composer.json) name the direct dependencies; the project scanner does not.
  const fromLock = group.deps.length === 0 && group.devDeps.length === 0 && read.direct;
  // An npm alias is declared under the folder name it installs into; the dependency is the package behind it.
  const real = (names: string[]) => (read.aliases ? [...new Set(names.map((name) => read.aliases?.get(name) ?? name))] : names);
  const deps = real(fromLock ? fromLock.deps : group.deps);
  const devDeps = real(fromLock ? fromLock.devDeps : group.devDeps);
  let resolved = resolveVersionsFrom(group.dir, deps, devDeps, ecosystem, read.versions, group.targets);
  // No lockfile: a ranged dependency's version is the range's floor, a label.
  const ranges = read.kind === "declared_ranges" ? read.ranges ?? new Map<string, string>() : null;
  if (ranges && ranges.size > 0) {
    resolved = resolved.map((dep) => {
      const declaredRange = ranges.get(dep.name);
      return declaredRange ? { ...dep, declaredRange } : dep;
    });
  }
  let drift: InstallDriftRecord[] = [];
  let driftAudit: ResolvedDependency[] = [];
  // Only a lockfile pins exact versions; comparing node_modules against a
  // manifest's specifier floor would report drift that is not there.
  if (ecosystem === "npm" && read.kind === "lockfile" && read.source) {
    const install = checkInstallState(group.dir, resolved, read.source);
    resolved = install.resolved;
    drift = install.drift;
    driftAudit = install.driftAuditDeps;
    for (const [file, signature] of install.signatures) signatures.set(file, signature);
  }

  const audit = [
    ...resolveAuditVersionsFrom(
      group.dir,
      deps,
      devDeps,
      ecosystem,
      read.versions,
      group.targets,
      resolved,
      read.instances,
    ),
    ...driftAudit,
  ].filter((dep) => !dep.declaredRange);

  const sources: ResolutionSourceRecord[] = read.kind
    ? readFiles.map((file) => ({ path: file, kind: read.kind!, mtimeMs: signatureMtime(signatures.get(file)) }))
    : [];
  // A manifest read with no lockfile: its ranges are not installs, and even its exact pins are
  // only themselves. What they pull in is resolved nowhere, so it was never checked.
  const pinned = ranges ? read.instances.length : 0;
  const unresolved = ranges && read.source && ranges.size + pinned > 0 ? { manifest: read.source, ranges: ranges.size, pinned } : null;
  const unpinned = [...(read.unpinned ?? []), ...(ecosystem === "PyPI" && !read.source ? pyprojectUnpinned(group.dir, read.uncheckable ?? []) : [])];

  return {
    group,
    resolved,
    audit,
    drift,
    source: sources[0] ?? null,
    sources,
    unresolved,
    uncheckable: read.uncheckable ?? [],
    privateIndex: read.privateIndex ?? [],
    extraIndexes: read.extraIndexes ?? [],
    unpinned,
    problems: read.problems ?? [],
    signatures,
    resolvedAt,
  };
}

/** Parent directories searched for a Python lockfile that covers a workspace member. */
const MAX_LOCK_PARENTS = 6;

/**
 * The dependencies a pyproject.toml declares when NO file in its directory
 * pins anything (no lockfile, no requirements file): none of them has a
 * version to check. Such a project scanned as "0 dependencies" with only a
 * hint to run `poetry install`, whatever tool it used (audit 2026-11-11,
 * M10). A uv or Poetry workspace member is pinned by a lockfile above it and
 * is left alone.
 */
function pyprojectUnpinned(dir: string, uncheckable: UncheckableDependency[]): UnpinnedRequirements[] {
  const file = path.join(dir, "pyproject.toml");
  let declared: string[];
  try {
    const parsed = parsePyprojectDependencies(readTextFile(file));
    declared = [...parsed.deps, ...parsed.devDeps];
  } catch {
    return [];
  }
  let parent = path.dirname(path.resolve(dir));
  for (let level = 0; level < MAX_LOCK_PARENTS; level++) {
    if (["uv.lock", "poetry.lock", "pdm.lock"].some((lock) => fs.existsSync(path.join(parent, lock)))) return [];
    if (fs.existsSync(path.join(parent, ".git")) || path.dirname(parent) === parent) break;
    parent = path.dirname(parent);
  }
  const elsewhere = new Set(uncheckable.map((u) => u.name));
  const names = declared.filter((name) => !elsewhere.has(name));
  return names.length > 0 ? [{ file, names }] : [];
}

/** True when any file the resolution depended on changed, appeared, or vanished. */
export function groupIsStale(result: GroupResolution): boolean {
  return anySignatureChanged(result.signatures);
}
