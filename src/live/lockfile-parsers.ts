// SPDX-License-Identifier: Apache-2.0
/**
 * Lockfile parsers, one per ecosystem, each reporting WHICH file it resolved
 * from as well as the versions it read.
 *
 * Priority per ecosystem: lock file (exact) > manifest (range/specifier).
 * Uses only Node.js built-ins — no external parsers. The source path is what
 * lets the live layer notice when that file changes and re-resolve (measured
 * 2026-09-10: a server started before a lockfile bump kept reporting hono
 * 4.13.3 after the lockfile said 4.13.5). The pnpm and yarn readers live in
 * js-lockfile-readers.ts; Python and Go in lockfile-parsers-pygo.ts.
 *
 * Every parser reports two things (2026-10-02):
 * - `instances`: EVERY installed copy, name@version, with the lockfile's own
 *   dev flag when it records one. A lockfile routinely holds several versions
 *   of one package (nested npm copies, two semver-incompatible crates). The
 *   reader used to keep one version per name, last one wins: measured against
 *   osv-scanner on 12 projects, nodegoat lost 287 of 1,091 installed copies
 *   and 4DA's src-tauri lost 143 of 934 — including its own `rsa 0.9.10`
 *   (RUSTSEC-2023-0071), overwritten by `rsa 0.10.0-rc.18` — and the direct
 *   `minimist@1.2.0` was reported as its nested `0.0.8`.
 * - `versions`: the ONE version per name a direct dependency resolves to (the
 *   top-level npm copy, the crate version a workspace member depends on),
 *   which dependency health and upgrade planning read.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { readBunLock } from "./bun-lockfile.js";
import {
  emptyReadReport,
  MAX_LOCKFILE_LINE,
  nonRegistrySource,
  pnpmLockDamage,
  readPnpmLock,
  readYarnLock,
  type LockDamage,
  type NonRegistryEntry,
} from "./js-lockfile-readers.js";
import { requirementFiles, resolveGo, resolvePython, tomlLockDamage } from "./lockfile-parsers-pygo.js";
import { emptySource, found, InstanceSet, type LockfileProblem, type PackageInstance, type VersionSource } from "./lockfile-types.js";
import { resolvePhp, resolveRuby } from "./lockfile-parsers-rbphp.js";
import { readTextFile } from "./text-file.js";
import { isPublicCratesSource, sourceLabel, type PrivateIndexEntry } from "./private-packages.js";
import type { OsvEcosystem } from "./types.js";

export type { PackageInstance, VersionSource } from "./lockfile-types.js";

const LOCKFILES: Partial<Record<OsvEcosystem, string[]>> = {
  npm: ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"],
  "crates.io": ["Cargo.lock"],
  PyPI: ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"],
  Go: ["go.mod", "go.sum"],
  RubyGems: ["Gemfile.lock"],
  Packagist: ["composer.lock"],
};

const MANIFESTS: Partial<Record<OsvEcosystem, string>> = {
  npm: "package.json",
  "crates.io": "Cargo.toml",
};

/**
 * Every lock file the resolver may read for this ecosystem, present or not,
 * in priority order; for Python also every requirements file present now.
 */
export function lockfileCandidates(cwd: string, ecosystem: OsvEcosystem): string[] {
  const fixed = (LOCKFILES[ecosystem] ?? []).map((name) => path.join(cwd, name));
  // bun.lockb cannot be read, but its arrival or removal changes what the answer must say.
  if (ecosystem === "npm") return [...fixed, path.join(cwd, BUN_BINARY_LOCK)];
  return ecosystem === "PyPI" ? [...fixed, ...requirementFiles(cwd)] : fixed;
}

/** Bun's binary lockfile (before Bun 1.2, and still written beside bun.lock by some setups). Not readable here. */
const BUN_BINARY_LOCK = "bun.lockb";

/** The manifest the resolver falls back to for this ecosystem, or null when it has none. */
export function manifestCandidate(cwd: string, ecosystem: OsvEcosystem): string | null {
  const name = MANIFESTS[ecosystem];
  return name ? path.join(cwd, name) : null;
}

/**
 * The versions one directory pins for one ecosystem, plus every lockfile that
 * is present but could not be read (`problems`). A damaged or conflicted
 * lockfile used to fall through silently to the next candidate or to "no
 * lockfile" (audit B-9): now the answer names the file and the error.
 */
export function resolveVersionSource(cwd: string, ecosystem: OsvEcosystem): VersionSource {
  let read: VersionSource;
  let thrown: LockfileProblem | null = null;
  try {
    read = readVersionSource(cwd, ecosystem);
  } catch (error) {
    read = emptySource();
    const file = (LOCKFILES[ecosystem] ?? []).map((n) => path.join(cwd, n)).find((f) => fs.existsSync(f));
    if (file) thrown = { file, error: describeParseError(file, error) ?? "could not be parsed" };
  }
  // The reader's own problems (a refused requirements include, M4) and the lockfiles it could not read.
  const problems = [...(read.problems ?? []), ...(thrown ? [thrown] : unreadLockfiles(cwd, ecosystem, read))];
  return problems.length > 0 ? { ...read, problems: problems.map((p) => ({ ...p, ecosystem })) } : read;
}

function readVersionSource(cwd: string, ecosystem: OsvEcosystem): VersionSource {
  switch (ecosystem) {
    case "npm":
      return resolveNpm(cwd);
    case "crates.io":
      return resolveRust(cwd);
    case "PyPI":
      return resolvePython(cwd);
    case "Go":
      return resolveGo(cwd);
    case "RubyGems":
      return resolveRuby(cwd);
    case "Packagist":
      return resolvePhp(cwd);
    default:
      return emptySource();
  }
}

/**
 * yarn.lock entries skipped because a line of theirs is past the reader's
 * length cap (B-10 keeps the patterns linear). Said, so the read is never
 * taken for complete (audit L5).
 */
function yarnSkippedProblem(file: string, skipped: number): LockfileProblem {
  const entries = skipped === 1 ? "1 entry" : `${skipped} entries`;
  return {
    file,
    skipped,
    error: `${entries} on a line longer than ${MAX_LOCKFILE_LINE} characters (not lockfile syntax) ${skipped === 1 ? "was" : "were"} skipped, so ${skipped === 1 ? "its version was" : "their versions were"} not checked`,
  };
}

function yarnSkips(file: string): number {
  try {
    return readYarnLock(readTextFile(file), new Map());
  } catch {
    return 0;
  }
}

/**
 * A lockfile that was read, but not all of it: truncated or damaged. The
 * packages before the damage were checked; the rest were not, and how many
 * that is can only be bounded from below (`missing`).
 */
function damagedProblem(file: string, damage: LockDamage): LockfileProblem {
  return {
    file,
    partial: true,
    ...(damage.missing > 0 ? { skipped: damage.missing } : {}),
    error: `${damage.reason}. It was read up to the damage only, so the packages after it were not checked: regenerate the lockfile`,
  };
}

/** Lines git writes into a file it could not merge. */
const CONFLICT_MARKER = /^(?:<{7}|>{7})(?: |$)|^={7}$/m;

/**
 * Lockfiles that exist here, rank above the file the versions came from (or
 * there is none), and were not read: each with the reason, re-derived from
 * the file so the note can say what is wrong with it.
 */
function unreadLockfiles(cwd: string, ecosystem: OsvEcosystem, read: VersionSource): LockfileProblem[] {
  const readFiles = new Set([read.source, ...(read.extraSources ?? [])].filter((f): f is string => Boolean(f)).map((f) => path.resolve(f)));
  const problems: LockfileProblem[] = [];
  for (const name of LOCKFILES[ecosystem] ?? []) {
    if (name === "go.sum") continue; // read with go.mod, never on its own
    const file = path.join(cwd, name);
    if (readFiles.has(path.resolve(file))) {
      // Python merges every lockfile it finds, so one that was read says nothing about the next.
      if (ecosystem === "PyPI") continue;
      break; // everything after it ranks lower (resolveNpm compares those itself)
    }
    if (!fs.existsSync(file)) continue;
    // A yarn.lock whose entries were all skipped for length: named with the count, even when the file is short (L5).
    const skipped = name === "yarn.lock" ? yarnSkips(file) : 0;
    if (skipped > 0) {
      problems.push(yarnSkippedProblem(file, skipped));
      continue;
    }
    const error = describeParseError(file, null);
    if (error) problems.push({ file, error });
  }
  return problems;
}

/**
 * Why a present lockfile yielded nothing, or null when nothing is wrong with
 * it (a valid lockfile of a project with no dependencies).
 */
function describeParseError(file: string, error: unknown): string | null {
  let content: string;
  try {
    content = readTextFile(file);
  } catch (readError) {
    return `could not be read (${readError instanceof Error ? readError.message : String(readError)})`;
  }
  if (CONFLICT_MARKER.test(content)) return "it contains git merge-conflict markers (<<<<<<< / >>>>>>>): resolve the conflict and reinstall to regenerate it";
  if (/\.json$/i.test(file)) {
    try {
      JSON.parse(content);
    } catch (parseError) {
      return `invalid JSON (${parseError instanceof Error ? parseError.message.slice(0, 120) : String(parseError)})`;
    }
  }
  if (error) return `could not be parsed (${error instanceof Error ? error.message.slice(0, 120) : String(error)})`;
  if (/\.json$/i.test(file)) return null;
  // A text lockfile of some size that gave no package at all is damaged or in a format this reader does not know.
  const lines = content.split(/\r?\n/).filter((l) => l.trim() !== "").length;
  return lines > 20 ? "no package versions could be read from it (unsupported format or damaged)" : null;
}

/** Instances for a manifest-only read: one per name, scope unknown. */
function manifestInstances(versions: Map<string, string>): PackageInstance[] {
  return [...versions].map(([name, version]) => ({ name, version }));
}

/**
 * A manifest read with no lockfile beside it. Only an exact pin names the
 * version that gets installed; any other requirement ("^1.2.0", "0.8") is
 * kept in `ranges`, and its floor in `versions` is a label, not an install.
 * nushell's samples/wasm/Cargo.toml (no Cargo.lock) was scanned as if its
 * floors were installed and produced 2 false findings (2026-10-10).
 */
function declaredRanges(declared: Map<string, string>, exact: (spec: string) => boolean, file: string): VersionSource {
  const versions = new Map<string, string>();
  const ranges = new Map<string, string>();
  for (const [name, spec] of declared) {
    // "0.3" and "1" are ranges too: their floor is 0.3.0 / 1.0.0.
    const partial = /(\d+)(?:\.(\d+))?/.exec(spec);
    const version = extractVersionFromSpec(spec) ?? (partial ? `${partial[1]}.${partial[2] ?? "0"}.0` : null);
    if (!version) continue;
    versions.set(name, version);
    if (!exact(spec)) ranges.set(name, spec);
  }
  // Only exact pins are installs; ranged names are not instances at all.
  const pinned = new Map([...versions].filter(([name]) => !ranges.has(name)));
  return found(versions, manifestInstances(pinned), file, "declared_ranges", { ranges });
}

// =============================================================================
// npm: package-lock.json > npm-shrinkwrap.json > pnpm-lock.yaml > yarn.lock > bun.lock > package.json ranges
// =============================================================================

/** What one npm-family lockfile holds, as its reader reports it. */
interface NpmLockRead {
  versions: Map<string, string>;
  instances: InstanceSet;
  uncheckable: NonRegistryEntry[];
  aliases?: Map<string, string>;
  problems: LockfileProblem[];
}

/**
 * The npm-family lockfiles in the order they are preferred, each with its
 * reader. A reader returns null for a file that holds no package at all and
 * throws for one it cannot parse.
 */
const NPM_LOCK_READERS: Array<{ name: string; read: (file: string, cwd: string) => NpmLockRead | null }> = [
  { name: "package-lock.json", read: readNpmLockFile },
  { name: "npm-shrinkwrap.json", read: readNpmLockFile },
  {
    // v5.x, v6 and v9, read by column; see js-lockfile-readers.ts
    name: "pnpm-lock.yaml",
    read(file) {
      const content = readTextFile(file);
      const versions = new Map<string, string>();
      const instances = new InstanceSet();
      const report = emptyReadReport();
      readPnpmLock(content, versions, instances, report);
      if (versions.size === 0) return null;
      const damage = pnpmLockDamage(content, report.missingDirect);
      return { versions, instances, uncheckable: report.uncheckable, problems: damage ? [damagedProblem(file, damage)] : [] };
    },
  },
  {
    // v1 and berry
    name: "yarn.lock",
    read(file, cwd) {
      const versions = new Map<string, string>();
      const instances = new InstanceSet();
      const specs = new Map<string, string>();
      const report = emptyReadReport();
      const skipped = readYarnLock(readTextFile(file), versions, instances, specs, report);
      // The copy a direct dependency resolves to is the one its package.json range names.
      for (const [name, range] of manifestRanges(cwd)) {
        const version = specs.get(`${name}@${range}`);
        if (version) versions.set(name, version);
      }
      if (versions.size === 0) return null;
      const problems: LockfileProblem[] = skipped > 0 ? [yarnSkippedProblem(file, skipped)] : [];
      if (report.incomplete > 0) {
        const entries = report.incomplete === 1 ? "1 entry names a package but no version" : `${report.incomplete} entries name a package but no version`;
        problems.push(damagedProblem(file, { reason: `it is truncated or damaged: ${entries}`, missing: report.incomplete }));
      }
      return { versions, instances, uncheckable: report.uncheckable, problems };
    },
  },
  {
    // Bun 1.2+ text lockfile; the binary bun.lockb is not readable (binaryBunLock)
    name: "bun.lock",
    read(file) {
      const versions = new Map<string, string>();
      const instances = new InstanceSet();
      const report = emptyReadReport();
      readBunLock(readTextFile(file), versions, instances, report);
      return versions.size > 0 ? { versions, instances, uncheckable: report.uncheckable, problems: [] } : null;
    },
  },
];

function readNpmLockFile(file: string): NpmLockRead | null {
  const read = readPackageLock(JSON.parse(readTextFile(file)));
  if (read.instances.size === 0 && read.uncheckable.length === 0) return null;
  return { versions: read.versions, instances: read.instances, uncheckable: read.uncheckable, aliases: read.aliases, problems: [] };
}

function resolveNpm(cwd: string): VersionSource {
  let chosen: { name: string; file: string; read: NpmLockRead } | null = null;
  const others: string[] = [];
  for (const reader of NPM_LOCK_READERS) {
    const file = path.join(cwd, reader.name);
    if (!fs.existsSync(file)) continue;
    if (chosen) {
      others.push(reader.name);
      continue;
    }
    try {
      const read = reader.read(file, cwd);
      if (read) chosen = { name: reader.name, file, read };
    } catch { /* unreadable: the next lockfile; unreadLockfiles names this one and why */ }
  }

  if (chosen) {
    const { file, read } = chosen;
    const problems = [...read.problems, ...lockfileConflicts(cwd, chosen, others)];
    return found(read.versions, read.instances, file, "lockfile", {
      ...(read.uncheckable.length > 0 ? { uncheckable: read.uncheckable.map((u) => ({ ...u, file })) } : {}),
      ...(read.aliases && read.aliases.size > 0 ? { aliases: read.aliases } : {}),
      ...(problems.length > 0 ? { problems } : {}),
    });
  }

  // No readable lockfile. A binary bun.lockb pins everything, but not in a form this server reads.
  const bunBinary = path.join(cwd, BUN_BINARY_LOCK);
  const problems: LockfileProblem[] = fs.existsSync(bunBinary)
    ? [
        {
          file: bunBinary,
          error:
            "bun.lockb is Bun's binary lockfile, which this server cannot read: run `bun install --save-text-lockfile` (Bun 1.2 or later) to write bun.lock, then scan again",
        },
      ]
    : [];

  // No lockfile: package.json declares ranges, not installed versions.
  const pkgPath = path.join(cwd, "package.json");
  if (fs.existsSync(pkgPath)) {
    const declared = new Map<string, string>();
    const uncheckable: NonRegistryEntry[] = [];
    const aliases = new Map<string, string>();
    try {
      const pkg = JSON.parse(readTextFile(pkgPath));
      for (const [name, spec] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
        if (typeof spec !== "string") continue;
        // `"x": "github:user/repo"` or a tarball URL is not a version of the registry's x.
        const other = nonRegistrySource(spec, spec);
        if (other === "local") continue;
        // `"my-lodash": "npm:lodash@4.17.20"` declares lodash, under another folder name.
        const alias = /^npm:((?:@[^/@\s]+\/)?[^/@\s]+)@(.+)$/.exec(spec.trim());
        if (other) uncheckable.push({ name, version: null, kind: other });
        else if (alias && NPM_NAME.test(alias[1])) {
          declared.set(alias[1], alias[2]);
          aliases.set(name, alias[1]);
        } else declared.set(name, spec);
      }
    } catch { /* skip */ }
    // npm installs exactly "1.2.3" (or "=1.2.3"); anything else is a range.
    const read = declaredRanges(declared, (spec) => /^=?v?\d+\.\d+\.\d+(?:-[\w.]+)?$/.test(spec.trim()), pkgPath);
    return {
      ...read,
      ...(uncheckable.length > 0 ? { uncheckable: uncheckable.map((u) => ({ ...u, file: pkgPath })) } : {}),
      ...(aliases.size > 0 ? { aliases } : {}),
      ...(problems.length > 0 ? { problems } : {}),
    };
  }

  return problems.length > 0 ? { ...emptySource(), problems } : emptySource();
}

/** How many differing names a conflict note spells out. */
const CONFLICT_EXAMPLES = 3;

/**
 * The other lockfiles in a directory whose lockfile was read, when they do
 * not agree with it. One directory, two package managers' lockfiles: only one
 * of them is what gets installed, and the reader took the first by rank
 * without a word. Now the answer says which was read and that the other
 * exists and pins something else (audit 2026-11-11).
 *
 * An empty lockfile beside a full one hides nothing and is not reported; one
 * that cannot be parsed is, because it could not be compared.
 */
function lockfileConflicts(cwd: string, chosen: { name: string; read: NpmLockRead }, others: string[]): LockfileProblem[] {
  const problems: LockfileProblem[] = [];
  const pins = (read: NpmLockRead) => {
    const byName = new Map<string, Set<string>>();
    for (const i of read.instances.toArray()) byName.set(i.name, (byName.get(i.name) ?? new Set()).add(i.version));
    return byName;
  };
  const mine = pins(chosen.read);
  for (const name of others) {
    const file = path.join(cwd, name);
    let other: NpmLockRead | null = null;
    let failure: string | null = null;
    try {
      other = NPM_LOCK_READERS.find((r) => r.name === name)?.read(file, cwd) ?? null;
      if (!other) failure = describeParseError(file, null);
    } catch (error) {
      failure = describeParseError(file, error) ?? "could not be parsed";
    }
    if (!other) {
      if (failure) problems.push({ file, conflict: true, error: `${chosen.name} was read instead, and this lockfile could not be compared with it: ${failure}` });
      continue;
    }
    const theirs = pins(other);
    const differing: string[] = [];
    for (const pkg of new Set([...mine.keys(), ...theirs.keys()])) {
      const a = [...(mine.get(pkg) ?? [])].sort();
      const b = [...(theirs.get(pkg) ?? [])].sort();
      if (a.join(",") !== b.join(",")) differing.push(`${pkg} ${b.join("/") || "absent"} here, ${a.join("/") || "absent"} in ${chosen.name}`);
    }
    if (differing.length === 0) continue;
    differing.sort();
    problems.push({
      file,
      conflict: true,
      error: `${chosen.name} was read instead (it ranks first), and this lockfile pins a different set: ${differing.length} package${differing.length === 1 ? "" : "s"} differ (${differing.slice(0, CONFLICT_EXAMPLES).join("; ")}${differing.length > CONFLICT_EXAMPLES ? "; ..." : ""}). One of the two is stale and the scan cannot tell which: delete the one your package manager does not write`,
    });
  }
  const bunBinary = path.join(cwd, BUN_BINARY_LOCK);
  if (chosen.name !== "bun.lock" && fs.existsSync(bunBinary)) {
    problems.push({
      file: bunBinary,
      conflict: true,
      error: `${chosen.name} was read instead; bun.lockb is Bun's binary lockfile, which this server cannot read, so it could not be compared. If Bun installs this project, ${chosen.name} may be stale`,
    });
  }
  return problems;
}

/** The package name a package-lock `packages` key installs: the segment after its LAST `node_modules/`. */
export function packageNameFromNodeModulesPath(lockPath: string): string {
  const marker = "node_modules/";
  const index = lockPath.lastIndexOf(marker);
  return index === -1 ? "" : lockPath.slice(index + marker.length);
}

interface LockEntry {
  /** v2/v3: the package's real name, written when it differs from the folder (an alias, a git dependency). */
  name?: string;
  version?: string;
  resolved?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, LockEntry | string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

/** A registry package name, scoped or not. */
const NPM_NAME = /^(?:@[a-z0-9~][a-z0-9._~-]*\/)?[a-z0-9~][a-z0-9._~-]*$/i;

/** v1: `"version": "npm:lodash@4.17.20"` under the alias's key. */
const V1_ALIAS = /^npm:((?:@[^/@\s]+\/)?[^/@\s]+)@(\d\S*)$/;

/**
 * package-lock.json / npm-shrinkwrap.json, lockfile v1, v2 and v3.
 *
 * v2/v3 `packages` keys are install paths: `node_modules/a` is the hoisted
 * copy a direct dependency of the root resolves to, `node_modules/a/node_modules/b`
 * a nested one. npm writes `dev: true` on every entry only reachable from
 * devDependencies (`devOptional` = also reachable as an optional runtime dep,
 * so runtime), which makes the dev scope of a TRANSITIVE known. v1 nests the
 * same information under `dependencies`.
 *
 * The folder is not always the package. An alias (`"my-lodash":
 * "npm:lodash@4.17.20"`) installs lodash into node_modules/my-lodash: v2/v3
 * write the real `name` on the entry, v1 writes the spec as the version. Both
 * were read under the alias, so OSV was asked about `my-lodash` and answered
 * "no advisories" for a vulnerable lodash (audit 2026-11-11, M9). And an entry
 * resolved from git or an arbitrary URL is not a registry release at all:
 * `uncheckable`, never an instance.
 */
export function readPackageLock(lock: {
  packages?: Record<string, LockEntry>;
  dependencies?: Record<string, LockEntry>;
}): { versions: Map<string, string>; instances: InstanceSet; uncheckable: NonRegistryEntry[]; aliases: Map<string, string> } {
  const versions = new Map<string, string>();
  const instances = new InstanceSet();
  const uncheckable: NonRegistryEntry[] = [];
  const aliases = new Map<string, string>();

  if (lock.packages) {
    // What asked for each name, to tell a URL dependency from a registry with tarball paths of its own.
    // Appended in place: copying the list on every request made a name requested by 50,000 packages
    // cost 50,000²/2 copies (100,000 entries: 6.2 s of a 7.1 s read; pre-publish round 7).
    const requested = new Map<string, string[]>();
    for (const entry of Object.values(lock.packages)) {
      for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const) {
        const specs = entry?.[field];
        if (!specs || typeof specs !== "object") continue;
        for (const name in specs) {
          if (!Object.hasOwn(specs, name)) continue;
          const spec = specs[name];
          if (typeof spec !== "string") continue;
          const list = requested.get(name);
          if (list) list.push(spec);
          else requested.set(name, [spec]);
        }
      }
    }
    const urlRequested = (folder: string): string | undefined => {
      const specs = requested.get(folder) ?? [];
      return specs.length > 0 && specs.every((s) => nonRegistrySource(s, s) !== null) ? specs[0] : undefined;
    };

    const hoistedAliases: Array<[string, string]> = [];
    for (const [key, value] of Object.entries(lock.packages)) {
      const folder = packageNameFromNodeModulesPath(key);
      if (!folder || !value || value.link) continue;
      const name = typeof value.name === "string" && NPM_NAME.test(value.name) ? value.name : folder;
      const other = typeof value.resolved === "string" ? nonRegistrySource(value.resolved, urlRequested(folder)) : null;
      if (other) {
        if (other !== "local") uncheckable.push({ name, version: value.version ?? null, kind: other });
        continue;
      }
      if (!value.version) continue;
      instances.add(name, value.version, value.dev === true);
      // The hoisted root copy is what `require(name)` from the project resolves to.
      if (key !== `node_modules/${folder}`) continue;
      if (name === folder) versions.set(name, value.version);
      else {
        aliases.set(folder, name);
        hoistedAliases.push([name, value.version]);
      }
    }
    // An aliased copy speaks for its package only when the package is not also installed under its own name.
    for (const [name, version] of hoistedAliases) {
      if (!versions.has(name)) versions.set(name, version);
    }
    // A workspace package's own nested copy (packages/x/node_modules/a) when nothing is hoisted.
    for (const instance of instances.toArray()) {
      if (!versions.has(instance.name)) versions.set(instance.name, instance.version);
    }
  }

  if (instances.size === 0 && uncheckable.length === 0 && lock.dependencies) {
    const topAliases: Array<[string, string]> = [];
    const walk = (deps: Record<string, LockEntry | string>, topLevel: boolean) => {
      for (const [folder, value] of Object.entries(deps)) {
        if (!value || typeof value !== "object") continue;
        const version = typeof value.version === "string" ? value.version : "";
        const alias = V1_ALIAS.exec(version);
        if (alias && NPM_NAME.test(alias[1])) {
          instances.add(alias[1], alias[2], value.dev === true);
          if (topLevel) {
            aliases.set(folder, alias[1]);
            topAliases.push([alias[1], alias[2]]);
          }
        } else if (/^\d/.test(version)) {
          instances.add(folder, version, value.dev === true);
          if (topLevel) versions.set(folder, version);
        } else if (version) {
          // v1 writes a git or URL dependency's location as its version.
          const other = nonRegistrySource(version, version);
          if (other && other !== "local") uncheckable.push({ name: folder, version: null, kind: other });
        }
        if (value.dependencies) walk(value.dependencies, false);
      }
    };
    walk(lock.dependencies, true);
    for (const [name, version] of topAliases) {
      if (!versions.has(name)) versions.set(name, version);
    }
  }

  return { versions, instances, uncheckable, aliases };
}

// =============================================================================
// Rust: Cargo.lock
// =============================================================================

interface CargoPackage {
  name: string;
  version: string;
  source: string | null;
  dependencies: string[];
}

/**
 * Every `[[package]]` table in a Cargo.lock, read field by field. The old
 * reader required `name` and `version` on consecutive lines; that holds for
 * cargo's own writer, but the table is TOML and nothing else guarantees it.
 */
export function parseCargoLockPackages(content: string): CargoPackage[] {
  const packages: CargoPackage[] = [];
  for (const block of content.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[(?!\[package\]\])/m)[0];
    const field = (key: string) => new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, "m").exec(body)?.[1] ?? null;
    const name = field("name");
    const version = field("version");
    if (!name || !version) continue;
    const depsMatch = /^dependencies\s*=\s*\[([\s\S]*?)\]/m.exec(body);
    const dependencies = depsMatch ? [...depsMatch[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]) : [];
    packages.push({ name, version, source: field("source"), dependencies });
  }
  return packages;
}

/** The line shapes cargo writes into a Cargo.lock (lockfile 1 to 4), trimmed. Anything else is not lockfile syntax. */
const CARGO_LOCK_LINES = [
  /^#/,
  /^version\s*=\s*\d+$/,
  /^\[\[[A-Za-z0-9_.-]+\]\]$/,
  /^\[[A-Za-z0-9_.-]+\]$/,
  /^(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*")\s*=\s*"(?:[^"\\]|\\.)*"$/,
  /^[A-Za-z0-9_-]+\s*=\s*\[(?:.*\])?$/,
  /^"(?:[^"\\]|\\.)*",?$/,
  /^\]$/,
];

/**
 * Why a Cargo.lock is not the whole file cargo wrote, or null when nothing
 * says so. A lockfile cut short still parses table by table, so a truncated
 * one read as 14 of its 85 packages with no notice (audit 2026-11-11, M12).
 *
 * Three signs, each absent from every file cargo writes: a line that is not
 * lockfile syntax (an unterminated string, a half-written table header), a
 * `[[package]]` table with no name or version, and a package named in some
 * `dependencies` list that has no table of its own. The last one catches a
 * file cut cleanly between two tables.
 */
export function cargoLockDamage(content: string, packages: CargoPackage[] = parseCargoLockPackages(content)): LockDamage | null {
  const malformed: number[] = [];
  let arrayOpen = false;
  content.split(/\r?\n/).forEach((raw, index) => {
    const text = raw.trim();
    if (text === "" || text.length > MAX_LOCKFILE_LINE) return;
    if (!CARGO_LOCK_LINES.some((shape) => shape.test(text))) malformed.push(index + 1);
    else if (/=\s*\[$/.test(text)) arrayOpen = true;
    else if (text === "]") arrayOpen = false;
  });
  const tables = content.split(/^\[\[package\]\]\s*$/m).length - 1;
  const nameless = tables - packages.length;
  const names = new Set(packages.map((pkg) => pkg.name));
  const dangling = new Set<string>();
  for (const pkg of packages) {
    for (const dep of pkg.dependencies) {
      const name = dep.split(" ")[0];
      if (name && !names.has(name)) dangling.add(name);
    }
  }

  const parts: string[] = [];
  if (malformed.length > 0) {
    parts.push(`line${malformed.length === 1 ? "" : "s"} ${malformed.slice(0, 5).join(", ")}${malformed.length > 5 ? ", ..." : ""} ${malformed.length === 1 ? "is" : "are"} not lockfile syntax`);
  }
  if (arrayOpen) parts.push("its last `dependencies` list is not closed");
  if (nameless > 0) parts.push(`${nameless} [[package]] table${nameless === 1 ? " has" : "s have"} no name or version`);
  if (dangling.size > 0) {
    const list = [...dangling].sort();
    parts.push(`${dangling.size} package${dangling.size === 1 ? "" : "s"} named as ${dangling.size === 1 ? "a dependency has" : "dependencies have"} no [[package]] table (${list.slice(0, 3).join(", ")}${list.length > 3 ? ", ..." : ""})`);
  }
  if (parts.length === 0) return null;
  return { reason: `it is truncated or damaged: ${parts.join("; ")}`, missing: dangling.size + Math.max(0, nameless) };
}

function resolveRust(cwd: string): VersionSource {
  const lockPath = path.join(cwd, "Cargo.lock");
  if (!fs.existsSync(lockPath)) {
    return resolveRustFromManifest(cwd);
  }

  const versions = new Map<string, string>();
  const instances = new InstanceSet();
  const problems: LockfileProblem[] = [];
  const privateIndex: PrivateIndexEntry[] = [];
  try {
    const content = readTextFile(lockPath);
    const packages = parseCargoLockPackages(content);
    const damage = cargoLockDamage(content, packages);
    if (damage) problems.push(damagedProblem(lockPath, damage));
    const versionsByName = new Map<string, string[]>();
    // Cargo writes `source` on every registry or git package. In a file it
    // wrote, a package with none is a workspace member or path dependency:
    // local code, not a release, so no advisory can be about it. A lockfile
    // with no `source` anywhere was not written by cargo; keep everything.
    const cargoWritten = packages.some((pkg) => pkg.source !== null);
    const isLocal = (pkg: CargoPackage) => cargoWritten && pkg.source === null;
    for (const pkg of packages) {
      // Local code is no crates.io release: its name is never sent either (R8: a path workspace member
      // went to crates.io and OSV.dev from dependency_check, upgrade_impact and the briefing).
      if (isLocal(pkg)) {
        privateIndex.push({ name: pkg.name, version: pkg.version, registry: "local code (a workspace member or path dependency)", file: lockPath, local: true });
        continue;
      }
      // From a registry other than crates.io, or from git: private (private-packages.ts). Kept as
      // an instance so the set is whole; the live layer leaves it out of every lookup.
      if (pkg.source && !isPublicCratesSource(pkg.source)) privateIndex.push({ name: pkg.name, version: pkg.version, registry: sourceLabel(pkg.source), file: lockPath });
      instances.add(pkg.name, pkg.version);
      versionsByName.set(pkg.name, [...(versionsByName.get(pkg.name) ?? []), pkg.version]);
    }
    // The version a direct dependency resolves to: the one a workspace member
    // names. Cargo writes "name version" when two versions coexist, else "name".
    for (const member of packages.filter(isLocal)) {
      for (const dep of member.dependencies) {
        const [name, version] = dep.split(" ");
        const candidates = versionsByName.get(name);
        if (!candidates || versions.has(name)) continue;
        if (version && candidates.includes(version)) versions.set(name, version);
        else if (!version && candidates.length === 1) versions.set(name, candidates[0]);
      }
    }
    for (const [name, list] of versionsByName) {
      if (!versions.has(name)) versions.set(name, list[0]);
    }
  } catch { /* skip */ }

  return found(versions, instances, lockPath, "lockfile", {
    ...(problems.length > 0 ? { problems } : {}),
    ...(privateIndex.length > 0 ? { privateIndex } : {}),
  });
}

function resolveRustFromManifest(cwd: string): VersionSource {
  const declared = new Map<string, string>();
  const cargoPath = path.join(cwd, "Cargo.toml");
  if (!fs.existsSync(cargoPath)) return emptySource();

  try {
    // name = "1.0" or name = { version = "1.0", ... }, inside dependency tables
    // only: [package]'s own `version = "0.1.0"` and `edition = "2021"` were read
    // as crates named "version" and "edition".
    let inDeps = false;
    for (const line of readTextFile(cargoPath).split(/\r?\n/)) {
      const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
      if (header) {
        inDeps = /(?:^|\.)(?:dev-|build-)?dependencies$/.test(header[1].trim());
        continue;
      }
      if (!inDeps) continue;
      const match = /^\s*([a-zA-Z_][\w-]*)\s*=\s*(?:"([^"]+)"|.*?\bversion\s*=\s*"([^"]+)")/.exec(line);
      const spec = match?.[2] ?? match?.[3];
      if (match && spec && /^[=^~]?\s*\d/.test(spec)) declared.set(match[1], spec);
    }
  } catch { /* skip */ }

  // Cargo reads "1.0" as "^1.0": only "=1.2.3" names one version.
  return declaredRanges(declared, (spec) => /^=\s*\d+\.\d+\.\d+/.test(spec.trim()), cargoPath);
}

// =============================================================================
// Helpers
// =============================================================================

/** package.json dependency ranges (all dependency fields), or none when unreadable. */
function manifestRanges(cwd: string): Array<[string, string]> {
  try {
    const pkg = JSON.parse(readTextFile(path.join(cwd, "package.json")));
    const out: Array<[string, string]> = [];
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const [name, range] of Object.entries(pkg[field] ?? {})) {
        if (typeof range === "string") out.push([name, range]);
      }
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Extract a usable version from an npm version specifier.
 * "^4.18.2" -> "4.18.2", "~1.0.0" -> "1.0.0", ">=2.0.0" -> "2.0.0"
 */
function extractVersionFromSpec(spec: string): string | null {
  if (!spec) return null;
  const match = spec.match(/(\d+\.\d+\.\d+(?:-[\w.]+)?)/);
  return match ? match[1] : null;
}
