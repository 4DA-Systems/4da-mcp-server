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
import * as os from "node:os";
import * as path from "node:path";
import { oversize, tooLargeText } from "./bounded-read.js";
import { anySignatureChanged, fileSignature, signatureMap, signatureMtime, type FileSignature } from "./file-signature.js";
import { requirementFiles } from "./lockfile-parsers-pygo.js";
import { checkInstallState } from "./install-state.js";
import { expandWorkspaces, memberNamesOf, pnpmYamlList, readManifestDeclarations } from "./js-manifests.js";
import { lazyNpmCatalogs } from "./npm-catalog.js";
import { classifyNpmSpec } from "./npm-spec.js";
import { AMBIGUOUS_SPEC_MARK, AMBIGUOUS_SPEC_START, UNREAD_CATALOG_MARK } from "./private-packages.js";
import { allOverrideSpecs } from "./overrides.js";
import { lockfileCandidates, manifestCandidate, manifestProblemText, manifestSyntaxProblem, resolveVersionSourceSteps } from "./lockfile-parsers.js";
import { lockScopeOf, mapEcosystem, resolveAuditVersionsFrom, resolveVersionsFrom } from "./version-resolver.js";
import { parsePyprojectDependencies } from "../project-manifests.js";
import { scanCurrentProject } from "../project-scanner.js";
import { workspaceSearchDirs } from "../project-tree.js";
import { readManifestText, readTextFile } from "./text-file.js";
import { runSteps, type Steps } from "./yield-point.js";
import type { InstallDriftRecord, ResolutionSourceRecord, ResolvedDependency } from "./types.js";
import type { LockfileProblem, UncheckableDependency, UnpinnedRequirements, VersionSource } from "./lockfile-types.js";
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
  /** PyPI: requirements options that make every name of the install private (VersionSource.registryWide). */
  registryWide: NonNullable<VersionSource["registryWide"]>;
  /** PyPI: every file read records each package's index (VersionSource.indexRecorded). */
  indexRecorded?: true;
  /** PyPI: requirements with no pinned version anywhere in this directory, by the file that lists them. */
  unpinned: UnpinnedRequirements[];
  /** Lockfiles present in this directory that could not be read, with the reason. */
  problems: LockfileProblem[];
  /**
   * npm: the dependencies of this directory that are not registry releases (nonRegistryDirect),
   * with what says so. None of their names is looked up anywhere: no row, and every tool withholds them.
   */
  notRegistry?: NotRegistryDependency[];
  signatures: Map<string, FileSignature>;
  /**
   * Inputs whose signature may move without what the resolution read from them changing (a script
   * edited in package.json, an editor's temporary file beside a requirements file): what was read,
   * as a digest. When only these moved and the digest holds, the group is not re-resolved.
   */
  digests?: Array<{ file: string; digest: string }>;
  resolvedAt: string;
}

/** An npm dependency that is not a registry release, and what says so. */
export interface NotRegistryDependency {
  name: string;
  /** The file that says so: the package.json that declares it, or the lockfile. */
  file: string;
  /** Where it comes from, in words: `the path ../libs/x`, `git (org/repo)`, `a link (a workspace member)`. */
  from: string;
  /** Local code: the directory it is in, when the spec or the workspace says. */
  at?: string;
  /** An alias key, or a key an override replaces with an alias: private only inside this project. */
  aliasKey?: true;
  /** Declared through a catalog that could not be read: where it comes from is not known. */
  unknownSource?: true;
}

/** Workspace member directories under `dir` (package.json `workspaces`, pnpm-workspace.yaml `packages`), relative. */
function workspaceMemberDirs(dir: string, workspaces: string[]): string[] {
  let patterns = workspaces;
  try {
    const yaml = path.join(dir, "pnpm-workspace.yaml");
    if (fs.existsSync(yaml)) patterns = [...patterns, ...pnpmYamlList(readTextFile(yaml), "packages")];
  } catch {
    // unreadable: the patterns package.json gives
  }
  if (patterns.length === 0) return [];
  try {
    return expandWorkspaces(dir, patterns).dirs;
  } catch {
    return [];
  }
}

/** A spec in words, for the reason a name is withheld. Paths and git spellings are the user's own. */
function specWords(kind: "git" | "url" | "file" | "local" | "catalog" | "ambiguous", spec: string, catalogSpec?: string): string {
  const shown = spec.length > 120 ? `${spec.slice(0, 117)}...` : spec;
  if (kind === "ambiguous") {
    const x = shown.replace(/^npm:/i, "");
    return `${AMBIGUOUS_SPEC_START}${x}, which npm reads as the package ${x} and Yarn as the tag or range ${x} of this name, ${AMBIGUOUS_SPEC_MARK}`;
  }
  if (kind === "catalog") return catalogSpec === undefined ? `a catalog entry that could not be found or read (${shown})` : `a catalog entry that is itself a catalog: spec (${shown})`;
  if (catalogSpec !== undefined) return `${specWords(kind, catalogSpec)}, from the catalog (${shown})`;
  if (kind === "git") return `git (${shown})`;
  if (kind === "url") return /^https?:\/\//i.test(spec) ? `the URL ${shown}` : `a source other than the npm registry (${shown})`;
  if (kind === "file") return `the local archive ${shown}`;
  return `the local path ${shown}`;
}

/**
 * The npm dependencies of this directory that are not registry releases, as npm reads them: a spec
 * package.json (or a workspace member's) gives as a path, an archive, git, a URL on a host other than
 * the public registry, `link:` or `workspace:` (classifyNpmSpec, npm-package-arg's rules); a workspace
 * member's own name; and a name the lockfile installs only as a link, from git, a URL or a local
 * archive (`read.elsewhere`, `read.uncheckable`), whatever spec package.json gives it. A name the
 * lockfile ALSO installs from a registry is not among the lockfile's: that copy is a registry release.
 *
 * The 6.5.1 candidate knew only `file:`, `github:` and URL prefixes, so `"../libs/x"`, `"org/repo"`,
 * `"vendor/x-1.0.0.tgz"` and a workspace member declared `^1.0.0` reached registry.npmjs.org,
 * api.npmjs.org and hn.algolia.com by name (review 2026-11-24).
 */
function nonRegistryDirect(dir: string, read: VersionSource, watched: Set<string>, aliases: Map<string, string>, catalogProblems: Array<{ file: string; why: string; names: string[] }> = []): NotRegistryDependency[] {
  const out = new Map<string, NotRegistryDependency>();
  const catalogsByDir = new Map<string, ReturnType<typeof lazyNpmCatalogs>>();
  const catalogsFor = (base: string) => {
    let c = catalogsByDir.get(base);
    if (!c) catalogsByDir.set(base, (c = lazyNpmCatalogs(base)));
    return c;
  };
  const add = (d: NotRegistryDependency) => {
    if (!out.has(d.name)) out.set(d.name, d);
  };
  const manifestFile = path.join(dir, "package.json");
  const root = readManifestDeclarations(manifestFile);
  const manifests: Array<{ file: string; base: string; declared: NonNullable<typeof root>["declared"] }> = root ? [{ file: manifestFile, base: dir, declared: root.declared }] : [];
  const members = root ? workspaceMemberDirs(dir, root.workspaces) : [];
  for (const rel of members) {
    const base = path.join(dir, rel);
    const file = path.join(base, "package.json");
    const member = readManifestDeclarations(file);
    if (member) manifests.push({ file, base, declared: member.declared });
  }
  for (const m of manifests) {
    for (const d of m.declared) {
      let spec = classifyNpmSpec(d.name, d.spec, catalogsFor(m.base));
      // A lockfile that records which package an ambiguous `npm:<x>` installed settles it.
      const locked = spec.kind === "ambiguous" ? read.aliases?.get(d.name) : undefined;
      if (locked) spec = { kind: "registry", name: locked, range: "*" };
      if (spec.kind === "registry") {
        // An `npm:` alias: the key is a folder name the project chose, never a registry package. It
        // installs the target, which is what is checked; the key itself is withheld, with the target named.
        if (spec.name.toLowerCase() !== d.name.toLowerCase()) {
          if (!aliases.has(d.name)) aliases.set(d.name, spec.name);
          add({ name: d.name, file: m.file, from: `an npm: alias of ${spec.name} (${d.spec.trim().slice(0, 120)}): it installs ${spec.name}, so ask about ${spec.name}`, aliasKey: true });
        }
        continue;
      }
      if (spec.kind === "catalog") {
        // Not known where it comes from: withheld, named with the catalog file and why, and the group's
        // scan is incomplete (re-check 2026-11-24: an anchored catalog read as unreadable left the
        // project "complete" with no word of the file).
        const cat = catalogsFor(m.base);
        const catFile = cat.file ?? m.file;
        const why = spec.catalogSpec !== undefined ? `its entry for ${d.name} is itself a catalog: spec` : cat.error ? cat.error : cat.file ? `it has no entry for ${d.name} in ${d.spec.trim() === "catalog:" ? "the default catalog" : d.spec.trim()}` : "no pnpm-workspace.yaml or Bun catalog was found above it";
        add({ name: d.name, file: catFile, from: `${UNREAD_CATALOG_MARK} (${catFile}: ${why})`, unknownSource: true });
        const known = catalogProblems.find((p) => p.file === catFile);
        if (known) known.names.push(d.name);
        else catalogProblems.push({ file: catFile, why, names: [d.name] });
        continue;
      }
      const where = (spec.catalogSpec ?? d.spec).trim().replace(/^(?:file|link|portal):/i, "");
      // Where local source code is (never for `workspace:`, which names a member, or `exec:`).
      const at = spec.kind === "local" && !/^(?:workspace|exec):/i.test((spec.catalogSpec ?? d.spec).trim()) && where !== "" ? path.resolve(m.base, where.replace(/^~(?=[\\/])/, os.homedir())) : undefined;
      add({ name: d.name, file: m.file, from: specWords(spec.kind, d.spec.trim(), spec.catalogSpec), ...(at ? { at } : {}) });
      const target = refusedAliasTarget(d.spec);
      if (target) add({ name: target, file: m.file, from: `named in an npm: alias npm refuses to install (${d.spec.trim().slice(0, 120)})` });
    }
  }
  if (members.length > 0) {
    const names = memberNamesOf(dir, members).names;
    for (const rel of members) {
      const member = readManifestDeclarations(path.join(dir, rel, "package.json"));
      if (member?.name && names.has(member.name)) add({ name: member.name, file: manifestFile, from: `a workspace member (${rel.split(path.sep).join("/")})`, at: path.join(dir, rel) });
    }
  }
  // An override, resolution or pnpm override that forces a dependency to local code, git or a URL
  // (privacy review 2026-11-24: with no lockfile all three names went to the registry and HN).
  if (root) {
    let manifest: unknown = null;
    try {
      manifest = JSON.parse(readManifestText(manifestFile));
    } catch {
      manifest = null;
    }
    const yamlFile = path.join(dir, "pnpm-workspace.yaml");
    let yaml: string | null = null;
    try {
      if (fs.existsSync(yamlFile)) {
        watched.add(yamlFile);
        yaml = readTextFile(yamlFile);
      }
    } catch {
      yaml = null;
    }
    for (const o of allOverrideSpecs(manifest, yaml)) {
      const spec = classifyNpmSpec(o.name, o.spec, catalogsFor(dir));
      const file = o.where.includes("pnpm-workspace.yaml") ? yamlFile : manifestFile;
      if (spec.kind === "registry") {
        // `"x": "npm:ms@2.1.3"` in an override: x is replaced by ms, so the name x installs nothing of
        // its own here, and asked about directly it is withheld, as an alias key is (re-check 2026-11-24).
        if (spec.name.toLowerCase() !== o.name.toLowerCase()) add({ name: o.name, file, from: `replaced by ${spec.name} through ${o.where} (${o.spec.trim().slice(0, 120)}), so ask about ${spec.name}`, aliasKey: true });
        continue;
      }
      const target = refusedAliasTarget(o.spec);
      if (target) add({ name: target, file, from: `named in an npm: alias npm refuses to install, in ${o.where}` });
      const raw = (spec.catalogSpec ?? o.spec).trim();
      const where = raw.replace(/^(?:file|link|portal):/i, "");
      const at = spec.kind === "local" && !/^(?:workspace|exec):/i.test(raw) && where !== "" ? path.resolve(dir, where.replace(/^~(?=[\\/])/, os.homedir())) : undefined;
      add({ name: o.name, file: o.where.includes("pnpm-workspace.yaml") ? yamlFile : manifestFile, from: `${specWords(spec.kind, o.spec.trim(), spec.catalogSpec)}, forced by ${o.where}`, ...(at ? { at } : {}) });
    }
  }
  // A member of a workspace whose root is above it: the root's own packages are this project's own
  // too, with or without a lockfile (review 2026-11-24: started in packages/a with no lockfile, the
  // sibling members' names went to the registry). Read within the bounds findWorkspaceRoot uses.
  if (!root || root.workspaces.length === 0) {
    const enclosing = enclosingNpmWorkspace(dir, watched);
    if (enclosing) for (const d of nonRegistryDirect(enclosing, NO_LOCKFILE, watched, aliases)) add(d);
  }
  if (read.source) {
    const lockNames = [...(read.elsewhere ?? []), ...(read.uncheckable ?? []).map((u) => u.name)];
    for (const name of lockNames) {
      if (!read.versions.has(name)) add({ name, file: read.source, from: "a link, git, a URL or a local archive (the lockfile's own entry)" });
    }
  }
  // A catalog that was read is watched: an edit to it re-resolves the group.
  for (const c of catalogsByDir.values()) {
    const got = c.read();
    if (got?.file) watched.add(got.file);
  }
  return [...out.values()];
}

/**
 * The target named by an `npm:` alias that npm refuses (an alias of an alias, a target with a URL or
 * path behind it): nothing installs it, and it was written by the project, so it is withheld too.
 */
function refusedAliasTarget(rawSpec: string): string | null {
  const spec = rawSpec.trim();
  if (!/^npm:/i.test(spec)) return null;
  const rest = spec.slice(4);
  const at = rest.indexOf("@", rest.startsWith("@") ? 1 : 0);
  const target = at > 0 ? rest.slice(0, at) : null;
  return target && /^(?:@[a-z0-9~][a-z0-9._~-]*\/)?[a-z0-9~][a-z0-9._~-]*$/i.test(target) ? target : null;
}

/** A version source with nothing read: the enclosing workspace root's manifests are read, not its lockfile. */
const NO_LOCKFILE = { kind: "none", source: null, versions: new Map<string, string>() } as unknown as VersionSource;

/**
 * The npm workspace root above `dir` that lists it as a member (package.json `workspaces` or
 * pnpm-workspace.yaml `packages`), nearest first, within workspaceSearchDirs's bounds; null when
 * none does. The files it reads are added to `watched`.
 */
function enclosingNpmWorkspace(dir: string, watched: Set<string>): string | null {
  for (const ancestor of workspaceSearchDirs(path.resolve(dir))) {
    const manifest = path.join(ancestor, "package.json");
    const yaml = path.join(ancestor, "pnpm-workspace.yaml");
    const hasYaml = fs.existsSync(yaml);
    const declared = readManifestDeclarations(manifest);
    if (!hasYaml && (!declared || declared.workspaces.length === 0)) continue;
    watched.add(manifest);
    if (hasYaml) watched.add(yaml);
    const rel = path.relative(ancestor, path.resolve(dir)).split(path.sep).join("/");
    const members = workspaceMemberDirs(ancestor, declared?.workspaces ?? []).map((m) => m.split(path.sep).join("/"));
    if (members.includes(rel)) return ancestor;
  }
  return null;
}

export function resolveGroup(group: ResolutionGroup): GroupResolution {
  return runSteps(resolveGroupSteps(group));
}

/**
 * resolveGroup as steps: the same resolution, pausing inside the lockfile read and between its
 * stages when run by runStepsYielding (the first call's init; pre-publish round 10, W11).
 */
export function* resolveGroupSteps(group: ResolutionGroup): Steps<GroupResolution> {
  const resolvedAt = new Date().toISOString();
  const ecosystem = mapEcosystem(group.language);
  const manifest = manifestCandidate(group.dir, ecosystem);
  // Python: the directory (and requirements/) too, so a requirements file created later is seen.
  const listings = ecosystem === "PyPI" ? [group.dir, path.join(group.dir, "requirements")] : [];
  const signatures = signatureMap([
    ...lockfileCandidates(group.dir, ecosystem),
    ...(manifest ? [manifest] : []),
    ...listings,
  ]);
  // Taken after the signatures, so an edit that lands in between reads as a change.
  const digests = [...(manifest ? [manifest] : []), ...listings].map((file) => ({ file, digest: inputDigest(file, group.dir) }));

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
      registryWide: [],
      unpinned: [],
      signatures,
      resolvedAt,
    };
  }

  const read = yield* resolveVersionSourceSteps(group.dir, ecosystem);
  // A manifest that cannot be parsed, whatever the lockfile beside it: named as unreadable, never
  // "nothing declared" (review 2026-11-24: beside a readable lockfile it read as complete and clean).
  const manifestNamed = manifest !== null && (read.problems ?? []).some((p) => path.resolve(p.file) === path.resolve(manifest));
  const manifestBroken = manifest !== null && !manifestNamed ? manifestSyntaxProblem(manifest) : null;
  const manifestProblems: LockfileProblem[] = manifest !== null && manifestBroken ? [{ file: manifest, error: manifestProblemText(manifestBroken), ecosystem }] : [];
  yield;
  const readFiles = read.source ? [read.source, ...(read.extraSources ?? [])] : [];
  // The manifest is watched whether or not a lockfile was read: a dependency added to or removed
  // from it is a direct row, or is gone, on the next call, and decides whether the lockfile is
  // older than it (review 2026-11-24: beside a read lockfile the manifest was dropped from the
  // signatures, so such an edit went unseen until a restart). Editing a script changes nothing the
  // resolution read (inputDigest), so it re-resolves nothing (groupIsStale).

  // Ruby and PHP: the lockfile (and composer.json) name the direct dependencies; the project scanner does not.
  const fromLock = group.deps.length === 0 && group.devDeps.length === 0 && read.direct;
  // An npm alias is declared under the folder name it installs into; the dependency is the package behind it.

  // npm: a dependency package.json takes from a path (a `file:` directory or archive), git or a URL
  // is not the registry package of its name, and the name may be private: it gets no direct row, so
  // no registry lookup is made by its name. 6.5.0 sent `"acme-lib": "file:libs/acme-lib"` to
  // registry.npmjs.org and api.npmjs.org from dependency_health and upgrade_planner. What such a
  // dependency installs is listed under coverage.not_checkable as before.
  const watched = new Set<string>();
  // npm: every alias key, from the lockfile reader (package-lock) and from the manifests themselves
  // (the pnpm, Yarn and Bun readers record none: review 2026-11-24, the key went to the registry).
  const manifestAliases = new Map<string, string>();
  const catalogProblems: Array<{ file: string; why: string; names: string[] }> = [];
  const notRegistry = ecosystem === "npm" ? nonRegistryDirect(group.dir, read, watched, manifestAliases, catalogProblems) : [];
  const aliasOf = (name: string) => read.aliases?.get(name) ?? manifestAliases.get(name) ?? name;
  const real = (names: string[]) => (read.aliases || manifestAliases.size > 0 ? [...new Set(names.map(aliasOf))] : names);
  for (const file of watched) if (!signatures.has(file)) signatures.set(file, signatureMap([file]).get(file) ?? "absent");
  const elsewhere = new Set(notRegistry.map((d) => d.name));
  const registryOnly = (names: string[]) => (elsewhere.size > 0 ? names.filter((name) => !elsewhere.has(name)) : names);
  const deps = registryOnly(real(fromLock ? fromLock.deps : group.deps));
  const devDeps = registryOnly(real(fromLock ? fromLock.devDeps : group.devDeps));
  const lockScope = lockScopeOf(read);
  let resolved = resolveVersionsFrom(group.dir, deps, devDeps, ecosystem, read.versions, group.targets, lockScope);
  // No lockfile: a ranged dependency's version is the range's floor, a label.
  const ranges = read.kind === "declared_ranges" ? read.ranges ?? new Map<string, string>() : null;
  if (ranges && ranges.size > 0) {
    resolved = resolved.map((dep) => {
      const declaredRange = ranges.get(dep.name);
      return declaredRange ? { ...dep, declaredRange } : dep;
    });
  }
  yield;
  let drift: InstallDriftRecord[] = [];
  let driftAudit: ResolvedDependency[] = [];
  // Only a lockfile pins exact versions; comparing node_modules against a
  // manifest's specifier floor would report drift that is not there.
  if (ecosystem === "npm" && read.kind === "lockfile" && read.source) {
    const install = checkInstallState(group.dir, resolved, read.source, read.versions);
    resolved = install.resolved;
    drift = install.drift;
    driftAudit = install.driftAuditDeps;
    for (const [file, signature] of install.signatures) signatures.set(file, signature);
  }

  yield;
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
      lockScope,
    ),
    ...driftAudit,
  ].filter((dep) => !dep.declaredRange);

  yield;
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
    registryWide: read.registryWide ?? [],
    ...(read.indexRecorded ? { indexRecorded: true as const } : {}),
    unpinned,
    problems: [
      ...(read.problems ?? []),
      ...manifestProblems,
      ...catalogProblems.map((c) => ({ file: c.file, ecosystem, error: `${c.why}, so ${c.names.slice(0, 5).join(", ")}${c.names.length > 5 ? ", ..." : ""}, declared through it, ${c.names.length === 1 ? "was" : "were"} not resolved and NOT checked: fix the catalog, then scan again` })),
    ],
    ...(notRegistry.length > 0 ? { notRegistry } : {}),
    signatures,
    digests,
    resolvedAt,
  };
}

/** The package.json fields a resolution reads; any other field (scripts, metadata) can change freely. */
const MANIFEST_FIELDS = ["name", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundleDependencies", "bundledDependencies", "workspaces", "overrides", "resolutions", "pnpm", "catalog", "catalogs", "packageManager"];

/**
 * What a resolution read from `file`, as a string that changes when that does: the dependency fields
 * of a package.json, the whole text of any other manifest, and for a directory the requirements files
 * it holds. "unreadable" or "absent" when it cannot be read.
 */
function inputDigest(file: string, groupDir: string): string {
  try {
    const st = fs.statSync(file);
    if (st.isDirectory()) return `dir:${requirementFiles(groupDir).join("|")}`;
  } catch {
    return "absent";
  }
  let text: string;
  try {
    text = readManifestText(file);
  } catch {
    return "unreadable";
  }
  if (path.basename(file) !== "package.json") return `text:${text}`;
  try {
    const parsed: unknown = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return `text:${text}`;
    const record = parsed as Record<string, unknown>;
    return `json:${JSON.stringify(MANIFEST_FIELDS.map((k) => record[k] ?? null))}`;
  } catch {
    return `text:${text}`;
  }
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

/**
 * A resolution group for each pyproject.toml below the root that has no lockfile beside it and no
 * workspace lockfile above it (`discovery.unlockedManifests`). Such a manifest was only counted:
 * its `[tool.uv] index-url`, `[[tool.uv.index]]`, `[[tool.poetry.source]]` or `[[tool.pdm.source]]`
 * was never read for that folder, its dependencies were never named, and dependency_check and the
 * briefing sent them, and a new name, to OSV.dev and pypi.org (pre-publish round 10, W4). As a
 * group, its index rules apply under it (PrivatePackageRules reads a group's directory) and its
 * dependencies are listed as unpinned, never checked (pyprojectUnpinned).
 */
export function unlockedPythonGroups(root: string, manifests: ReadonlyArray<{ path: string; ecosystem: string }>, known: ReadonlyArray<ResolutionGroup>): ResolutionGroup[] {
  const taken = new Set(known.filter((g) => g.language === "python").map((g) => path.resolve(g.dir).toLowerCase()));
  const out: ResolutionGroup[] = [];
  for (const m of manifests) {
    if (m.ecosystem !== "PyPI" || path.basename(m.path) !== "pyproject.toml") continue;
    const dir = path.resolve(root, path.dirname(m.path));
    if (taken.has(dir.toLowerCase())) continue;
    taken.add(dir.toLowerCase());
    try {
      const parsed = parsePyprojectDependencies(readTextFile(path.join(dir, "pyproject.toml")));
      out.push({ dir, language: "python", deps: parsed.deps, devDeps: parsed.devDeps, targets: {} });
    } catch {
      // unreadable: the discovery note already says it was not checked
    }
  }
  return out;
}

/** True when any file the resolution depended on changed, appeared, or vanished. */
export function groupIsStale(result: GroupResolution): boolean {
  if (!anySignatureChanged(result.signatures)) return false;
  const digests = new Map((result.digests ?? []).map((d) => [d.file, d.digest]));
  const moved: string[] = [];
  for (const [file, recorded] of result.signatures) if (fileSignature(file) !== recorded) moved.push(file);
  // Only inputs with a digest moved, and what was read from them is the same: take the new
  // signatures and keep the resolution (a script edited in package.json, a temporary file).
  if (moved.length === 0 || moved.some((file) => !digests.has(file) || inputDigest(file, result.group.dir) !== digests.get(file))) return moved.length > 0;
  for (const file of moved) result.signatures.set(file, fileSignature(file));
  return false;
}

/**
 * The group with the dependency names its directory declares now, read by the same scanner that
 * named them at startup (scanCurrentProject, as the project-tree walk does). A group is re-resolved
 * because one of its files changed, and the change may be a dependency added or removed: re-run
 * with the startup names, the versions and the advisory set followed the files while the direct
 * rows did not. package.json `{ ms }` with no lockfile, `lodash` added: vulnerability_scan scanned
 * 2 pins and dependency_health listed `ms` alone until the server restarted (6.5.0 and the 6.5.1
 * candidate). Only called for a group that is stale, so an unchanged project reads nothing.
 */
export function withDeclaredNames(group: ResolutionGroup): ResolutionGroup {
  let scan: ReturnType<typeof scanCurrentProject>;
  try {
    scan = scanCurrentProject(group.dir);
  } catch {
    return group;
  }
  const ecosystem = mapEcosystem(group.language);
  // The scanner's keys ("npm", "rust", ...) and a group's language ("javascript" from the test seam) name the same ecosystem.
  const declared = Object.entries(scan.depsByEcosystem).find(([language]) => mapEcosystem(language) === ecosystem)?.[1];
  // Nothing declared now (every dependency removed; Ruby and PHP, which the lockfile names): no names, as at startup.
  return { ...group, deps: declared?.deps ?? [], devDeps: declared?.devDeps ?? [], targets: scan.depTargets };
}
