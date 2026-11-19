// SPDX-License-Identifier: Apache-2.0
/**
 * Version Resolver
 *
 * Extracts exact dependency versions from lock files.
 * Priority: lock file (exact) > manifest (range/specifier).
 * Uses only Node.js built-ins — no external parsers. The per-ecosystem
 * parsers live in lockfile-parsers.ts, which also reports which file each
 * resolution read from.
 */

import type { OsvEcosystem, ResolvedDependency } from "./types.js";
import { targetActiveOnHost } from "./platform.js";
import { activeCratesForHost, hostTriple } from "./cargo-platform.js";
import { resolveVersionSource, type PackageInstance, type VersionSource } from "./lockfile-parsers.js";
import type { DeclaredDependency } from "./lockfile-types.js";
import { normalizePythonName } from "./lockfile-parsers-pygo.js";

// Alias -> OSV ecosystem. Mirrors the desktop app's canonical
// `Ecosystem::parse` (src-tauri/src/ecosystem.rs) so both sides recognize the
// SAME aliases — they previously drifted (the Rust side knew csharp/dart/php
// while this map keyed C# as "dotnet" and omitted Dart entirely, mislabeling
// those deps). Keep this in sync with that enum.
const ECOSYSTEM_MAP: Record<string, OsvEcosystem> = {
  npm: "npm",
  javascript: "npm",
  typescript: "npm",
  node: "npm",
  js: "npm",
  ts: "npm",
  rust: "crates.io",
  cargo: "crates.io",
  "crates.io": "crates.io",
  crates: "crates.io",
  python: "PyPI",
  pypi: "PyPI",
  pip: "PyPI",
  py: "PyPI",
  go: "Go",
  golang: "Go",
  java: "Maven",
  maven: "Maven",
  kotlin: "Maven",
  gradle: "Maven",
  csharp: "NuGet",
  "c#": "NuGet",
  dotnet: "NuGet",
  nuget: "NuGet",
  php: "Packagist",
  composer: "Packagist",
  packagist: "Packagist",
  ruby: "RubyGems",
  rubygems: "RubyGems",
  gem: "RubyGems",
  dart: "Pub",
  flutter: "Pub",
  pub: "Pub",
};

/**
 * Map a language/ecosystem alias to its OSV ecosystem id (case-insensitive).
 *
 * Falls back to "npm" ONLY for genuinely unrecognized input — a last resort, not
 * a real default. OSV-unindexed languages (Swift, C/C++) and unknowns produce no
 * OSV matches anyway (their package names don't collide with the npm namespace),
 * so this never fabricates a vulnerability. Ecosystems that lack a version
 * resolver here (NuGet/Maven/Packagist/RubyGems/Pub) still get the CORRECT label,
 * so the moment a resolver is added the scan is right by construction.
 */
export function mapEcosystem(language: string): OsvEcosystem {
  return ECOSYSTEM_MAP[language.trim().toLowerCase()] || "npm";
}

/**
 * crates.io treats `-` and `_` as one namespace (you cannot publish both
 * `http-body-util` and `http_body_util`), but the two spellings reach this
 * resolver from different sources: Cargo.lock records the publisher's canonical
 * name while ACE's import scraper reports the IMPORT identifier, which is
 * always underscored. An exact-match lookup then fails for the import spelling
 * and the same crate surfaces twice — once versioned, once `version: null`
 * (observed live 2026-08-30: http_body_util, async_trait, tower_http,
 * ed25519_dalek, ts_rs, proc_macro2, victauri_test, all null beside their
 * hyphenated versioned twins). Resolve via the spelling the lock file actually
 * uses and RETURN that spelling, so downstream dedupe merges the variants.
 */
function canonicalCrateName(name: string, versionMap: Map<string, string>): string {
  if (versionMap.has(name)) return name;
  const swapped = name.includes("_") ? name.replace(/_/g, "-") : name.replace(/-/g, "_");
  return versionMap.has(swapped) ? swapped : name;
}

/** What a lockfile read established beyond one version per name (lockfile-types.ts VersionSource). */
export interface LockScope {
  /** Every installed copy, with the scope the lockfile gives it. */
  instances?: PackageInstance[];
  /** Copies the project's own manifests declare, workspace members included. */
  declared?: DeclaredDependency[];
  /** True when the reader graded every copy's scope itself (VersionSource.scopeGraded). */
  graded?: boolean;
}

interface ScopeIndex {
  /** `name\0version` to the lockfile's own scope for that copy: true dev-only, false runtime, undefined not stated. */
  lockDev: Map<string, boolean | undefined>;
  /** `name\0version` of copies a manifest declares: true when a runtime section does. */
  declaredRuntime: Map<string, boolean>;
  graded: boolean;
}

function scopeIndex(ecosystem: OsvEcosystem, scope: LockScope = {}): ScopeIndex {
  const lockDev = new Map<string, boolean | undefined>();
  for (const copy of scope.instances ?? []) lockDev.set(copyKey(copy.name, copy.version, ecosystem), copy.dev);
  const declaredRuntime = new Map<string, boolean>();
  for (const copy of scope.declared ?? []) {
    const key = copyKey(copy.name, copy.version, ecosystem);
    declaredRuntime.set(key, (declaredRuntime.get(key) ?? false) || copy.runtime);
  }
  return { lockDev, declaredRuntime, graded: scope.graded === true };
}

/**
 * The scope of a copy the project declares. It is dev-only only when nothing
 * runtime reaches it: declared in a runtime section anywhere, or marked
 * runtime by the lockfile (a runtime dependency also installs it), it is
 * runtime. `devOnlySection` is false when the manifest itself lists the name
 * in a runtime section. When the reader grades scope itself and could not
 * establish this copy's, it is unknown, never dev-only on the manifest's word.
 */
function declaredScope(index: ScopeIndex, key: string, devOnlySection: boolean): { isDev: boolean; devScopeKnown: boolean } {
  if (!devOnlySection || index.declaredRuntime.get(key) === true) return { isDev: false, devScopeKnown: true };
  const lock = index.lockDev.get(key);
  if (lock === false) return { isDev: false, devScopeKnown: true };
  if (lock === undefined && index.graded) return { isDev: false, devScopeKnown: false };
  return { isDev: true, devScopeKnown: true };
}

export function resolveVersions(
  cwd: string,
  deps: string[],
  devDeps: string[],
  language: string,
  targets: Record<string, string> = {},
): ResolvedDependency[] {
  const ecosystem = mapEcosystem(language);
  const read = resolveVersionSource(cwd, ecosystem);
  return resolveVersionsFrom(cwd, deps, devDeps, ecosystem, read.versions, targets, lockScopeOf(read));
}

/** The scope facts of a lockfile read, as the resolvers take them. */
export function lockScopeOf(read: Pick<VersionSource, "instances" | "declared" | "scopeGraded">): LockScope {
  return { instances: read.instances, declared: read.declared, graded: read.scopeGraded === true };
}

/** `resolveVersions` over a version map the caller already read from `cwd`. */
export function resolveVersionsFrom(
  cwd: string,
  deps: string[],
  devDeps: string[],
  ecosystem: OsvEcosystem,
  versionMap: Map<string, string>,
  targets: Record<string, string> = {},
  scope: LockScope = {},
): ResolvedDependency[] {
  const results: ResolvedDependency[] = [];
  const index = scopeIndex(ecosystem, scope);
  const runtimeNames = new Set(deps);

  const build = (rawName: string, isDev: boolean): ResolvedDependency => {
    const name =
      ecosystem === "crates.io" ? canonicalCrateName(rawName, versionMap) : rawName;
    const target = targets[rawName] ?? targets[name] ?? null;
    const version = versionMap.get(normalizePackageName(name, ecosystem)) || null;
    // A devDependency is graded by what reaches the copy it resolves to, not by its section alone.
    const graded = isDev && version ? declaredScope(index, copyKey(name, version, ecosystem), !runtimeNames.has(rawName)) : { isDev, devScopeKnown: true };
    return {
      name,
      version,
      ecosystem,
      isDev: graded.isDev,
      isDirect: true,
      devScopeKnown: graded.devScopeKnown,
      target,
      platformActive: targetActiveOnHost(target),
      // Provenance recorded at the point of resolution: this version came from
      // THIS manifest directory's lock file, not from "the project" generally.
      sourceDirs: [cwd],
    };
  };

  for (const name of deps) results.push(build(name, false));
  for (const name of devDeps) results.push(build(name, true));

  return results;
}

/**
 * Resolve the complete lockfile package set for vulnerability scanning.
 * Direct dependency health and upgrade planning continue to use resolveVersions.
 */
export function resolveAuditVersions(
  cwd: string,
  deps: string[],
  devDeps: string[],
  language: string,
  targets: Record<string, string> = {},
): ResolvedDependency[] {
  const ecosystem = mapEcosystem(language);
  const read = resolveVersionSource(cwd, ecosystem);
  return resolveAuditVersionsFrom(cwd, deps, devDeps, ecosystem, read.versions, targets, undefined, read.instances, lockScopeOf(read));
}

/**
 * `resolveAuditVersions` over a version map the caller already read. `direct`
 * lets the caller pass direct entries it has already enriched (install state)
 * so the audit set carries the same objects' context. `instances` is every
 * installed copy the lockfile holds; without it the version map (one copy per
 * name) is all there is. `scope` carries what the lockfile read established
 * about scope and about the copies workspace members declare.
 */
export function resolveAuditVersionsFrom(
  cwd: string,
  deps: string[],
  devDeps: string[],
  ecosystem: OsvEcosystem,
  versionMap: Map<string, string>,
  targets: Record<string, string> = {},
  directEntries?: ResolvedDependency[],
  instances: PackageInstance[] = [...versionMap].map(([name, version]) => ({ name, version })),
  scope: Omit<LockScope, "instances"> = {},
): ResolvedDependency[] {
  const lockScope: LockScope = { ...scope, instances };
  const direct = directEntries ?? resolveVersionsFrom(cwd, deps, devDeps, ecosystem, versionMap, targets, lockScope);
  const index = scopeIndex(ecosystem, lockScope);
  // Canonicalize the same way resolveVersions does, so a dep declared under its
  // import spelling still marks the lock file's canonical entry as direct.
  const canonical = (name: string) =>
    normalizePackageName(
      ecosystem === "crates.io" ? canonicalCrateName(name, versionMap) : name,
      ecosystem,
    );
  const directNames = new Set(deps.map(canonical));
  const devNames = new Set(devDeps.map(canonical));
  const seen = new Set(direct.map((dep) => dependencyKey(dep)));
  const results = [...direct];

  // Cargo.lock is target-agnostic, so a Windows lockfile still lists the whole
  // Linux GTK3 stack Tauri pulls in. `[target.'cfg(...)']` parsing only ever
  // covered DIRECT gated deps, and that cluster is entirely transitive — which
  // is why nine unreachable crates were reported while the scan claimed to be
  // platform-filtered. Ask cargo to resolve the graph for this host instead.
  // `null` means cargo could not answer; every crate then stays active, because
  // "unknown" must never silently hide a real advisory.
  //
  // THE SHARED PREDICATE — keep in step with the app's
  // `src-tauri/src/platform_filter.rs`, which documents it in full:
  //
  //   a crate that is not RESOLVED FOR THE HOST is platform-inactive
  //
  // Two independent facts can make that true, and both are recorded because
  // the copy differs: (1) the manifest gates it behind a `cfg(...)` for a
  // target this machine is not — `targetActiveOnHost(declaredTarget)`, the
  // app's `project_dependencies.target_cfg`; (2) cargo builds it for no
  // target/feature combination here — `builtOnHost`, the app's
  // `user_dependencies.target_cfg = 'lockfile-only'` (schema 122). Neither
  // fact alone is the whole picture: (1) covers only DIRECT deps, and (2) is
  // the only one that can see a transitive.
  const hostCrates = ecosystem === "crates.io" ? activeCratesForHost(cwd) : null;
  const triple = hostCrates ? hostTriple() : null;

  for (const { name, version, dev } of instances) {
    const normalized = normalizePackageName(name, ecosystem);
    const key = copyKey(name, version, ecosystem);
    // Direct only for the copy a manifest dependency resolves to; another
    // installed version of the same name is somebody else's transitive.
    const resolvesHere = versionMap.get(name) === version;
    const inRuntimeSection = resolvesHere && directNames.has(normalized);
    const isDirect = inRuntimeSection || (resolvesHere && devNames.has(normalized));
    const graded = isDirect ? declaredScope(index, key, !inRuntimeSection) : { isDev: dev === true, devScopeKnown: dev !== undefined };
    const declaredTarget = targets[name] ?? null;
    const builtOnHost = hostCrates ? hostCrates.has(name) : true;
    // Prefer the manifest's own cfg() spec when it has one — it is the more
    // precise, human-readable explanation. Fall back to naming the triple the
    // crate is absent from.
    const target =
      declaredTarget ?? (builtOnHost || !triple ? null : `not built for ${triple}`);
    const candidate: ResolvedDependency = {
      name,
      version,
      ecosystem,
      // A transitive's scope is whatever the lockfile recorded for that copy
      // (npm `dev`, pnpm 5/6 `dev`, Pipfile `develop`, poetry `category`, or
      // the reader's own reachability), else unknown. A declared copy's is
      // declaredScope: its section, unless something runtime reaches it too.
      isDev: graded.isDev,
      isDirect,
      devScopeKnown: graded.devScopeKnown,
      target,
      platformActive: targetActiveOnHost(declaredTarget) && builtOnHost,
      sourceDirs: [cwd],
    };
    const candidateKey = dependencyKey(candidate);
    if (!seen.has(candidateKey)) {
      seen.add(candidateKey);
      results.push(candidate);
    }
  }

  return results;
}

function normalizePackageName(name: string, ecosystem: OsvEcosystem): string {
  // PEP 503: the lockfile readers store Python names normalised the same way.
  return ecosystem === "PyPI" ? normalizePythonName(name) : name;
}

/** One installed copy, by normalised name and version. */
function copyKey(name: string, version: string, ecosystem: OsvEcosystem): string {
  return `${normalizePackageName(name, ecosystem)}\0${version}`;
}

function dependencyKey(dep: ResolvedDependency): string {
  return `${dep.ecosystem}\0${normalizePackageName(dep.name, dep.ecosystem)}\0${dep.version ?? ""}`;
}
