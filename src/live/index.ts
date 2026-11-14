// SPDX-License-Identifier: Apache-2.0
/**
 * Live Intelligence Coordinator
 *
 * Orchestrates vulnerability scanning and headline fetching.
 * Manages cache lifecycle and offline fallback.
 *
 * Privacy: sends package names/versions and tech keywords, never a private package name
 * (private-packages.ts: a scope mapped to a private registry, GOPRIVATE, a private Cargo or PyPI
 * index, FOURDA_PRIVATE_PACKAGES). Set FOURDA_OFFLINE=true to disable all network calls.
 */

import type { SqliteDatabase } from "../sqlite-driver.js";
import { LiveCache } from "./cache.js";
import { RateLimiter, DEFAULT_RATE_LIMITS } from "./rate-limiter.js";
import { OsvScanner, type AdvisorySource } from "./osv-scanner.js";
import { HNFetcher } from "./hn-fetcher.js";
import { NpmRegistry } from "./npm-registry.js";
import { CratesRegistry } from "./crates-registry.js";
import { PyPIRegistry } from "./pypi-registry.js";
import { GoRegistry } from "./go-registry.js";
import { NpmPackumentReader } from "./npm-packument.js";
import { CratesVersionsReader } from "./crates-versions.js";
import { PypiReleasesReader } from "./pypi-releases.js";
import { GoReleasesReader } from "./go-releases.js";
import { FixPathSources } from "./fix-paths.js";
import type { CheckEcosystem, ReleaseMetadataSource } from "./release-metadata.js";
import { fetchRegistryHealthFor } from "./registry-health.js";
import { commonPathRoot, dedupeDependencies, emptyVulnResult } from "./dependency-set.js";
import { LOOKUPS_DISABLED } from "./scan-coverage.js";
import { groupIsStale, resolveGroup, type GroupResolution, type ResolutionGroup } from "./resolution.js";
import { mapEcosystem } from "./version-resolver.js";
import type { TreeDiscovery } from "../project-tree.js";
import { applyInstanceDevScope } from "./dev-scope.js";
import { isDevOnlyCopy } from "./severity-scope.js";
import type { LockfileProblem, UncheckableDependency, UnpinnedRequirements } from "./lockfile-types.js";
import { manifestPrivateSources, normName, npmLockPrivateSources, PrivatePackageRules, type PrivateDependency, type PrivateIndexEntry } from "./private-packages.js";
import { declaredMirror } from "./private-configs.js";
import { PrivateAwareFixPathSources } from "./private-fix-sources.js";
import { nameForms, privateShortIndex, registerPrivateNames, rememberedPrivate, rememberedPrivateCount, rememberPrivateName, shortKey, unregisterPrivateNames, withPrivateContext } from "./private-guard.js";
import type {
  InstallDriftRecord,
  ResolutionProvenance,
  ResolutionSourceRecord,
  ResolvedDependency,
  RegistryPackageInfo,
  VulnerabilityScanResult,
  LiveHeadline,
  LiveIntelligenceStatus,
} from "./types.js";
import { isOfflineMode } from "../env-flags.js";

export type {
  VulnerabilityScanResult,
  VulnerabilityEntry,
  LiveHeadline,
  LiveIntelligenceStatus,
  RegistryPackageInfo,
  DependencyHealthResult,
  InstallDriftRecord,
  ResolutionProvenance,
} from "./types.js";

/** Minimum gap between vulnerability warmup attempts after an offline result. */
const WARMUP_RETRY_MS = 60_000;
/** Every ecosystem a private rule can name: privateReason judges a name under all of them. */
const ALL_PRIVATE_ECOSYSTEMS = ["npm", "crates.io", "PyPI", "Go", "RubyGems", "Packagist"];

/**
 * How long a finished scan may stand in for a new one. The server lives as
 * long as the IDE that started it: with no limit, a scan taken on Monday
 * morning answered `what_should_i_know`, `upgrade_planner` and
 * `dependency_health` on Friday as long as no lockfile had changed, however
 * many advisories OSV published in between (audit 2026-11-11, T7). One hour
 * is the life of an OSV answer in the cache (osv-scanner.ts OSV_CACHE_TTL):
 * past it the scan is taken again.
 */
export const MAX_STORED_SCAN_AGE_MS = 60 * 60 * 1000;

export class LiveIntelligence {
  private db: SqliteDatabase | null;
  private cache: LiveCache;
  private rateLimiter: RateLimiter;
  private osvScanner: OsvScanner;
  private hnFetcher: HNFetcher;
  private npmRegistry: NpmRegistry;
  private cratesRegistry: CratesRegistry;
  private pypiRegistry: PyPIRegistry;
  private goRegistry: GoRegistry;
  private npmPackuments: NpmPackumentReader;
  private cratesVersions: CratesVersionsReader;
  private pypiReleases: PypiReleasesReader;
  private goReleases: GoReleasesReader;
  private fixPathSources: PrivateAwareFixPathSources;
  private enabled: boolean;

  private lastVulnScan: VulnerabilityScanResult | null = null;
  /** Whether the stored scan included direct devDependencies. */
  private lastVulnScanIncludesDev = false;
  /**
   * Order of scan REQUESTS. A scan's result is stored only if no later request
   * has stored one already: the init warmup (runtime scope) used to finish
   * after an agent's `include_dev` scan and replace it, so `upgrade_planner`
   * read a scan without the dev dependencies the agent had just scanned and
   * sent node-fetch 2.6.0 to the ESM-only 3.3.2 with no advisories (2 of 6
   * runs, 2026-10-03 pre-publish verification).
   */
  private scanRequests = 0;
  /** Scans running now, by generation, scope and path: a request for one of them awaits it. */
  private scansInFlight = new Map<string, Promise<VulnerabilityScanResult>>();
  private storedScanRequest = 0;
  private lastHeadlines: LiveHeadline[] = [];
  /** Why the last headline fetch read nothing, when it did not (ecosystem_pulse says so). */
  private headlineError: string | null = null;
  private resolvedDeps: ResolvedDependency[] = [];
  private auditDeps: ResolvedDependency[] = [];
  /** What the machine says is private (private-packages.ts), for the project in use. */
  private privateRules: PrivatePackageRules;
  /** Audit copies left out of every lookup because their names are private, each with why. */
  private privateDeps: PrivateDependency[] = [];
  /** The same copies as resolved (dev scope and all), for scoping them like a scan. */
  private privateAudit: ResolvedDependency[] = [];
  /** npm groups: packages their lockfile installs from a non-public registry host (`resolved`). */
  private npmLockPrivate = new Map<GroupResolution, PrivateIndexEntry[]>();
  /** Groups whose manifest takes packages from a private registry or index (manifestPrivateSources). */
  private manifestPrivate = new Map<GroupResolution, PrivateIndexEntry[]>();
  /**
   * Every name a group declares, resolves or lists, by `${ecosystem}\0${normalised name}`, when its
   * ecosystem's registry, index or proxy is not public (PrivatePackageRules.ecosystemWide), with why.
   */
  private wideNames = new Map<string, string>();
  /** privateReason's indexes (lockPrivateIndex); reset by rebuildDependencySet. */
  private lockPrivateIndexes = new WeakMap<GroupResolution, Map<string, Map<string, PrivateIndexEntry[]>>>();
  private publicNames: Set<string> | null = null;
  private privateSet: Map<string, string> | null = null;
  /** privateShortIndex of this project, reset with privateSet. */
  private privateShorts: ReturnType<typeof privateShortIndex> | null = null;
  private initialized = false;
  private projectRoot: string | null = null;
  /** One entry per resolution group: its inputs, result, and the file signatures that say when it went stale. */
  private groupResults: GroupResolution[] = [];
  /** The project-tree walk's report of what it left out, when the groups came from one. */
  private discovery: TreeDiscovery | null = null;
  /** When the dependency set in use was assembled: at init, or at the last re-resolution. */
  private resolvedAt: string | null = null;
  /**
   * Bumped by every re-resolution. A scan started under an older generation
   * describes a dependency set that no longer exists: it may still be handed
   * to the call that asked for it, but it is never stored or served later.
   */
  private generation = 0;
  /**
   * The background vulnerability scan started at server init. Tools that need
   * scan data before answering (`what_should_i_know`) await this through
   * `ensureVulnerabilities` instead of reading the cache and finding it empty.
   */
  private warmup: Promise<VulnerabilityScanResult> | null = null;
  /** When the last warmup came back offline; gates the retry so an offline host is not re-probed on every call. */
  private warmupFailedAt: number | null = null;
  /** When the warmup in `warmup` was started: one older than MAX_STORED_SCAN_AGE_MS is not reused. */
  private warmupStartedAt: number | null = null;

  /**
   * `advisorySource` replaces OSV.dev for vulnerability scans (the conformance
   * harness passes pinned records). A source that needs no network keeps
   * scanning enabled under FOURDA_OFFLINE; nothing else changes.
   */
  constructor(db: SqliteDatabase | null, options: { advisorySource?: AdvisorySource } = {}) {
    this.db = db;
    this.enabled = !isOfflineMode() || options.advisorySource?.network === false;
    this.cache = new LiveCache(db);
    this.privateRules = new PrivatePackageRules([]);
    this.rateLimiter = new RateLimiter(DEFAULT_RATE_LIMITS);
    this.osvScanner = new OsvScanner(this.cache, this.rateLimiter, options.advisorySource);
    this.hnFetcher = new HNFetcher(this.cache, this.rateLimiter);
    this.npmRegistry = new NpmRegistry(this.cache, this.rateLimiter);
    this.cratesRegistry = new CratesRegistry(this.cache, this.rateLimiter);
    this.pypiRegistry = new PyPIRegistry(this.cache, this.rateLimiter);
    this.goRegistry = new GoRegistry(this.cache, this.rateLimiter);
    this.npmPackuments = new NpmPackumentReader(this.cache, this.rateLimiter);
    this.cratesVersions = new CratesVersionsReader(this.cache, this.rateLimiter);
    this.pypiReleases = new PypiReleasesReader(this.cache, this.rateLimiter);
    this.goReleases = new GoReleasesReader(this.cache, this.rateLimiter);
    // Fix-path lookups (upgrade_planner, held dependencies) refuse private names (private-fix-sources.ts),
    // and the HTTP choke point refuses any request naming one this layer knows (private-guard.ts).
    this.fixPathSources = new PrivateAwareFixPathSources(this.cache, this.rateLimiter, this);
    // Weakly: a request made for this layer runs in its context, which holds it (private-guard.ts).
    // The server's own layer is also held strongly (live-singleton.ts).
    registerPrivateNames(this);
  }

  /** Advisory, registry and parent-requirement lookups for fix paths; null when offline. */
  getFixPathSources(): FixPathSources | null {
    return this.enabled ? this.fixPathSources : null;
  }

  /**
   * The lockfile one manifest directory resolved this ecosystem from, or null
   * when it resolved from a manifest or nothing. `dir` is spelled as the
   * resolution group spells it (the scan's sourceDirs).
   */
  lockfileFor(dir: string, ecosystem: string): string | null {
    for (const r of this.groupResults) {
      if (r.group.dir === dir && mapEcosystem(r.group.language) === ecosystem && r.source?.kind === "lockfile") return r.source.path;
    }
    return null;
  }

  /**
   * Initialize with project data. Call once after project scan.
   * @deprecated Use initFromMultiEcosystem for correct per-ecosystem resolution.
   */
  initFromProject(
    projectPath: string,
    deps: string[],
    devDeps: string[],
    language: string,
  ): void {
    this.applyGroups([{ dir: projectPath, language, deps, devDeps, targets: {} }], projectPath);
  }

  /**
   * Initialize with per-ecosystem project data. Resolves versions per language
   * so Rust crates go to crates.io, npm packages to npm, etc.
   * Call once after project scan.
   */
  initFromMultiEcosystem(
    projectPath: string,
    depsByEcosystem: Record<string, { deps: string[]; devDeps: string[] }>,
    depTargets: Record<string, string> = {},
  ): void {
    const groups = Object.entries(depsByEcosystem).map(([language, { deps, devDeps }]) => ({
      dir: projectPath,
      language,
      deps,
      devDeps,
      targets: depTargets,
    }));
    this.applyGroups(groups, projectPath);
  }

  /**
   * Initialize from every independently-locked project under `root` (see
   * project-tree.ts): each group resolves from its own directory and keeps
   * its manifest's platform targets; `root` is the reported project root.
   */
  initFromProjectTree(root: string, groups: ResolutionGroup[], discovery: TreeDiscovery | null = null): void {
    this.applyGroups(groups, root, discovery?.registryConfigDirs ?? []);
    this.discovery = discovery;
  }

  /**
   * Manifests with no lockfile beside them, whose ranged dependencies were not
   * scanned: their versions are declared ranges, not installs.
   */
  getUnresolvedManifests(): Array<{ dir: string; manifest: string; ranges: number; pinned: number }> {
    return this.groupResults.flatMap((r) => (r.unresolved ? [{ dir: r.group.dir, ...r.unresolved }] : []));
  }

  /**
   * Dependencies the lockfiles install from git, a URL or a local archive.
   * They are not registry releases, so they were never sent to OSV under the
   * registry package's name: listed so their absence from the findings is not
   * read as "no advisories".
   */
  getUncheckableDependencies(): UncheckableDependency[] {
    const seen = new Set<string>();
    return this.groupResults
      .flatMap((r) => r.uncheckable ?? [])
      .filter((u) => {
        const key = `${u.file.toLowerCase()}|${u.name}|${u.version ?? ""}|${u.kind}`;
        return !seen.has(key) && (seen.add(key), true);
      });
  }

  /** PyPI requirements with no pinned version anywhere in their directory (`pydantic>=2.0.0`): nothing to check, by file. */
  getUnpinnedRequirements(): UnpinnedRequirements[] {
    const byFile = new Map<string, Set<string>>();
    for (const r of this.groupResults) {
      for (const { file, names } of r.unpinned ?? []) {
        const set = byFile.get(file) ?? new Set<string>();
        for (const name of names) set.add(name);
        byFile.set(file, set);
      }
    }
    return [...byFile].map(([file, names]) => ({ file, names: [...names] }));
  }

  /** Lockfiles present in a resolved directory that could not be read, each with the reason. */
  getLockfileProblems(): LockfileProblem[] {
    const seen = new Set<string>();
    return this.groupResults.flatMap((r) => r.problems ?? []).filter((p) => !seen.has(p.file) && (seen.add(p.file), true));
  }

  /** What the project-tree walk left out (lockfiles past its bounds); null when the set did not come from a walk. */
  getDiscovery(): TreeDiscovery | null {
    return this.discovery;
  }

  /**
   * Initialize from dependency groups that each carry their own resolution
   * directory. Used in 4DA database mode, where dependencies span multiple
   * manifests in different locations (Rust crates under src-tauri/, relay/,
   * etc.; npm packages at the repo root and in sub-packages). Each group
   * resolves versions from its own lock file, so a single global cwd no longer
   * silently drops every dependency whose manifest lives in a subdirectory.
   * Deduplicates by ecosystem+name+version so a crate shared across workspaces
   * is scanned once.
   */
  initFromDependencyGroups(
    groups: Array<{ dir: string; language: string; deps: string[]; devDeps: string[] }>,
  ): void {
    // Each resolver stamps `sourceDirs: [dir]` at the point of resolution, so
    // the dedupe can union provenance instead of discarding it.
    this.applyGroups(
      groups.map((g) => ({ ...g, targets: {} })),
      commonPathRoot(groups.map((g) => g.dir)),
    );
  }

  private applyGroups(groups: ResolutionGroup[], projectRoot: string | null, memberConfigDirs: string[] = []): void {
    this.privateRules = new PrivatePackageRules([...new Set([...(projectRoot ? [projectRoot] : []), ...groups.map((g) => g.dir)])], process.env, memberConfigDirs);
    this.groupResults = groups.map(resolveGroup);
    this.rebuildDependencySet();
    this.projectRoot = projectRoot;
    this.initialized = true;
  }

  /**
   * The dependency set, private names taken out of it (private-packages.ts): what no lookup may
   * send. They are kept in `privateDeps` so every answer says they were not checked.
   */
  private rebuildDependencySet(): void {
    this.lockPrivateIndexes = new WeakMap();
    this.publicNames = null;
    this.privateSet = null;
    this.privateShorts = null;
    this.npmLockPrivate = new Map(
      this.groupResults
        .filter((r) => mapEcosystem(r.group.language) === "npm")
        .map((r) => [r, npmLockPrivateSources(r.group.dir, this.privateRules.publicMirrors)] as const),
    );
    // A private registry or index the manifest itself names (Cargo `registry =`, uv `index =`,
    // Poetry `source =`): private with no lockfile too (blind audit round 4).
    this.manifestPrivate = new Map(
      this.groupResults.map((r) => [r, manifestPrivateSources(r.group.dir, mapEcosystem(r.group.language))] as const).filter(([, list]) => list.length > 0),
    );
    // A registry, index or proxy that is not public and is consulted for any name: every name the
    // group knows, ranged and unpinned ones included, so no tool sends one (R7, 2).
    this.wideNames = new Map();
    for (const r of this.groupResults) {
      const ecosystem = mapEcosystem(r.group.language);
      const why = this.privateRules.ecosystemWide(ecosystem, r.source?.kind === "lockfile");
      if (!why) continue;
      const names = [
        ...r.group.deps,
        ...r.group.devDeps,
        ...r.resolved.map((d) => d.name),
        ...r.audit.map((d) => d.name),
        ...(r.unpinned ?? []).flatMap((u) => u.names),
        ...(r.uncheckable ?? []).map((u) => u.name),
      ];
      for (const name of names) {
        const k = `${ecosystem}\0${normName(ecosystem, name)}`;
        if (!this.wideNames.has(k)) this.wideNames.set(k, why);
      }
    }
    const key = (dep: { ecosystem: string; name: string; version: string | null }) => `${dep.ecosystem}\0${dep.name}\0${dep.version ?? ""}`;
    const privateWhy = new Map<string, string>();
    const isPublic = (r: GroupResolution, dep: ResolvedDependency) => {
      const why = this.privateReasonIn(r, dep.ecosystem, dep.name, dep.version);
      if (why && !privateWhy.has(key(dep))) privateWhy.set(key(dep), why);
      return !why;
    };
    this.resolvedDeps = dedupeDependencies(this.groupResults.flatMap((r) => r.resolved.filter((dep) => isPublic(r, dep))));
    const audit = this.groupResults.flatMap((r) => r.audit.map((dep) => ({ dep, open: isPublic(r, dep) })));
    this.auditDeps = dedupeDependencies(audit.filter((a) => a.open).map((a) => a.dep));
    this.privateAudit = dedupeDependencies(audit.filter((a) => !a.open).map((a) => a.dep));
    this.privateDeps = this.privateAudit.map((dep) => ({
      ecosystem: dep.ecosystem,
      name: dep.name,
      version: dep.version,
      why: privateWhy.get(key(dep)) ?? "private",
    }));
    // Private for the rest of the process, for every project (private-guard.ts, blind audit round 5, 4).
    for (const p of this.privateDeps) rememberPrivateName(p.ecosystem, p.name, p.why);
    this.resolvedAt = new Date().toISOString();
  }

  /**
   * Take out of the dependency set every copy the request guard would refuse (a name another
   * project's scan found private, a spelling the per-group rules did not read), each with why, so a
   * scan never hands the guard a batch it refuses. A refused batch failed whole: every public
   * dependency came back NOT CHECKED and the summary said "OSV.dev unreachable" (blind audit round 5, 2).
   */
  private takeOutRefused(): void {
    if (this.privateRules.empty && this.privateDeps.length === 0 && rememberedPrivateCount() === 0) return;
    const refused = new Map<string, string>();
    const key = (d: { ecosystem: string; name: string }) => `${d.ecosystem}\0${d.name}`;
    for (const d of this.auditDeps) {
      if (refused.has(key(d))) continue;
      const why = this.privateReason(d.ecosystem, d.name);
      if (why) refused.set(key(d), why);
    }
    if (refused.size === 0) return;
    const out = this.auditDeps.filter((d) => refused.has(key(d)));
    this.auditDeps = this.auditDeps.filter((d) => !refused.has(key(d)));
    this.resolvedDeps = this.resolvedDeps.filter((d) => !refused.has(key(d)));
    this.privateAudit = dedupeDependencies([...this.privateAudit, ...out]);
    this.privateDeps = [...this.privateDeps, ...out.map((d) => ({ ecosystem: d.ecosystem, name: d.name, version: d.version, why: refused.get(key(d)) ?? "private" }))];
    for (const d of out) rememberPrivateName(d.ecosystem, d.name, refused.get(key(d)) ?? "private");
    this.publicNames = null;
    this.privateSet = null;
    this.privateShorts = null;
  }

  /** Why a dependency of this group is private, or null: its lockfile's source, then the name rules. */
  private privateReasonIn(r: GroupResolution, ecosystem: string, name: string, version: string | null): string | null {
    const fromLock = this.lockPrivateIndex(r, ecosystem)
      .get(normName(ecosystem, name))
      ?.find((p) => p.version === null || version === null || p.version === version);
    if (fromLock) return `${fromLock.file} installs it from ${fromLock.registry}, not the public registry`;
    // A registry, index or proxy that is not public and serves any name: pip's configured index or
    // an extra one (for what a requirements file installs), uv's, Poetry's, npm's default registry,
    // GOPROXY, a Cargo source replacement (PrivatePackageRules.ecosystemWide).
    const wide = mapEcosystem(r.group.language) === ecosystem ? this.privateRules.ecosystemWide(ecosystem, r.source?.kind === "lockfile") : null;
    if (wide) return wide;
    return this.privateRules.reasonFor(ecosystem, name);
  }

  /**
   * Why a package name is private for this project, or null: the name rules (a scope mapped to a
   * private registry, GOPRIVATE, FOURDA_PRIVATE_PACKAGES), then any lockfile that installs it
   * from a private registry or index. dependency_check asks this before any lookup.
   */
  privateReason(ecosystem: string, name: string): string | null {
    return this.privateMatch(ecosystem, name)?.why ?? null;
  }

  /**
   * privateReason, with the ecosystem whose rule or lockfile makes the name private (the briefing
   * reported a PyPI-private name as `npm`: blind audit round 5, 5).
   */
  privateMatch(ecosystem: string, name: string): { ecosystem: string; why: string } | null {
    // Any form of the name a registry could read as it (`npm:x`, `x@1.0.0`, `x[extra]`, a URL...),
    // under any ecosystem: the name is the secret, whichever registry it would be sent to.
    // `{npm, omega-internal-risk}` (private on PyPI) and `{PyPI, acme-crypto-core}` (a private
    // crate) reached OSV.dev and the registries (blind audit round 3, should-fix 2).
    const forms = nameForms(name);
    for (const eco of [ecosystem, ...ALL_PRIVATE_ECOSYSTEMS.filter((e) => e !== ecosystem)]) {
      for (const form of forms) {
        const why = this.privateReasonExact(eco, form) ?? this.privateSetReason(eco, form);
        if (why) return { ecosystem: eco, why };
      }
    }
    const scope = this.privateScopeFragment(forms);
    if (scope) return { ecosystem: "npm", why: scope };
    const short = this.privateShortName(forms);
    if (short) return short;
    // Found private by any scan in this process, for any project (blind audit round 5, 4).
    return rememberedPrivate(name, (eco, n) => this.installsPublicly(eco, n));
  }

  /**
   * A bare private scope used as a package name: `zqxacme` when `.npmrc` maps `@zqxacme` to a
   * private registry. It names the private organisation as surely as `@zqxacme/vault-core` does,
   * and went to OSV.dev and registry.npmjs.org (blind audit round 5, 1). Only the exact scope name:
   * suffixes and other fragments (`omega-internal` of `zqx-omega-internal`) are ordinary public
   * names (`internal`, `core`, `utils`), and refusing them would block public packages. A project
   * that installs the bare name from the public registry still asks about it.
   */
  private privateScopeFragment(forms: string[]): string | null {
    for (const form of forms) {
      if (form.includes("/")) continue;
      const bare = form.replace(/^@/, "").toLowerCase();
      if (!bare) continue;
      const file = this.privateRules.privateScopeFile(`@${bare}`);
      if (file && !this.installsPublicly("npm", bare)) return `the bare name of the private scope @${bare} (mapped to a private registry in ${file})`;
    }
    return null;
  }

  /**
   * The short name of one of this project's private packages, in any form of the name
   * (privateShortIndex): `zqsecretlib` for the private `@zqvault/zqsecretlib`, under any ecosystem.
   * A form the project installs from a public registry is that public package.
   */
  private privateShortName(forms: string[]): { ecosystem: string; why: string } | null {
    if (this.privateDeps.length === 0) return null;
    this.privateShorts ??= privateShortIndex(this.privateDeps, this.auditDeps);
    for (const form of forms) {
      if (/\s/.test(form) || ALL_PRIVATE_ECOSYSTEMS.some((eco) => this.installsPublicly(eco, form))) continue;
      const hit = this.privateShorts.get(shortKey(form));
      if (hit) return { ecosystem: hit.ecosystem, why: `the short name of the private package ${hit.name} (${hit.why})` };
    }
    return null;
  }

  /** Whether this project installs `name` (normalised for `ecosystem`) from the public registry. */
  installsPublicly(ecosystem: string, name: string): boolean {
    this.publicNames ??= new Set(this.auditDeps.map((d) => `${d.ecosystem}\0${normName(d.ecosystem, d.name)}`));
    return this.publicNames.has(`${ecosystem}\0${normName(ecosystem, name)}`);
  }

  /**
   * Why the scan's own private set holds this name, or null. That set applies every rule, PIP_INDEX_URL
   * and pip's config file included; privateReasonExact did not read those, so dependency_check,
   * upgrade_impact and the briefing sent a pin the scan had just called private (blind audit round 3, B1).
   */
  private privateSetReason(ecosystem: string, name: string): string | null {
    this.privateSet ??= new Map(this.privateDeps.map((p) => [`${p.ecosystem}\0${normName(p.ecosystem, p.name)}`, p.why]));
    return this.privateSet.get(`${ecosystem}\0${normName(ecosystem, name)}`) ?? null;
  }

  private privateReasonExact(ecosystem: string, name: string): string | null {
    const byName = this.privateRules.reasonFor(ecosystem, name);
    if (byName) return byName;
    // Every spelling the registry treats as the same name (`acme_core`, `Acme-Core`; review of #64, X1).
    const n = normName(ecosystem, name);
    // A name this project ALSO installs from the public registry is public (a git fork of serde
    // beside serde itself): asking about it reveals nothing.
    this.publicNames ??= new Set(this.auditDeps.map((d) => `${d.ecosystem}\0${normName(d.ecosystem, d.name)}`));
    if (this.publicNames.has(`${ecosystem}\0${n}`)) return null;
    const wide = this.wideNames.get(`${ecosystem}\0${n}`);
    if (wide) return wide;
    for (const r of this.groupResults) {
      if (mapEcosystem(r.group.language) !== ecosystem) continue;
      const hit = this.lockPrivateIndex(r, ecosystem).get(n)?.[0];
      if (hit) return `${hit.file} installs it from ${hit.registry}, not the public registry`;
    }
    return null;
  }

  /**
   * A group's private lockfile entries by normalised name. privateReason runs for every name in
   * every outgoing request, and once per dependency while the set is built: scanning the whole
   * dependency list each time made a 40,000-dependency scan take 34 s with the event loop blocked
   * (blind audit 2026-11-14, F3). Indexes are rebuilt with the dependency set.
   */
  private lockPrivateIndex(r: GroupResolution, ecosystem: string): Map<string, PrivateIndexEntry[]> {
    let byEco = this.lockPrivateIndexes.get(r);
    if (!byEco) this.lockPrivateIndexes.set(r, (byEco = new Map()));
    let index = byEco.get(ecosystem);
    if (!index) {
      index = new Map();
      for (const p of this.lockPrivateOf(r)) {
        const k = normName(ecosystem, p.name);
        const list = index.get(k);
        if (list) list.push(p);
        else index.set(k, [p]);
      }
      byEco.set(ecosystem, index);
    }
    return index;
  }

  /** What a group's lockfiles install from a private source: the readers' entries, and npm's `resolved` hosts. */
  private lockPrivateOf(r: GroupResolution): PrivateIndexEntry[] {
    const npm = this.npmLockPrivate.get(r) ?? [];
    const manifest = this.manifestPrivate.get(r) ?? [];
    const all = npm.length > 0 || manifest.length > 0 ? [...(r.privateIndex ?? []), ...npm, ...manifest] : (r.privateIndex ?? []);
    // A host FOURDA_PUBLIC_MIRRORS declares a mirror of the public registry serves public packages,
    // whether a lockfile, a requirements file or the configuration names it (R7: one policy).
    const mirrors = this.privateRules.publicMirrors;
    return mirrors.size === 0 ? all : all.filter((p) => !declaredMirror(p.registry.replace(/^[a-z]+\+/i, ""), mirrors));
  }

  /** Private names a fix-path lookup was refused for in this process, with why. */
  getPrivateRefusals(): ReadonlyMap<string, string> {
    return this.fixPathSources.refusals;
  }

  /**
   * Re-read the private-package rules when a file they came from (`.npmrc`, `.yarnrc.yml`, the
   * `go env -w` file) or the environment behind them changed, and rebuild the dependency set with
   * them. Stat calls only; called at the top of every tool call. True when anything changed.
   */
  refreshPrivateRules(): boolean {
    if (!this.privateRules.stale()) return false;
    const before = this.privateRules.fingerprint();
    this.privateRules = this.privateRules.reread();
    // A file rewritten with the same rules (a touched .npmrc) changes nothing: the dependency set
    // and the stored scan stand. Dropping them anyway lost a scan to a test worker rewriting the
    // shared empty .npmrc (CI run 43253624606).
    if (this.privateRules.fingerprint() === before) return false;
    if (this.initialized) {
      this.rebuildDependencySet();
      this.generation++;
      this.lastVulnScan = null;
      this.warmup = null;
      this.warmupFailedAt = null;
    }
    return true;
  }

  /** The notice for an `.npmrc` default registry that is not public (PrivatePackageRules.npmRegistryNotice), or null. */
  getRegistryNotice(): string | null {
    const notices = [
      this.groupResults.some((r) => mapEcosystem(r.group.language) === "npm") || this.groupResults.length === 0 ? this.privateRules.npmRegistryNotice() : null,
      this.pipExtraNotice(),
    ].filter((n): n is string => Boolean(n));
    return notices.length > 0 ? notices.join(" ") : null;
  }

  /** pip extra indexes that are not public, from pip's configuration or a requirements file (S4). */
  private pipExtraNotice(): string | null {
    const fromFiles = this.groupResults.flatMap((r) => (r.extraIndexes ?? []).map((e) => e.index));
    const usesPip = this.groupResults.some((r) => mapEcosystem(r.group.language) === "PyPI");
    return PrivatePackageRules.pipExtraNotice([...fromFiles, ...(usesPip ? this.privateRules.pipExtra : [])]);
  }

  /** Dependencies left out of every lookup because they are private, each with why. */
  getPrivateDependencies(): PrivateDependency[] {
    return this.privateDeps;
  }

  /** The same copies as resolved (with their directories): read from the lockfiles, never sent. */
  getPrivateAuditDeps(): ResolvedDependency[] {
    return this.privateAudit;
  }

  /** The private part of a scan in this scope, attached to its result so every answer reports it. */
  private withPrivate(scan: VulnerabilityScanResult, includeDev: boolean): VulnerabilityScanResult {
    const notice = this.getRegistryNotice();
    const result = notice ? { ...scan, registryNotice: notice } : scan;
    if (this.privateAudit.length === 0) return result;
    const scoped = applyInstanceDevScope(this.db, this.privateAudit);
    const inScope = includeDev ? scoped : scoped.filter((d) => !isDevOnlyCopy(d));
    if (inScope.length === 0) return result;
    const why = new Map(this.privateDeps.map((p) => [`${p.ecosystem}\0${p.name}\0${p.version ?? ""}`, p.why]));
    return {
      ...result,
      privateExcluded: {
        count: inScope.length,
        dependencies: inScope.slice(0, 50).map((d) => ({
          ecosystem: d.ecosystem,
          name: d.name,
          version: d.version,
          why: why.get(`${d.ecosystem}\0${d.name}\0${d.version ?? ""}`) ?? "private",
        })),
      },
    };
  }

  /**
   * Re-resolve every group whose inputs changed since they were read (a
   * lockfile rewritten, created or deleted; the fallback manifest; for npm,
   * the node_modules install state), and drop every answer that described the
   * old set: the stored scan and the warmup. Returns true when anything was
   * re-resolved. Stat calls only, so it is cheap enough for the top of every
   * tool call. A process that started before a `git pull` no longer answers
   * for the dependency set it saw at startup.
   */
  refreshIfLockfilesChanged(): boolean {
    const rulesChanged = this.refreshPrivateRules();
    if (!this.initialized || this.groupResults.length === 0) return rulesChanged;
    let changed = false;
    this.groupResults = this.groupResults.map((result) => {
      if (!groupIsStale(result)) return result;
      changed = true;
      return resolveGroup(result.group);
    });
    if (!changed) return rulesChanged;
    this.rebuildDependencySet();
    this.generation++;
    this.lastVulnScan = null;
    this.warmup = null;
    this.warmupFailedAt = null;
    return true;
  }

  /** When the dependency set in use was resolved, and from which files. Null before init. */
  getResolutionProvenance(): ResolutionProvenance | null {
    if (!this.initialized || !this.resolvedAt) return null;
    const seen = new Set<string>();
    const sources: ResolutionSourceRecord[] = [];
    for (const result of this.groupResults) {
      for (const source of result.sources) {
        if (seen.has(source.path)) continue;
        seen.add(source.path);
        sources.push(source);
      }
    }
    return { resolvedAt: this.resolvedAt, sources };
  }

  /** npm direct dependencies whose installed copy differs from the lockfile, per manifest directory. */
  getInstallDrift(): InstallDriftRecord[] {
    return this.groupResults.flatMap((r) => r.drift);
  }

  /**
   * Root directory the dependency set was resolved from, or null before init.
   * For multi-manifest (grouped) init this is the deepest common ancestor of
   * the group directories — honest scope reporting for tool output, instead
   * of whatever `process.cwd()` happens to be.
   */
  getProjectRoot(): string | null {
    return this.projectRoot;
  }

  /**
   * Run vulnerability scan (returns cached if fresh, fetches otherwise).
   *
   * Without `includeDev`, every dev-only copy is left out (severity-scope.ts
   * isDevOnlyCopy: a direct devDependency, or a transitive whose every path
   * is a dev one), the population dependency_health and upgrade_planner leave
   * out too. A copy of unknown scope stays: it must not be hidden.
   */
  /**
   * Run `fn` as a request made for this project (private-guard.ts): every lookup it makes is
   * judged by this project's private rules, not another project's.
   */
  runInContext<T>(fn: () => T): T {
    return withPrivateContext(this, fn);
  }

  /** Forget this layer's private rules in the HTTP guard (it is no longer used). */
  dispose(): void {
    unregisterPrivateNames(this);
  }

  async scanVulnerabilities(
    projectPath: string,
    options?: { includeDev?: boolean; forceRefresh?: boolean },
  ): Promise<VulnerabilityScanResult> {
    return this.runInContext(() => this.scanVulnerabilitiesIn(projectPath, options));
  }

  private async scanVulnerabilitiesIn(
    projectPath: string,
    options?: { includeDev?: boolean; forceRefresh?: boolean },
  ): Promise<VulnerabilityScanResult> {
    if (!this.enabled) {
      return this.withPrivate(emptyVulnResult(projectPath, true, { count: this.auditDeps.length, reason: LOOKUPS_DISABLED }), options?.includeDev ?? false);
    }

    // Names the guard would refuse are taken out first, each with why (takeOutRefused).
    this.takeOutRefused();
    // Read at scan time, not init time: the app rewrites its inventory on
    // every rescan, and the freshest determination is the one to grade by.
    const scoped = applyInstanceDevScope(this.db, this.auditDeps);
    const deps = options?.includeDev ? scoped : scoped.filter((d) => !isDevOnlyCopy(d));

    if (deps.length === 0) {
      return this.withPrivate(emptyVulnResult(projectPath, false), options?.includeDev ?? false);
    }

    if (options?.forceRefresh) {
      this.cache.invalidateSource("osv");
    }

    // The same scan already running (the startup warm-up, or a second call
    // while the first is out) is awaited, not repeated. A forced refresh
    // always runs its own.
    const shareKey = `${this.generation} ${options?.includeDev ? "dev" : "runtime"} ${projectPath}`;
    const running = options?.forceRefresh ? undefined : this.scansInFlight.get(shareKey);
    if (running) return running;
    const scan = this.runScan(deps, projectPath, options?.includeDev ?? false);
    if (!options?.forceRefresh) {
      this.scansInFlight.set(shareKey, scan);
      void scan.finally(() => this.scansInFlight.delete(shareKey));
    }
    return scan;
  }

  private async runScan(deps: ResolvedDependency[], projectPath: string, includeDev: boolean): Promise<VulnerabilityScanResult> {
    const generation = this.generation;
    const request = ++this.scanRequests;
    try {
      const result = this.withPrivate(await this.osvScanner.scan(deps, projectPath), includeDev);
      if (generation === this.generation && request > this.storedScanRequest) {
        this.lastVulnScan = result;
        this.lastVulnScanIncludesDev = includeDev;
        this.storedScanRequest = request;
      }
      return result;
    } catch (error) {
      // The scanner reports unreachable dependencies itself; reaching here is
      // an unexpected failure. Nothing was checked, and the answer says so
      // (it used to hand back the last scan or an empty one, read as clean).
      const reason = `the scan failed (${error instanceof Error ? error.message.slice(0, 120) : String(error)})`;
      return this.withPrivate({ ...emptyVulnResult(projectPath, true, { count: deps.length, reason }), ecosystemsScanned: [...new Set(deps.map((d) => d.ecosystem))] }, includeDev);
    }
  }

  /**
   * Start the vulnerability scan in the background without blocking startup.
   * Never rejects: a failed scan resolves to an empty OFFLINE result so the
   * warmup can be awaited by anyone. Idempotent while a warmup is in flight.
   *
   * Before this existed, full-database mode initialised the dependency set
   * and warmed headlines but never scanned, so `lastVulnScan` stayed null
   * until some tool happened to call `vulnerability_scan` — and the first
   * `what_should_i_know` of a session read an empty cache and reported
   * "safe_to_delegate" for a task naming a package with an open advisory.
   */
  startVulnerabilityWarmup(projectPath: string): void {
    if (this.warmup) return;
    this.warmupFailedAt = null;
    this.warmupStartedAt = Date.now();
    this.warmup = this.scanVulnerabilities(projectPath).catch((error) =>
      emptyVulnResult(projectPath, true, { count: this.auditDeps.length, reason: `the scan failed (${String(error).slice(0, 120)})` }),
    );
  }

  /**
   * A usable vulnerability scan, or null. Re-resolves first when a lockfile
   * changed. Returns the stored scan when one exists, otherwise awaits the
   * warmup (starting one if none is running) for at most `timeoutMs`. Null
   * means the scan is not available: disabled, still running past the
   * deadline, finished offline (an offline scan makes no clean-dependency
   * claims, so it cannot support a "safe" verdict), or overtaken by a
   * re-resolution while it ran. Never throws. A timed-out warmup keeps running
   * so a later call can use it.
   */
  async ensureVulnerabilities(
    projectPath: string,
    timeoutMs: number,
    options?: { includeDev?: boolean },
  ): Promise<VulnerabilityScanResult | null> {
    if (!this.enabled) return null;
    this.refreshIfLockfilesChanged();
    // A scan past its hour is not an answer about today's advisories: scan again (bounded, below).
    this.dropExpiredScan();
    const wantDev = options?.includeDev ?? false;
    if (this.lastVulnScan && !this.lastVulnScan.offline && (!wantDev || this.lastVulnScanIncludesDev)) {
      return this.lastVulnScan;
    }
    // A caller that needs direct devDependencies covered (a briefing whose task
    // names a dev dependency) cannot use the runtime-scope warmup: it reported
    // "vulnerabilities: []" for node-fetch 2.6.0, which has two advisories
    // (2026-10-03 pre-publish verification). Scan at the wider scope, bounded.
    if (wantDev) return this.awaitScan(this.scanVulnerabilities(projectPath, { includeDev: true }), timeoutMs);

    if (!this.warmup) {
      if (this.warmupFailedAt !== null && Date.now() - this.warmupFailedAt < WARMUP_RETRY_MS) {
        return null;
      }
      this.startVulnerabilityWarmup(projectPath);
    }
    const pending = this.warmup;
    if (!pending) return null;
    const generation = this.generation;

    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), Math.max(0, timeoutMs));
    });
    try {
      const settled = await Promise.race([pending, deadline]);
      if (settled === null) return null; // still scanning; keep the warmup alive
      // Re-resolved while waiting: that scan describes a set that no longer exists.
      if (generation !== this.generation) return null;
      const result = this.lastVulnScan ?? settled;
      if (result.offline) {
        // Failed or rate-limited: allow a fresh attempt after the backoff.
        this.warmup = null;
        this.warmupFailedAt = Date.now();
        return null;
      }
      return result;
    } catch {
      return null;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /** A scan's result within `timeoutMs`, or null when it times out, comes back offline, or is overtaken by a re-resolution. */
  private async awaitScan(
    pending: Promise<VulnerabilityScanResult>,
    timeoutMs: number,
  ): Promise<VulnerabilityScanResult | null> {
    const generation = this.generation;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), Math.max(0, timeoutMs));
    });
    try {
      const settled = await Promise.race([pending, deadline]);
      if (settled === null || generation !== this.generation || settled.offline) return null;
      return settled;
    } catch {
      return null;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /**
   * Fetch relevant headlines for the user's tech stack.
   */
  async fetchHeadlines(techStack: string[]): Promise<LiveHeadline[]> {
    return this.runInContext(() => this.fetchHeadlinesIn(techStack));
  }

  private async fetchHeadlinesIn(techStack: string[]): Promise<LiveHeadline[]> {
    if (!this.enabled) return [];
    // A private package name is never a search term (private-packages.ts): private by any rule, in
    // any ecosystem, in any spelling (privateReason reads every form under every ecosystem).
    const privateNames = new Set(this.privateDeps.map((p) => p.name.toLowerCase()));
    const terms = techStack.filter((t) => !privateNames.has(t.toLowerCase()) && !this.privateReason("npm", t));
    if (terms.length === 0) return [];

    try {
      this.lastHeadlines = await this.hnFetcher.fetch(terms);
      this.headlineError = null;
      return this.lastHeadlines;
    } catch (err) {
      this.headlineError = err instanceof Error ? err.message : String(err);
      return this.lastHeadlines; // Return last known
    }
  }

  /**
   * The last vulnerability scan (from memory, no network), or null when there
   * is none or it is older than MAX_STORED_SCAN_AGE_MS: an expired scan is
   * never handed out as the current state.
   */
  getVulnerabilities(): VulnerabilityScanResult | null {
    return this.lastVulnScan && !this.scanExpired(this.lastVulnScan) ? this.lastVulnScan : null;
  }

  /** Whether the stored scan covered direct devDependencies (false when there is none). */
  lastScanIncludesDev(): boolean {
    return this.getVulnerabilities() !== null && this.lastVulnScanIncludesDev;
  }

  /** True when a scan was taken more than MAX_STORED_SCAN_AGE_MS ago (or carries no readable time). */
  private scanExpired(scan: VulnerabilityScanResult): boolean {
    const takenAt = Date.parse(scan.scannedAt);
    return !Number.isFinite(takenAt) || Date.now() - takenAt > MAX_STORED_SCAN_AGE_MS;
  }

  /** Forget the stored scan, and the warmup behind it, once they have outlived MAX_STORED_SCAN_AGE_MS. */
  private dropExpiredScan(): void {
    if (this.lastVulnScan && this.scanExpired(this.lastVulnScan)) this.lastVulnScan = null;
    if (this.warmup && this.warmupStartedAt !== null && Date.now() - this.warmupStartedAt > MAX_STORED_SCAN_AGE_MS) {
      this.warmup = null;
      this.warmupFailedAt = null;
    }
  }

  /**
   * Get last headlines (from cache/memory, no network).
   */
  /** Why the last headline fetch read nothing, or null when it answered. */
  getHeadlineError(): string | null {
    return this.headlineError;
  }

  getHeadlines(): LiveHeadline[] {
    return this.lastHeadlines;
  }

  /**
   * Get resolved dependencies with versions.
   */
  getResolvedDeps(): ResolvedDependency[] {
    return this.resolvedDeps;
  }

  getAuditDeps(): ResolvedDependency[] {
    return this.auditDeps;
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  async fetchRegistryHealth(deps: ResolvedDependency[]): Promise<RegistryPackageInfo[]> {
    return this.runInContext(() => this.fetchRegistryHealthIn(deps));
  }

  private async fetchRegistryHealthIn(deps: ResolvedDependency[]): Promise<RegistryPackageInfo[]> {
    // Registries are read at call time (not captured at construction) so a
    // test can substitute one.
    return fetchRegistryHealthFor(
      deps,
      { npm: this.npmRegistry, crates: this.cratesRegistry, pypi: this.pypiRegistry, go: this.goRegistry },
      this.enabled,
    );
  }

  /** Per-release registry readers for dependency_check (name-only requests). */
  getReleaseSources(): Record<CheckEcosystem, ReleaseMetadataSource> {
    // Every read runs as made for this project (private-guard.ts).
    const scoped = (reader: ReleaseMetadataSource): ReleaseMetadataSource => ({
      getReleases: (name, wanted) => this.runInContext(() => reader.getReleases(name, wanted)),
      getCreatedAt: (name) => this.runInContext(() => reader.getCreatedAt(name)),
    });
    return { npm: scoped(this.npmPackuments), "crates.io": scoped(this.cratesVersions), PyPI: scoped(this.pypiReleases), Go: scoped(this.goReleases) };
  }


  /**
   * OSV advisories for explicit (ecosystem, name, version) triples that need
   * not be in the project, e.g. a version an agent is about to install. Same
   * scanner, cache and rate limit as vulnerability_scan; never touches the
   * stored project scan. Disabled or failed yields an `offline` result.
   */
  async queryAdvisories(deps: ResolvedDependency[]): Promise<VulnerabilityScanResult> {
    return this.runInContext(() => this.queryAdvisoriesIn(deps));
  }

  private async queryAdvisoriesIn(deps: ResolvedDependency[]): Promise<VulnerabilityScanResult> {
    if (!this.enabled) return emptyVulnResult("dependency_check", true, { count: deps.length, reason: LOOKUPS_DISABLED });
    // A private name is never asked about (a held dependency of a private parent): it has no
    // answer, so the result is not checked for it, never clean.
    const priv = deps.filter((d) => this.privateReason(d.ecosystem, d.name));
    const open = priv.length > 0 ? deps.filter((d) => !priv.includes(d)) : deps;
    let result: VulnerabilityScanResult;
    try {
      result = open.length > 0 ? await this.osvScanner.scan(open, "dependency_check") : emptyVulnResult("dependency_check", false);
    } catch (error) {
      return emptyVulnResult("dependency_check", true, { count: deps.length, reason: `the scan failed (${String(error).slice(0, 120)})` });
    }
    if (priv.length === 0) return result;
    const names = [...new Set(priv.map((d) => d.name))];
    return {
      ...result,
      offline: true,
      totalScanned: result.totalScanned + priv.length,
      unchecked: (result.unchecked ?? 0) + priv.length,
      uncheckedReason: [result.uncheckedReason, `${names.slice(0, 3).join(", ")}${names.length > 3 ? ", ..." : ""} ${names.length === 1 ? "is" : "are"} private and not sent`].filter(Boolean).join("; "),
    };
  }

  getStatus(): LiveIntelligenceStatus {
    return {
      enabled: this.enabled,
      offline: !this.enabled,
      lastOsvRefresh: this.lastVulnScan?.scannedAt || null,
      lastHnRefresh: this.lastHeadlines.length > 0 ? new Date().toISOString() : null,
      cachedVulnCount: this.lastVulnScan?.totalVulnerable || 0,
      cachedHeadlineCount: this.lastHeadlines.length,
    };
  }
}
