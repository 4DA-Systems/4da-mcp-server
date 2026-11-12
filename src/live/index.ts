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
import { normName, npmLockPrivateSources, PrivatePackageRules, type PrivateDependency, type PrivateIndexEntry } from "./private-packages.js";
import { PrivateAwareFixPathSources } from "./private-fix-sources.js";
import { registerPrivateNames } from "./private-guard.js";
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
    this.enabled = process.env.FOURDA_OFFLINE !== "true" || options.advisorySource?.network === false;
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
    this.fixPathSources = new PrivateAwareFixPathSources(this.cache, this.rateLimiter, (ecosystem, name) => this.privateReason(ecosystem, name));
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
    this.applyGroups(groups, root);
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

  private applyGroups(groups: ResolutionGroup[], projectRoot: string | null): void {
    this.privateRules = new PrivatePackageRules([...new Set([...(projectRoot ? [projectRoot] : []), ...groups.map((g) => g.dir)])]);
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
    this.npmLockPrivate = new Map(
      this.groupResults
        .filter((r) => mapEcosystem(r.group.language) === "npm")
        .map((r) => [r, npmLockPrivateSources(r.group.dir, this.privateRules.npmMirrorHosts)] as const),
    );
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
    this.resolvedAt = new Date().toISOString();
  }

  /** Why a dependency of this group is private, or null: its lockfile's source, then the name rules. */
  private privateReasonIn(r: GroupResolution, ecosystem: string, name: string, version: string | null): string | null {
    const n = normName(ecosystem, name);
    const fromLock = this.lockPrivateOf(r).find((p) => normName(ecosystem, p.name) === n && (p.version === null || version === null || p.version === version));
    if (fromLock) return `${fromLock.file} installs it from ${fromLock.registry}, not the public registry`;
    return this.privateRules.reasonFor(ecosystem, name);
  }

  /**
   * Why a package name is private for this project, or null: the name rules (a scope mapped to a
   * private registry, GOPRIVATE, FOURDA_PRIVATE_PACKAGES), then any lockfile that installs it
   * from a private registry or index. dependency_check asks this before any lookup.
   */
  privateReason(ecosystem: string, name: string): string | null {
    const byName = this.privateRules.reasonFor(ecosystem, name);
    if (byName) return byName;
    // Every spelling the registry treats as the same name (`acme_core`, `Acme-Core`; review of #64, X1).
    const norm = (n: string) => normName(ecosystem, n);
    // A name this project ALSO installs from the public registry is public (a git fork of serde
    // beside serde itself): asking about it reveals nothing.
    if (this.auditDeps.some((d) => d.ecosystem === ecosystem && norm(d.name) === norm(name))) return null;
    for (const r of this.groupResults) {
      if (mapEcosystem(r.group.language) !== ecosystem) continue;
      const hit = this.lockPrivateOf(r).find((p) => norm(p.name) === norm(name));
      if (hit) return `${hit.file} installs it from ${hit.registry}, not the public registry`;
    }
    return null;
  }

  /** What a group's lockfiles install from a private source: the readers' entries, and npm's `resolved` hosts. */
  private lockPrivateOf(r: GroupResolution): PrivateIndexEntry[] {
    const npm = this.npmLockPrivate.get(r);
    return npm && npm.length > 0 ? [...(r.privateIndex ?? []), ...npm] : (r.privateIndex ?? []);
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
    this.privateRules = this.privateRules.reread();
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
    return this.privateRules.npmRegistryNotice();
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
    const notice = this.auditDeps.some((d) => d.ecosystem === "npm") ? this.privateRules.npmRegistryNotice() : null;
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
  async scanVulnerabilities(
    projectPath: string,
    options?: { includeDev?: boolean; forceRefresh?: boolean },
  ): Promise<VulnerabilityScanResult> {
    if (!this.enabled) {
      return this.withPrivate(emptyVulnResult(projectPath, true, { count: this.auditDeps.length, reason: LOOKUPS_DISABLED }), options?.includeDev ?? false);
    }

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
    if (!this.enabled) return [];
    // A private package name is never a search term (private-packages.ts).
    const privateNames = new Set(this.privateDeps.map((p) => p.name.toLowerCase()));
    const terms = techStack.filter(
      (t) => !privateNames.has(t.toLowerCase()) && !["npm", "crates.io", "PyPI", "Go"].some((eco) => this.privateRules.reasonFor(eco, t)),
    );
    if (terms.length === 0) return [];

    try {
      this.lastHeadlines = await this.hnFetcher.fetch(terms);
      return this.lastHeadlines;
    } catch {
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
    return { npm: this.npmPackuments, "crates.io": this.cratesVersions, PyPI: this.pypiReleases, Go: this.goReleases };
  }

  /**
   * OSV advisories for explicit (ecosystem, name, version) triples that need
   * not be in the project, e.g. a version an agent is about to install. Same
   * scanner, cache and rate limit as vulnerability_scan; never touches the
   * stored project scan. Disabled or failed yields an `offline` result.
   */
  async queryAdvisories(deps: ResolvedDependency[]): Promise<VulnerabilityScanResult> {
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
