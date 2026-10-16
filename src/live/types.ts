// SPDX-License-Identifier: Apache-2.0

export type OsvEcosystem =
  | "npm"
  | "crates.io"
  | "PyPI"
  | "Go"
  | "Maven"
  | "NuGet"
  | "RubyGems"
  | "Packagist"
  | "Pub";

/** The reinstall command that brings node_modules back in line with a directory's lockfile. */
export type InstallFixCommand = "pnpm install" | "npm ci" | "yarn install" | "bun install";

export interface ResolvedDependency {
  name: string;
  version: string | null;
  ecosystem: OsvEcosystem;
  isDev: boolean;
  isDirect: boolean;
  devScopeKnown: boolean;
  /** Target spec gating this dep (e.g. `cfg(windows)`), or null if unconditional. */
  target: string | null;
  /** False when `target` is not active on the host platform (advisory is not relevant). */
  platformActive: boolean;
  /**
   * Manifest directories this exact (ecosystem, name, version) resolved from.
   *
   * A scan root can span several independent workspaces — `src-tauri/`,
   * `relay/`, `victauri-gauntlet/` all sit under one repo and pin their own
   * versions. Without this, dedupe collapsed them and the report named a
   * vulnerable version with no way to say WHICH workspace pinned it, so a
   * patched primary crate looked vulnerable because a sibling lagged.
   */
  sourceDirs: string[];
  /**
   * npm DIRECT deps resolved from a lockfile only: the version node_modules
   * actually holds (walking up for hoisted workspaces), or null when it is not
   * installed or unreadable. Undefined when the check did not run (another
   * ecosystem, no node_modules, or versions read from a manifest).
   */
  installedVersion?: string | null;
  /**
   * Set on the extra audit entry that asks OSV about an INSTALLED version the
   * lockfile does not pin: the lockfile's version of the same package. The
   * entry exists so `vulnerable_installed` is OSV's answer, not a guess.
   */
  installDriftOf?: string;
  /** On drift entries: the command that reinstalls from the lockfile. */
  installFix?: InstallFixCommand;
  /**
   * Set when no lockfile pins this dependency: the requirement the manifest
   * declares ("^1.2.0"). `version` is then that range's floor, NOT an
   * installed version, and the dependency is never sent to OSV as if it were.
   */
  declaredRange?: string;
}

/**
 * One npm direct dependency whose installed copy differs from its lockfile.
 * `dir` is the manifest directory, spelled as the resolution group spells it.
 */
export interface InstallDriftRecord {
  package: string;
  dir: string;
  lockfileVersion: string;
  installedVersion: string;
  fix: InstallFixCommand;
  isDev: boolean;
}

/** A file one resolution group read its versions from. */
export interface ResolutionSourceRecord {
  /** Absolute path. */
  path: string;
  /** lockfile = exact versions; manifest = exact requirement pins; declared_ranges = no lockfile, range floors only. */
  kind: "lockfile" | "manifest" | "declared_ranges";
  /** Modification time when it was read, or null if it vanished since. */
  mtimeMs: number | null;
}

/** When the dependency set in use was assembled, and from which files. */
export interface ResolutionProvenance {
  resolvedAt: string;
  sources: ResolutionSourceRecord[];
}

/**
 * An OSV record. The `/v1/querybatch` endpoint returns only `{ id, modified }`
 * per vulnerability (a lightweight index); the rich fields are populated only
 * after hydrating each advisory via `/v1/vulns/{id}`. Hence every field beyond
 * `id` is optional — consumers must tolerate the un-hydrated shape.
 */
export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package: { name: string; ecosystem: string };
    ranges: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string; limit?: string }>;
    }>;
    /** Versions listed explicitly, in addition to (or instead of) the ranges. */
    versions?: string[];
  }>;
  references?: Array<{ type: string; url: string }>;
  /** GitHub-advisory severity label: LOW | MODERATE | HIGH | CRITICAL. */
  database_specific?: { severity?: string };
  /** Set (to an RFC3339 timestamp) when the advisory has been withdrawn/retracted. */
  withdrawn?: string;
  published?: string;
  modified?: string;
}

export interface VulnerabilityEntry {
  package: string;
  currentVersion: string;
  ecosystem: OsvEcosystem;
  isDev: boolean;
  isDirect: boolean;
  devScopeKnown: boolean;
  vulnId: string;
  aliases: string[];
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  cvssScore: number | null;
  summary: string;
  fixedVersion: string | null;
  published: string;
  references: string[];
  /** Target spec gating the affected dep, or null if unconditional. */
  target: string | null;
  /** False when the affected dep is not active on the host platform. */
  platformActive: boolean;
  /**
   * Manifest directories that pin this vulnerable version. Answers the first
   * question a reader asks — *which project do I go fix?* — which a flat
   * package-name list cannot.
   */
  sourceDirs: string[];
  /**
   * Set when this row is about an INSTALLED version the lockfile does not pin
   * (node_modules drift): the lockfile's version of the same package.
   */
  installDriftOf?: string;
  /** On drift rows: the command that reinstalls from the lockfile. */
  installFix?: InstallFixCommand;
}

export interface VulnerabilityScanResult {
  scannedAt: string;
  projectPath: string;
  ecosystemsScanned: string[];
  totalScanned: number;
  totalVulnerable: number;
  /** Vulnerable packages that are NOT active on the host platform (relevance noise). */
  platformInactiveVulnerable: number;
  bySeverity: { critical: number; high: number; medium: number; low: number; unknown: number };
  vulnerabilities: VulnerabilityEntry[];
  /** Dependencies OSV answered for and found no advisory on (unchecked ones are never counted clean). */
  cleanCount: number;
  scanDurationMs: number;
  cached: boolean;
  /** True when any dependency has no advisory answer (`unchecked` > 0), or lookups are disabled. */
  offline: boolean;
  /**
   * Dependencies with NO advisory answer: OSV.dev could not be reached, failed,
   * timed out, or the query budget ran out, and no earlier answer was cached.
   * Their absence from `vulnerabilities` means nothing. Absent (= 0) on older
   * stubs.
   */
  unchecked?: number;
  /** Why `unchecked` dependencies have no answer, in words; null when every one was answered. */
  uncheckedReason?: string | null;
  /** Dependencies answered from an OSV answer older than the 1 h cache life, because a fresh query failed. */
  staleAnswers?: number;
}

/** How much of a dependency set OSV actually answered for. */
export interface VulnerabilityCoverage {
  complete: false;
  /** Dependencies sent for checking. */
  total_dependencies: number;
  /** Dependencies with an advisory answer (fresh or stale). */
  checked_dependencies: number;
  /** Dependencies with NO answer: nothing is known about their advisories. */
  unchecked_dependencies: number;
  /** Why, in words ("OSV.dev unreachable (fetch failed)", "live lookups disabled (FOURDA_OFFLINE=true)"). */
  reason: string;
  /** One line to read first; never a clean result. */
  note: string;
}

export interface LiveHeadline {
  id: string;
  title: string;
  url: string | null;
  source: "hacker_news";
  points: number;
  comments: number;
  published: string;
  relevanceScore: number;
  relevanceReason: string;
}

export interface LiveIntelligenceStatus {
  enabled: boolean;
  offline: boolean;
  lastOsvRefresh: string | null;
  lastHnRefresh: string | null;
  cachedVulnCount: number;
  cachedHeadlineCount: number;
}

// =============================================================================
// Registry Package Info (Phase 2)
// =============================================================================

export interface RegistryPackageInfo {
  name: string;
  ecosystem: OsvEcosystem;
  currentVersion: string | null;
  latestVersion: string | null;
  latestStableVersion: string | null;
  versionsBehind: SemverDistance | null;
  deprecated: boolean;
  deprecationMessage: string | null;
  lastPublished: string | null;
  license: string | null;
  weeklyDownloads: number | null;
  isDev: boolean;
  fetchError: string | null;
  /**
   * No lockfile: the declared requirement ("^1.2.0"); `currentVersion` is then
   * its floor, not an installed version.
   */
  declaredRange?: string;
  /**
   * The version node_modules actually holds, present only when it differs
   * from `currentVersion` (the lockfile's). Several differing installs across
   * workspaces are listed comma-separated.
   */
  installedVersion?: string;
}

export interface SemverDistance {
  major: number;
  minor: number;
  patch: number;
  label: "up-to-date" | "patch" | "minor" | "major";
}

export interface DependencyHealthResult {
  scannedAt: string;
  projectPath: string;
  ecosystemsScanned: string[];
  /**
   * Direct dependencies checked against their registries (the rows in
   * `dependencies`; devDependencies only with include_dev). Freshness,
   * deprecation and `outdatedCount` / `deprecatedCount` are over these.
   */
  totalDeps: number;
  /** Installed packages (direct and transitive) the vulnerability scan covered: what `vulnerableCount` ranges over. */
  treeDeps?: number;
  /** Of `vulnerableCount`, the packages a manifest declares directly. Null when the check is incomplete. */
  vulnerableDirectCount?: number | null;
  /** The penalties the score subtracts from 100, and how each is computed. Absent when the score is withheld. */
  healthScoreBasis?: { vulnerabilities: number; outdated: number; deprecated: number; note: string };
  outdatedCount: number;
  deprecatedCount: number;
  /**
   * Distinct packages with an advisory that is built on this host and is not a
   * maintenance notice — the same set `vulnerability_scan` reports as
   * `total_vulnerable_packages`, so the two tools agree over one scan.
   */
  /**
   * Distinct vulnerable packages across the full installed tree (`treeDeps`),
   * the same set vulnerability_scan reports as `total_vulnerable_packages`
   * for the same scope. It can exceed `totalDeps`, which counts direct
   * dependencies only. Null when any dependency could not be checked.
   */
  vulnerableCount: number | null;
  /**
   * Distinct advisories the scan returned (records naming each other, such as
   * a GHSA and its PYSEC twin, are one advisory per installed copy, as in
   * vulnerability_scan), before the platform and maintenance splits. Present
   * so nothing is hidden by the `vulnerableCount` filter: the difference is
   * platform-inactive packages and unmaintained-dependency notices.
   */
  advisoryCount: number;
  /** Null when vulnerability data is missing or incomplete: a score computed without it would read as healthier than it is. */
  healthScore: number | null;
  /** Present when the vulnerability check is incomplete: what was not checked and why. */
  vulnerabilityCoverage?: VulnerabilityCoverage;
  dependencies: RegistryPackageInfo[];
  /** Advisories (not packages) on the full tree by severity, over the same actionable set. */
  vulnerabilitySummary: { critical: number; high: number; medium: number; low: number } | null;
  summary: string;
  scanDurationMs: number;
  cached: boolean;
}
