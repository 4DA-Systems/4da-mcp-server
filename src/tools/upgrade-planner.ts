// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_planner tool
 *
 * One brain (AD-049): when the 4DA app's database holds its persisted Upgrade
 * Plan (current schema), the tool returns that plan's machine-readable work
 * order (`provenance.mode: "app_plan"`, flagged `stale` past its horizon) —
 * see ./app-plan.ts. Only without one does it run the standalone heuristic
 * below: version freshness, vulnerability data and deprecation status from
 * the local lockfiles (`provenance.mode: "standalone_heuristic"`).
 *
 * Honesty contract (Phase 0 hardening):
 * - Transitive CVEs are surfaced as `waiting_on_upstream` steps instead of
 *   being counted-but-never-recommended. No dependency-graph parsing happens
 *   here — parent mapping is the desktop core's job; the honest label is ours.
 * - Output carries explicit heuristic provenance: this is a point-in-time
 *   standalone plan, not the 4DA app's cross-project, version-confirmed plan.
 * - `projectPath` reports the directory set the dependencies were actually
 *   resolved from, not whatever `process.cwd()` happens to be.
 * - When no vulnerability scan has run, the planner runs one (bounded); if it
 *   cannot finish, the plan says it is CVE-blind instead of ranking silently.
 * - When node_modules holds a different version than the lockfile, the row
 *   says so (`installedVersion`) and a reinstall is the step when nothing
 *   else about the lockfile's version needs changing.
 */

import type { FourDADatabase } from "../db.js";
import type { LiveIntelligence } from "../live/index.js";
import { isActionableVulnerability, isMaintenanceNotice } from "../live/maintenance.js";
import { computeSemverDistance } from "../live/semver-utils.js";
import { compareVersions, inEcosystemForm, maxVersion, namesPackage } from "../live/version-compare.js";
import { formatAppPlan, readAppPlan, type AppPlanResult } from "./app-plan.js";
import { dirsLabel, driftFor } from "./install-drift-notes.js";
import { emptyAnswerNote } from "./package-presence.js";
import { relativeDir } from "./vulnerability-scan-format.js";
import { liveIntelFor, resolveProjectScope } from "./project-scope.js";
import { reconcileDirectTargets, verifyFixPaths, type FixPathInput, type ParentUpgrade } from "./upgrade-planner-fixpaths.js";
import { groupAdvisories } from "../live/advisory-groups.js";
import { isDevOnlyCopy, rankedSeverity } from "../live/severity-scope.js";
import { discoveryNote, exclusionNotes, unreadableNotes } from "../project-tree.js";
import { vulnerabilityCoverage } from "../live/scan-coverage.js";
import { uncheckedOfferNote, vetOfferedReleases } from "../live/offered-release.js";
import type { VulnerabilityCoverage, VulnerabilityEntry } from "../live/types.js";

export interface UpgradePlannerParams {
  include_dev?: boolean;
  max_recommendations?: number;
  risk_threshold?: "all" | "low" | "medium" | "high" | "critical";
  package?: string;
  /** Project directory to plan for; "*" for every project. Default: the server's project, when it is one. */
  project_path?: string;
}

interface UpgradeRecommendation {
  package: string;
  ecosystem: string;
  currentVersion: string | null;
  /**
   * Where to upgrade to. With a vulnerability: the SMALLEST version that fixes
   * every fixable advisory on the installed line, not the newest major (which
   * sent node-fetch 2.6.1 to the ESM-only 3.x when 2.6.7 fixes both CVEs).
   * Otherwise the latest stable release.
   */
  targetVersion: string | null;
  /** Latest stable release, when it differs from the target. */
  latestVersion?: string | null;
  /** Distance from currentVersion to targetVersion. */
  upgradeType: "patch" | "minor" | "major" | "unknown";
  risk: "low" | "medium" | "high" | "critical";
  reasons: string[];
  breaking: boolean;
  isDev: boolean;
  /** Whether this package is declared in a manifest (direct) or only present via the lockfile (transitive). */
  scope: "direct" | "transitive";
  /**
   * Direct deps you can bump yourself; `lockfile_refresh` = transitive, and
   * every parent's declared requirement already admits a clean version, so
   * `refreshCommands` fixes it (`refreshInferred` when that is inferred from
   * semver because a requirement could not be read); `waiting_on_upstream` =
   * transitive, and a parent's requirement excludes every clean version (or
   * none could be read and the target leaves the semver-compatible range);
   * `reinstall` = the lockfile's version is fine
   * but node_modules holds another one, so the fix is `installFix`;
   * `upgrade_parent` = transitive, a parent's requirement excludes every clean
   * version and a newer release of that parent exists: `parentUpgrades` names
   * the smallest release whose own requirement admits a clean version (read
   * from the registry), through the direct dependency it arrives by when the
   * parent is transitive, or the parent's newest release to check when its
   * requirements could not be read;
   * `override_or_replace` = transitive, a parent's requirement excludes every
   * clean version and that parent will not move (deprecated, already at its
   * latest release, or no release up to the latest admits one): force the version (npm `overrides`, pnpm
   * `pnpm.overrides`, yarn `resolutions`, Cargo `[patch]`) or replace the parent;
   * `no_fix_available` = vulnerable with no fixed release to move to;
   * `not_built_on_this_host` = every advisory is against code this host never compiles;
   * `upgrade_parent_unverified` = transitive, a parent release that admits a clean version exists,
   * but no release of the declared dependency that brings it in was verified (every lever's `to`
   * is null): `parentUpgrades` says what to check; nothing is counted as fixed;
   * `remove_dependency` = the installed version is npm's security placeholder and every newer
   * release is known-affected (crossenv: 1.0.0 and 1.0.1 are malware): remove the dependency;
   * `hold_current` = no advisory affects the installed version, and every newer release is
   * known-affected or withdrawn: stay on it (the reasons say why).
   * Every release a row offers, the newest one included, is checked against the package's
   * advisories and the registry's withdrawals, as dependency_check checks one.
   */
  action:
    | "upgrade_direct"
    | "lockfile_refresh"
    | "upgrade_parent"
    | "upgrade_parent_unverified"
    | "waiting_on_upstream"
    | "override_or_replace"
    | "reinstall"
    | "no_fix_available"
    | "not_built_on_this_host"
    | "remove_dependency"
    | "hold_current";
  /** upgrade_parent / override_or_replace: the parent release that admits a clean version, per blocking parent that can move. */
  parentUpgrades?: ParentUpgrade[];
  /**
   * For a vulnerable package: whether the target was checked against EVERY
   * known advisory of the package (`all_advisories`), or only against the
   * advisories of the installed version because the lookups failed or ran
   * out of time (`installed_advisories_only`; the target may then be
   * affected by an advisory the installed version predates).
   */
  fixPathChecked?: "all_advisories" | "installed_advisories_only";
  /**
   * Releases the registry withdrew (crates.io/PyPI yanked; npm deprecated with a later clean
   * release on its line) that targetVersion steps over, or, with no target, the only releases
   * that fixed it: "no installable fix", not "no fix published". The reasons say why (FX-H5).
   */
  withheld?: string[];
  /** lockfile_refresh: the command to run, per lockfile directory. */
  refreshCommands?: Array<{ dir: string; command: string }>;
  /**
   * upgrade_direct: the command that moves the declared dependency to
   * targetVersion where it is declared, per lockfile directory (npm install,
   * pnpm up, yarn upgrade / yarn up, cargo add with --dev for a
   * dev-dependency). Absent for tools no command is named for.
   */
  upgradeCommands?: Array<{ dir: string; command: string; refresh?: true }>;
  /** upgrade_direct: a manifest edit where no single verified command makes it (a workspace-inherited crate, a requirements.txt pin). */
  upgradeInstructions?: Array<{ dir: string; instruction: string }>;
  /**
   * lockfile_refresh: true when not every parent's requirement could be read
   * (none read excludes the target) and the target is semver-compatible with
   * the installed version, so the refresh is inferred rather than read.
   */
  refreshInferred?: boolean;
  /** False when the dependency is gated behind a target spec not active on this host (label, never suppressed). */
  platformActive: boolean;
  /** npm: the version node_modules holds, when it differs from `currentVersion` (the lockfile's). */
  installedVersion?: string;
  /** npm: the command that reinstalls from the lockfile, when `installedVersion` is set. */
  installFix?: string;
  /** No lockfile: the manifest's declared requirement; `currentVersion` is its floor, not an install. */
  declaredRange?: string;
}

interface UpgradePlanResult {
  generatedAt: string;
  projectPath: string;
  totalDeps: number;
  recommendations: UpgradeRecommendation[];
  summary: string;
  quickWins: number;
  breakingChanges: number;
  waitingOnUpstream: number;
  /** Transitive steps a lockfile refresh fixes (every parent already admits a clean version). */
  lockfileRefreshes: number;
  /** Transitive steps fixed by upgrading the parent that pins them (`parentUpgrades` names the release). */
  parentUpgradeSteps: number;
  /** False unless OSV answered for EVERY dependency in scope: a plan over missing or partial data is not CVE-aware. */
  vulnerabilityDataAvailable: boolean;
  /** Present when the vulnerability check is missing or incomplete: what was not checked and why. */
  vulnerabilityCoverage?: VulnerabilityCoverage;
  provenance: {
    mode: "standalone_heuristic";
    note: string;
  };
  /** Why the 4DA app's own plan was not used (no database, no snapshot, other schema). */
  appPlanUnavailable?: string;
  /** The project the plan covers, or null when it is not narrowed to one. */
  projectScope?: string | null;
}

/** Time the plan spends checking the newer releases its rows offer against their advisories. */
const OFFER_CHECK_BUDGET_MS = 10_000;

/** The newer release a registry row would offer (its latest stable), or null when it offers none. */
function offeredUpgrade(dep: { ecosystem: string; currentVersion: string | null; latestStableVersion: string | null; latestVersion: string | null }): string | null {
  const latest = dep.latestStableVersion || dep.latestVersion;
  if (!latest || !dep.currentVersion) return null;
  return compareVersions(latest, dep.currentVersion, dep.ecosystem) > 0 ? latest : null;
}

/** How long a plan waits for its own OSV scan before answering CVE-blind (the scan keeps running). */
const PLANNER_SCAN_TIMEOUT_MS = 60_000;

const PROVENANCE_NOTE =
  "Point-in-time heuristic from local lockfiles plus live registry/OSV lookups. " +
  "Not the 4DA desktop app's cross-project, version-confirmed plan (none was available).";

export const upgradePlannerTool = {
  name: "upgrade_planner",
  description:
    "Ranked dependency upgrade plan for one project — call before upgrading, adding, or auditing any dependency to pick the safest order. `project_path` picks the project (default: the one the server was started in; \"*\" for every project). When the 4DA desktop app has computed its plan, returns that plan's work order (provenance app_plan): per package the ecosystem, each installed version with its minimum clean target, upgrade type (patch/minor/major), the projects that hold it (direct/dev) and the mechanism (manifest_bump, lockfile_or_parent_update, mixed, no_fix); flagged stale past its freshness horizon. Otherwise falls back to a standalone plan from local lockfiles (provenance standalone_heuristic): the smallest version that fixes each vulnerability (direct and transitive), checked against every known advisory of the package, whether a lockfile refresh already reaches it (lockfile_refresh with the command) or a parent blocks it: upgrade_parent with `parentUpgrades` naming the smallest parent release whose requirement admits a clean version (through the direct dependency it arrives by), override_or_replace with the override syntax when no parent release will (deprecated, already latest, or none admits one), waiting_on_upstream when nothing could be read; direct steps carry `upgradeCommands` and are raised to the release that also clears the transitives they pin; a copy bundled inside its owner waits on the owner; dev-only rows are included and labelled `isDev`, as in vulnerability_scan; deprecation and version distance; it runs the OSV scan itself when none has run. When OSV.dev could not answer for every dependency, `vulnerabilityDataAvailable` is false, `vulnerabilityCoverage` counts the unchecked ones and the summary starts with \"NOT CHECKED\": the plan then misses whatever those dependencies carry. `package` narrows either plan to one package. Privacy: the fallback may query public registries and OSV with package names and versions; it never sends source code.",
  inputSchema: {
    type: "object" as const,
    properties: {
      include_dev: {
        type: "boolean",
        description:
          "Dev-only packages (labelled isDev). Default (unset): vulnerable devDependencies and dev-only transitive packages are planned, as in vulnerability_scan; true also checks every devDependency for newer releases and deprecation; false leaves dev-only packages out and the summary counts them.",
      },
      max_recommendations: {
        type: "number",
        description: "Max recommendations to return. Default: 20",
      },
      risk_threshold: {
        type: "string",
        enum: ["all", "low", "medium", "high", "critical"],
        description: "Only show upgrades at or above this risk level. Default: all",
      },
      package: {
        type: "string",
        description: "Plan for this one package only (exact name, any ecosystem). Default: every dependency.",
      },
      project_path: {
        type: "string",
        description:
          "Project directory to plan for: the app's plan is narrowed to the steps (and installed lines) that touch it; the standalone plan resolves that project's lockfiles. \"*\" for every project the app tracks. Default: the project the server was started in, when that directory is a project.",
      },
    },
  },
};

const RISK_LEVELS: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** critical > high > medium > low, then runtime before dev-only, then fixable now (direct) before transitive, then non-breaking first (quick wins). */
function planOrder(a: UpgradeRecommendation, b: UpgradeRecommendation): number {
  const riskDiff = RISK_LEVELS[b.risk] - RISK_LEVELS[a.risk];
  if (riskDiff !== 0) return riskDiff;
  if (a.isDev !== b.isDev) return a.isDev ? 1 : -1;
  if (a.scope !== b.scope) return a.scope === "direct" ? -1 : 1;
  if (a.breaking !== b.breaking) return a.breaking ? 1 : -1;
  return 0;
}

/**
 * The grade a row ranks by: the scope-adjusted severity vulnerability_scan presents (transitive
 * caps critical at high; dev-only drops one level), over the 4DA app's base urgency (an ungraded
 * advisory medium, a MAL- record high: severity-scope.ts rankedSeverity). A dev-only medium is low,
 * as the scan presents it; it used to stay medium. Ranking on the raw grade let dev-only criticals
 * push a runtime high out of max_recommendations (readiness review 2026-10-17, finding 6).
 */
function riskOf(entries: VulnerabilityEntry[]): UpgradeRecommendation["risk"] {
  const tiers = entries.map((v) => rankedSeverity(v));
  for (const t of ["critical", "high", "medium"] as const) if (tiers.includes(t)) return t;
  return "low";
}

/** Distance between the installed and target versions (patch/minor/major), or unknown. */
function upgradeTypeBetween(current: string | null, target: string | null): UpgradeRecommendation["upgradeType"] {
  if (!current || !target) return "unknown";
  const distance = computeSemverDistance(current, target);
  return !distance || distance.label === "up-to-date" ? "unknown" : distance.label;
}

function higherRisk(
  a: UpgradeRecommendation["risk"],
  b: UpgradeRecommendation["risk"],
): UpgradeRecommendation["risk"] {
  return RISK_LEVELS[b] > RISK_LEVELS[a] ? b : a;
}

export async function executeUpgradePlanner(
  db: FourDADatabase,
  params: UpgradePlannerParams,
  liveIntel: LiveIntelligence | null,
): Promise<UpgradePlanResult | AppPlanResult> {
  const scope = resolveProjectScope(params.project_path);
  if (scope.kind === "error") throw new Error(scope.error);
  const scopePath = scope.kind === "project" ? scope.path : null;
  // One brain: the app's plan wins whenever there is one, stale or not (a
  // stale plan is returned flagged, never silently replaced by a heuristic).
  // It covers every project the app tracks, so it is narrowed to this one.
  const appPlan = readAppPlan(db);
  if (appPlan.kind === "plan") return formatAppPlan(appPlan, params, scopePath);
  // The live layer already covers the server's own project; only an explicit
  // project_path elsewhere resolves another tree.
  const scoped =
    scope.kind === "project" && scope.source === "argument"
      ? (liveIntelFor(liveIntel, db, scope) as LiveIntelligence | null)
      : liveIntel;
  const standalone = await executeStandalonePlanner(params, scoped);
  return { ...standalone, appPlanUnavailable: appPlan.reason, projectScope: scopePath ?? standalone.projectPath };
}

async function executeStandalonePlanner(
  params: UpgradePlannerParams,
  liveIntel: LiveIntelligence | null,
): Promise<UpgradePlanResult> {
  if (!liveIntel || !liveIntel.isInitialized()) {
    return {
      generatedAt: new Date().toISOString(),
      projectPath: process.cwd(),
      totalDeps: 0,
      recommendations: [],
      summary: "No project detected. Run from a directory with package.json, Cargo.toml, pyproject.toml, or go.mod.",
      quickWins: 0,
      breakingChanges: 0,
      waitingOnUpstream: 0,
      lockfileRefreshes: 0,
      parentUpgradeSteps: 0,
      vulnerabilityDataAvailable: false,
      provenance: { mode: "standalone_heuristic", note: PROVENANCE_NOTE },
    };
  }

  // A long-lived server must not plan from the versions it read at startup:
  // re-resolve if a lockfile (or node_modules) changed. Stat calls only.
  liveIntel.refreshIfLockfilesChanged();

  // Dev dependencies by default, as vulnerability_scan (A8): leaving them out hid 30 of navcal's
  // 34 vulnerable versions, vitest's critical among them (readiness audit H4).
  const includeDev = params.include_dev ?? true;
  const only = params.package?.trim();
  const named = (name: string, ecosystem: string) => !only || namesPackage(only, name, ecosystem);
  let deps = liveIntel.getResolvedDeps();
  if (only) deps = deps.filter((d) => named(d.name, d.ecosystem));
  const devDirect = includeDev ? [] : deps.filter((d) => d.isDev);
  if (!includeDev) deps = deps.filter((d) => !d.isDev);
  const drift = liveIntel.getInstallDrift();
  const root = liveIntel.getProjectRoot() ?? process.cwd();

  // Vulnerability data at the plan's scope, loaded here (bounded) when no scan
  // has run. Telling the agent to "run vulnerability_scan first" made the first
  // plan of every session CVE-blind (2026-10-03 agent eval). A plan that
  // includes dev dependencies must not read a scan that left them out, so
  // ensureVulnerabilities rescans at the wider scope when needed.
  const vulnResult =
    (await liveIntel.ensureVulnerabilities(root, PLANNER_SCAN_TIMEOUT_MS, { includeDev })) ?? liveIntel.getVulnerabilities();
  // include_dev: false: the summary counts the vulnerable devDependencies it left out, when the
  // scan read them; otherwise how many it did not check (readiness review 2026-10-17, finding 10).
  const devScanned = devDirect.length > 0 && liveIntel.lastScanIncludesDev();
  const devVulnerable = new Set(
    (vulnResult?.vulnerabilities ?? []).filter((v) => v.isDirect && v.isDev && !isMaintenanceNotice(v)).map((v) => `${v.ecosystem}\0${v.package}\0${v.currentVersion}`),
  );
  const devDirectLeftOut = devScanned ? devDirect.filter((d) => devVulnerable.has(`${d.ecosystem}\0${d.name}\0${d.version}`)).length : 0;
  const devDirectUnchecked = devScanned ? 0 : devDirect.length;

  // Registry rows (freshness, deprecation) for direct deps. By default a devDependency gets one
  // only when it is vulnerable: fetching every dev tool's registry document (typescript,
  // @types/node, vite...) more than doubled navcal's lookups for rows no advisory asks for.
  // include_dev: true checks every devDependency's freshness too.
  const vulnerableNames = new Set((vulnResult?.vulnerabilities ?? []).filter((v) => !isMaintenanceNotice(v)).map((v) => `${v.ecosystem}\0${v.package}`));
  const registryDeps =
    params.include_dev === undefined ? deps.filter((d) => !d.isDev || vulnerableNames.has(`${d.ecosystem}\0${d.name}`)) : deps;
  const devFreshnessSkipped = deps.length - registryDeps.length;
  // Fetch registry data (live lookups for direct deps; cached where fresh)
  const registryData = await liveIntel.fetchRegistryHealth(registryDeps);
  // Every newer release a row offers is checked as dependency_check checks one (offered-release.ts):
  // crossenv 0.0.2-security was sent to 1.0.1, the malware itself (final release audit of 6.2.5).
  const offerSources = liveIntel.getFixPathSources();
  const offers = await vetOfferedReleases(
    offerSources,
    registryData
      .filter((d) => offeredUpgrade(d) !== null)
      .map((d) => ({ key: `${d.ecosystem}\0${d.name}\0${d.currentVersion ?? "unknown"}`, ecosystem: d.ecosystem, name: d.name, installed: d.currentVersion, offered: offeredUpgrade(d)! })),
    OFFER_CHECK_BUDGET_MS,
  );
  // Complete vulnerability data only: a partial scan (OSV.dev unreachable or
  // rate limited for some dependencies) ranks what it found and says the rest
  // is unchecked; it never claims the plan is CVE-aware (6.2.4 said
  // vulnerabilityDataAvailable: true over 10,568 unchecked dependencies).
  const scopeTotal = liveIntel.getAuditDeps().filter((d) => includeDev || !isDevOnlyCopy(d)).length;
  const coverage = vulnerabilityCoverage(vulnResult, {
    enabled: liveIntel.isEnabled(),
    expectedTotal: scopeTotal,
    notLoaded: `the OSV.dev scan did not finish within ${PLANNER_SCAN_TIMEOUT_MS / 1000} s or OSV.dev was unreachable`,
  });
  const vulnerabilityDataAvailable = vulnResult !== null && coverage === null;
  // Keyed by ecosystem + name + INSTANCE version. A name-only key attached every
  // instance's CVEs to whichever row asked first: the direct anyhow 1.0.104 was
  // charged with RUSTSEC-2026-0190 (fixed in 1.0.103 — it isn't affected) while
  // the actually-vulnerable transitive anyhow 1.0.102 was hidden by the
  // direct-name skip below. Scan entries are created per scanned instance, so
  // the instance version is exact.
  const instanceKey = (ecosystem: string, name: string, version: string | null) =>
    `${ecosystem}\0${name}\0${version ?? "unknown"}`;
  const vulnsByPackage = new Map<string, VulnerabilityEntry[]>();
  // "X is unmaintained" (RUSTSEC informational) is not a CVE and has nothing
  // to upgrade to; it was counted as "1 known CVE" on paste, ttf-parser and
  // five unic-* crates. Counted separately, never ranked.
  const maintenanceNotices = new Set<string>();
  if (vulnResult) {
    for (const v of vulnResult.vulnerabilities) {
      if (!named(v.package, v.ecosystem)) continue;
      if (isMaintenanceNotice(v)) {
        maintenanceNotices.add(`${v.package}@${v.currentVersion}`);
        continue;
      }
      const key = instanceKey(v.ecosystem, v.package, v.currentVersion);
      if (!vulnsByPackage.has(key)) vulnsByPackage.set(key, []);
      vulnsByPackage.get(key)!.push(v);
    }
  }

  // Build recommendations — direct deps (registry-informed)
  const recommendations: UpgradeRecommendation[] = [];
  const directPackages = new Set<string>();
  // Per vulnerable step: the per-advisory fixes and where it is pinned, for fix-path verification.
  const fixPathInputs = new Map<UpgradeRecommendation, Omit<FixPathInput, "step">>();

  for (const dep of registryData) {
    directPackages.add(instanceKey(dep.ecosystem, dep.name, dep.currentVersion));
    const reasons: string[] = [];
    let risk: UpgradeRecommendation["risk"] = "low";
    const registryLatest = dep.latestStableVersion || dep.latestVersion;
    // The newest release this row may offer: the registry's latest, unless an advisory affects it or
    // the registry withdrew it; then the newest release above the installed one that is neither.
    const offered = offeredUpgrade(dep);
    const vet = offered ? offers.get(instanceKey(dep.ecosystem, dep.name, dep.currentVersion)) : undefined;
    const offerNote = offered ? (vet ? vet.note : offerSources ? uncheckedOfferNote(dep.name, offered) : null) : null;
    const latestStable = vet?.checked && vet.note ? vet.safe : registryLatest;
    const noSafeUpgrade = Boolean(offered && vet?.checked && vet.note && vet.safe === null);
    let targetVersion = latestStable;
    let platformActive = true;
    let fixable = false;

    // Check vulnerabilities
    const vulns = vulnsByPackage.get(instanceKey(dep.ecosystem, dep.name, dep.currentVersion));
    // One advisory per alias group: GHSA + PYSEC records of one issue counted twice (django 96 for 51, M1).
    const groups = groupAdvisories(vulns);
    const unfixedGroups = groups.filter((g) => !g.members.some((m) => m.fixedVersion));
    if (vulns && vulns.length > 0) {
      reasons.push(vulnerabilitiesReason(groups));
      if (vulns.every((v) => !v.platformActive)) {
        // Code this host never compiles is not this host's exposure: listed,
        // never ranked as high (openssl topped the plan on Windows).
        platformActive = false;
        risk = "low";
        reasons.push("Affected code is gated behind a target not active on this platform");
      } else {
        risk = riskOf(vulns.filter((v) => v.platformActive));
      }

      // The smallest version that fixes every fixable advisory: each
      // fixedVersion is already the fix on the installed release line.
      const fixedVersions = vulns.map((v) => v.fixedVersion).filter((f): f is string => Boolean(f));
      if (fixedVersions.length > 0) {
        targetVersion = maxVersion(fixedVersions, dep.ecosystem);
        fixable = true;
        if (unfixedGroups.length > 0) reasons.push(noFixReason(unfixedGroups.length));
      }
    }

    // Check deprecation
    if (dep.deprecated) {
      if (risk === "low") risk = "high";
      reasons.push(dep.deprecationMessage ? `Deprecated: ${dep.deprecationMessage}` : "Package is deprecated");
    }

    // Check version distance: to the release this row may offer, not to a known-affected latest.
    const behind = latestStable === registryLatest ? dep.versionsBehind : latestStable && dep.currentVersion ? computeSemverDistance(dep.currentVersion, latestStable) : null;
    if (behind && behind.label !== "up-to-date") {
      const d = behind;
      if (d.label === "major" && d.major === 0) {
        // A 0.x bump: breaking under caret rules, though the major number is unchanged.
        const n = d.minor > 0 ? d.minor : d.patch;
        const unit = d.minor > 0 ? "minor version" : "patch";
        reasons.push(`${n} 0.x ${unit}${n !== 1 ? (unit === "patch" ? "es" : "s") : ""} behind (breaking: below 1.0 a ${unit === "patch" ? "0.0.x patch" : "minor"} bump is a major one)`);
        if (risk === "low") risk = "medium";
      } else if (d.label === "major") {
        reasons.push(`${d.major} major version${d.major !== 1 ? "s" : ""} behind`);
        if (risk === "low") risk = "medium";
      } else if (d.label === "minor") {
        reasons.push(`${d.minor} minor version${d.minor !== 1 ? "s" : ""} behind`);
      } else if (d.label === "patch") {
        reasons.push(`${d.patch} patch${d.patch !== 1 ? "es" : ""} behind`);
      }
    }

    // Install drift: node_modules holds another version than this lockfile
    // row, and until a reinstall the installed copy's advisories are the real
    // exposure. Without this, a patched, up-to-date lockfile version had no
    // reasons and the row was skipped, so a vulnerable installed copy never
    // appeared in the plan at all.
    const lockfileReasons = reasons.length;
    const drifted = dep.ecosystem === "npm" ? driftFor(drift, dep.name, dep.currentVersion) : [];
    let installedVersion: string | undefined;
    let installFix: string | undefined;
    if (drifted.length > 0) {
      installedVersion = [...new Set(drifted.map((r) => r.installedVersion))].join(", ");
      installFix = drifted[0].fix;
      const where = dirsLabel(drifted.map((r) => r.dir), (d) => relativeDir(d, root));
      reasons.push(`node_modules has ${installedVersion}, not the lockfile's ${dep.currentVersion} — run \`${installFix}\` in ${where}`);
      for (const installed of new Set(drifted.map((r) => r.installedVersion))) {
        const installedVulns = vulnsByPackage.get(instanceKey("npm", dep.name, installed));
        if (!installedVulns || installedVulns.length === 0) continue;
        const installedGroups = groupAdvisories(installedVulns);
        reasons.push(
          `The installed ${installed} has ${installedGroups.length} known CVE${installedGroups.length !== 1 ? "s" : ""} (${installedGroups.map((g) => g.best.vulnId).join(", ")})`,
        );
        risk = higherRisk(risk, riskOf(installedVulns));
      }
    }

    // Every newer release is known-affected or withdrawn: the row says so (crossenv: remove it).
    if (noSafeUpgrade && offerNote) reasons.push(offerNote);
    // Skip if no upgrade needed (no vuln, not deprecated, not behind, no drift => no reasons)
    if (reasons.length === 0) continue;
    // The newer release it would have offered was replaced or could not be checked: said, never silent.
    if (offerNote && !noSafeUpgrade) reasons.push(offerNote);
    if (dep.declaredRange) {
      reasons.push(`No lockfile: ${dep.currentVersion} is the floor of the declared range "${dep.declaredRange}", not an installed version`);
    }

    // Never recommend a downgrade: when the current version is a prerelease
    // AHEAD of the latest stable (rsa 0.10.0-rc.18 vs stable 0.9.10), the
    // stable line is not an upgrade target.
    if (
      targetVersion &&
      dep.currentVersion &&
      compareVersions(dep.currentVersion, targetVersion, dep.ecosystem) >= 0
    ) {
      targetVersion = null;
    }

    const upgradeType = upgradeTypeBetween(dep.currentVersion, targetVersion);
    // Drift is the only problem: the lockfile's version is the target, and
    // reinstalling it is the whole step.
    const reinstallOnly = drifted.length > 0 && lockfileReasons === 0;
    const vulnerable = Boolean(vulns && vulns.length > 0);
    const action: UpgradeRecommendation["action"] = reinstallOnly
      ? "reinstall"
      : vulnerable && !platformActive
        ? "not_built_on_this_host"
        : vulnerable && !fixable
          ? "no_fix_available"
          : !vulnerable && noSafeUpgrade
            ? vet?.holding
              ? "remove_dependency"
              : "hold_current"
            : targetVersion
              ? "upgrade_direct"
              : "no_fix_available";

    const rec: UpgradeRecommendation = {
      package: dep.name,
      ecosystem: dep.ecosystem,
      currentVersion: dep.currentVersion,
      // A vulnerable row with no fix names no release (its newest is affected too): the parent_release
      // vectors' own_target is null there (pr-006, request 2.88.0), and verifyFixPaths names one only
      // when a release past a last_affected bound is clean.
      targetVersion: reinstallOnly ? dep.currentVersion : action === "no_fix_available" ? null : targetVersion,
      ...(latestStable && latestStable !== targetVersion ? { latestVersion: latestStable } : {}),
      upgradeType: action === "no_fix_available" ? "unknown" : upgradeType,
      risk,
      reasons,
      breaking: action !== "no_fix_available" && upgradeType === "major",
      isDev: dep.isDev,
      scope: "direct",
      action,
      platformActive,
      ...(installedVersion ? { installedVersion, installFix } : {}),
      ...(dep.declaredRange ? { declaredRange: dep.declaredRange } : {}),
    };
    recommendations.push(rec);
    if (fixable && !reinstallOnly && action === "upgrade_direct" && vulns) {
      // The manifest directories that declare it: where its upgrade command runs (audit E8).
      fixPathInputs.set(rec, {
        fixes: vulns.map((v) => v.fixedVersion).filter((f): f is string => Boolean(f)),
        sourceDirs: [...new Set(vulns.flatMap((v) => v.sourceDirs ?? []))],
        unfixed: unfixedGroups.map((g) => ({ id: g.best.vulnId, ids: [...g.ids] })),
      });
    } else if (vulnerable && action === "no_fix_available") {
      fixPathInputs.set(rec, { fixes: [], sourceDirs: [] });
    }
  }

  // Transitive vulnerable packages — previously counted in scan totals but
  // never recommended. Surfaced as waiting_on_upstream with honest labels.
  // The skip is instance-aware: a transitive instance at a DIFFERENT version
  // than a same-named direct dep is its own finding (anyhow 1.0.102 transitive
  // beside anyhow 1.0.104 direct), not a duplicate of the direct row.
  let devTransitiveLeftOut = 0;
  if (vulnResult) {
    const transitive = new Map<string, typeof vulnResult.vulnerabilities>();
    const devSkipped = new Set<string>();
    for (const v of vulnResult.vulnerabilities) {
      if (v.isDirect) continue;
      if (!named(v.package, v.ecosystem)) continue;
      if (isMaintenanceNotice(v)) continue;
      if (directPackages.has(instanceKey(v.ecosystem, v.package, v.currentVersion))) continue;
      const key = instanceKey(v.ecosystem, v.package, v.currentVersion);
      if (!includeDev && isDevOnlyCopy(v)) {
        devSkipped.add(key);
        continue;
      }
      if (!transitive.has(key)) transitive.set(key, []);
      transitive.get(key)!.push(v);
    }

    devTransitiveLeftOut = [...devSkipped].filter((k) => !transitive.has(k)).length;
    for (const entries of transitive.values()) {
      const first = entries[0];
      const fixedVersions = entries.map((e) => e.fixedVersion).filter((f): f is string => Boolean(f));
      const platformActive = !entries.every((e) => !e.platformActive);
      const groups = groupAdvisories(entries);
      const reasons = [
        vulnerabilitiesReason(groups),
        "Transitive dependency — not declared in your manifest; the fix arrives via a parent package update or a lockfile refresh",
      ];
      if (!platformActive) {
        reasons.push("Affected code is gated behind a target not active on this platform");
      }
      const target = fixedVersions.length > 0 ? maxVersion(fixedVersions, first.ecosystem) : null;

      const rec: UpgradeRecommendation = {
        package: first.package,
        ecosystem: first.ecosystem,
        currentVersion: first.currentVersion,
        targetVersion: target,
        upgradeType: upgradeTypeBetween(first.currentVersion, target),
        risk: platformActive ? riskOf(entries.filter((e) => e.platformActive)) : "low",
        reasons,
        breaking: false,
        isDev: entries.every((e) => e.isDev),
        scope: "transitive",
        action: !platformActive ? "not_built_on_this_host" : target ? "waiting_on_upstream" : "no_fix_available",
        platformActive,
      };
      recommendations.push(rec);
      if (rec.action === "waiting_on_upstream" || rec.action === "no_fix_available") {
        const unfixed = groups.filter((g) => !g.members.some((m) => m.fixedVersion));
        fixPathInputs.set(rec, {
          fixes: fixedVersions,
          sourceDirs: [...new Set(entries.flatMap((e) => e.sourceDirs ?? []))],
          unfixed: unfixed.map((g) => ({ id: g.best.vulnId, ids: [...g.ids] })),
        });
      }
    }
  }

  // Defensive dedupe: identical (ecosystem, package, version, scope) rows can
  // still arrive when upstream dep lists carry duplicates. Keep the first.
  const seenRecs = new Set<string>();
  const deduped = recommendations.filter((r) => {
    const key = `${r.ecosystem}\0${r.package}\0${r.currentVersion ?? ""}\0${r.scope}`;
    if (seenRecs.has(key)) return false;
    seenRecs.add(key);
    return true;
  });

  // Filter by risk threshold
  const threshold = params.risk_threshold ?? "all";
  const filtered = threshold === "all"
    ? deduped
    : deduped.filter((r) => RISK_LEVELS[r.risk] >= RISK_LEVELS[threshold]);

  // Sort: critical > high > medium > low, then fixable-now (direct) before
  // waiting-on-upstream (transitive), then non-breaking first (quick wins).
  filtered.sort(planOrder);

  const maxRecs = params.max_recommendations ?? 20;
  const limited = filtered.slice(0, maxRecs);
  // Verify the fix path of every vulnerable step the plan returns: a target
  // no advisory affects, and whether a lockfile refresh already reaches it.
  const verifiedInputs = limited.filter((r) => fixPathInputs.has(r)).map((r) => ({ step: r, ...fixPathInputs.get(r)! }));
  const unverified = await verifyFixPaths(verifiedInputs, liveIntel);
  // A direct bump must not stop at a release that still pins a vulnerable transitive a slightly
  // newer release clears (express 4.20.0 still pins path-to-regexp 0.1.10; audit H1).
  await reconcileDirectTargets(limited, verifiedInputs, liveIntel);
  limited.sort(planOrder);
  // Go module versions carry their `v` in every field, as currentVersion does (audit 7e).
  for (const r of limited) {
    r.targetVersion = inEcosystemForm(r.ecosystem, r.targetVersion);
    if (r.latestVersion !== undefined) r.latestVersion = inEcosystemForm(r.ecosystem, r.latestVersion);
  }
  const upgrades = limited.filter((r) => r.scope === "direct" && r.action === "upgrade_direct");
  const quickWins = upgrades.filter((r) => !r.breaking).length;
  const breakingChanges = upgrades.filter((r) => r.breaking).length;
  const waitingOnUpstream = limited.filter((r) => r.action === "waiting_on_upstream").length;
  const lockfileRefreshes = limited.filter((r) => r.action === "lockfile_refresh").length;
  const parentUpgradeSteps = limited.filter((r) => r.action === "upgrade_parent").length;
  const devOnly = limited.filter((r) => r.isDev).length;
  const overrides = limited.filter((r) => r.action === "override_or_replace").length;
  const reinstalls = limited.filter((r) => r.action === "reinstall").length;
  const noFix = limited.filter((r) => r.action === "no_fix_available").length;
  const inactive = limited.filter((r) => r.action === "not_built_on_this_host").length;
  const unverifiedParents = limited.filter((r) => r.action === "upgrade_parent_unverified").length;
  const removals = limited.filter((r) => r.action === "remove_dependency").length;
  const holds = limited.filter((r) => r.action === "hold_current").length;

  // Summary
  const parts: string[] = [];
  if (coverage) parts.push(`${coverage.note} This plan ranks only what the checked part showed`);
  parts.push(
    filtered.length > limited.length
      ? `Showing ${limited.length} of ${filtered.length} recommendations (raise max_recommendations for the rest)`
      : `${limited.length} recommendation${limited.length !== 1 ? "s" : ""}`,
  );
  if (upgrades.length > 0) parts.push(`${upgrades.length} upgradable directly (${quickWins} non-breaking, ${breakingChanges} crossing a major version)`);
  if (reinstalls > 0) parts.push(`${reinstalls} need only a reinstall (node_modules behind the lockfile)`);
  if (lockfileRefreshes > 0) parts.push(`${lockfileRefreshes} transitive, fixed by a lockfile refresh (every parent already admits a clean version)`);
  if (parentUpgradeSteps > 0) parts.push(`${parentUpgradeSteps} transitive, fixed by upgrading the parent that pins it (parentUpgrades names the release)`);
  if (unverifiedParents > 0) {
    parts.push(
      `${unverifiedParents} transitive, a parent release that admits a clean version exists but no release of the declared dependency that brings it in was verified (parentUpgrades says what to check; not counted as fixed)`,
    );
  }
  if (waitingOnUpstream > 0) parts.push(`${waitingOnUpstream} transitive, waiting on upstream`);
  if (removals > 0) parts.push(`${removals} to remove: npm's security placeholder, every newer release known-affected (malware)`);
  if (holds > 0) parts.push(`${holds} to keep where ${holds === 1 ? "it is" : "they are"}: every newer release is known-affected or withdrawn`);
  if (overrides > 0) parts.push(`${overrides} transitive, blocked by a parent that will not move (deprecated, already its latest release, or no release admits a clean version): override the version or replace the parent`);
  if (unverified > 0) parts.push(`${unverified} fix target${unverified !== 1 ? "s" : ""} checked only against the installed version's advisories (offline, or OSV or the registry did not answer in time; see fixPathChecked)`);
  if (noFix > 0) parts.push(`${noFix} vulnerable with no fixed release yet`);
  if (inactive > 0) parts.push(`${inactive} vulnerable only in code not built on this host`);
  const criticalCount = limited.filter((r) => r.risk === "critical").length;
  if (criticalCount > 0) parts.push(`${criticalCount} critical`);
  if (devOnly > 0) parts.push(`${devOnly} dev-only (isDev)`);
  // The population, worded as dependency_health and vulnerability_scan word it (finding 6).
  if (vulnResult) parts.push(populationNote(vulnResult.vulnerabilities, liveIntel.getAuditDeps(), includeDev, named));
  if (devDirectLeftOut + devTransitiveLeftOut + devDirectUnchecked > 0) {
    const left: string[] = [];
    if (devDirectLeftOut > 0) left.push(`${devDirectLeftOut} vulnerable devDependenc${devDirectLeftOut !== 1 ? "ies" : "y"}`);
    if (devDirectUnchecked > 0) left.push(`${devDirectUnchecked} devDependenc${devDirectUnchecked !== 1 ? "ies" : "y"} not checked for vulnerabilities`);
    if (devTransitiveLeftOut > 0) left.push(`${devTransitiveLeftOut} dev-only vulnerable transitive cop${devTransitiveLeftOut !== 1 ? "ies" : "y"}`);
    parts.push(`include_dev: false left out ${left.join(" and ")} (the default, true, plans them)`);
  }
  if (devFreshnessSkipped > 0) {
    parts.push(
      `${devFreshnessSkipped} devDependenc${devFreshnessSkipped !== 1 ? "ies" : "y"} with no known vulnerability ${devFreshnessSkipped !== 1 ? "were" : "was"} not checked for newer releases or deprecation (include_dev: true checks them)`,
    );
  }
  if (maintenanceNotices.size > 0) {
    parts.push(`${maintenanceNotices.size} unmaintained-package notice${maintenanceNotices.size !== 1 ? "s" : ""} not ranked (no fix exists; see vulnerability_scan maintenance_notices)`);
  }
  const partial = discoveryNote(liveIntel.getDiscovery());
  if (partial) parts.push(partial.replace(/[.]$/, ""));
  // Ecosystems not read, test fixtures left out, lockfiles that could not be read: never silent.
  for (const note of [...exclusionNotes(liveIntel.getDiscovery()), ...unreadableNotes(liveIntel.getLockfileProblems())]) parts.push(note.replace(/[.]$/, ""));
  const nothing = vulnerabilityDataAvailable ? "nothing to upgrade (no known vulnerability, deprecation, or newer release of a direct dependency)" : "no vulnerability data to plan from";
  if (only && limited.length === 0) parts.push(emptyAnswerNote(only, liveIntel, includeDev, nothing));

  return {
    generatedAt: new Date().toISOString(),
    projectPath: liveIntel.getProjectRoot() ?? vulnResult?.projectPath ?? process.cwd(),
    totalDeps: deps.length,
    recommendations: limited,
    summary: parts.join(". ") + ".",
    quickWins,
    breakingChanges,
    waitingOnUpstream,
    lockfileRefreshes,
    parentUpgradeSteps,
    vulnerabilityDataAvailable,
    ...(coverage ? { vulnerabilityCoverage: coverage } : {}),
    provenance: { mode: "standalone_heuristic", note: PROVENANCE_NOTE },
  };
}

/**
 * "Planned over N vulnerable packages (M installed copies) in the full tree of T installed
 * (K dev-only copies left out)": the same population, counted the same way, as
 * dependency_health's vulnerableCount and vulnerability_scan's total_vulnerable_packages.
 */
function populationNote(
  vulns: VulnerabilityEntry[],
  tree: Array<{ name: string; ecosystem: string; version: string | null; isDev: boolean; devScopeKnown?: boolean }>,
  includeDev: boolean,
  named: (name: string, ecosystem: string) => boolean,
): string {
  const active = vulns.filter((v) => isActionableVulnerability(v) && (includeDev || !isDevOnlyCopy(v)) && named(v.package, v.ecosystem));
  const packages = new Set(active.map((v) => `${v.ecosystem}\0${v.package}`)).size;
  const copies = new Set(active.map((v) => `${v.ecosystem}\0${v.package}\0${v.currentVersion}`)).size;
  const versioned = tree.filter((d) => d.version !== null);
  const devOnly = versioned.filter((d) => isDevOnlyCopy(d)).length;
  const total = includeDev ? versioned.length : versioned.length - devOnly;
  const dev = devOnly > 0 ? (includeDev ? "; dev-only copies included" : `; ${devOnly.toLocaleString("en-US")} dev-only cop${devOnly === 1 ? "y" : "ies"} left out`) : "";
  return `Planned over ${packages} vulnerable package${packages !== 1 ? "s" : ""} (${copies} installed cop${copies !== 1 ? "ies" : "y"}) in the full tree of ${total.toLocaleString("en-US")} installed${dev ? ` (${dev.slice(2)})` : ""}`;
}

/** "N known vulnerabilities (ids)", one per alias group. */
function vulnerabilitiesReason(groups: ReturnType<typeof groupAdvisories>): string {
  const n = groups.length;
  return `${n} known vulnerabilit${n !== 1 ? "ies" : "y"} (${groups.map((g) => g.best.vulnId).join(", ")})`;
}

/** Before the fix path is checked; verifyFixPaths rewrites it once the target is known (M2). */
function noFixReason(n: number): string {
  return `${n} of them ${n === 1 ? "has" : "have"} no published fix`;
}
