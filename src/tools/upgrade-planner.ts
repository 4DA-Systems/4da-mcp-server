// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_planner tool
 *
 * The plan for a project is always computed here, from the lockfiles on disk
 * (`provenance.mode: "lockfile_engine"`), with or without the 4DA app: version
 * freshness, vulnerability data and deprecation status. With the app's
 * database attached, `app_plan_check` says how the app's stored plan compares
 * (app-plan-check.ts); it never replaces this plan. The one exception is the
 * all-projects scope with the app attached: only the app's stored plan covers
 * every project, so it is returned as the app's (`provenance.mode:
 * "app_plan"`, ./app-plan.ts), labelled as not checked against the disk and
 * stale whenever anything shows it is.
 *
 * Honesty contract (Phase 0 hardening):
 * - Transitive CVEs are surfaced as `waiting_on_upstream` steps instead of
 *   being counted-but-never-recommended. No dependency-graph parsing happens
 *   here — parent mapping is the desktop core's job; the honest label is ours.
 * - Output carries its provenance: computed here from the lockfiles on disk,
 *   at the time of the call.
 * - `projectPath` reports the directory set the dependencies were actually
 *   resolved from, not whatever `process.cwd()` happens to be.
 * - When no vulnerability scan has run, the planner runs one (bounded); if it
 *   cannot finish, the plan says it is CVE-blind instead of ranking silently.
 * - When node_modules holds a different version than the lockfile, the row
 *   says so (`installedVersion`) and a reinstall is the step when nothing
 *   else about the lockfile's version needs changing.
 */

import { markPrivateParents } from "./upgrade-planner-private.js";
import { pushAll } from "../array-utils.js";
import type { FourDADatabase } from "../db.js";
import type { LiveIntelligence } from "../live/index.js";
import { isActionableVulnerability, isMaintenanceNotice } from "../live/maintenance.js";
import { computeSemverDistance } from "../live/semver-utils.js";
import { compareVersions, inEcosystemForm, maxVersion, namesPackage } from "../live/version-compare.js";
import { formatAppPlan, readAppPlan, type AppPlanResult } from "./app-plan.js";
import { checkAllProjectsPlan, checkProjectPlan, serverPlanFacts, type AppPlanCheck } from "./app-plan-check.js";
import { dirsLabel, driftFor } from "./install-drift-notes.js";
import { emptyAnswerNote } from "./package-presence.js";
import { relativeDir } from "./vulnerability-scan-format.js";
import { liveIntelFor, resolveProjectScope, serverDirectoryRefusal, systemDirectoryProblem } from "./project-scope.js";
import { FIX_PATH_UNDETERMINED, judgeDirectRequirements, reconcileDirectTargets, settleTransitiveBreaking, verifyFixPaths, type FixPathInput, type ParentUpgrade } from "./upgrade-planner-fixpaths.js";
import { builtDirs, fixInputOf, TRANSITIVE_PENDING } from "./fix-verdicts.js";
import { groupAdvisories } from "../live/advisory-groups.js";
import { HELD_UNCLEAN_REASON } from "../live/fix-paths.js";
import { MAX_REQUIRED_TARGETS, REQUIRES_AFFECTED_REASON, REQUIRES_CAP_REASON, REQUIRES_UNEXAMINED_REASON } from "../live/required-targets.js";
import { unconfirmedTargetNote, withholdUnconfirmedTargets } from "./unconfirmed-targets.js";
import { dedupeParentCommands } from "./upgrade-planner-dedupe.js";
import { SHARED_COPY_REASON } from "./upgrade-planner-shared-copy.js";
import { isDevOnlyCopy, rankedSeverity } from "../live/severity-scope.js";
import { discoveryNote, exclusionNotes, splitLockfileProblems, unreadableNotes } from "../project-tree.js";
import { vulnerabilityCoverage } from "../live/scan-coverage.js";
import { uncheckedOfferNote, vetOfferedReleases } from "../live/offered-release.js";
import { registryQuote } from "../untrusted-text.js";
import type { VulnerabilityCoverage, VulnerabilityEntry } from "../live/types.js";
import { scanUnfinishedText, withinCallBudget } from "../call-budget.js";
import { attachCommands, sequencePlan, type PlanCommand, type RunOrderStep } from "./upgrade-plan-sequence.js";
import { explainCommandlessRows } from "./upgrade-planner-commandless.js";
import { rustVersionRunOrderNote, rustVersionSummary, withRustVersions, type RustVersionNeed } from "./upgrade-planner-rust-version.js";
import { declaredNpmOperator, staleLocksNote, uvWorkspaces, withoutOwnPackageUpgrades, withPythonSupport, withUvWorkspaceLocks, withYarnClassicResolutions, workspaceOwnNames } from "./upgrade-plan-runnable.js";

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
  /**
   * "unknown": OSV.dev gave no answer for this copy, so its advisories are not known (r7: it read
   * "low"). Ranked and filtered with "critical": incomplete coverage never lowers a row.
   */
  risk: "low" | "medium" | "high" | "critical" | "unknown";
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
   * `not_built_on_this_host` = every advisory is against code this host never compiles: kept apart
   * from this host's steps and never counted with them, with the fix for where it IS built on the
   * row (`whenBuilt`, `appliesWhenBuiltFor` and the usual commands);
   * `upgrade_parent_unverified` = transitive, a parent release that admits a clean version exists,
   * but no release of the declared dependency that brings it in was verified (every lever's `to`
   * is null): `parentUpgrades` says what to check; nothing is counted as fixed;
   * `remove_dependency` = the installed copy is flagged malicious and no later release is clean of
   * it (crossenv: 1.0.0 and 1.0.1 are malware), or the installed version is a placeholder and every
   * newer release is known-affected: remove or replace the dependency. A malware record with a
   * clean later release (fsevents 1.2.9, MAL-2023-462, clean from 1.2.11) is an upgrade instead;
   * `hold_current` = no advisory affects the installed version, and every newer release is
   * known-affected or withdrawn: stay on it (the reasons say why);
   * `not_checked` = OSV.dev gave no answer for the installed copy (risk "unknown") and no newer
   * release is offered: its advisories are not known, so it is neither vulnerable nor clean;
   * `not_determined` = transitive and vulnerable, but how it is fixed was not established in this
   * call: the registry or the lockfile could not be read, live lookups are off, the time budget ran
   * out, or it arrives through a private parent that is never looked up. Never counted as waiting
   * on upstream, which is said only once the paths to the fix were read and found blocked.
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
    | "hold_current"
    | "not_checked"
    | "not_determined";
  /** upgrade_parent / override_or_replace: the parent release that admits a clean version, per blocking parent that can move. */
  parentUpgrades?: ParentUpgrade[];
  /**
   * For a vulnerable package: whether the target was checked against EVERY
   * known advisory of the package and judged a clean fix (`all_advisories`),
   * or not (`installed_advisories_only`): the lookups failed or ran out of
   * time (the target may then be affected by an advisory the installed
   * version predates), or, for npm, the target pins an affected dependency or
   * what it pins could not be checked (the reasons say which; audit 6.2.5 D-4).
   */
  fixPathChecked?: "all_advisories" | "installed_advisories_only";
  /** crates.io: releases this row installs that need a newer Rust than the manifest's rust-version declares (upgrade-planner-rust-version.ts). */
  needsNewerRust?: RustVersionNeed[];
  /**
   * Releases the registry withdrew (crates.io/PyPI yanked; npm deprecated with a later clean
   * release on its line) that targetVersion steps over, or, with no target, the only releases
   * that fixed it: "no installable fix", not "no fix published". The reasons say why (FX-H5).
   */
  withheld?: string[];
  /** lockfile_refresh: the command to run, per lockfile directory. */
  refreshCommands?: Array<{ dir: string; command: string }>;
  /** lockfile_refresh of the copies installed on their own: the copies other packages bundle, which wait on their owner (upgrade-planner-fixpaths.ts). */
  bundledCopies?: Array<{ owner: string; ownerVersion: string | null; action: "waiting_on_upstream" }>;
  /**
   * upgrade_direct: the command that moves the declared dependency to
   * targetVersion where it is declared, per lockfile directory (npm install,
   * pnpm up, yarn upgrade / yarn up, cargo add with --dev for a
   * dev-dependency). Absent for tools no command is named for. `installs`: the release a command
   * written with a range installs, when that is not targetVersion; it was checked as the target was
   * (a command whose release could not be checked names the target exactly instead).
   */
  upgradeCommands?: Array<{ dir: string; command: string; refresh?: true; installs?: string }>;
  /**
   * upgrade_direct: a manifest edit where no single verified command makes it (a workspace-inherited
   * crate, a requirements.txt pin). Also on a PyPI row, direct or transitive, whose pin sits in a
   * compiled requirements file: the re-compile with `--upgrade-package` (audit 6.2.5 A-4).
   */
  upgradeInstructions?: Array<{ dir: string; instruction: string }>;
  /**
   * lockfile_refresh: true when not every parent's requirement could be read
   * (none read excludes the target) and the target is semver-compatible with
   * the installed version, so the refresh is inferred rather than read.
   */
  refreshInferred?: boolean;
  /** False when the dependency is gated behind a target spec not active on this host (label, never suppressed). */
  platformActive: boolean;
  /**
   * not_built_on_this_host: where the copy is built, so where its fix applies: the target spec
   * that gates it (`cfg(unix)`), or "a target other than <this host's triple>" when cargo builds it
   * for no target here.
   */
  appliesWhenBuiltFor?: string[];
  /**
   * not_built_on_this_host: the action that fixes the copy where it is built (upgrade_direct,
   * lockfile_refresh, upgrade_parent, override_or_replace, ...), whose commands this row carries;
   * "not_determined" when that could not be read.
   */
  whenBuilt?: string;
  /** npm: the version node_modules holds, when it differs from `currentVersion` (the lockfile's). */
  installedVersion?: string;
  /** npm: the command that reinstalls from the lockfile, when `installedVersion` is set. */
  installFix?: string;
  /** No lockfile: the manifest's declared requirement; `currentVersion` is its floor, not an install. */
  declaredRange?: string;
  /** Private packages this transitive step arrives through: never looked up, so its fix path is not checked (upgrade-planner-private.ts). */
  privateParents?: Array<{ parent: string; why: string }>;
  /** Every command this row tells the developer to run, as data (upgrade-plan-sequence.ts); empty when its reasons say why nothing is run. */
  commands: PlanCommand[];
}

export interface UpgradePlanResult {
  generatedAt: string;
  projectPath: string;
  totalDeps: number;
  recommendations: UpgradeRecommendation[];
  summary: string;
  quickWins: number;
  breakingChanges: number;
  waitingOnUpstream: number;
  /** Transitive steps whose fix path was not established (action `not_determined`): unread, not blocked. */
  fixPathNotDetermined: number;
  /** Transitive steps a lockfile refresh fixes (every parent already admits a clean version); a row with `bundledCopies` counts here and in waitingOnUpstream. */
  lockfileRefreshes: number;
  /** Transitive steps fixed by upgrading the parent that pins them (`parentUpgrades` names the release). */
  parentUpgradeSteps: number;
  /** False unless OSV answered for EVERY dependency in scope: a plan over missing or partial data is not CVE-aware. */
  vulnerabilityDataAvailable: boolean;
  /** Present when the vulnerability check is missing or incomplete: what was not checked and why. */
  vulnerabilityCoverage?: VulnerabilityCoverage;
  /** The rows shown as one script, safe to run from the first step to the last (upgrade-plan-sequence.ts). */
  run_order: RunOrderStep[];
  /** What run_order covers (the rows shown) and what it leaves out, and why. */
  run_order_note: string;
  provenance: {
    mode: "lockfile_engine";
    note: string;
  };
  /** With the 4DA app's database attached: how the app's stored plan compares with this plan (app-plan-check.ts). */
  app_plan_check?: AppPlanCheck;
  /** The project the plan covers, or null when it is not narrowed to one. */
  projectScope?: string | null;
}

/** Time the plan spends checking the newer releases its rows offer against their advisories. */
const OFFER_CHECK_BUDGET_MS = 10_000;
/** Time run_order may spend reading the go.mod of the `go get` targets it combines. */
const SEQUENCE_BUDGET_MS = 3_000;
/** Time the Cargo rows may spend reading the rust-version of releases not already in the cache. */
const RUST_VERSION_BUDGET_MS = 4_000;

/** The newer release a registry row would offer (its latest stable), or null when it offers none. */
function offeredUpgrade(dep: { ecosystem: string; currentVersion: string | null; latestStableVersion: string | null; latestVersion: string | null }): string | null {
  const latest = dep.latestStableVersion || dep.latestVersion;
  if (!latest || !dep.currentVersion) return null;
  return compareVersions(latest, dep.currentVersion, dep.ecosystem) > 0 ? latest : null;
}

/**
 * How long a plan waits for its own OSV scan before answering CVE-blind (the scan keeps running).
 * Inside a tool call the wait is what the call's budget has left (call-budget.ts), less
 * PLAN_RESERVE_MS for the registry rows and fix paths that follow.
 */
const PLANNER_SCAN_TIMEOUT_MS = 60_000;
const PLAN_RESERVE_MS = 9_000;

const PROVENANCE_NOTE = "Computed by this server from the project's lockfiles on disk, with live registry and OSV.dev lookups.";
/** Added with the 4DA app attached: its stored plan is compared, never relayed. */
const APP_ATTACHED_NOTE = "The 4DA app's stored plan is never used in its place; app_plan_check says how it compares.";

export const upgradePlannerTool = {
  name: "upgrade_planner",
  description:
    "Ranked dependency upgrade plan for one project — call before upgrading, adding, or auditing any dependency to pick the safest order. `project_path` picks the project (default: the one the server was started in; \"*\" for every project). The plan is computed by this server from the project's lockfiles on disk, with or without the 4DA desktop app (provenance lockfile_engine). With the app's database attached, `app_plan_check` says how the app's stored plan compares (agrees; differs, with up to 10 `differences`; not_comparable when its plan format is one this server does not read, its advisory data is more than 24 hours old, or a lockfile changed after it was generated; no_plan); the app's plan never replaces this one. The exception is project_path \"*\" with the app attached: the answer is then the app's stored plan across every project it tracks (provenance app_plan, `app_plan_check.status` unverified, not checked against the lockfiles on disk): per package the ecosystem, each installed version with its minimum clean target, upgrade type, the projects that hold it, the mechanism (manifest_bump, lockfile_refresh, parent_update, blocked_upstream, lockfile_or_parent_update, mixed, no_fix) and `next_step` in words, `stale` when past its expiry, when its advisory data is more than 24 hours old, or when a lockfile of a project it covers changed after it. The plan: the smallest version that fixes each vulnerability (direct and transitive), checked against every known advisory of the package, whether a lockfile refresh already reaches it (lockfile_refresh with the command) or a parent blocks it: upgrade_parent with `parentUpgrades` naming the smallest parent release whose requirement admits a clean version (through the direct dependency it arrives by), override_or_replace with the override syntax when no parent release will (deprecated, already latest, or none admits one), waiting_on_upstream only when the paths were read and a parent the project cannot move blocks them, not_determined when the fix path could not be read (registry or lockfile unread, lookups off, out of time: unknown, never waiting); direct steps carry `upgradeCommands` and are raised to the release that also clears the transitives they pin; a copy bundled inside its owner waits on the owner; a Cargo row whose release needs a newer Rust than the manifest's rust-version says so in `needsNewerRust` (the step stays: the build on the declared Rust is what fails); dev-only rows are included and labelled `isDev`, as in vulnerability_scan; deprecation and version distance; it runs the OSV scan itself when none has run. When OSV.dev could not answer for every dependency, `vulnerabilityDataAvailable` is false, `vulnerabilityCoverage` counts the unchecked ones and the summary starts with \"NOT CHECKED\", a row with no answer and nothing newer to move to is action not_checked (never counted as vulnerable or clean): the plan then misses whatever those dependencies carry. `package` narrows the plan to one package. Privacy: the plan may query public registries and OSV with package names and versions; it never sends source code.",
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
          "Project directory to plan for, from its lockfiles on disk. \"*\" for every project: with the 4DA app attached, the app's stored plan across every project it tracks (not checked against the lockfiles). Default: the project the server was started in, when that directory is a project.",
      },
    },
  },
};

const RISK_LEVELS: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3, unknown: 3 };

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * critical > high > medium > low, then runtime before dev-only, then fixable now (direct) before
 * transitive, then non-breaking first (quick wins); then a total tiebreak (ecosystem, package,
 * directories, version), so which tied rows max_recommendations shows never depends on the order
 * the lookups returned them in.
 */
function planOrder(dirsOf: (r: UpgradeRecommendation) => string): (a: UpgradeRecommendation, b: UpgradeRecommendation) => number {
  return (a, b) => {
    const riskDiff = RISK_LEVELS[b.risk] - RISK_LEVELS[a.risk];
    if (riskDiff !== 0) return riskDiff;
    if (a.isDev !== b.isDev) return a.isDev ? 1 : -1;
    if (a.scope !== b.scope) return a.scope === "direct" ? -1 : 1;
    if (a.breaking !== b.breaking) return a.breaking ? 1 : -1;
    const av = a.currentVersion ?? "";
    const bv = b.currentVersion ?? "";
    return byText(a.ecosystem, b.ecosystem) || byText(a.package, b.package) || byText(dirsOf(a), dirsOf(b)) || compareVersions(av, bv, a.ecosystem) || byText(av, bv);
  };
}

/**
 * The grade a row ranks by: the scope-adjusted severity vulnerability_scan presents (transitive
 * caps critical at high; dev-only drops one level), over the 4DA app's base urgency (an ungraded
 * advisory medium, a MAL- record high: severity-scope.ts rankedSeverity). A dev-only medium is low,
 * as the scan presents it; it used to stay medium. Ranking on the raw grade let dev-only criticals
 * push a runtime high out of max_recommendations (readiness review 2026-10-17, finding 6).
 */
function hasVulns(vulns: VulnerabilityEntry[] | undefined): boolean {
  return Boolean(vulns && vulns.length > 0);
}

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
  db: FourDADatabase | null,
  params: UpgradePlannerParams,
  liveIntel: LiveIntelligence | null,
): Promise<UpgradePlanResult | AppPlanResult> {
  const scope = resolveProjectScope(params.project_path);
  if (scope.kind === "error") throw new Error(scope.error);
  const scopePath = scope.kind === "project" ? scope.path : null;
  // The desktop app's database, when it is the one attached (not this server's own store).
  const app = db && !db.isStandalone ? db : null;
  const appPlan = app ? readAppPlan(app) : null;
  // Every project: only the app's stored plan covers more than one, so it is the answer, labelled
  // as the app's and not checked against the disk, and stale whenever anything shows it is.
  if (app && scope.kind === "all" && appPlan?.kind === "plan") return formatAppPlan(appPlan, params, checkAllProjectsPlan(app, appPlan));
  // One project: this server's own plan from the lockfiles on disk, in every mode. The live layer
  // already covers the server's own project; only an explicit project_path elsewhere resolves another tree.
  const scoped =
    scope.kind === "project" && scope.source === "argument"
      ? (liveIntelFor(liveIntel, db, scope) as LiveIntelligence | null)
      : liveIntel;
  const plan = await executeStandalonePlanner(params, scoped);
  const result: UpgradePlanResult = { ...plan, projectScope: scopePath ?? plan.projectPath };
  if (!app || !appPlan) return result;
  return {
    ...result,
    provenance: { mode: "lockfile_engine", note: `${PROVENANCE_NOTE} ${APP_ATTACHED_NOTE}` },
    app_plan_check: checkProjectPlan(app, appPlan, scopePath ?? plan.projectPath, serverPlanFacts(plan, scoped), params),
  };
}

async function executeStandalonePlanner(
  params: UpgradePlannerParams,
  liveIntel: LiveIntelligence | null,
): Promise<UpgradePlanResult> {
  // A server started in an operating-system directory scanned nothing (project-scope.ts): said, not "0 recommendations".
  const refused = liveIntel?.getProjectRoot() ? systemDirectoryProblem(liveIntel.getProjectRoot()!) : null;
  if (!liveIntel || !liveIntel.isInitialized() || refused) {
    return {
      generatedAt: new Date().toISOString(),
      projectPath: liveIntel?.getProjectRoot() ?? process.cwd(),
      totalDeps: 0,
      recommendations: [],
      summary: refused
        ? `Nothing was planned. ${serverDirectoryRefusal(refused)}`
        : "No project detected. Run from a directory with package.json, Cargo.toml, pyproject.toml, or go.mod.",
      quickWins: 0,
      breakingChanges: 0,
      waitingOnUpstream: 0,
      fixPathNotDetermined: 0,
      lockfileRefreshes: 0,
      parentUpgradeSteps: 0,
      vulnerabilityDataAvailable: false,
      run_order: [],
      run_order_note: "run_order is empty: nothing was planned.",
      provenance: { mode: "lockfile_engine", note: PROVENANCE_NOTE },
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
  const scanWaitMs = withinCallBudget(PLANNER_SCAN_TIMEOUT_MS, PLAN_RESERVE_MS);
  const vulnResult = (await liveIntel.ensureVulnerabilities(root, scanWaitMs, { includeDev })) ?? liveIntel.getVulnerabilities();
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
    withinCallBudget(OFFER_CHECK_BUDGET_MS, PLAN_RESERVE_MS / 2),
    undefined,
    (d) => liveIntel.queryAdvisories(d),
  );
  // Complete vulnerability data only: a partial scan (OSV.dev unreachable or
  // rate limited for some dependencies) ranks what it found and says the rest
  // is unchecked; it never claims the plan is CVE-aware (6.2.4 said
  // vulnerabilityDataAvailable: true over 10,568 unchecked dependencies).
  const scopeTotal = liveIntel.getAuditDeps().filter((d) => includeDev || !isDevOnlyCopy(d)).length;
  const coverage = vulnerabilityCoverage(vulnResult, {
    enabled: liveIntel.isEnabled(),
    expectedTotal: scopeTotal,
    notLoaded: `${scanUnfinishedText(scanWaitMs)}, or OSV.dev was unreachable`,
  });
  // A project whose only manifests are ones this server does not read (pom.xml), or could not read
  // (an unparseable package.json, a damaged lockfile), has no data at all (audit 6.2.5 A-6).
  const nothingReadable =
    (vulnResult?.totalScanned ?? 0) === 0 && ((liveIntel.getDiscovery()?.notCoveredCount ?? 0) > 0 || liveIntel.getLockfileProblems().length > 0);
  // A lockfile that holds merge-conflict markers, could not be parsed, or was read only in part,
  // whatever ecosystem it is: what it pins was not (all) checked, so the plan is no CVE-aware one,
  // as vulnerability_scan's coverage.complete is false beside it. 6.5.0 said true beside a
  // conflicted Cargo.lock once an npm lockfile next to it was read. (A go.sum is left out, as the
  // scan leaves it out: from go 1.17 the versions are go.mod's.)
  const lockfilesNotRead = lockfilesNotFullyRead(liveIntel.getLockfileProblems());
  // No lockfile read: declared ranges are not installs, so there is no vulnerability data to plan by.
  const vulnerabilityDataAvailable = vulnResult !== null && coverage === null && !nothingReadable && liveIntel.wasLockfileRead() && lockfilesNotRead === 0;
  // Keyed by ecosystem + name + INSTANCE version. A name-only key attached every
  // instance's CVEs to whichever row asked first: the direct anyhow 1.0.104 was
  // charged with RUSTSEC-2026-0190 (fixed in 1.0.103 — it isn't affected) while
  // the actually-vulnerable transitive anyhow 1.0.102 was hidden by the
  // direct-name skip below. Scan entries are created per scanned instance, so
  // the instance version is exact.
  const instanceKey = (ecosystem: string, name: string, version: string | null) =>
    `${ecosystem}\0${name}\0${version ?? "unknown"}`;
  // Copies OSV.dev gave no answer for: their advisories are unknown, never "none" (r7).
  const unanswered = new Set(vulnResult?.uncheckedDependencies ?? []);
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
  // Per reinstall row: the directories whose node_modules drifted, where its command runs.
  const installDirsOf = new Map<UpgradeRecommendation, string[]>();

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

      const elsewhere = notBuiltIn(vulns, root);
      if (platformActive && elsewhere) reasons.push(elsewhere);

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
      // The registry's words, quoted and capped inside this server's sentence (blind audit round 5).
      // The registry's words go to quoted_from_registry, never into this server's reason (r7).
      reasons.push(`Package is deprecated${dep.deprecationMessage ? registryQuote(dep.name, dep.deprecationMessage) : ""}`);
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
    // r7: OSV.dev gave no answer for this copy. Its advisories are unknown: the row is listed, its
    // risk is unknown (never the "low" an empty answer reads as), and the release it would move to
    // was not confirmed, so it is named only in a NOT CHECKED reason, never in targetVersion.
    // r8: the same when the whole scan did not finish within the call (vulnResult null): every row's
    // advisories are unknown, so none may read "low" and drop out of risk_threshold "high".
    const noAnswer = !(vulns && vulns.length > 0) && (vulnResult === null || unanswered.has(instanceKey(dep.ecosystem, dep.name, dep.currentVersion)));
    if (noAnswer) {
      risk = "unknown";
      const why = vulnResult === null ? "the OSV.dev scan did not finish within this call" : (vulnResult.uncheckedReason ?? "the query failed");
      reasons.unshift(`NOT CHECKED: OSV.dev gave no answer for ${dep.name} ${dep.currentVersion ?? ""}`.trimEnd() + ` (${why}), so its advisories are not known; this is not a clean result`);
    }
    // A newer release offered without being confirmed free of the package's advisories (OSV.dev's
    // batch query failed, or the check ran out of time) is named only in that reason (#80's rule).
    const unconfirmedOffer = Boolean(offered && !hasVulns(vulns) && (!vet || !vet.checked) && targetVersion);
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

    if (unconfirmedOffer) {
      reasons.unshift(unconfirmedTargetNote(dep.name, targetVersion, null));
      if (offerNote && !reasons.includes(offerNote)) reasons.push(offerNote);
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
            : targetVersion || unconfirmedOffer
              ? "upgrade_direct"
              : // No advisory is known because OSV.dev never answered, not because none exists: never
                // "no_fix_available", which the summary counts as "vulnerable with no fixed release
                // yet" (pre-publish round 10, W8: three unchecked rows read as three vulnerable).
                noAnswer
                ? "not_checked"
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
      ...(action === "not_built_on_this_host" && vulns ? { appliesWhenBuiltFor: builtFor(vulns) } : {}),
      ...(installedVersion ? { installedVersion, installFix } : {}),
      ...(dep.declaredRange ? { declaredRange: dep.declaredRange } : {}),
      commands: [],
    };
    recommendations.push(rec);
    if (installFix) installDirsOf.set(rec, [...new Set(drifted.map((r) => relativeDir(r.dir, root)))]);
    if (fixable && !reinstallOnly && action === "upgrade_direct" && vulns) {
      // The manifest directories that declare it: where its upgrade command runs (audit E8).
      fixPathInputs.set(rec, {
        fixes: vulns.map((v) => v.fixedVersion).filter((f): f is string => Boolean(f)),
        sourceDirs: builtDirs(vulns),
        unfixed: unfixedGroups.map((g) => ({ id: g.best.vulnId, ids: [...g.ids] })),
        ids: vulns.map((v) => v.vulnId),
      });
    } else if (vulnerable && action === "no_fix_available") {
      fixPathInputs.set(rec, { fixes: [], sourceDirs: [] });
    } else if (vulnerable && action === "not_built_on_this_host" && fixable && vulns) {
      // Its target is checked like any other: never a yanked or withdrawn release (audit 2026-11-11).
      fixPathInputs.set(rec, fixInputOf(vulns));
    }
  }

  // Transitive vulnerable packages — previously counted in scan totals but
  // never recommended. Surfaced as waiting_on_upstream with honest labels.
  // The skip is instance-aware: a transitive instance at a DIFFERENT version
  // than a same-named direct dep is its own finding (anyhow 1.0.102 transitive
  // beside anyhow 1.0.104 direct), not a duplicate of the direct row.
  let devTransitiveLeftOut = 0;
  // A copy a workspace member (or a root optional or peer section) declares is direct, but not one
  // of the root's resolved rows above: it is planned below, as a direct row.
  const rootDirect = new Set(liveIntel.getResolvedDeps().filter((d) => d.isDirect).map((d) => instanceKey(d.ecosystem, d.name, d.version)));
  const devDeclaredSkipped = new Set<string>();
  if (vulnResult) {
    const transitive = new Map<string, typeof vulnResult.vulnerabilities>();
    const devSkipped = new Set<string>();
    for (const v of vulnResult.vulnerabilities) {
      if (v.isDirect && (v.installDriftOf || rootDirect.has(instanceKey(v.ecosystem, v.package, v.currentVersion)))) continue;
      if (!named(v.package, v.ecosystem)) continue;
      if (isMaintenanceNotice(v)) continue;
      if (directPackages.has(instanceKey(v.ecosystem, v.package, v.currentVersion))) continue;
      const key = instanceKey(v.ecosystem, v.package, v.currentVersion);
      if (!includeDev && isDevOnlyCopy(v)) {
        (v.isDirect ? devDeclaredSkipped : devSkipped).add(key);
        continue;
      }
      if (!transitive.has(key)) transitive.set(key, []);
      transitive.get(key)!.push(v);
    }

    devTransitiveLeftOut = [...devSkipped].filter((k) => !transitive.has(k)).length;
    for (const k of devDeclaredSkipped) if (transitive.has(k)) devDeclaredSkipped.delete(k);
    for (const entries of transitive.values()) {
      const first = entries[0];
      const fixedVersions = entries.map((e) => e.fixedVersion).filter((f): f is string => Boolean(f));
      const platformActive = !entries.every((e) => !e.platformActive);
      const groups = groupAdvisories(entries);
      // Declared by a manifest of the project, as vulnerability_scan builds the same step (fix-verdicts.ts stepOf).
      const declared = entries.some((e) => e.isDirect === true);
      const reasons = declared ? [vulnerabilitiesReason(groups)] : [vulnerabilitiesReason(groups), TRANSITIVE_PENDING];
      if (!platformActive) {
        reasons.push("Affected code is gated behind a target not active on this platform");
      }
      const target = fixedVersions.length > 0 ? maxVersion(fixedVersions, first.ecosystem) : null;
      const elsewhere = notBuiltIn(entries, root);
      if (platformActive && elsewhere) reasons.push(elsewhere);

      const rec: UpgradeRecommendation = {
        package: first.package,
        ecosystem: first.ecosystem,
        currentVersion: first.currentVersion,
        targetVersion: target,
        upgradeType: upgradeTypeBetween(first.currentVersion, target),
        risk: platformActive ? riskOf(entries.filter((e) => e.platformActive)) : "low",
        reasons,
        breaking: declared && upgradeTypeBetween(first.currentVersion, target) === "major",
        isDev: entries.every((e) => e.isDev),
        scope: declared ? "direct" : "transitive",
        action: !platformActive ? "not_built_on_this_host" : target ? (declared ? "upgrade_direct" : "waiting_on_upstream") : "no_fix_available",
        platformActive,
        ...(!platformActive ? { appliesWhenBuiltFor: builtFor(entries) } : {}),
        commands: [],
      };
      recommendations.push(rec);
      // The same input vulnerability_scan verifies for this copy (fix-verdicts.ts): one answer per finding.
      // A copy not built on this host is checked too, for its target only (never a yanked release).
      if (rec.action === "waiting_on_upstream" || rec.action === "upgrade_direct" || rec.action === "no_fix_available" || (rec.action === "not_built_on_this_host" && target)) {
        fixPathInputs.set(rec, fixInputOf(entries));
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
  // waiting-on-upstream (transitive), then non-breaking first (quick wins), then a total tiebreak.
  const dirsOf = (r: UpgradeRecommendation) => [...new Set((fixPathInputs.get(r)?.sourceDirs ?? []).map((d) => relativeDir(d, root)))].sort().join("\n");
  const order = planOrder(dirsOf);
  filtered.sort(order);

  const maxRecs = params.max_recommendations ?? 20;
  const limited = filtered.slice(0, maxRecs);
  // Verify the fix path of every vulnerable step the plan returns: a target
  // no advisory affects, and whether a lockfile refresh already reaches it.
  const verifiedInputs = limited.filter((r) => fixPathInputs.has(r)).map((r) => ({ step: r, ...fixPathInputs.get(r)! }));
  const unverified = await verifyFixPaths(verifiedInputs, liveIntel);
  // A direct bump must not stop at a release that still pins a vulnerable transitive a slightly
  // newer release clears (express 4.20.0 still pins path-to-regexp 0.1.10; audit H1).
  await reconcileDirectTargets(limited, verifiedInputs, liveIntel);
  // Go, crates.io, PyPI: a direct target is judged by what the release itself requires (required-targets.ts).
  await judgeDirectRequirements(limited, liveIntel);
  // A transitive fix that needs a major upgrade of what the project declares is breaking.
  settleTransitiveBreaking(limited);
  // One command per move: two parents reached through one direct dependency name its upgrade once (r7).
  dedupeParentCommands(limited);
  // A fix path through a private parent was never looked up: said first, never a proceed (upgrade-planner-private.ts).
  markPrivateParents(limited, (r) => fixPathInputs.get(r)?.sourceDirs ?? [], liveIntel);
  limited.sort(order);
  // Go module versions carry their `v` in every field, as currentVersion does (audit 7e).
  for (const r of limited) {
    r.targetVersion = inEcosystemForm(r.ecosystem, r.targetVersion);
    if (r.latestVersion !== undefined) r.latestVersion = inEcosystemForm(r.ecosystem, r.latestVersion);
  }
  // A target OSV.dev did not confirm clean is named only in a NOT CHECKED reason, never in targetVersion.
  withholdUnconfirmedTargets(limited);
  // A fix path that was not read is not determined; "waiting on upstream" is kept for the paths read and found blocked.
  markUndetermined(limited);
  // A copy this host does not build: its fix is on the row, labelled with where it applies.
  labelOtherTargets(limited);
  // What a command can do here: a uv workspace member's own uv.lock is not the one uv uses, the
  // workspace's own packages are not upgraded from the registry, and a uv pin whose release needs a
  // newer Python than the project supports is a hand step first (upgrade-plan-runnable.ts).
  const uvSpaces = uvWorkspaces(root);
  const staleUvLocks = withUvWorkspaceLocks(limited, root, uvSpaces);
  withoutOwnPackageUpgrades(limited, workspaceOwnNames(root, uvSpaces));
  withYarnClassicResolutions(limited, root);
  await withPythonSupport(limited, root, liveIntel.getFixPathSources());
  // A Cargo step that installs a release needing a newer Rust than the project's rust-version says so (upgrade-planner-rust-version.ts).
  await withRustVersions(limited, root, liveIntel, withinCallBudget(RUST_VERSION_BUDGET_MS, 500));
  // Every command a row names, as data, from the fields its words were built from (all passes done).
  attachCommands(limited, (r) => ({ root, installDirs: installDirsOf.get(r) }));
  // A direct upgrade with nothing to run says why, and the hand step that takes it.
  explainCommandlessRows(limited, (r) => fixPathInputs.has(r));
  // Targets that pin (or narrowly range) an affected dependency, or whose held dependencies could not be
  // judged (D-4): checked, NOT clean fixes, counted on their own and never as fixed by the step they
  // ride on (an upgrade, a refresh, a parent upgrade; 6.2.6 second review I1).
  const heldUnclean = (r: (typeof limited)[number]) => r.reasons.some((x) => HELD_UNCLEAN_REASON.test(x));
  const heldRows = limited.filter(heldUnclean);
  // The rows shown as one script safe to run top to bottom (upgrade-plan-sequence.ts).
  const declaredNpm = new Set(
    [...liveIntel.getResolvedDeps(), ...(liveIntel.getAuditDeps() as Array<{ ecosystem: string; name: string; version: string | null; isDirect?: boolean }>)]
      .filter((d) => d.isDirect && d.ecosystem === "npm")
      .map((d) => `${d.name}\0${d.version}`),
  );
  const sequence = await sequencePlan(limited, {
    totalRows: filtered.length,
    heldUnclean: (r) => r.reasons.some((x) => HELD_UNCLEAN_REASON.test(x)),
    goSource: liveIntel.getReleaseSources().Go,
    peers: { root, lockfileFor: (dir) => liveIntel.lockfileFor(dir, "npm"), isDirect: (name, version) => declaredNpm.has(`${name}\0${version}`) },
    declaredOperator: (dir, name) => declaredNpmOperator(root, dir, name),
    budgetMs: withinCallBudget(SEQUENCE_BUDGET_MS, 500),
  });
  // A direct upgrade after which other packages keep an affected copy of the package fixes only the project's own (upgrade-planner-shared-copy.ts).
  const sharedLeft = (r: (typeof limited)[number]) => r.reasons.some((x) => SHARED_COPY_REASON.test(x));
  const directRows = limited.filter((r) => r.scope === "direct" && r.action === "upgrade_direct" && !heldUnclean(r) && r.targetVersion !== null);
  const upgrades = directRows.filter((r) => !sharedLeft(r));
  const partlyDirect = directRows.length - upgrades.length;
  // Rows whose advisories OSV.dev did not answer for, or whose newer release was not confirmed (r7).
  const unknownRisk = limited.filter((r) => r.risk === "unknown").length;
  const unconfirmedNewer = limited.filter((r) => r.scope === "direct" && r.action === "upgrade_direct" && r.targetVersion === null && r.fixPathChecked === undefined && !heldUnclean(r)).length;
  const quickWins = upgrades.filter((r) => !r.breaking).length;
  const breakingChanges = upgrades.filter((r) => r.breaking).length;
  // A refresh row with a bundled copy (`bundledCopies`) is a real refresh AND leaves a vulnerable
  // copy waiting on its owner: it counts in both, and the summary says so, never as fully fixed.
  const partlyBundled = limited.filter((r) => r.action === "lockfile_refresh" && (r.bundledCopies?.length ?? 0) > 0).length;
  const waitingOnUpstream = limited.filter((r) => r.action === "waiting_on_upstream").length + partlyBundled;
  const fixPathNotDetermined = limited.filter((r) => r.action === "not_determined").length;
  const lockfileRefreshes = limited.filter((r) => r.action === "lockfile_refresh" && !heldUnclean(r)).length;
  const refreshesPartlyBundled = limited.filter((r) => r.action === "lockfile_refresh" && !heldUnclean(r) && (r.bundledCopies?.length ?? 0) > 0).length;
  const parentUpgradeSteps = limited.filter((r) => r.action === "upgrade_parent" && !heldUnclean(r)).length;
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
      ? // The counts that follow describe the rows shown, not the whole plan (audit 6.2.5 D-6: 6 waiting shown vs 43 real).
        `Showing ${limited.length} of ${filtered.length} recommendations (raise max_recommendations for the rest); the counts below are for the ${limited.length} shown`
      : `${limited.length} recommendation${limited.length !== 1 ? "s" : ""}`,
  );
  if (upgrades.length > 0) parts.push(`${upgrades.length} upgradable directly (${quickWins} non-breaking, ${breakingChanges} crossing a major version)`);
  if (partlyDirect > 0) {
    parts.push(
      `${partlyDirect} direct upgrade${partlyDirect !== 1 ? "s" : ""} that move${partlyDirect === 1 ? "s" : ""} only this project's own copy: other packages keep an affected copy on the old line, moved by hand (their reasons say which; not counted as fixed, not in run_order)`,
    );
  }
  if (reinstalls > 0) parts.push(`${reinstalls} need only a reinstall (node_modules behind the lockfile)`);
  if (lockfileRefreshes > 0) {
    parts.push(
      `${lockfileRefreshes} transitive, fixed by a lockfile refresh (every parent already admits a clean version)${refreshesPartlyBundled > 0 ? `, ${refreshesPartlyBundled} of them only partly: a bundled copy stays, waiting on the package that bundles it (bundledCopies), and is counted as waiting on upstream too` : ""}`,
    );
  }
  if (parentUpgradeSteps > 0) parts.push(`${parentUpgradeSteps} transitive, fixed by upgrading the parent that pins it (parentUpgrades names the release)`);
  if (unverifiedParents > 0) {
    parts.push(
      `${unverifiedParents} transitive, a parent release that admits a clean version exists but no release of the declared dependency that brings it in was verified (parentUpgrades says what to check; not counted as fixed)`,
    );
  }
  if (waitingOnUpstream > 0) parts.push(`${waitingOnUpstream} transitive, waiting on upstream${partlyBundled > 0 ? ` (${partlyBundled} a bundled copy beside a refresh that fixes the copies that are not bundled)` : ""}`);
  if (fixPathNotDetermined > 0) {
    parts.push(
      `${fixPathNotDetermined} transitive, fix path not determined (the registry or the lockfile could not be read, live lookups are off, or time ran out): unread, not blocked, so ask again before deciding`,
    );
  }
  // "later": only releases above the installed copy were judged; an earlier one is not denied (W6).
  if (removals > 0) parts.push(`${removals} to remove or replace: no later release is clean of the malware or advisories affecting the installed copy`);
  if (holds > 0) parts.push(`${holds} to keep where ${holds === 1 ? "it is" : "they are"}: every newer release is known-affected or withdrawn`);
  if (overrides > 0) parts.push(`${overrides} transitive, blocked by a parent that will not move (deprecated, already its latest release, or no release admits a clean version): override the version or replace the parent`);
  if (heldRows.length > 0) {
    parts.push(
      `${heldRows.length} fix target${heldRows.length !== 1 ? "s" : ""} NOT a clean fix: the release exact-pins, narrowly ranges or holds a range whose newest release is affected, or what it holds could not be checked (see reasons; confirm with dependency_check)`,
    );
  }
  // Go, crates.io, PyPI: which of those the target's own requirements decided, and how many were not examined (required-targets.ts).
  const requiresAffected = heldRows.filter((r) => r.reasons.some((x) => REQUIRES_AFFECTED_REASON.test(x))).length;
  const requiresUnexamined = heldRows.filter((r) => r.reasons.some((x) => REQUIRES_UNEXAMINED_REASON.test(x)));
  if (requiresAffected > 0) {
    parts.push(`${requiresAffected} of them because the target's own requirements (a Go go.mod, a crate's or PyPI release's requirements) carry advisories: the reasons name which, how many, and what to raise afterwards`);
  }
  if (requiresUnexamined.length > 0) {
    const capped = requiresUnexamined.filter((r) => r.reasons.some((x) => REQUIRES_CAP_REASON.test(x))).length;
    parts.push(
      `${requiresUnexamined.length} target${requiresUnexamined.length !== 1 ? "s" : ""} whose own requirements were not examined${capped > 0 ? ` (${capped} past the ${MAX_REQUIRED_TARGETS} a call examines)` : ""}: not a clean fix until dependency_check examines ${requiresUnexamined.length === 1 ? "it" : "them"}`,
    );
  }
  const newerRust = rustVersionSummary(limited);
  if (newerRust) parts.push(newerRust);
  if (unverified > 0) parts.push(`${unverified} fix target${unverified !== 1 ? "s" : ""} checked only against the installed version's advisories (offline, or OSV or the registry did not answer in time; see fixPathChecked)`);
  if (unknownRisk > 0) parts.push(`${unknownRisk} NOT CHECKED: OSV.dev gave no answer for ${unknownRisk === 1 ? "it" : "them"}, so ${unknownRisk === 1 ? "its" : "their"} advisories are not known (risk "unknown", not low)`);
  if (unconfirmedNewer > 0) parts.push(`${unconfirmedNewer} newer release${unconfirmedNewer !== 1 ? "s" : ""} NOT CHECKED against advisories, so no targetVersion is given (run dependency_check before writing one)`);
  if (noFix > 0) parts.push(`${noFix} vulnerable with no fixed release yet`);
  if (inactive > 0) {
    const targets = [...new Set(limited.filter((r) => r.action === "not_built_on_this_host").flatMap((r) => r.appliesWhenBuiltFor ?? []))];
    parts.push(`${inactive} vulnerable only in code not built on this host (the fix on each row applies when you build for its target: ${targets.join("; ")})`);
  }
  const criticalCount = limited.filter((r) => r.risk === "critical").length;
  if (criticalCount > 0) parts.push(`${criticalCount} critical`);
  if (devOnly > 0) parts.push(`${devOnly} dev-only (isDev)`);
  // The population, worded as dependency_health and vulnerability_scan word it (finding 6).
  if (vulnResult) parts.push(populationNote(vulnResult.vulnerabilities, liveIntel.getAuditDeps(), includeDev, named));
  // A workspace member's vulnerable devDependency is one too.
  const devDeclaredLeftOut = devDirectLeftOut + devDeclaredSkipped.size;
  if (devDeclaredLeftOut + devTransitiveLeftOut + devDirectUnchecked > 0) {
    const left: string[] = [];
    if (devDeclaredLeftOut > 0) left.push(`${devDeclaredLeftOut} vulnerable devDependenc${devDeclaredLeftOut !== 1 ? "ies" : "y"}`);
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
  // An answer that starts with NOT CHECKED or STALE is incomplete (the server's instructions): a plan
  // whose vulnerability data is not complete says so first, never after its counts.
  if (!vulnerabilityDataAvailable && !INCOMPLETE.test(parts[0] ?? "")) {
    const said = parts.filter((p) => INCOMPLETE.test(p));
    const rest = parts.filter((p) => !INCOMPLETE.test(p));
    parts.length = 0;
    if (said.length === 0) parts.push(notCheckedLead(liveIntel.wasLockfileRead(), nothingReadable));
    pushAll(parts, said);
    pushAll(parts, rest);
  }

  return {
    generatedAt: new Date().toISOString(),
    projectPath: liveIntel.getProjectRoot() ?? vulnResult?.projectPath ?? process.cwd(),
    totalDeps: deps.length,
    recommendations: limited,
    summary: parts.join(". ") + ".",
    quickWins,
    breakingChanges,
    waitingOnUpstream,
    fixPathNotDetermined,
    lockfileRefreshes,
    parentUpgradeSteps,
    vulnerabilityDataAvailable,
    ...(coverage ? { vulnerabilityCoverage: coverage } : {}),
    run_order: sequence.run_order,
    run_order_note: [sequence.run_order_note, staleUvLocks.length > 0 ? staleLocksNote(staleUvLocks) : null, rustVersionRunOrderNote(limited, sequence.run_order)]
      .filter((s): s is string => Boolean(s))
      .join(" "),
    provenance: { mode: "lockfile_engine", note: PROVENANCE_NOTE },
  };
}

/** A summary sentence that marks the answer incomplete. */
const INCOMPLETE = /^(?:NOT CHECKED|STALE)\b/;

/**
 * How many lockfiles were not read whole: merge-conflicted, unparseable, or read only in part (the
 * kinds vulnerability_scan's coverage counts as not read). Not a refused include, a stale twin of a
 * lockfile that was read, or one not cross-checked against its manifests: those leave nothing
 * unread. A go.sum is not counted (from go 1.17 the versions are go.mod's).
 */
function lockfilesNotFullyRead(problems: Parameters<typeof splitLockfileProblems>[0]): number {
  const { mergeConflicts, unreadable, partial } = splitLockfileProblems(problems);
  return new Set([...mergeConflicts, ...unreadable, ...partial].filter((p) => !/(?:^|[\\/])go\.sum$/.test(p.file)).map((p) => p.file)).size;
}

/** The first sentence of a plan whose vulnerability data is not complete, when no other part already says why. */
function notCheckedLead(lockfileRead: boolean, nothingReadable: boolean): string {
  if (!lockfileRead) {
    return "NOT CHECKED: no lockfile was read, so no installed version is known and none was checked for advisories (a declared range is not an install); generate the lockfile, then plan again";
  }
  if (nothingReadable) return "NOT CHECKED: nothing found here could be read as a dependency this server checks (the notes below say why)";
  return "NOT CHECKED: this plan's vulnerability data is not complete, so a missing row or a low risk is not a clean result";
}

/** Where a copy this host does not build IS built, in words: its declared target spec, or any target but this host's. */
function builtFor(entries: VulnerabilityEntry[]): string[] {
  const specs = [...new Set(entries.filter((e) => !e.platformActive).map((e) => e.target).filter((t): t is string => Boolean(t)))];
  const words = specs.map((spec) => {
    const triple = /^not built for (\S+)$/.exec(spec)?.[1];
    return triple ? `a target other than ${triple}` : spec;
  });
  return words.length > 0 ? [...new Set(words)] : ["another target"];
}

/**
 * The reason that carries a not-built-here row's fix: what to do where the copy is built, with the
 * commands the row holds. The row keeps its own action and count; nothing here is this host's step.
 */
function labelOtherTargets(rows: UpgradeRecommendation[]): void {
  for (const r of rows) {
    if (r.action !== "not_built_on_this_host" || !r.appliesWhenBuiltFor) continue;
    const pending = r.reasons.indexOf(TRANSITIVE_PENDING);
    if (pending >= 0) r.reasons[pending] = "Transitive dependency — not declared in your manifest";
    const named = [...(r.upgradeCommands ?? []), ...(r.refreshCommands ?? [])].map((c) => "`" + c.command + "` in " + c.dir);
    const edits = (r.upgradeInstructions ?? []).map((i) => i.instruction);
    const run = named.length + edits.length > 0 ? ` (${[...named, ...edits].join("; ")})` : "";
    const copy = `${r.package} ${r.currentVersion ?? ""}`.trimEnd();
    const how = !r.targetVersion
      ? "no release is named for it (the reasons above say why)"
      : r.whenBuilt === "upgrade_direct"
        ? `upgrade ${copy} to ${r.targetVersion}${run}`
        : r.whenBuilt === "lockfile_refresh"
          ? `a lockfile refresh moves ${copy} to ${r.targetVersion}${run}`
          : r.whenBuilt === "upgrade_parent"
            ? `upgrade the parent that pins ${copy} (the reasons above and parentUpgrades name the release)`
            : r.whenBuilt === "upgrade_parent_unverified"
              ? `a parent of ${copy} has to move, and no release of it was verified (parentUpgrades says what to check)`
              : r.whenBuilt === "override_or_replace"
                ? `force ${copy} to ${r.targetVersion} with an override, or replace the parent that pins it (the reasons above say how)`
                : r.whenBuilt === "waiting_on_upstream"
                  ? `${copy} waits on a parent release (the reasons above say which)`
                  : `${r.targetVersion} is the release to move ${copy} to; how it is reached there was NOT DETERMINED in this call (the registry or the lockfile could not be read, or time ran out): ask again`;
    r.reasons.push(`Applies when you build for ${r.appliesWhenBuiltFor.join(", ")}: this host does not compile ${r.package}, so this is not one of its steps; where that target is built or deployed, ${how}`);
  }
}

/** What a transitive row says in place of its pending reason once its fix path is known to be undetermined. */
const NOT_DETERMINED_REASON =
  "Transitive dependency — not declared in your manifest. How it is fixed (a lockfile refresh, a parent upgrade or an override) was NOT DETERMINED in this call";
const NOT_DETERMINED_WHY =
  ": the registry or the lockfile could not be read, live lookups are off, or the time budget ran out. Unread is not blocked: call upgrade_planner again (answers are cached); never bump it directly";

/**
 * "Waiting on upstream" says the paths to the fix were read and a parent the project cannot move
 * blocks them. A transitive row still carrying its pending reason was never decided (nothing
 * could be read, or only part), and one that arrives through a private parent was never looked
 * up: both are `not_determined`.
 */
function markUndetermined(rows: UpgradeRecommendation[]): void {
  for (const r of rows) {
    if (r.scope !== "transitive" || r.action !== "waiting_on_upstream") continue;
    const at = r.reasons.indexOf(TRANSITIVE_PENDING);
    if (at < 0 && !r.privateParents) continue;
    r.action = "not_determined";
    // The lookups that did run say what they read (FIX_PATH_UNDETERMINED); otherwise the general causes.
    const said = r.privateParents !== undefined || r.reasons.some((x) => x.startsWith(FIX_PATH_UNDETERMINED));
    if (at >= 0) r.reasons[at] = `${NOT_DETERMINED_REASON}${said ? "" : NOT_DETERMINED_WHY}`;
  }
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

/**
 * Platform activity is per lockfile (dependency-set.ts): the directories that lock this copy
 * without building it on this host, so the row's commands are read as being for the others.
 */
function notBuiltIn(entries: VulnerabilityEntry[], root: string): string | null {
  const unbuilt = new Set(entries.flatMap((e) => e.platformInactiveDirs ?? []));
  if (unbuilt.size === 0) return null;
  const dirs = [...unbuilt].map((d) => relativeDir(d, root)).sort();
  const built = builtDirs(entries).map((d) => relativeDir(d, root)).sort();
  return `Built on this host in ${dirsLabel(built, (d) => d)} only: ${dirsLabel(dirs, (d) => d)} lock${dirs.length === 1 ? "s" : ""} the same version without building it here, so this step is not about ${dirs.length === 1 ? "it" : "them"}`;
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
