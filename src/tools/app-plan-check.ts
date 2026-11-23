// SPDX-License-Identifier: Apache-2.0
/**
 * `app_plan_check`: how the 4DA app's stored upgrade plan stands against the answer this server
 * computed from the lockfiles on disk (DESIGN section 3).
 *
 * The app's plan is never the answer for one project: it is read only to say whether it agrees.
 * It is compared by ecosystem + package + installed version, and only when it can be: the plan is
 * in a format this server reads, the app's advisory data is at most a day old, and no lockfile on
 * disk changed after the plan was generated. For the all-projects scope, where the app's plan is
 * the only plan that covers every project, the same facts decide whether it is stale.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { FourDADatabase } from "../db.js";
import { NEWEST_TESTED_APP, OLDEST_SUPPORTED_APP, SUPPORTED_PLAN_FORMATS } from "../app-compat.js";
import { maxOf } from "../array-utils.js";
import type { LiveIntelligence } from "../live/index.js";
import { isMaintenanceNotice } from "../live/maintenance.js";
import { inEcosystemForm } from "../live/version-compare.js";
import { scopeAppPlanSteps, type AppPlanRead, type AppPlanSnapshot, type AppPlanStepView } from "./app-plan.js";
import { isWithin, normalizeProjectPath } from "./project-scope.js";

export type AppPlanCheckStatus = "agrees" | "differs" | "not_comparable" | "no_plan" | "unverified";

export interface AppPlanDifference {
  ecosystem: string;
  package: string;
  installed: string;
  /** What the app's stored plan moves this copy to; null when it names no move for it. */
  app_target: string | null;
  /** What this server's plan moves it to; null when it names no move for it (or has no row: no advisory affects it on disk). */
  server_target: string | null;
}

export interface AppPlanCheck {
  status: AppPlanCheckStatus;
  note: string;
  plan_generated_at?: string;
  /** Hours since the advisory data the app's plan was built on was last verified; null when the app records no time. */
  advisory_data_age_hours?: number | null;
  /** At most MAX_DIFFERENCES rows; the note gives the full count. */
  differences?: AppPlanDifference[];
}

/** Advisory data older than this cannot stand behind a plan. */
export const MAX_ADVISORY_AGE_HOURS = 24;
export const MAX_DIFFERENCES = 10;
/** Projects named in a stale plan's `staleness` when their lockfiles changed after it was generated. */
export const MAX_CHANGED_PROJECTS_NAMED = 5;

/** Files whose change means a project's installed versions may have moved. */
const LOCKFILE_NAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
  "Cargo.lock",
  "poetry.lock",
  "uv.lock",
  "pdm.lock",
  "Pipfile.lock",
  "requirements.txt",
  "go.mod",
  "go.sum",
  "Gemfile.lock",
  "gems.locked",
  "composer.lock",
]);

/**
 * An app timestamp as epoch ms: RFC 3339 as the plan writes it, or SQLite's `YYYY-MM-DD HH:MM:SS`
 * (UTC, no zone) as `osv_sync_status` holds it. NaN when unreadable.
 */
export function appTimeMs(stamp: string | null | undefined): number {
  if (!stamp || !stamp.trim()) return Number.NaN;
  const s = stamp.trim();
  const sqlite = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)$/.exec(s);
  return Date.parse(sqlite ? `${sqlite[1]}T${sqlite[2]}Z` : s);
}

/**
 * How old the advisory data under the app's plan is: the older of the plan's own `source_freshness`
 * (the oldest ecosystem sync when it was generated) and the oldest verified sync the app records
 * now (`osv_sync_status.last_synced_at`; an empty time means never verified and is not a time).
 */
export function advisoryDataAge(db: FourDADatabase, snapshot: Pick<AppPlanSnapshot, "sourceFreshness"> | null, now: number = Date.now()): { hours: number | null; since: string | null } {
  const stamps: string[] = [];
  if (snapshot?.sourceFreshness) stamps.push(snapshot.sourceFreshness);
  try {
    if (db.hasColumn("osv_sync_status", "last_synced_at")) {
      const rows = db.getRawDb().prepare("SELECT last_synced_at FROM osv_sync_status").all() as Array<{ last_synced_at: unknown }>;
      for (const r of rows) if (typeof r.last_synced_at === "string" && r.last_synced_at.trim()) stamps.push(r.last_synced_at);
    }
  } catch {
    // No sync record to read: the plan's own stamp, if any, still stands.
  }
  let oldest: { ms: number; stamp: string } | null = null;
  for (const stamp of stamps) {
    const ms = appTimeMs(stamp);
    if (Number.isNaN(ms)) continue;
    if (!oldest || ms < oldest.ms) oldest = { ms, stamp };
  }
  if (!oldest) return { hours: null, since: null };
  return { hours: Math.max(0, Math.round(((now - oldest.ms) / 3_600_000) * 10) / 10), since: oldest.stamp };
}

/** "advisory data last verified 960 hours ago (2026-10-14 03:00:00), older than 24 hours", or null when within the limit or unknown. */
function advisoryAgeProblem(age: { hours: number | null; since: string | null }): string | null {
  if (age.hours === null || age.hours <= MAX_ADVISORY_AGE_HOURS) return null;
  return `the app's advisory data was last verified ${age.hours} hours ago (${age.since}), more than ${MAX_ADVISORY_AGE_HOURS} hours, so the plan may miss advisories published since`;
}

/** Why a stored plan in an unknown format cannot be read, naming both versions and the side to update. */
export function planFormatNote(found: unknown): string {
  const formats = `this server reads plan formats ${SUPPORTED_PLAN_FORMATS.join(" and ")} (${OLDEST_SUPPORTED_APP.release} through ${NEWEST_TESTED_APP.release})`;
  if (typeof found === "number" && found > maxOf(SUPPORTED_PLAN_FORMATS)) {
    return `The 4DA app stored its plan in format ${found} and ${formats}: the app is newer than this server, so update @4da/mcp-server to compare them.`;
  }
  if (typeof found === "number") {
    return `The 4DA app stored its plan in format ${found} and ${formats}: the app is older than this server supports, so update the 4DA app to compare them.`;
  }
  return `The 4DA app's stored plan could not be read (no format number) and ${formats}: update the 4DA app so it rewrites the plan.`;
}

/** The project directories the app's plan covers: every site and hold in its steps, and every project its inventory tracks. */
function planProjects(db: FourDADatabase, steps: AppPlanStepView[]): string[] {
  const dirs = new Map<string, string>();
  const add = (p: string | null | undefined) => {
    if (p && p.trim()) dirs.set(normalizeProjectPath(p), p);
  };
  for (const step of steps) {
    for (const line of step.lines) for (const site of line.sites) add(site.project);
    for (const hold of step.blocked_upstream ?? []) add(hold.project);
  }
  try {
    for (const r of db.getRawDb().prepare("SELECT DISTINCT project_path FROM project_dependencies").all() as Array<{ project_path: unknown }>) {
      if (typeof r.project_path === "string") add(r.project_path);
    }
  } catch {
    // No inventory table: the plan's own sites are the projects it covers.
  }
  return [...dirs.values()];
}

/** The newest lockfile directly in `dir` modified after `sinceMs`, or null. Read-only: one directory listing and a stat per lockfile. */
function lockfileChangedSince(dir: string, sinceMs: number): { file: string; mtimeMs: number } | null {
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return null;
  }
  let newest: { file: string; mtimeMs: number } | null = null;
  for (const name of names) {
    if (!LOCKFILE_NAMES.has(name)) continue;
    try {
      const mtimeMs = fs.statSync(path.join(dir, name)).mtimeMs;
      if (mtimeMs > sinceMs && (!newest || mtimeMs > newest.mtimeMs)) newest = { file: path.join(dir, name), mtimeMs };
    } catch {
      // Gone between the listing and the stat.
    }
  }
  return newest;
}

/**
 * The plan as one map: per installed copy, the target the app's plan names for it. A line whose
 * sites all lie in directories this answer does not scan (gitignored, test fixtures: its coverage
 * names them) is out of its reach, counted in `outOfScan`, never a difference.
 */
function appLines(steps: AppPlanStepView[], includeDev: boolean, excludedDirs: string[]): { lines: Map<string, AppPlanDifference>; outOfScan: number } {
  const lines = new Map<string, AppPlanDifference>();
  let outOfScan = 0;
  for (const step of steps) {
    for (const line of step.lines) {
      if (!includeDev && line.sites.length > 0 && line.sites.every((s) => s.dev)) continue;
      if (line.sites.length > 0 && line.sites.every((s) => excludedDirs.some((d) => isWithin(s.project, d)))) {
        outOfScan++;
        continue;
      }
      const key = copyKey(step.ecosystem, step.package, line.installed);
      if (!lines.has(key)) lines.set(key, { ecosystem: step.ecosystem, package: step.package, installed: line.installed, app_target: line.target ?? null, server_target: null });
    }
  }
  return { lines, outOfScan };
}

/** ecosystem + package + installed version, spelled the same on both sides (case, PyPI separators, Go's `v`). */
export function copyKey(ecosystem: string, name: string, version: string | null): string {
  const eco = ecosystem.toLowerCase();
  const pkg = eco === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : eco === "go" ? name : name.toLowerCase();
  return `${eco}\0${pkg}\0${sameVersion(ecosystem, version) ?? ""}`;
}

function sameVersion(ecosystem: string, version: string | null): string | null {
  if (!version) return null;
  return (inEcosystemForm(ecosystem, version) ?? version).replace(/^v(?=\d)/, "");
}

/** What this server's answer holds for the comparison. */
export interface ServerPlanFacts {
  /** The rows the answer shows. */
  rows: Array<{ ecosystem: string; package: string; currentVersion: string | null; targetVersion: string | null }>;
  /** Copies the server's own scan found vulnerable (shown or not), by copyKey. */
  vulnerable: Set<string>;
  /** The scan answered for every dependency in scope (no NOT CHECKED part). */
  complete: boolean;
  /** The newest lockfile the plan was resolved from, when one was read. */
  newestLockfile: { file: string; mtimeMs: number } | null;
  /** The project root, for naming files relative to it. */
  root: string;
  /** Directories below the root that this answer does not scan (skipped lockfiles' directories, test-fixture directories). */
  excludedDirs: string[];
}

/** The live layer's view of a project, as far as the comparison needs it. */
type PlanLiveLayer = Pick<LiveIntelligence, "getVulnerabilities" | "getResolutionProvenance" | "getDiscovery">;

/** What the app's stored plan is compared with: the rows shown, every copy the scan found vulnerable, the newest lockfile read. */
export function serverPlanFacts(
  plan: { recommendations: ServerPlanFacts["rows"]; vulnerabilityDataAvailable: boolean; projectPath: string },
  live: PlanLiveLayer | null,
): ServerPlanFacts {
  const scan = live?.getVulnerabilities() ?? null;
  const vulnerable = new Set((scan?.vulnerabilities ?? []).filter((v) => !isMaintenanceNotice(v)).map((v) => copyKey(v.ecosystem, v.package, v.currentVersion)));
  let newestLockfile: ServerPlanFacts["newestLockfile"] = null;
  for (const source of live?.getResolutionProvenance()?.sources ?? []) {
    if (source.kind !== "lockfile") continue;
    let mtimeMs = source.mtimeMs;
    try {
      mtimeMs = fs.statSync(source.path).mtimeMs;
    } catch {
      // Gone since it was read: the time it had then stands.
    }
    if (mtimeMs !== null && (!newestLockfile || mtimeMs > newestLockfile.mtimeMs)) newestLockfile = { file: source.path, mtimeMs };
  }
  const discovery = live?.getDiscovery() ?? null;
  const root = plan.projectPath;
  const excludedDirs = [...(discovery?.skipped ?? []).map((s) => path.dirname(s.path)), ...(discovery?.fixtures?.dirs ?? [])]
    .map((rel) => path.resolve(root, rel))
    .filter((dir) => normalizeProjectPath(dir) !== normalizeProjectPath(root));
  return { rows: plan.recommendations, vulnerable, complete: plan.vulnerabilityDataAvailable, newestLockfile, root, excludedDirs };
}

/**
 * The check for one project's answer. `read` is the app's stored plan (or why there is none);
 * `scope` the project directory the answer is for.
 */
export function checkProjectPlan(
  db: FourDADatabase,
  read: AppPlanRead,
  scope: string,
  server: ServerPlanFacts,
  params: { include_dev?: boolean; package?: string },
  now: number = Date.now(),
): AppPlanCheck {
  const computed = "This answer is computed from the lockfiles on disk";
  if (read.kind === "absent") {
    const age = advisoryDataAge(db, null, now);
    const base = { advisory_data_age_hours: age.hours };
    if (read.cause === "format") return { status: "not_comparable", note: `${computed}. ${read.formatNote ?? planFormatNote(read.found)}`, ...base };
    return { status: "no_plan", note: `${computed}; the 4DA app has stored no upgrade plan to compare it with (${read.reason}).`, ...base };
  }
  const { snapshot } = read;
  const age = advisoryDataAge(db, snapshot, now);
  const base = { plan_generated_at: snapshot.generatedAt, advisory_data_age_hours: age.hours };
  const generatedMs = appTimeMs(snapshot.generatedAt);
  const problems: string[] = [];
  const stale = advisoryAgeProblem(age);
  if (stale) problems.push(stale);
  if (Number.isNaN(generatedMs)) problems.push(`the plan's generation time "${snapshot.generatedAt}" cannot be read`);
  else if (server.newestLockfile && server.newestLockfile.mtimeMs > generatedMs) {
    const rel = path.relative(server.root, server.newestLockfile.file).replace(/\\/g, "/") || server.newestLockfile.file;
    problems.push(`the plan was generated (${snapshot.generatedAt}) before ${rel} was last modified (${new Date(server.newestLockfile.mtimeMs).toISOString()})`);
  }
  if (!server.complete) problems.push("this server's own scan is incomplete (NOT CHECKED), so there is nothing settled to compare the app's plan with");
  if (problems.length > 0) {
    return { status: "not_comparable", note: `${computed}; the 4DA app's stored plan is not compared with it: ${problems.join("; and ")}.`, ...base };
  }

  const wanted = params.package?.trim().toLowerCase();
  const steps = scopeAppPlanSteps(snapshot.steps, scope).filter((s) => !wanted || s.package.toLowerCase() === wanted);
  const { lines: app, outOfScan } = appLines(steps, params.include_dev ?? true, server.excludedDirs);
  const shown = new Map<string, string | null>();
  for (const r of server.rows) {
    const key = copyKey(r.ecosystem, r.package, r.currentVersion);
    if (server.vulnerable.has(key) && !shown.has(key)) shown.set(key, r.targetVersion);
  }
  const differences: AppPlanDifference[] = [];
  let notCompared = 0;
  for (const [key, line] of app) {
    if (shown.has(key)) {
      const serverTarget = shown.get(key) ?? null;
      if (sameVersion(line.ecosystem, line.app_target) !== sameVersion(line.ecosystem, serverTarget)) differences.push({ ...line, server_target: serverTarget });
    } else if (server.vulnerable.has(key)) {
      notCompared++;
    } else if (line.app_target) {
      differences.push(line);
    }
  }
  for (const r of server.rows) {
    const key = copyKey(r.ecosystem, r.package, r.currentVersion);
    if (!shown.has(key) || app.has(key) || !r.targetVersion || !r.currentVersion) continue;
    if (differences.some((d) => copyKey(d.ecosystem, d.package, d.installed) === key)) continue;
    differences.push({ ecosystem: r.ecosystem, package: r.package, installed: r.currentVersion, app_target: null, server_target: r.targetVersion });
  }
  const packages = new Set(differences.map((d) => `${d.ecosystem.toLowerCase()}\0${d.package.toLowerCase()}`)).size;
  const asides = [
    ...(notCompared > 0 ? [`${notCompared} of the app's rows name copies this answer does not show (raise max_recommendations or lower risk_threshold to compare them)`] : []),
    ...(outOfScan > 0 ? [`${outOfScan} of the app's rows are in directories this answer does not scan (its coverage names them)`] : []),
  ];
  const unseen = asides.length > 0 ? ` (${asides.join("; ")})` : "";
  const ageNote = age.hours === null ? " The app records no time for its advisory data." : "";
  if (differences.length === 0) {
    return { status: "agrees", note: `${computed}; the 4DA app's stored plan (generated ${snapshot.generatedAt}) agrees with it on every package either one names${unseen}.${ageNote}`, ...base };
  }
  return {
    status: "differs",
    note: `${computed}; the 4DA app's stored plan (generated ${snapshot.generatedAt}) differs from it on ${packages} package${packages === 1 ? "" : "s"}, and this answer is the one to follow${unseen}.${ageNote}`,
    ...base,
    differences: differences.slice(0, MAX_DIFFERENCES),
  };
}

/** The all-projects scope: whether the app's stored plan is stale, and its check (never compared row by row). */
export interface AllProjectsPlanCheck {
  /** Why the plan is stale, in words; empty when nothing shows it is. */
  staleReasons: string[];
  check: AppPlanCheck;
}

export function checkAllProjectsPlan(db: FourDADatabase, read: Extract<AppPlanRead, { kind: "plan" }>, now: number = Date.now()): AllProjectsPlanCheck {
  const { snapshot } = read;
  const age = advisoryDataAge(db, snapshot, now);
  const base = { plan_generated_at: snapshot.generatedAt, advisory_data_age_hours: age.hours };
  const staleReasons: string[] = [];
  if (read.stale) staleReasons.push(`past its freshness horizon (${snapshot.expiresAt})`);
  const ageProblem = advisoryAgeProblem(age);
  if (ageProblem) staleReasons.push(ageProblem);
  const generatedMs = appTimeMs(snapshot.generatedAt);
  if (!Number.isNaN(generatedMs)) {
    const changed = planProjects(db, snapshot.steps)
      .map((dir) => ({ dir, changed: lockfileChangedSince(dir, generatedMs) }))
      .filter((p) => p.changed !== null);
    if (changed.length > 0) {
      const named = changed.slice(0, MAX_CHANGED_PROJECTS_NAMED).map((p) => p.dir);
      const more = changed.length - named.length;
      staleReasons.push(`a lockfile changed after the plan was generated in ${named.join(", ")}${more > 0 ? ` and ${more} more project${more === 1 ? "" : "s"}` : ""}`);
    }
  }
  const perProject = "For a plan computed from one project's lockfiles, call upgrade_planner with that project's path.";
  const check: AppPlanCheck = ageProblem
    ? { status: "not_comparable", note: `This is the 4DA app's stored plan, not checked against the lockfiles on disk by this server, and it cannot stand behind it: ${ageProblem}. ${perProject}`, ...base }
    : { status: "unverified", note: `This is the 4DA app's stored plan, not checked against the lockfiles on disk by this server. ${perProject}`, ...base };
  return { staleReasons, check };
}
