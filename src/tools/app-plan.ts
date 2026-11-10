// SPDX-License-Identifier: Apache-2.0
/**
 * The 4DA app's persisted Upgrade Plan, read for `upgrade_planner` (AD-049).
 *
 * The desktop app writes its ranked plan to `kv_store` under
 * `upgrade_plan_snapshot` after every plan compute (the same envelope
 * `4da plan --json` prints). From schema 4 the envelope carries `steps`: a
 * machine-readable work order keyed by plan item id, built in Rust from the
 * same per-line targets as the item titles. This module only READS it — no
 * range matching, target walking or scope grading is reimplemented here, so
 * the agent gets the app's answer, not a second opinion.
 *
 * Schema 5 (the app's Y5, 2026-11-10) adds the mechanisms `lockfile_refresh`,
 * `parent_update` and `blocked_upstream`, narrows `lockfile_or_parent_update`
 * to "the route of some copy is undecided, or the copies' routes differ", and
 * lets a step carry `blocked_upstream` holds: copies no published release can
 * fix yet, with what holds each and the options. Both 4 and 5 are read; each
 * step gets a `next_step` sentence in the schema's own terms, and a blocked fix
 * is never worded as an upgrade.
 *
 * Fail-closed like the Rust reader: any schema version not in
 * APP_PLAN_SCHEMA_VERSIONS is treated as absent and the caller falls back to
 * its standalone heuristic, saying why.
 */

import type { FourDADatabase } from "../db.js";
import { isWithin } from "./project-scope.js";

/** The snapshot schemas this reader understands (Rust `PLAN_SCHEMA_VERSION`, 4 and 5). */
export const APP_PLAN_SCHEMA_VERSIONS: readonly number[] = [4, 5];
/** The newest of them, the one the app writes today. */
export const APP_PLAN_SCHEMA_VERSION = 5;

const PLAN_KV_KEY = "upgrade_plan_snapshot";

export interface AppPlanSite {
  project: string;
  direct: boolean;
  dev: boolean;
}

export interface AppPlanLine {
  installed: string;
  target: string | null;
  upgrade_type: "patch" | "minor" | "major" | null;
  clears_all_known: boolean;
  sites: AppPlanSite[];
  /** npm: what the held-dependency rule said about `target` (passed through as the app wrote it). */
  held?: unknown;
}

/** Schema 5: one transitive copy no published release can fix yet (Rust `BlockedHold`). */
export interface AppPlanBlockedHold {
  project: string;
  installed: string;
  /** The version that clears the advisories. */
  cleared_version: string;
  /** The package that pulls the copy in, and its installed version. */
  parent: string;
  parent_version: string;
  /** The parent's requirement on the package, when it was read. */
  requirement?: string;
  /** The package whose newest release keeps the copy (the parent, or the dependency it arrives through). */
  held_by: string;
  held_by_newest: string;
  /** What can be done instead, in order. */
  options: string[];
}

export type AppPlanMechanism =
  | "manifest_bump"
  | "lockfile_or_parent_update"
  | "lockfile_refresh"
  | "parent_update"
  | "blocked_upstream"
  | "mixed"
  | "no_fix";

export interface AppPlanStep {
  item_id: string;
  ecosystem: string;
  package: string;
  lines: AppPlanLine[];
  mechanism: AppPlanMechanism;
  /** Schema 5: the copies no published release can fix yet; absent when none is blocked. */
  blocked_upstream?: AppPlanBlockedHold[];
  advisory_ids: string[];
  verification: string;
}

interface AppPlanItem {
  id: string;
  title: string;
  urgency: string;
}

/** A step with the title and urgency of the plan item it belongs to. */
export interface AppPlanStepView extends AppPlanStep {
  title: string | null;
  urgency: string | null;
  /** What to do, in words, from the mechanism (and the schema's meaning of it); a blocked fix is never "upgrade". */
  next_step: string;
}

export interface AppPlanSnapshot {
  schemaVersion: number;
  generatedAt: string;
  expiresAt: string;
  generatorVersion: string | null;
  sourceFreshness: string | null;
  multiVersionCoverage: boolean | null;
  validationDropCount: number | null;
  itemCount: number;
  steps: AppPlanStepView[];
}

export type AppPlanRead =
  | { kind: "plan"; snapshot: AppPlanSnapshot; stale: boolean }
  | { kind: "absent"; reason: string };

/**
 * Read the app's plan from the shared database. Never throws: a missing
 * database, a standalone database without `kv_store`, no snapshot, bad JSON
 * or another schema version all come back as `absent` with the reason.
 */
export function readAppPlan(db: FourDADatabase | null | undefined, now: Date = new Date()): AppPlanRead {
  if (!db) return { kind: "absent", reason: "no 4DA database" };
  let raw: string | undefined;
  try {
    const row = db
      .getRawDb()
      .prepare("SELECT value FROM kv_store WHERE key = ?")
      .get(PLAN_KV_KEY) as { value?: unknown } | undefined;
    raw = typeof row?.value === "string" ? row.value : undefined;
  } catch {
    return { kind: "absent", reason: "the database has no plan store (the 4DA app has not run on it)" };
  }
  if (raw === undefined) {
    return { kind: "absent", reason: "the 4DA app has not computed an upgrade plan yet" };
  }

  let env: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { kind: "absent", reason: "the app's plan snapshot is unreadable" };
    }
    env = parsed as Record<string, unknown>;
  } catch {
    return { kind: "absent", reason: "the app's plan snapshot is unreadable" };
  }

  const version = env.schema_version;
  if (typeof version !== "number" || !APP_PLAN_SCHEMA_VERSIONS.includes(version)) {
    return {
      kind: "absent",
      reason: `the app's plan snapshot is schema ${String(version)}, this server reads schemas ${APP_PLAN_SCHEMA_VERSIONS.join(" and ")}`,
    };
  }
  if (!Array.isArray(env.steps) || !Array.isArray(env.items)) {
    return { kind: "absent", reason: "the app's plan snapshot has no work order" };
  }
  if (typeof env.generated_at !== "string" || typeof env.expires_at !== "string") {
    return { kind: "absent", reason: "the app's plan snapshot has no freshness stamp" };
  }

  const items = new Map<string, AppPlanItem>();
  for (const item of env.items as AppPlanItem[]) {
    if (item && typeof item.id === "string") items.set(item.id, item);
  }
  const steps: AppPlanStepView[] = (env.steps as AppPlanStep[]).map((raw) => {
    const item = items.get(raw.item_id);
    // A v4 snapshot has no holds; a v5 one omits the field when nothing is blocked.
    const step: AppPlanStep = { ...raw };
    if (!Array.isArray(step.blocked_upstream) || step.blocked_upstream.length === 0) delete step.blocked_upstream;
    return { ...step, title: item?.title ?? null, urgency: item?.urgency ?? null, next_step: nextStep(step, version) };
  });

  const expires = Date.parse(env.expires_at);
  // An unparseable horizon cannot prove freshness: treat it as stale.
  const stale = Number.isNaN(expires) || now.getTime() > expires;

  return {
    kind: "plan",
    stale,
    snapshot: {
      schemaVersion: version,
      generatedAt: env.generated_at,
      expiresAt: env.expires_at,
      generatorVersion: typeof env.generator_version === "string" ? env.generator_version : null,
      sourceFreshness: typeof env.source_freshness === "string" ? env.source_freshness : null,
      multiVersionCoverage: typeof env.multi_version_coverage === "boolean" ? env.multi_version_coverage : null,
      validationDropCount: typeof env.validation_drop_count === "number" ? env.validation_drop_count : null,
      itemCount: items.size,
      steps,
    },
  };
}

/** "5.28.4 -> 6.28.1 (major)", per installed line with a target. */
function moves(step: AppPlanStep): string {
  const lines = step.lines.filter((l) => l.target);
  return lines.map((l) => `${l.installed} -> ${l.target}${l.upgrade_type ? ` (${l.upgrade_type})` : ""}`).join(", ");
}

/** "zip 8.6.0 in d:/app is held by docx-rs 0.4.22 (its newest release), which requires ^8.6.0; 9.0.5 clears it. Options: a; or b". */
export function blockedText(step: AppPlanStep, hold: AppPlanBlockedHold): string {
  const newest = hold.held_by === hold.parent && hold.held_by_newest === hold.parent_version ? " (its newest release)" : `, whose newest release ${hold.held_by_newest} still holds it`;
  const via = hold.held_by === hold.parent ? `${hold.parent} ${hold.parent_version}${newest}` : `${hold.parent} ${hold.parent_version}, through ${hold.held_by}${newest}`;
  const req = hold.requirement ? `, which requires ${step.package} ${hold.requirement}` : "";
  const options = hold.options.length > 0 ? ` Options: ${hold.options.join("; or ")}.` : "";
  return `${step.package} ${hold.installed} in ${hold.project} is held by ${via}${req}; ${hold.cleared_version} would clear it, and no published release lets it in yet.${options}`;
}

/**
 * The step in words. Schema 4's `lockfile_or_parent_update` covered every transitive step; from
 * schema 5 it means the route is undecided (or differs between copies), and the decided routes have
 * their own mechanisms. A `blocked_upstream` step names no upgrade to make: it says what holds each
 * copy and lists the options.
 */
export function nextStep(step: AppPlanStep, schema: number): string {
  const blocked = step.blocked_upstream ?? [];
  const blockedNote = blocked.length > 0 ? ` Blocked upstream: ${blocked.map((h) => blockedText(step, h)).join(" ")}` : "";
  switch (step.mechanism) {
    case "manifest_bump":
      return `Bump ${step.package} in each project's manifest: ${moves(step)}.`;
    case "lockfile_refresh":
      return `Refresh the lockfile so ${step.package} resolves to the fixed release (${moves(step)}); every parent's requirement already admits it, so no manifest changes.`;
    case "parent_update":
      return `Update the parent that pulls ${step.package} in to a release whose requirement admits the fix (${moves(step)}); see the plan item for which parent. Copies whose parents already admit it need only a lockfile refresh.`;
    case "blocked_upstream":
      return `Do not upgrade ${step.package}: no published release of what pulls it in admits the fixed version yet.${blockedNote}`;
    case "lockfile_or_parent_update":
      return schema >= 5
        ? `Transitive only, and the route is undecided or differs between copies: refresh the lockfile where the parent's requirement admits the fix, else update the parent (${moves(step)}); the plan item says which.${blockedNote}`
        : `Transitive only: refresh the lockfile, or update the parent that pulls ${step.package} in (${moves(step)}); the plan item says which.`;
    case "mixed":
      return `Bump ${step.package} in the projects that declare it, and refresh the lockfile or update the parent where it is transitive (${moves(step)}).${blockedNote}`;
    case "no_fix":
      return `No fix is published for ${step.package}: nothing to upgrade to yet.`;
    default:
      return `This server does not know the mechanism "${String(step.mechanism)}": read the plan item before acting on it.${blockedNote}`;
  }
}

const URGENCY_RISK: Record<string, number> = { critical: 3, high: 2, medium: 1, watch: 0 };
const RISK_LEVELS: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export interface AppPlanResult {
  generatedAt: string;
  expiresAt: string;
  /** True past `expiresAt`: the security data the plan read may have moved on. */
  stale: boolean;
  staleness: string | null;
  totalSteps: number;
  steps: AppPlanStepView[];
  summary: string;
  /** The project the steps were narrowed to, or null for every project in the plan. */
  projectScope: string | null;
  /** Steps of the full plan that only touch other projects (left out by projectScope). */
  otherProjectSteps?: number;
  snapshot: Omit<AppPlanSnapshot, "steps" | "generatedAt" | "expiresAt">;
  provenance: { mode: "app_plan"; note: string };
}

/**
 * The steps that touch `scope` (a project directory): each step keeps only the
 * installed lines with a site in that project, and those lines keep only
 * those sites. Null keeps everything.
 */
export function scopeAppPlanSteps(steps: AppPlanStepView[], scope: string | null): AppPlanStepView[] {
  if (!scope) return steps;
  const out: AppPlanStepView[] = [];
  for (const step of steps) {
    const lines = step.lines
      .map((line) => ({ ...line, sites: line.sites.filter((s) => isWithin(s.project, scope)) }))
      .filter((line) => line.sites.length > 0);
    if (lines.length === 0) continue;
    const holds = step.blocked_upstream?.filter((h) => isWithin(h.project, scope));
    const { blocked_upstream: _all, ...rest } = step;
    out.push(holds && holds.length > 0 ? { ...rest, lines, blocked_upstream: holds } : { ...rest, lines });
  }
  return out;
}

const APP_PROVENANCE_NOTE =
  "The 4DA desktop app's own cross-project, version-confirmed Upgrade Plan, read from its database " +
  "(the same plan the app shows and `4da plan --json` prints). Each step is keyed by the app's item id.";

/** Shape the app's plan as the tool result; `risk_threshold` / `max_recommendations` narrow it. */
export function formatAppPlan(
  read: Extract<AppPlanRead, { kind: "plan" }>,
  params: { risk_threshold?: string; max_recommendations?: number; package?: string },
  scope: string | null = null,
): AppPlanResult {
  const { snapshot, stale } = read;
  const threshold = params.risk_threshold ?? "all";
  const scoped = scopeAppPlanSteps(snapshot.steps, scope);
  let steps = scoped;
  // `package` narrows the app's plan the same way it narrows the standalone one.
  const wanted = params.package?.trim().toLowerCase();
  if (wanted) steps = steps.filter((s) => s.package.toLowerCase() === wanted);
  if (threshold !== "all" && threshold in RISK_LEVELS) {
    steps = steps.filter((s) => (URGENCY_RISK[s.urgency ?? ""] ?? 1) >= RISK_LEVELS[threshold]);
  }
  // The same default as the standalone plan (20). All 53 steps of a real plan
  // came to ~11k tokens, past the size Claude Code warns about (2026-10-03).
  const selected = steps.slice(0, params.max_recommendations ?? 20);

  const count = (m: AppPlanStep["mechanism"]) => selected.filter((s) => s.mechanism === m).length;
  const majors = selected.filter((s) => s.lines.some((l) => l.upgrade_type === "major")).length;
  const parts = [
    `${selected.length} step${selected.length !== 1 ? "s" : ""} from the 4DA app's plan (generated ${snapshot.generatedAt})${scope ? ` for ${scope}` : " across every project it tracks"}`,
  ];
  const otherProjectSteps = snapshot.steps.length - scoped.length;
  if (count("manifest_bump") > 0) parts.push(`${count("manifest_bump")} manifest bump(s)`);
  if (count("lockfile_refresh") > 0) parts.push(`${count("lockfile_refresh")} lockfile refresh(es) (transitive, no manifest change)`);
  if (count("parent_update") > 0) parts.push(`${count("parent_update")} parent update(s) (transitive)`);
  if (count("lockfile_or_parent_update") > 0) {
    parts.push(
      snapshot.schemaVersion >= 5
        ? `${count("lockfile_or_parent_update")} transitive with the route undecided or mixed (lockfile refresh or parent update)`
        : `${count("lockfile_or_parent_update")} lockfile or parent update(s) (transitive only)`,
    );
  }
  if (count("blocked_upstream") > 0) {
    parts.push(`${count("blocked_upstream")} blocked upstream (no published release admits the fix yet: nothing to upgrade, options listed per step)`);
  }
  if (count("mixed") > 0) parts.push(`${count("mixed")} mixed (direct in some projects, transitive in others)`);
  if (count("no_fix") > 0) parts.push(`${count("no_fix")} with no fix published`);
  if (majors > 0) parts.push(`${majors} cross a major version`);
  if (selected.length < scoped.length) {
    parts.push(`${scoped.length} in ${scope ? "the plan for this project" : "the full plan"} (raise max_recommendations for the rest)`);
  }
  if (scope && otherProjectSteps > 0) {
    parts.push(`${otherProjectSteps} step${otherProjectSteps !== 1 ? "s" : ""} only touch other projects (project_path "*" lists every project)`);
  }
  const staleness = stale
    ? `STALE: past its freshness horizon (${snapshot.expiresAt}). The advisories or installs may have changed since; open the 4DA app to recompute.`
    : null;
  if (staleness) parts.push(staleness);

  return {
    generatedAt: snapshot.generatedAt,
    expiresAt: snapshot.expiresAt,
    stale,
    staleness,
    totalSteps: scoped.length,
    steps: selected,
    summary: parts.join(". ") + ".",
    projectScope: scope,
    ...(scope ? { otherProjectSteps } : {}),
    snapshot: {
      schemaVersion: snapshot.schemaVersion,
      generatorVersion: snapshot.generatorVersion,
      sourceFreshness: snapshot.sourceFreshness,
      multiVersionCoverage: snapshot.multiVersionCoverage,
      validationDropCount: snapshot.validationDropCount,
      itemCount: snapshot.itemCount,
    },
    provenance: { mode: "app_plan", note: APP_PROVENANCE_NOTE },
  };
}
