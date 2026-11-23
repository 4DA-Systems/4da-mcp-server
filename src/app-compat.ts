// SPDX-License-Identifier: Apache-2.0
/**
 * Which versions of the 4DA desktop app this server reads, and what it says when the app whose
 * database is attached is outside them.
 *
 * The app and this server are released independently, so a user can pair any app with any server.
 * The bounds below are the app releases this server is tested against: every app release adds its
 * schema file to `contract/released/` and moves these bounds in the same change
 * (contract/README.md), and `a1123-appmode-released-schemas.test.ts` runs every tool against each
 * released schema. Outside the bounds the app-backed answers carry `_meta.app_compatibility`,
 * which says in plain words which side to update; an answer that cannot be served because the
 * app's tables are not the ones this server reads is an error that carries the same note
 * (appCompatibilityError), never the bare SQLite text.
 *
 * The app records its schema version in `schema_version` (one row per applied version; the
 * highest is current) and its plan format as `schema_version` inside the `upgrade_plan_snapshot`
 * envelope in `kv_store`.
 */

import type { FourDADatabase } from "./db.js";
import type { SqliteDatabase } from "./sqlite-driver.js";

/** The oldest app release this server supports: 4DA v1.0.3 (2026-10-05), schema 124, plan format 4. */
export const OLDEST_SUPPORTED_APP = { release: "4DA v1.0.3", schema: 124, planFormat: 4 } as const;
/** The newest app this server was tested with: the app's main branch at 2026-11-22 (unreleased), schema 131, plan format 5. */
export const NEWEST_TESTED_APP = { release: "4DA main of 2026-11-22 (unreleased)", schema: 131, planFormat: 5 } as const;

/** Plan formats (the snapshot envelope's `schema_version`) this server reads. */
export const SUPPORTED_PLAN_FORMATS: readonly number[] = Array.from(
  { length: NEWEST_TESTED_APP.planFormat - OLDEST_SUPPORTED_APP.planFormat + 1 },
  (_, i) => OLDEST_SUPPORTED_APP.planFormat + i,
);

export type AppCompatibilityStatus = "supported" | "app_older_than_supported" | "app_newer_than_tested";

export interface AppCompatibility {
  status: AppCompatibilityStatus;
  /** The attached app's schema version, or null when its database records none this server can read. */
  app_schema: number | null;
  /** The format of the app's stored upgrade plan, or null when it stored none. */
  app_plan_format: number | null;
  supported: {
    app_schema: { min: number; max: number };
    plan_format: { min: number; max: number };
    oldest_release: string;
    newest_tested: string;
  };
  note: string;
}

const SUPPORTED: AppCompatibility["supported"] = {
  app_schema: { min: OLDEST_SUPPORTED_APP.schema, max: NEWEST_TESTED_APP.schema },
  plan_format: { min: OLDEST_SUPPORTED_APP.planFormat, max: NEWEST_TESTED_APP.planFormat },
  oldest_release: `${OLDEST_SUPPORTED_APP.release} (schema ${OLDEST_SUPPORTED_APP.schema}, plan format ${OLDEST_SUPPORTED_APP.planFormat})`,
  newest_tested: `${NEWEST_TESTED_APP.release} (schema ${NEWEST_TESTED_APP.schema}, plan format ${NEWEST_TESTED_APP.planFormat})`,
};

/** The app's schema version: the highest row of `schema_version`, or null when there is none to read. */
export function readAppSchemaVersion(raw: SqliteDatabase): number | null {
  try {
    const row = raw.prepare("SELECT MAX(version) AS version FROM schema_version").get() as { version?: unknown } | undefined;
    return typeof row?.version === "number" && Number.isFinite(row.version) ? row.version : null;
  } catch {
    return null;
  }
}

/** The format of the app's stored plan (its envelope's `schema_version`), or null when none is stored or it is unreadable. */
export function readAppPlanFormat(raw: SqliteDatabase): number | null {
  try {
    const row = raw.prepare("SELECT value FROM kv_store WHERE key = ?").get("upgrade_plan_snapshot") as { value?: unknown } | undefined;
    if (typeof row?.value !== "string") return null;
    const parsed = JSON.parse(row.value) as { schema_version?: unknown };
    return typeof parsed?.schema_version === "number" ? parsed.schema_version : null;
  } catch {
    return null;
  }
}

/** Where an app with this schema and plan format stands against the supported range, with the note to show. */
export function classifyAppCompatibility(appSchema: number | null, planFormat: number | null): AppCompatibility {
  const base = { app_schema: appSchema, app_plan_format: planFormat, supported: SUPPORTED };
  const range = `schema ${SUPPORTED.app_schema.min} to ${SUPPORTED.app_schema.max}, plan format ${SUPPORTED.plan_format.min} to ${SUPPORTED.plan_format.max}: ${SUPPORTED.oldest_release} through ${SUPPORTED.newest_tested}`;
  const newer = (appSchema !== null && appSchema > SUPPORTED.app_schema.max) || (planFormat !== null && planFormat > SUPPORTED.plan_format.max);
  const older = appSchema === null || appSchema < SUPPORTED.app_schema.min || (planFormat !== null && planFormat < SUPPORTED.plan_format.min);
  const what = [appSchema === null ? "records no schema version this server can read" : `is schema ${appSchema}`, ...(planFormat !== null ? [`its stored plan is format ${planFormat}`] : [])].join(", and ");
  if (newer) {
    return {
      status: "app_newer_than_tested",
      ...base,
      note: `The 4DA app's database ${what}, newer than this server was tested with (${range}). Update @4da/mcp-server to a release that supports it; until then, answers that read the app's data may be incomplete or wrong.`,
    };
  }
  if (older) {
    return {
      status: "app_older_than_supported",
      ...base,
      note: `The 4DA app's database ${what}, older than this server supports (${range}). Update the 4DA app (https://github.com/4DA-Systems/4DA/releases/latest); until then, answers that read the app's data may be incomplete or wrong.`,
    };
  }
  return { status: "supported", ...base, note: `The 4DA app's database ${what}, within what this server supports (${range}).` };
}

/** How long one classification of an attached database is reused (the app can migrate while the server runs). */
const RECHECK_MS = 60_000;
const memo = new WeakMap<FourDADatabase, { at: number; value: AppCompatibility }>();

/** The attached app's compatibility, or null for a standalone database (no app attached). */
export function appCompatibilityFor(db: FourDADatabase | null | undefined, now: number = Date.now()): AppCompatibility | null {
  if (!db || db.isStandalone) return null;
  const hit = memo.get(db);
  if (hit && now - hit.at < RECHECK_MS) return hit.value;
  const raw = db.getRawDb();
  const value = classifyAppCompatibility(readAppSchemaVersion(raw), readAppPlanFormat(raw));
  memo.set(db, { at: now, value });
  return value;
}

/** Tools whose answers read or write the app's database (the app-backed tools, get_context, the planner's plan check, memory and decisions). */
export const APP_COMPATIBILITY_TOOLS: ReadonlySet<string> = new Set([
  "get_context",
  "get_relevant_content",
  "get_actionable_signals",
  "knowledge_gaps",
  "developer_dna",
  "record_feedback",
  "what_should_i_know",
  "upgrade_planner",
  "decision_memory",
  "check_decision_alignment",
  "agent_memory",
]);

/** What an attached app outside the supported range is said as, in `_meta.app_compatibility`. */
function compatibilityMeta(compat: AppCompatibility) {
  return { status: compat.status, app_schema: compat.app_schema, app_plan_format: compat.app_plan_format, supported: compat.supported, note: compat.note };
}

/** A SQLite error that says the database's tables are not the ones a query reads. */
const SCHEMA_MISMATCH = /\bno such (?:table|column)\b|\bhas no column named\b/i;

/**
 * The error answer for a tool that read an attached app outside the supported range and failed
 * because the app's tables are not the ones this server reads (a table or column it lacks): the
 * failure, with `_meta.app_compatibility` and its note saying which side to update. Null when no
 * app is attached, the app is supported, the tool does not read the app's data, or the error is of
 * another kind (that one is answered as it is).
 */
export function appCompatibilityError(name: string, db: FourDADatabase | null, error: unknown): { error: string; _meta: { app_compatibility: ReturnType<typeof compatibilityMeta> } } | null {
  if (!APP_COMPATIBILITY_TOOLS.has(name)) return null;
  const message = error instanceof Error ? error.message : String(error);
  if (!SCHEMA_MISMATCH.test(message)) return null;
  let compat: AppCompatibility | null;
  try {
    compat = appCompatibilityFor(db);
  } catch {
    return null;
  }
  if (!compat || compat.status === "supported") return null;
  return {
    error: `${name} could not read the 4DA app's database (${message.slice(0, 200)}): ${compat.note}`,
    _meta: { app_compatibility: compatibilityMeta(compat) },
  };
}

/**
 * `payload` with `_meta.app_compatibility` when the attached app is outside the supported range and
 * `name` reads or writes its database; otherwise `payload` unchanged. Never throws: a failed read
 * leaves the answer as it was.
 */
export function withAppCompatibility(name: string, db: FourDADatabase | null, payload: unknown): unknown {
  if (!APP_COMPATIBILITY_TOOLS.has(name)) return payload;
  let compat: AppCompatibility | null;
  try {
    compat = appCompatibilityFor(db);
  } catch {
    return payload;
  }
  if (!compat || compat.status === "supported") return payload;
  const app_compatibility = compatibilityMeta(compat);
  if (Array.isArray(payload)) return { item_count: payload.length, items: payload, _meta: { app_compatibility } };
  if (payload && typeof payload === "object") {
    const p = payload as Record<string, unknown>;
    const meta = p._meta && typeof p._meta === "object" && !Array.isArray(p._meta) ? (p._meta as Record<string, unknown>) : {};
    return { ...p, _meta: { ...meta, app_compatibility } };
  }
  return { result: payload, _meta: { app_compatibility } };
}
