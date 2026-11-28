// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, G-5 (app_plan_check side): the app's advisory data verified at a time in the
 * future read as 0 hours old (the age was clamped to 0), and a plan generated in the future never
 * saw a lockfile change after it. Beyond FUTURE_SKEW_MINUTES ahead of this clock, the age is a
 * problem (not_comparable), and a future generation time is a problem for one project and a stale
 * reason for every project ("*").
 */
import { describe, expect, it } from "vitest";
import type { FourDADatabase } from "../db.js";
import { FUTURE_SKEW_MINUTES } from "../db.js";
import { advisoryDataAge, checkAllProjectsPlan, checkProjectPlan, type ServerPlanFacts } from "../tools/app-plan-check.js";
import type { AppPlanSnapshot } from "../tools/app-plan.js";

const NOW = Date.UTC(2026, 10, 26, 12, 0, 0);
const HOUR = 3_600_000;
const sql = (ms: number) => new Date(ms).toISOString().slice(0, 19).replace("T", " ");
const iso = (ms: number) => new Date(ms).toISOString();

/** A database stub whose osv_sync_status holds `synced`. */
function db(synced: string[]): FourDADatabase {
  return {
    hasColumn: (table: string, column: string) => table === "osv_sync_status" && column === "last_synced_at",
    getRawDb: () => ({
      prepare: (q: string) => ({ all: () => (q.includes("osv_sync_status") ? synced.map((s) => ({ last_synced_at: s })) : []) }),
    }),
  } as unknown as FourDADatabase;
}

function snapshot(over: Partial<AppPlanSnapshot> = {}): AppPlanSnapshot {
  return {
    schemaVersion: 5,
    generatedAt: iso(NOW - HOUR),
    expiresAt: iso(NOW + 5 * HOUR),
    generatorVersion: "1.0.4",
    sourceFreshness: sql(NOW - 2 * HOUR),
    multiVersionCoverage: true,
    validationDropCount: 0,
    itemCount: 0,
    steps: [],
    ...over,
  };
}

const server: ServerPlanFacts = { rows: [], vulnerable: new Set(), complete: true, newestLockfile: null, root: "/p", excludedDirs: [] };

describe("advisory data verified in the future", () => {
  it("has no age, and says so", () => {
    const age = advisoryDataAge(db([sql(NOW + 365 * 24 * HOUR)]), null, NOW);
    expect(age.hours).toBeNull();
    expect(age.future).toBe(true);
  });

  it("within the clock skew it is still 0 hours old", () => {
    const age = advisoryDataAge(db([sql(NOW + (FUTURE_SKEW_MINUTES - 1) * 60_000)]), null, NOW);
    expect(age.hours).toBe(0);
    expect(age.future).toBeUndefined();
  });

  it("makes one project's check not_comparable, naming why", () => {
    const check = checkProjectPlan(db([sql(NOW + 30 * 24 * HOUR)]), { kind: "plan", snapshot: snapshot(), stale: false }, "/p", server, {}, NOW);
    expect(check.status).toBe("not_comparable");
    expect(check.note).toMatch(/last verified time in the future .*so its age cannot be told/);
    expect(check.advisory_data_age_hours).toBeNull();
  });

  it("a future plan source_freshness counts too", () => {
    const check = checkProjectPlan(db([sql(NOW - HOUR)]), { kind: "plan", snapshot: snapshot({ sourceFreshness: sql(NOW + 48 * HOUR) }), stale: false }, "/p", server, {}, NOW);
    expect(check.status).toBe("not_comparable");
  });

  it("makes the all-projects plan not_comparable and stale", () => {
    const { check, staleReasons } = checkAllProjectsPlan(db([sql(NOW + 30 * 24 * HOUR)]), { kind: "plan", snapshot: snapshot(), stale: false }, NOW);
    expect(check.status).toBe("not_comparable");
    expect(staleReasons.join(" ")).toMatch(/in the future/);
  });

  it("an ordinary recent sync still agrees", () => {
    const check = checkProjectPlan(db([sql(NOW - HOUR)]), { kind: "plan", snapshot: snapshot(), stale: false }, "/p", server, {}, NOW);
    expect(check.status).toBe("agrees");
    expect(check.advisory_data_age_hours).toBe(2);
  });
});

describe("a plan generated in the future", () => {
  it("is not compared for one project", () => {
    const check = checkProjectPlan(db([sql(NOW - HOUR)]), { kind: "plan", snapshot: snapshot({ generatedAt: iso(NOW + 365 * 24 * HOUR) }), stale: false }, "/p", server, {}, NOW);
    expect(check.status).toBe("not_comparable");
    expect(check.note).toMatch(/the plan's generated time is in the future/);
  });

  it("is stale for every project", () => {
    const { check, staleReasons } = checkAllProjectsPlan(db([sql(NOW - HOUR)]), { kind: "plan", snapshot: snapshot({ generatedAt: iso(NOW + 365 * 24 * HOUR) }), stale: false }, NOW);
    expect(staleReasons.join(" ")).toMatch(/the plan's generated time is in the future/);
    expect(check.status).toBe("unverified");
  });

  it("a minute ahead (clock skew) is not", () => {
    const check = checkProjectPlan(db([sql(NOW - HOUR)]), { kind: "plan", snapshot: snapshot({ generatedAt: iso(NOW + 60_000) }), stale: false }, "/p", server, {}, NOW);
    expect(check.status).toBe("agrees");
  });
});
