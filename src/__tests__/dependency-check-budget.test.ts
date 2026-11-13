// SPDX-License-Identifier: Apache-2.0
/**
 * A dependency_check that runs out of the call's time budget answers every item that finished,
 * with its real verdict, and marks only the unfinished ones unknown (`not_checked: "time_budget"`).
 * The first 25-item call from a folder with a real project came back all NOT CHECKED: one batch
 * pipeline, so the slowest item held every other one past the budget (black-box re-run of 96c16d2,
 * 2026-11-13). An agent retries all 25 blindly, or gives up.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { runWithCallBudget } from "../call-budget.js";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-14T00:00:00Z");
const NAMES = Array.from({ length: 25 }, (_, i) => `fixture-budget-pkg-${String(i).padStart(2, "0")}`);
const HANGING = new Set([NAMES[3], NAMES[11], NAMES[20]]);

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const packument = (name: string) => ({
  name,
  "dist-tags": { latest: "1.0.0" },
  time: { created: "2020-01-01T00:00:00Z", "1.0.0": "2020-01-01T00:00:00Z" },
  versions: { "1.0.0": { name, version: "1.0.0", dependencies: {}, dist: { tarball: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz` } } },
});

let priorOffline: string | undefined;
let priorBudget: string | undefined;
let querybatches = 0;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  priorBudget = process.env.FOURDA_CALL_BUDGET_MS;
  delete process.env.FOURDA_OFFLINE;
  process.env.FOURDA_CALL_BUDGET_MS = "4000";
  querybatches = 0;
  vi.stubGlobal("fetch", (input: string | URL, init?: RequestInit) => {
    const u = new URL(String(input));
    if (u.hostname === "registry.npmjs.org") {
      const name = decodeURIComponent(u.pathname.slice(1)).split("/")[0];
      // Three registries never answer (a stalled connection): their items cannot finish.
      if (HANGING.has(name)) return new Promise<Response>(() => undefined);
      return Promise.resolve(NAMES.includes(name) ? json(packument(name)) : json({ error: "Not found" }, 404));
    }
    if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
      querybatches++;
      const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
      return Promise.resolve(json({ results: queries.map(() => ({ vulns: [] })) }));
    }
    if (u.hostname === "api.osv.dev") return Promise.resolve(json({ vulns: [] }));
    return Promise.resolve(json({}));
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  if (priorBudget === undefined) delete process.env.FOURDA_CALL_BUDGET_MS;
  else process.env.FOURDA_CALL_BUDGET_MS = priorBudget;
});

describe("a call that runs out of budget keeps what finished", () => {
  it("3 of 25 items hang: 22 real verdicts and 3 unknown (time_budget), inside the budget", async () => {
    const live = new LiveIntelligence(new Database(":memory:"));
    const started = Date.now();
    const out = await runWithCallBudget(started, () =>
      executeDependencyCheck(noDb, { items: NAMES.map((name) => ({ ecosystem: "npm", package: name, to: "1.0.0" })) }, live, { now: NOW }),
    );
    const ms = Date.now() - started;
    expect(ms).toBeLessThan(4000);
    expect(out.results.map((r) => r.package)).toEqual(NAMES);
    const timedOut = out.results.filter((r) => r.not_checked === "time_budget");
    expect(timedOut.map((r) => r.package).sort()).toEqual([...HANGING].sort());
    for (const r of timedOut) {
      expect(r.verdict).toBe("unknown");
      expect(r.reason).toMatch(/^NOT CHECKED \(time budget\): .* Call dependency_check again for this item\. This is not a clean result\./);
    }
    const done = out.results.filter((r) => !HANGING.has(r.package));
    expect(done).toHaveLength(22);
    for (const r of done) expect(r.verdict, `${r.package}: ${r.reason}`).not.toBe("unknown");
    // The finished items' OSV.dev questions still went out together, not one request per item.
    expect(querybatches).toBeLessThanOrEqual(5);
    expect(out.summary.startsWith('NOT CHECKED: 3 of 25 items did not finish within 4 s (not_checked: "time_budget"): call dependency_check again for them')).toBe(true);
    expect(out._meta).toMatchObject({ call_budget_exceeded: true, unfinished_items: 3 });
  }, 15_000);
});
