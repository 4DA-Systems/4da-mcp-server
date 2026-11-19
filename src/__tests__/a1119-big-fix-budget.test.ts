// SPDX-License-Identifier: Apache-2.0
/**
 * The upgrade-target checks of a scan stay inside the call's budget. Their confirmation and
 * held-dependency steps each had a 3 s floor that ignored the call's budget, so a scan whose
 * advisory read ended late spent past it and the whole answer was replaced by the dispatcher's
 * "did not finish" (seen at 12 s and 20 s budgets on a 2,084-dependency tree, 2026-11-19). The
 * floors now give way to the budget; what is cut short is reported as not confirmed.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { FixPathSources, verifyFixTargets, type FixTargetResult } from "../live/fix-paths.js";
import { RateLimiter, DEFAULT_RATE_LIMITS } from "../live/rate-limiter.js";
import { raceCallBudget, runWithCallBudget, withinCallBudget } from "../call-budget.js";

const record = {
  id: "GHSA-p6mc-m468-83gw",
  summary: "lodash advisory",
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
};

let priorBudget: string | undefined;

beforeEach(() => {
  priorBudget = process.env.FOURDA_CALL_BUDGET_MS;
  vi.stubGlobal("fetch", async (input: string | URL) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/query")) return json({ vulns: [record] });
    if (url.startsWith("https://registry.npmjs.org/lodash")) return json({ name: "lodash", "dist-tags": { latest: "4.17.21" }, versions: { "4.17.15": {}, "4.17.21": {} } });
    return json({}, 404);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorBudget === undefined) delete process.env.FOURDA_CALL_BUDGET_MS;
  else process.env.FOURDA_CALL_BUDGET_MS = priorBudget;
});

describe("verifyFixTargets inside a call", () => {
  it("answers before the call's budget ends even when the confirming query never answers", async () => {
    process.env.FOURDA_CALL_BUDGET_MS = "3000";
    const sources = new FixPathSources(new LiveCache(new Database(":memory:")), new RateLimiter(DEFAULT_RATE_LIMITS));
    const items = [{ key: "npm|lodash|4.17.15", ecosystem: "npm" as const, name: "lodash", fixes: ["4.17.21"], installed: "4.17.15", ids: ["GHSA-p6mc-m468-83gw"] }];
    type Outcome = { late: boolean; targets: Map<string, FixTargetResult> | null };
    const outcome = await runWithCallBudget(Date.now(), () =>
      raceCallBudget<Outcome>(
        verifyFixTargets(sources, items, withinCallBudget(5_000, 500), undefined, { heldQuery: () => new Promise(() => undefined) }).then((targets) => ({ late: false, targets })),
        () => ({ late: true, targets: null }),
      ),
    );
    expect(outcome.late).toBe(false);
    // Worked out from the advisory list, and said not to be confirmed: the query never answered.
    const target = outcome.targets?.get("npm|lodash|4.17.15");
    expect(target?.target).toBe("4.17.21");
    expect(target?.unconfirmed).toBeTruthy();
  });
});
