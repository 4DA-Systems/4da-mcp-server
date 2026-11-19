// SPDX-License-Identifier: Apache-2.0
/**
 * Two fail-closed rules of dependency_check's verdict, held by tests of their own:
 *
 * - `unknown` outranks `wait`. With OSV.dev unreachable and the release inside the release-age
 *   hold, the answer is `unknown` (the advisories were not checked), never `wait`, which reads as
 *   "apply it in three days".
 * - An expired cached batch answer is never a current one. With the batch query failing, only an
 *   expired cached answer to stand in for it and an empty advisory list, no release is named safe.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck, runDependencyCheck } from "../tools/dependency-check.js";
import { decide, type Signal } from "../tools/dependency-check-signals.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, npmDoc, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-19T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

const sig = (id: Signal["id"], effect: Signal["effect"], evidence: string): Signal => ({ id, value: null, evidence, effect });

describe("unknown outranks wait", () => {
  it("decide: an unchecked source and a young release read unknown, and the reason carries what was not checked", () => {
    const decided = decide([
      sig("advisories", "unknown", "OSV.dev could not be reached: lookup failed or was rate limited"),
      sig("release_age", "wait", "2.0.0 was published 1 day ago; releases younger than 3 days are held."),
      sig("yanked_or_deprecated", "proceed", "2.0.0 is neither yanked nor deprecated."),
    ]);
    expect(decided.verdict).toBe("unknown");
    expect(decided.reason).toContain("OSV.dev could not be reached");
    // Without the unchecked source the same release is a plain wait.
    expect(decide([sig("advisories", "proceed", "No known vulnerability affects 2.0.0."), sig("release_age", "wait", "young")]).verdict).toBe("wait");
  });

  it("OSV.dev unreachable and the release one day old: unknown, not wait (npm and PyPI)", async () => {
    net.npm["young-lib"] = npmDoc("young-lib", { "1.0.0": { at: daysAgo(400) }, "2.0.0": { at: daysAgo(1) } });
    net.pypi["young-py"] = { releases: { "1.0.0": [{ upload_time_iso_8601: daysAgo(400) }], "2.0.0": [{ upload_time_iso_8601: daysAgo(1) }] }, requires: { "2.0.0": [] } };
    net.down = ["api.osv.dev"];
    const out = await executeDependencyCheck(
      noDb,
      { items: [{ ecosystem: "npm", package: "young-lib", to: "2.0.0" }, { ecosystem: "PyPI", package: "young-py", to: "2.0.0" }] },
      new LiveIntelligence(new Database(":memory:")),
      { now: NOW },
    );
    for (const r of out.results) {
      expect(r.signals.find((s) => s.id === "release_age")!.effect, r.package).toBe("wait");
      expect(r.signals.find((s) => s.id === "advisories")!.effect, r.package).toBe("unknown");
      expect(r.verdict, r.package).toBe("unknown");
      expect(r.reason, r.package).toContain("OSV.dev could not be reached");
    }
  });
});

describe("an expired cached batch answer is never treated as a fresh one", () => {
  it("batch query failing, expired cache entries, empty advisory list: no safe version is named", async () => {
    net.npm["stale-lib"] = npmDoc("stale-lib", { "4.0.0": { at: daysAgo(900) }, "4.1.0": { at: daysAgo(600) }, "4.2.0": { at: daysAgo(300) } });
    const db = new Database(":memory:");
    const items = [{ ecosystem: "npm", package: "stale-lib", to: "4.x" }];

    // A healthy run first: it names the safe releases, and its batch answers are cached.
    const healthy = await executeDependencyCheck(noDb, { items }, new LiveIntelligence(db), { now: NOW });
    expect(healthy.results[0]).toMatchObject({ verdict: "proceed", to: "4.2.0" });
    expect(healthy.results[0].range_check).toMatchObject({ smallest_safe_in_range: "4.0.0", newest_safe_in_range: "4.2.0" });

    // An hour and more later: every cached batch answer is past its life, and OSV.dev's batch query fails.
    const expired = db.prepare("UPDATE live_cache SET fetched_at = datetime('now', '-3 hours'), expires_at = datetime('now', '-2 hours') WHERE cache_key LIKE 'osv:%'").run();
    expect(expired.changes).toBeGreaterThanOrEqual(2);
    net.batchStatus = 400;

    const live = new LiveIntelligence(db);
    // The premise: the scanner answers from the expired entries alone, and says so.
    const scan = await live.queryAdvisories(
      ["4.0.0", "4.2.0"].map((version) => ({ name: "stale-lib", version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [] })),
    );
    expect(scan).toMatchObject({ offline: false, staleAnswers: 2 });

    const detailed = await executeDependencyCheck(noDb, { items }, live, { now: NOW });
    const r = detailed.results[0];
    expect(r.verdict).toBe("unknown");
    expect(r.range_check).toBeUndefined();
    expect(r.reason).toMatch(/NOT CHECKED: OSV\.dev's batch query gave no current answer \(only an expired cached answer/);
    expect(r.reason).toMatch(/no release of stale-lib is named safe/);
    expect(r.reason).not.toMatch(/Safe in 4\.x|smallest 4\.0\.0/);

    const concise = (await runDependencyCheck(noDb, { items }, live)) as { results: Array<Record<string, unknown>> };
    expect(concise.results[0].verdict).toBe("unknown");
    expect(concise.results[0]).not.toHaveProperty("safe");
  });
});
