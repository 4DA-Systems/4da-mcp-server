// SPDX-License-Identifier: Apache-2.0
/**
 * A constraint's smallest safe release is the smallest one that is safe, not the smallest of the
 * candidates a call happened to judge. `chrono ^0.4.19` from 0.4.19 named 0.4.38: the ten smallest
 * releases above 0.4.19 require an affected `time ^0.1.43`, the eight newest were judged clean, and
 * 0.4.30 to 0.4.37 (clean) were never judged, while the same server answered `=0.4.30` proceed.
 * Releases below the named pick that were not judged are now judged before it is named.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { advisory, emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-23T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

type Dep = Record<string, unknown>;
const dep = (name: string, req: string): Dep => ({ name, req, features: [], optional: false, default_features: true, target: null, kind: "normal" });
const line = (name: string, vers: string, deps: Dep[]) => ({ name, vers, deps, cksum: "0", features: {}, yanked: false });
function crate(name: string, versions: Array<[string, Dep[]]>) {
  return {
    versions: versions.map(([num], i) => ({ num, created_at: daysAgo(900 - i * 30) })).reverse(),
    sparse: versions.map(([v, deps]) => line(name, v, deps)),
  };
}

const CHRONO = Array.from({ length: 27 }, (_, i) => `0.4.${19 + i}`); // 0.4.19 .. 0.4.45
const usesTime = (v: string) => Number(v.split(".")[2]) < 30;

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  net.crates.chrono = crate("chrono", CHRONO.map((v) => [v, [...(usesTime(v) ? [dep("time", "^0.1.43")] : []), dep("num-traits", "^0.2")]]));
  net.crates.time = crate("time", [["0.1.43", []], ["0.1.44", []], ["0.1.45", []]]);
  net.crates["num-traits"] = crate("num-traits", [["0.2.19", []]]);
  net.osv = [advisory("RUSTSEC-2020-0071", "crates.io", "time", "0.2.23", { severity: "MODERATE" })];
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

const check = (items: unknown[]) => executeDependencyCheck(noDb, { items }, new LiveIntelligence(new Database(":memory:")), { now: NOW });

describe("a constraint's smallest safe release", () => {
  it("chrono ^0.4.19 from 0.4.19: 0.4.30, the first release clear of the affected time, not the first one judged", async () => {
    const r = (await check([{ ecosystem: "crates.io", package: "chrono", from: "0.4.19", to: "^0.4.19" }])).results[0];
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "0.4.30", smallest_safe_upgrade: "0.4.30", newest_safe_in_range: "0.4.45" });
    expect(r.range_check!.held_not_checked ?? 0).toBe(0);
    // safe_versions lists the newest safe releases; none of them requires the affected time.
    expect(r.range_check!.safe_versions!.length).toBeGreaterThan(0);
    expect(r.range_check!.safe_versions!.filter(usesTime)).toEqual([]);
    // The release it names answers the same on its own.
    const exact = (await check([{ ecosystem: "crates.io", package: "chrono", from: "0.4.19", to: "=0.4.30" }])).results[0];
    expect(exact.verdict).toBe("proceed");
  });

  it("without `from`: the range's smallest safe release is judged too", async () => {
    const r = (await check([{ ecosystem: "crates.io", package: "chrono", to: "^0.4.19" }])).results[0];
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "0.4.30", newest_safe_in_range: "0.4.45" });
  });
});
