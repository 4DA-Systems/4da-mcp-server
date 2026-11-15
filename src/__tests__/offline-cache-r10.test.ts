// SPDX-License-Identifier: Apache-2.0
/**
 * Offline scans answer from the cache (pre-publish round 10, W5). With FOURDA_OFFLINE every scan
 * said NOT CHECKED even when OSV.dev's answers were cached. Now a cached answer is used with its
 * age, a dependency without one stays NOT CHECKED, nothing is fetched, and an empty cache is never
 * clean.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import { vulnerabilityCoverage } from "../live/scan-coverage.js";
import type { ResolvedDependency, VulnerabilityEntry } from "../live/types.js";

const dep = (name: string, version = "1.0.0"): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [],
});

const advisory = (pkg: string, version: string): VulnerabilityEntry =>
  ({ package: pkg, currentVersion: version, ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: false, vulnId: "GHSA-test-0001", aliases: [], summary: "test", severity: "high", fixedVersion: "2.0.0", platformActive: true, references: [] }) as unknown as VulnerabilityEntry;

function seed(db: Database.Database, key: string, data: unknown, fetched: string, expires: string, source = "osv"): void {
  db.prepare(`INSERT OR REPLACE INTO live_cache (cache_key, data, source, fetched_at, expires_at) VALUES (?, ?, ?, datetime('now', ?), datetime('now', ?))`).run(key, JSON.stringify(data), source, fetched, expires);
}

function noFetch() {
  const calls: string[] = [];
  vi.stubGlobal("fetch", async (input: string | URL) => {
    calls.push(String(input));
    throw new TypeError("fetch failed");
  });
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("OsvScanner cacheOnly (offline)", () => {
  it("answers from fresh and expired cached answers with their age; a dependency without one stays NOT CHECKED; nothing is fetched", async () => {
    const calls = noFetch();
    const db = new Database(":memory:");
    const cache = new LiveCache(db);
    seed(db, "osv:v9:npm:lodash:4.17.20", [advisory("lodash", "4.17.20")], "-10 minutes", "+50 minutes");
    seed(db, "osv:v9:npm:ms:2.1.3", [], "-3 hours", "-2 hours");
    const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
    const result = await new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter)).scan(
      [dep("lodash", "4.17.20"), dep("ms", "2.1.3"), dep("left-pad", "1.3.0")],
      "/proj",
      { cacheOnly: true },
    );
    expect(calls).toEqual([]);
    expect(result.cacheOnly).toBe(true);
    expect(result.staleAnswers).toBe(2);
    expect(result.staleExpired).toBe(1);
    expect(result.unchecked).toBe(1);
    expect(result.offline).toBe(true);
    expect(result.uncheckedDependencies).toEqual(["npm\0left-pad\x001.3.0"]);
    expect(result.vulnerabilities.map((v) => v.vulnId)).toEqual(["GHSA-test-0001"]);
    const coverage = vulnerabilityCoverage(result, { enabled: false })!;
    expect(coverage.note).toMatch(/^NOT CHECKED: live lookups are disabled \(FOURDA_OFFLINE=true\) — 1 of 3 dependencies/);
    expect(coverage.note).toMatch(/2 dependencies were answered only from the local cache, not asked now \(the oldest checked \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC, \d+ (min|h) ago\)/);
    expect(coverage.note).toMatch(/not a current all-clear\. 1 of them is past the 1 h cache life/);
  });

  it("every dependency cached: STALE with the age, never a current all-clear", async () => {
    noFetch();
    const db = new Database(":memory:");
    const cache = new LiveCache(db);
    seed(db, "osv:v9:npm:ms:2.1.3", [], "-5 minutes", "+55 minutes");
    const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
    const result = await new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter)).scan([dep("ms", "2.1.3")], "/proj", { cacheOnly: true });
    expect(result.unchecked).toBe(0);
    expect(result.staleAnswers).toBe(1);
    expect(vulnerabilityCoverage(result, { enabled: false })).toMatchObject({ complete: false, stale_dependencies: 1, unchecked_dependencies: 0 });
    expect(vulnerabilityCoverage(result, { enabled: false })!.note).toMatch(/^STALE: live lookups are disabled/);
  });

  it("an empty cache offline is NOT CHECKED for every dependency, never clean", async () => {
    const calls = noFetch();
    const cache = new LiveCache(new Database(":memory:"));
    const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
    const result = await new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter)).scan([dep("a"), dep("b")], "/proj", { cacheOnly: true });
    expect(calls).toEqual([]);
    expect(result.unchecked).toBe(2);
    expect(result.cleanCount).toBe(0);
    expect(result.offline).toBe(true);
    expect(result.uncheckedReason).toMatch(/FOURDA_OFFLINE/);
  });
});

describe("LiveIntelligence with FOURDA_OFFLINE", () => {
  it("queryAdvisories reads the cache, sends nothing, and leaves uncached releases unchecked", async () => {
    vi.stubEnv("FOURDA_OFFLINE", "1");
    const calls = noFetch();
    const db = new Database(":memory:");
    const li = new LiveIntelligence(db);
    expect(li.isEnabled()).toBe(false);
    expect(li.answersFromCache()).toBe(true);
    seed(db, "osv:v9:npm:lodash:4.17.20", [advisory("lodash", "4.17.20")], "-10 minutes", "+50 minutes");
    const result = await li.queryAdvisories([dep("lodash", "4.17.20"), dep("left-pad", "1.3.0")]);
    expect(calls).toEqual([]);
    expect(result.cacheOnly).toBe(true);
    expect(result.vulnerabilities.map((v) => v.package)).toEqual(["lodash"]);
    expect(result.unchecked).toBe(1);
  });
});

describe("LiveCache purge keeps recent OSV answers as stale stand-ins", () => {
  it("an expired OSV row within 7 days survives a restart; an older one and expired non-OSV rows do not", () => {
    const db = new Database(":memory:");
    new LiveCache(db);
    seed(db, "osv:v9:npm:recent:1.0.0", [], "-3 hours", "-2 hours");
    seed(db, "osv:v9:npm:old:1.0.0", [], "-9 days", "-8 days");
    seed(db, "npm:registry:x", {}, "-3 hours", "-2 hours", "npm");
    new LiveCache(db); // a new process: the purge runs at construction
    const keys = (db.prepare("SELECT cache_key FROM live_cache ORDER BY cache_key").all() as Array<{ cache_key: string }>).map((r) => r.cache_key);
    expect(keys).toEqual(["osv:v9:npm:recent:1.0.0"]);
  });
});
