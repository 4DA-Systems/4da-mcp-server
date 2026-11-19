// SPDX-License-Identifier: Apache-2.0
/**
 * Reading advisory records is bounded per scan: at most MAX_DETAIL_FETCHES records are asked for,
 * none after the time a scan has for them, and a dependency whose answer names more advisories
 * than any release has is not read at all. What was not read is NOT CHECKED, never clean, and a
 * later scan reads on from the cache. An answer naming very many ids used to start one request
 * per id (22,973 in 30 s, still running after the answer was returned).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { MAX_ADVISORIES_PER_DEPENDENCY, MAX_DETAIL_FETCHES, OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import { vulnerabilityCoverage } from "../live/scan-coverage.js";
import { conciseScanResult } from "../tools/vulnerability-scan-concise.js";
import { formatScanResult } from "../tools/vulnerability-scan-format.js";
import type { ResolvedDependency } from "../live/types.js";

const dep = (name: string, version = "1.0.0"): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [],
});

const id = (n: number) => `GHSA-${String(n).padStart(4, "0")}-aaaa-bbbb`;

/** OSV stub: `idsFor(name)` are a dependency's advisory ids; every record asked for is counted and answered HIGH. */
function stubOsv(idsFor: (name: string) => string[]) {
  const stats = { records: 0 };
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      return new Response(JSON.stringify({ results: queries.map((q) => ({ vulns: idsFor(q.package.name).map((v) => ({ id: v })) })) }), { status: 200 });
    }
    if (url.includes("/v1/vulns/")) {
      stats.records++;
      const asked = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
      return new Response(JSON.stringify({ id: asked, summary: `advisory ${asked}`, database_specific: { severity: "HIGH" } }), { status: 200 });
    }
    // The per-dependency second route is not what this test is about: it has no answer.
    return new Response("{}", { status: 503 });
  });
  return stats;
}

function scannerWith(limits?: { maxDetailFetches?: number; detailWindowMs?: number }): OsvScanner {
  const cache = new LiveCache(new Database(":memory:"));
  const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter, undefined, limits), { aliasBudgetMs: 50 });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("advisory records read per scan are bounded", () => {
  // Three dependencies, 1,500 advisories each, all distinct: 4,500 records to read.
  const PER_DEP = 1_500;
  const idsFor = (name: string) => {
    const base = Number(name.split("-")[1]) * PER_DEP;
    return Array.from({ length: PER_DEP }, (_, i) => id(base + i));
  };
  const deps = [dep("pkg-0"), dep("pkg-1"), dep("pkg-2")];

  it("asks for at most MAX_DETAIL_FETCHES records, and the rest are NOT CHECKED, not clean", async () => {
    const stats = stubOsv(idsFor);
    const result = await scannerWith().scan(deps, "/proj");
    expect(MAX_DETAIL_FETCHES).toBe(2_000);
    expect(stats.records).toBe(MAX_DETAIL_FETCHES);
    // Nothing more goes out once the scan has answered.
    await new Promise((resolve) => setImmediate(resolve));
    expect(stats.records).toBe(MAX_DETAIL_FETCHES);

    expect(result.detailsUnchecked).toHaveLength(3 * PER_DEP - MAX_DETAIL_FETCHES);
    expect(result.detailsUncheckedReason).toMatch(/at most 2,000 advisory records/);
    expect(result.cleanCount).toBe(0);
    expect(result.vulnerabilities).toHaveLength(3 * PER_DEP);
    const unread = result.vulnerabilities.filter((v) => v.detailUnavailable);
    expect(unread).toHaveLength(3 * PER_DEP - MAX_DETAIL_FETCHES);
    expect(unread.every((v) => v.severity === "unknown" && /NOT CHECKED/.test(v.summary))).toBe(true);

    const coverage = vulnerabilityCoverage(result, { enabled: true });
    expect(coverage?.complete).toBe(false);
    expect(coverage?.note).toMatch(/^NOT CHECKED \(advisory details\)/);
    expect(coverage?.note).toMatch(/2,500 advisories/);
    expect(coverage?.note).toMatch(/at most 2,000 advisory records/);
    expect(coverage?.note).toMatch(/Call again/);
  });

  it("the next scans read on from where the cache ends, until every record is read", async () => {
    const stats = stubOsv(idsFor);
    const s = scannerWith();
    expect((await s.scan(deps, "/proj")).detailsUnchecked).toHaveLength(2_500);
    const second = await s.scan(deps, "/proj");
    expect(stats.records).toBe(4_000);
    expect(second.detailsUnchecked).toHaveLength(500);
    const third = await s.scan(deps, "/proj");
    expect(stats.records).toBe(4_500);
    expect(third.detailsUnchecked).toBeUndefined();
    expect(third.detailsUncheckedReason).toBeUndefined();
    expect(third.vulnerabilities.every((v) => v.severity === "high" && !v.detailUnavailable)).toBe(true);
    expect(vulnerabilityCoverage(third, { enabled: true })).toBeNull();
  });

  it("no record is asked for once the time a scan has for them is over", async () => {
    const stats = stubOsv(() => [id(1), id(2), id(3)]);
    const result = await scannerWith({ detailWindowMs: 0 }).scan([dep("pkg-0")], "/proj");
    expect(stats.records).toBe(0);
    expect(result.detailsUnchecked).toEqual([id(1), id(2), id(3)]);
    expect(result.detailsUncheckedReason).toMatch(/stopped/);
    expect(result.cleanCount).toBe(0);
  });

  it("a small limit is honoured the same way (the limit is what bounds the requests)", async () => {
    const stats = stubOsv(() => Array.from({ length: 10 }, (_, i) => id(i)));
    const result = await scannerWith({ maxDetailFetches: 4 }).scan([dep("pkg-0")], "/proj");
    expect(stats.records).toBe(4);
    expect(result.detailsUnchecked).toHaveLength(6);
  });

  it("the tool answer leads with NOT CHECKED and words the unread rows as not asked for, not as OSV.dev's failure", async () => {
    stubOsv(() => Array.from({ length: 10 }, (_, i) => id(i)));
    const result = await scannerWith({ maxDetailFetches: 4 }).scan([dep("pkg-0")], "/proj");
    const full = formatScanResult(result, undefined, { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true });
    expect(full.summary).toMatch(/^NOT CHECKED \(advisory details\): OSV\.dev matched 6 advisories .*not asked for in this call \(a scan asks for at most 4 advisory records/);
    expect(full.total_vulnerable_packages).toBeNull();
    expect(full.clean_dependencies).toBeNull();
    const unread = full.vulnerabilities.filter((v) => "details" in v);
    expect(unread).toHaveLength(6);
    expect(unread.every((v) => /was not asked for in this call/.test(String((v as { details_note?: string }).details_note)))).toBe(true);
    // An unread row is never filtered out as "below" a severity.
    expect(formatScanResult(result, "critical", { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true }).vulnerabilities).toHaveLength(6);
    const concise = conciseScanResult(full);
    expect(concise.summary).toMatch(/^NOT CHECKED/);
    expect(concise.vulnerable_packages[0]).toMatchObject({ package: "pkg-0", details_not_checked: 6 });
  });
});

describe("an answer naming more advisories for one release than any release has", () => {
  it("leaves that dependency unchecked: no record is fetched for it and it is not clean", async () => {
    const flood = Array.from({ length: MAX_ADVISORIES_PER_DEPENDENCY + 1 }, (_, i) => id(i));
    const stats = stubOsv((name) => (name === "flooded" ? flood : name === "real" ? [id(900_001)] : []));
    const result = await scannerWith().scan([dep("flooded"), dep("real"), dep("clean")], "/proj");
    expect(stats.records).toBe(1);
    expect(result.unchecked).toBe(1);
    expect(result.uncheckedDependencies).toEqual(["npm\0flooded\u00001.0.0"]);
    expect(result.uncheckedReason).toMatch(/more advisories for one release/);
    expect(result.vulnerabilities.map((v) => v.package)).toEqual(["real"]);
    expect(result.cleanCount).toBe(1);
    expect(result.offline).toBe(true);
  });

  it("a release with as many advisories as the limit allows is read as usual", async () => {
    const many = Array.from({ length: 300 }, (_, i) => id(i));
    stubOsv((name) => (name === "busy" ? many : []));
    const result = await scannerWith().scan([dep("busy")], "/proj");
    expect(result.unchecked).toBe(0);
    expect(result.vulnerabilities).toHaveLength(300);
    expect(result.detailsUnchecked).toBeUndefined();
  });
});
