// SPDX-License-Identifier: Apache-2.0
/**
 * An OSV answer that is old, half-read or cut short is never the whole answer
 * (audit 2026-11-11, T7 and the querybatch paging gap).
 *
 * - The stored project scan never aged. The server lives as long as the IDE,
 *   so `what_should_i_know`, `upgrade_planner` and `dependency_health` could
 *   answer from a scan taken days earlier.
 * - A failed advisory-detail fetch left a stub (severity `unknown`, no fix
 *   version) that was cached for an hour: a critical read "unknown, no fix
 *   version published", and `severity_filter: "high"` dropped it.
 * - `next_page_token` from querybatch was ignored: a dependency with more
 *   advisories than one page holds was recorded with the first page only.
 *
 * Each test here fails on 6.2.7 and on main before this change.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence, MAX_STORED_SCAN_AGE_MS } from "../live/index.js";
import { OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import { vulnerabilityCoverage } from "../live/scan-coverage.js";
import type { ResolvedDependency, VulnerabilityScanResult } from "../live/types.js";
import { conciseScanResult } from "../tools/vulnerability-scan-concise.js";
import { formatScanResult } from "../tools/vulnerability-scan-format.js";

const dep = (name: string, version = "1.0.0", extra: Partial<ResolvedDependency> = {}): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: ["/proj"], ...extra,
});

function scannerWith(limits = DEFAULT_RATE_LIMITS, tokenWaitMs?: number): OsvScanner {
  const cache = new LiveCache(new Database(":memory:"));
  const limiter = new RateLimiter(limits);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter, tokenWaitMs));
}

const ctx = { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// A failed detail fetch: marked NOT CHECKED, never cached
// ---------------------------------------------------------------------------

describe("an advisory whose record could not be fetched", () => {
  /** querybatch: `critical-pkg` has GHSA-crit; details answer only while `detailsUp` is true. */
  function stubOsv(state: { detailsUp: boolean; detailRequests: number; batches: number }) {
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        state.batches++;
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
        return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === "critical-pkg" ? { vulns: [{ id: "GHSA-crit-0000-0001" }] } : {})) }), { status: 200 });
      }
      if (url.includes("/v1/vulns/")) {
        state.detailRequests++;
        if (!state.detailsUp) return new Response("unavailable", { status: 503 });
        const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
        return new Response(
          JSON.stringify({
            id,
            summary: "Remote code execution in critical-pkg",
            database_specific: { severity: "CRITICAL" },
            affected: [{ package: { name: "critical-pkg", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.1" }] }] }],
          }),
          { status: 200 },
        );
      }
      throw new TypeError(`fetch failed (${url})`);
    });
  }

  it("is marked NOT CHECKED, kept by severity_filter, never worded as 'no fix', and not cached", async () => {
    const state = { detailsUp: false, detailRequests: 0, batches: 0 };
    stubOsv(state);
    const scanner = scannerWith();
    const deps = [dep("critical-pkg"), dep("clean-pkg")];

    const first = await scanner.scan(deps, "/proj");
    expect(first.vulnerabilities).toHaveLength(1);
    expect(first.vulnerabilities[0]).toMatchObject({ vulnId: "GHSA-crit-0000-0001", detailUnavailable: true, severity: "unknown", fixedVersion: null });
    expect(first.vulnerabilities[0].summary).toMatch(/advisory details NOT CHECKED/);
    expect(first.detailsUnchecked).toEqual(["GHSA-crit-0000-0001"]);

    // Every consumer of the scan sees an incomplete answer, with the reason first.
    const coverage = vulnerabilityCoverage(first, { enabled: true });
    expect(coverage).toMatchObject({ complete: false, details_unchecked: 1, unchecked_dependencies: 0 });
    expect(coverage!.note).toMatch(/^NOT CHECKED \(advisory details\): OSV\.dev matched 1 advisory \(GHSA-crit-0000-0001\) but did not return its record, so its severity and fix version are unknown: unknown is not low/);

    // severity_filter "high" cannot drop a row whose grade nobody read.
    const detailed = formatScanResult(first, "high", ctx);
    expect(detailed.summary).toMatch(/^NOT CHECKED \(advisory details\)/);
    expect(detailed.total_vulnerable_packages).toBeNull();
    expect(detailed.vulnerabilities).toHaveLength(1);
    expect(detailed.vulnerabilities[0]).toMatchObject({ package: "critical-pkg", severity: "unknown", fixed_version: null, details: "NOT CHECKED" });
    expect(detailed.coverage).toMatchObject({ complete: false, details_unchecked: 1 });
    // A null fix is not "no fix published".
    expect(detailed.recommendations).toHaveLength(1);
    expect(detailed.recommendations[0]).toMatch(/details were NOT CHECKED \(OSV\.dev did not return the record\): severity and fix version are unknown, not absent/);
    expect(JSON.stringify(detailed.recommendations)).not.toMatch(/no fix version published/);

    const concise = conciseScanResult(detailed);
    expect(concise.vulnerable_packages[0]).toMatchObject({ package: "critical-pkg", details_not_checked: 1, fixed_version: null });
    expect(concise.vulnerable_packages[0]).not.toHaveProperty("unfixed_advisories");
    expect(concise.coverage).toMatchObject({ complete: false, details_unchecked: 1 });

    // OSV recovers. The stub was not cached: the same scanner asks again and reads the real record.
    state.detailsUp = true;
    const batchesBefore = state.batches;
    const second = await scanner.scan(deps, "/proj");
    expect(state.batches).toBe(batchesBefore + 1);
    expect(second.vulnerabilities[0]).toMatchObject({ vulnId: "GHSA-crit-0000-0001", severity: "critical", fixedVersion: "1.0.1" });
    expect(second.vulnerabilities[0].detailUnavailable).toBeUndefined();
    expect(second.detailsUnchecked).toBeUndefined();
    expect(vulnerabilityCoverage(second, { enabled: true })).toBeNull();

    // The dependency with no advisory was answered in full the first time, and that answer was cached.
    const third = await scanner.scan(deps, "/proj");
    expect(third.cached).toBe(true);
    expect(state.batches).toBe(batchesBefore + 1);
  });

  it("an id a record that WAS read names as its alias is the same advisory, not an unread one", async () => {
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
        return new Response(JSON.stringify({ results: queries.map(() => ({ vulns: [{ id: "GHSA-read-0000-0001" }, { id: "PYSEC-2026-1" }] })) }), { status: 200 });
      }
      if (url.endsWith("/v1/vulns/GHSA-read-0000-0001")) {
        return new Response(JSON.stringify({ id: "GHSA-read-0000-0001", aliases: ["PYSEC-2026-1"], summary: "x", database_specific: { severity: "HIGH" } }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    });
    const result = await scannerWith().scan([dep("pkg")], "/proj");
    expect(result.vulnerabilities.map((v) => v.vulnId)).toEqual(["GHSA-read-0000-0001"]);
    expect(result.detailsUnchecked).toBeUndefined();
  });

  it("read and unread advisories on one package: the advice names the fix it knows and says what it was not checked against", () => {
    const base = {
      package: "pkg", currentVersion: "1.0.0", ecosystem: "npm" as const, isDev: false, isDirect: true, devScopeKnown: true, aliases: [], cvssScore: null,
      published: "", references: [], target: null, platformActive: true, sourceDirs: ["/proj"], maintenance: false,
    };
    const scan: VulnerabilityScanResult = {
      scannedAt: new Date().toISOString(), projectPath: "/proj", ecosystemsScanned: ["npm"], totalScanned: 1, totalVulnerable: 1, platformInactiveVulnerable: 0,
      bySeverity: { critical: 0, high: 0, medium: 1, low: 0, unknown: 1 }, cleanCount: 0, scanDurationMs: 1, cached: false, offline: false,
      detailsUnchecked: ["GHSA-unread-0000-0001"],
      vulnerabilities: [
        { ...base, vulnId: "GHSA-read-0000-0002", severity: "medium", summary: "read", fixedVersion: "1.0.1" },
        { ...base, vulnId: "GHSA-unread-0000-0001", severity: "unknown", summary: "GHSA-unread-0000-0001: advisory details NOT CHECKED", fixedVersion: null, detailUnavailable: true },
      ],
    };
    const detailed = formatScanResult(scan, "high", ctx);
    // The medium row is filtered out by "high"; the unread one is not.
    expect(detailed.vulnerabilities.map((v) => v.vuln_id)).toEqual(["GHSA-unread-0000-0001"]);
    const all = formatScanResult(scan, undefined, ctx);
    expect(all.recommendations[0]).toMatch(/^Upgrade pkg 1\.0\.0 .*1 more advisory \(GHSA-unread-0000-0001\) matched, details NOT CHECKED .*the target was not checked against it$/);
    const row = conciseScanResult(all).vulnerable_packages[0];
    expect(row).toMatchObject({ advisories: 2, details_not_checked: 1, fixed_version: "1.0.1" });
    expect(row).not.toHaveProperty("unfixed_advisories");
  });
});

// ---------------------------------------------------------------------------
// querybatch paging
// ---------------------------------------------------------------------------

describe("querybatch next_page_token", () => {
  type Query = { package: { name: string }; version?: string; page_token?: string };
  const detail = (url: string) => {
    const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
    return new Response(JSON.stringify({ id, summary: id, database_specific: { severity: "HIGH" } }), { status: 200 });
  };

  it("every page of a long answer is read", async () => {
    const bodies: Query[][] = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (!url.endsWith("/v1/querybatch")) return detail(url);
      const { queries } = JSON.parse(String(init?.body)) as { queries: Query[] };
      bodies.push(queries);
      return new Response(
        JSON.stringify({
          results: queries.map((q) => {
            if (q.package.name !== "many") return {};
            if (!q.page_token) return { vulns: [{ id: "GHSA-page-0001" }], next_page_token: "t2" };
            if (q.page_token === "t2") return { vulns: [{ id: "GHSA-page-0002" }], next_page_token: "t3" };
            return { vulns: [{ id: "GHSA-page-0003" }] };
          }),
        }),
        { status: 200 },
      );
    });
    const result = await scannerWith().scan([dep("clean"), dep("many", "2.0.0")], "/proj");
    expect(result.vulnerabilities.map((v) => v.vulnId).sort()).toEqual(["GHSA-page-0001", "GHSA-page-0002", "GHSA-page-0003"]);
    expect(result.offline).toBe(false);
    expect(result.cleanCount).toBe(1);
    // Only the query whose answer was cut short is asked again, with its token and the same package and version.
    expect(bodies).toHaveLength(3);
    expect(bodies[1]).toEqual([{ package: { name: "many", ecosystem: "npm" }, version: "2.0.0", page_token: "t2" }]);
    expect(bodies[2]).toEqual([{ package: { name: "many", ecosystem: "npm" }, version: "2.0.0", page_token: "t3" }]);
  });

  it("a later page that cannot be had leaves that dependency unanswered: a first page alone is not the answer", async () => {
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (!url.endsWith("/v1/querybatch")) return detail(url);
      const { queries } = JSON.parse(String(init?.body)) as { queries: Query[] };
      if (queries.some((q) => q.page_token)) return new Response("unavailable", { status: 503 });
      return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === "many" ? { vulns: [{ id: "GHSA-page-0001" }], next_page_token: "t2" } : {})) }), { status: 200 });
    });
    const result = await scannerWith().scan([dep("clean"), dep("many", "2.0.1")], "/proj");
    expect(result.offline).toBe(true);
    expect(result.unchecked).toBe(1);
    expect(result.uncheckedReason).toMatch(/HTTP 503 while reading page 2 of the answer/);
    // The dependency answered in full is still clean; the other is neither clean nor listed with half its advisories.
    expect(result.cleanCount).toBe(1);
    expect(result.vulnerabilities).toEqual([]);
    expect(vulnerabilityCoverage(result, { enabled: true })?.note).toMatch(/^NOT CHECKED: .*1 of 2 dependencies have no vulnerability answer/);
  });

  it("a token that never ends is not followed forever", async () => {
    let requests = 0;
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (!url.endsWith("/v1/querybatch")) return detail(url);
      requests++;
      const { queries } = JSON.parse(String(init?.body)) as { queries: Query[] };
      return new Response(JSON.stringify({ results: queries.map(() => ({ vulns: [{ id: `GHSA-loop-${requests}` }], next_page_token: "again" })) }), { status: 200 });
    });
    const result = await scannerWith({ osv: { maxPerMinute: 1000 } }).scan([dep("looping", "3.0.0")], "/proj");
    expect(requests).toBe(20);
    expect(result.unchecked).toBe(1);
    expect(result.uncheckedReason).toMatch(/ran past 20 pages/);
  });

  it("a page token that is not a string is a malformed answer, not an empty one", async () => {
    vi.stubGlobal("fetch", async (input: string | URL) => {
      const url = String(input);
      if (!url.endsWith("/v1/querybatch")) return detail(url);
      return new Response(JSON.stringify({ results: [{ vulns: [], next_page_token: 7 }] }), { status: 200 });
    });
    const result = await scannerWith().scan([dep("odd", "4.0.0")], "/proj");
    expect(result.unchecked).toBe(1);
    expect(result.uncheckedReason).toMatch(/malformed result/);
  });
});

// ---------------------------------------------------------------------------
// The stored scan ages
// ---------------------------------------------------------------------------

describe("the stored project scan has a maximum age", () => {
  const stored = dep("jsonwebtoken", "9.3.1", { ecosystem: "crates.io" });

  function scanResult(overrides: Partial<VulnerabilityScanResult> = {}): VulnerabilityScanResult {
    return {
      scannedAt: new Date().toISOString(), projectPath: "d:/proj", ecosystemsScanned: ["crates.io"], totalScanned: 1, totalVulnerable: 0,
      platformInactiveVulnerable: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities: [], cleanCount: 1,
      scanDurationMs: 1, cached: false, offline: false, unchecked: 0, uncheckedReason: null, staleAnswers: 0, ...overrides,
    };
  }

  function intel(scanImpl: () => Promise<VulnerabilityScanResult>): LiveIntelligence {
    const prior = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    const li = new LiveIntelligence(new Database(":memory:"));
    if (prior !== undefined) process.env.FOURDA_OFFLINE = prior;
    const priv = li as unknown as { auditDeps: ResolvedDependency[]; osvScanner: { scan: () => Promise<VulnerabilityScanResult> } };
    priv.auditDeps = [stored];
    priv.osvScanner = { scan: scanImpl };
    return li;
  }

  it("is about one hour", () => {
    expect(MAX_STORED_SCAN_AGE_MS).toBe(60 * 60 * 1000);
  });

  it("a scan is reused inside the hour and taken again after it", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-11T08:00:00Z"));
    let scans = 0;
    const li = intel(async () => {
      scans++;
      return scanResult();
    });

    const first = await li.ensureVulnerabilities("d:/proj", 2000);
    expect(scans).toBe(1);
    expect(first?.scannedAt).toBe("2026-11-11T08:00:00.000Z");

    vi.setSystemTime(new Date("2026-11-11T08:59:00Z"));
    expect(await li.ensureVulnerabilities("d:/proj", 2000)).toBe(first);
    expect(li.getVulnerabilities()).toBe(first);
    expect(scans).toBe(1);

    // Friday, same server process, no lockfile changed: the Monday scan is not today's answer.
    vi.setSystemTime(new Date("2026-11-11T09:00:01Z"));
    expect(li.getVulnerabilities()).toBeNull();
    const again = await li.ensureVulnerabilities("d:/proj", 2000);
    expect(scans).toBe(2);
    expect(again).not.toBe(first);
    expect(again?.scannedAt).toBe("2026-11-11T09:00:01.000Z");
    expect(li.getVulnerabilities()).toBe(again);
  });

  it("when the rescan gets no answer, the expired scan is not handed out in its place", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-11T08:00:00Z"));
    let osvUp = true;
    const li = intel(async () => (osvUp ? scanResult() : scanResult({ offline: true, unchecked: 1, uncheckedReason: "OSV.dev unreachable (fetch failed)", cleanCount: 0 })));
    expect(await li.ensureVulnerabilities("d:/proj", 2000)).not.toBeNull();

    vi.setSystemTime(new Date("2026-11-11T11:00:00Z"));
    osvUp = false;
    expect(await li.ensureVulnerabilities("d:/proj", 2000)).toBeNull();
    // What dependency_health and upgrade_planner fall back to (`?? getVulnerabilities()`): nothing, so they say NOT CHECKED.
    expect(li.getVulnerabilities()?.offline ?? true).toBe(true);
    expect(li.getVulnerabilities()?.scannedAt).not.toBe("2026-11-11T08:00:00.000Z");
  });

  it("a wider-scope request after the hour is a new scan too", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-11T08:00:00Z"));
    let scans = 0;
    const li = intel(async () => {
      scans++;
      return scanResult();
    });
    await li.ensureVulnerabilities("d:/proj", 2000, { includeDev: true });
    expect(scans).toBe(1);
    await li.ensureVulnerabilities("d:/proj", 2000, { includeDev: true });
    expect(scans).toBe(1);
    vi.setSystemTime(new Date("2026-11-11T10:00:00Z"));
    await li.ensureVulnerabilities("d:/proj", 2000, { includeDev: true });
    expect(scans).toBe(2);
  });
});
