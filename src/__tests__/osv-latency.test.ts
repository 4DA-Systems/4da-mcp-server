// SPDX-License-Identifier: Apache-2.0
/**
 * vulnerability_scan latency (2026-10-10 corpus: median ~30 s, superset 115 s,
 * where osv-scanner took ~12 s). Advisory details were fetched in rounds of 8,
 * each round waiting for its slowest request, and the startup warm-up scan ran
 * beside the first tool call's scan with neither able to reuse the other's
 * requests.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { OsvScanner } from "../live/osv-scanner.js";
import { RateLimiter } from "../live/rate-limiter.js";
import type { ResolvedDependency } from "../live/types.js";

const dep = (name: string): ResolvedDependency => ({
  name, version: "1.0.0", ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [],
});

/** OSV stub: every dependency has its own advisory; detail requests take `delayMs` and are counted. */
function stubOsv(opts: { delayMs?: number; failFirst?: Set<string> } = {}) {
  const stats = { batch: 0, detail: new Map<string, number>(), inFlight: 0, maxInFlight: 0 };
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      stats.batch++;
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      return new Response(JSON.stringify({ results: queries.map((q) => ({ vulns: [{ id: `GHSA-${q.package.name}` }] })) }), { status: 200 });
    }
    const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
    stats.detail.set(id, (stats.detail.get(id) ?? 0) + 1);
    stats.inFlight++;
    stats.maxInFlight = Math.max(stats.maxInFlight, stats.inFlight);
    await new Promise((resolve) => setTimeout(resolve, opts.delayMs ?? 5));
    stats.inFlight--;
    if (opts.failFirst?.has(id)) {
      opts.failFirst.delete(id);
      return new Response("slow down", { status: 429 });
    }
    return new Response(JSON.stringify({ id, summary: `advisory ${id}`, database_specific: { severity: "HIGH" } }), { status: 200 });
  });
  return stats;
}

const scanner = () => new OsvScanner(new LiveCache(new Database(":memory:")), new RateLimiter({ osv: { maxPerMinute: 10 } }));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OSV advisory hydration", () => {
  it("keeps up to 24 detail requests in flight instead of rounds of 8", async () => {
    const stats = stubOsv({ delayMs: 20 });
    const deps = Array.from({ length: 60 }, (_, i) => dep(`pkg-${i}`));
    const result = await scanner().scan(deps, "/proj");
    expect(result.vulnerabilities).toHaveLength(60);
    expect(result.vulnerabilities.every((v) => v.severity === "high")).toBe(true);
    expect(stats.maxInFlight).toBeGreaterThan(8);
    expect(stats.maxInFlight).toBeLessThanOrEqual(24);
  });

  it("two scans at once fetch each advisory once (the warm-up and the first tool call)", async () => {
    const stats = stubOsv({ delayMs: 30 });
    const deps = Array.from({ length: 20 }, (_, i) => dep(`pkg-${i}`));
    // Separate scanners and caches, as a project_path scan beside the startup scan.
    const [a, b] = await Promise.all([scanner().scan(deps, "/proj"), scanner().scan(deps, "/proj")]);
    expect(a.vulnerabilities).toHaveLength(20);
    expect(b.vulnerabilities).toHaveLength(20);
    expect([...stats.detail.values()].every((n) => n === 1)).toBe(true);
  });

  it("a throttled detail request is retried once, so the advisory keeps its severity and summary", async () => {
    const stats = stubOsv({ failFirst: new Set(["GHSA-pkg-0"]) });
    const result = await scanner().scan([dep("pkg-0")], "/proj");
    expect(stats.detail.get("GHSA-pkg-0")).toBe(2);
    expect(result.vulnerabilities[0]).toMatchObject({ vulnId: "GHSA-pkg-0", severity: "high", summary: "advisory GHSA-pkg-0" });
  });
});

describe("cache writes", () => {
  it("a scan writes its per-dependency and per-advisory rows in one transaction each, not one commit per row", async () => {
    stubOsv();
    const cache = new LiveCache(new Database(":memory:"));
    const single = vi.spyOn(cache, "set");
    const many = vi.spyOn(cache, "setMany");
    const deps = Array.from({ length: 50 }, (_, i) => dep(`pkg-${i}`));
    await new OsvScanner(cache, new RateLimiter({ osv: { maxPerMinute: 10 } })).scan(deps, "/proj");
    expect(single).not.toHaveBeenCalled();
    expect(many).toHaveBeenCalledTimes(2);
    // Every row is readable afterwards: a second scan is served from the cache.
    expect(cache.get(`osv:npm:pkg-7:1.0.0`)).toHaveLength(1);
    expect(cache.get(`osv:detail:GHSA-pkg-7`)).toMatchObject({ id: "GHSA-pkg-7" });
  });

  it("setMany is atomic and works without a database (in-memory cache)", () => {
    const cache = new LiveCache(new Database(":memory:"));
    cache.setMany([["a", 1], ["b", { x: 2 }]], "osv", 60);
    expect(cache.get("a")).toBe(1);
    expect(cache.get("b")).toEqual({ x: 2 });
  });
});

describe("LiveIntelligence shares a scan already running", () => {
  it("the warm-up and an identical request are one scan", async () => {
    const stats = stubOsv({ delayMs: 30 });
    const li = new LiveIntelligence(new Database(":memory:"));
    (li as unknown as { auditDeps: ResolvedDependency[] }).auditDeps = Array.from({ length: 10 }, (_, i) => dep(`pkg-${i}`));
    (li as unknown as { initialized: boolean }).initialized = true;
    li.startVulnerabilityWarmup("/proj");
    const result = await li.scanVulnerabilities("/proj");
    expect(result.vulnerabilities).toHaveLength(10);
    expect(stats.batch).toBe(1);
    expect([...stats.detail.values()].every((n) => n === 1)).toBe(true);
    // A forced refresh never reuses a running scan.
    await li.scanVulnerabilities("/proj", { forceRefresh: true });
    expect(stats.batch).toBe(2);
  });
});
