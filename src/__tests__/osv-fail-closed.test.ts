// SPDX-License-Identifier: Apache-2.0
/**
 * A scan OSV.dev could not answer is never a clean result (audit A1/B-1/B-2,
 * 2026-10-12).
 *
 * 6.2.4 reserved one rate-limit token per 1,000-dependency batch up front
 * (10 a minute) and threw when any was missing, and any OSV outage, 503 or
 * timeout threw the same way. The scan then came back `offline: true` with
 * totals from cache only: D:\4DA\src-tauri (10,568 dependencies) on an empty
 * cache reported `total_vulnerable_packages: 0`, dependency_health scored it
 * 75/100 and upgrade_planner said `vulnerabilityDataAvailable: true`.
 *
 * These tests block or break OSV.dev every way the audit did and assert that
 * no tool can return a clean-looking answer.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import type { ResolvedDependency } from "../live/types.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import type { FourDADatabase } from "../db.js";

const dep = (name: string, version = "1.0.0"): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [],
});

type FetchMode = "throw" | "503" | "timeout" | "answer";

/** OSV stub: querybatch answers per `mode(batchIndex)`; details answer a HIGH advisory. */
function stubOsv(mode: (batch: number) => FetchMode, advisoryFor: (name: string) => string | null = () => null) {
  const stats = { batches: 0 };
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const m = mode(stats.batches++);
      if (m === "throw") throw new TypeError("fetch failed");
      if (m === "503") return new Response("unavailable", { status: 503 });
      if (m === "timeout") throw Object.assign(new Error("This operation was aborted"), { name: "AbortError" });
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      return new Response(
        JSON.stringify({ results: queries.map((q) => { const id = advisoryFor(q.package.name); return id ? { vulns: [{ id }] } : {}; }) }),
        { status: 200 },
      );
    }
    if (url.includes("osv.dev")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
      return new Response(JSON.stringify({ id, summary: `advisory ${id}`, database_specific: { severity: "HIGH" } }), { status: 200 });
    }
    throw new TypeError(`fetch failed (${url})`);
  });
  return stats;
}

function scannerWith(limits = DEFAULT_RATE_LIMITS, tokenWaitMs?: number): OsvScanner {
  const cache = new LiveCache(new Database(":memory:"));
  const limiter = new RateLimiter(limits);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter, tokenWaitMs));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OSV scanner: no answer is never an empty answer", () => {
  it.each([
    ["fetch throws (OSV unreachable)", "throw" as const, /OSV\.dev unreachable/],
    ["HTTP 503", "503" as const, /HTTP 503/],
    ["timeout", "timeout" as const, /did not answer within/],
  ])("%s: every dependency is unchecked, none clean", async (_label, mode, reason) => {
    stubOsv(() => mode);
    const deps = [dep("lodash", "4.17.15"), dep("minimist", "1.2.0")];
    const result = await scannerWith().scan(deps, "/proj");
    expect(result.offline).toBe(true);
    expect(result.unchecked).toBe(2);
    expect(result.cleanCount).toBe(0);
    expect(result.uncheckedReason).toMatch(reason);
    expect(result.vulnerabilities).toEqual([]);
  });

  it("a tree past 10,000 dependencies is answered in full (6.2.4 threw past 10 batches)", async () => {
    const stats = stubOsv(() => "answer", (name) => (name === "pkg-10567" ? "GHSA-last" : null));
    const deps = Array.from({ length: 10_568 }, (_, i) => dep(`pkg-${i}`));
    const result = await scannerWith().scan(deps, "/proj");
    expect(stats.batches).toBe(11);
    expect(result.offline).toBe(false);
    expect(result.unchecked).toBe(0);
    expect(result.vulnerabilities.map((v) => v.vulnId)).toEqual(["GHSA-last"]);
    expect(result.cleanCount).toBe(10_567);
  });

  it("past the query budget, batches wait for tokens; what never gets one is unchecked, not clean", async () => {
    stubOsv(() => "answer");
    const deps = Array.from({ length: 2_500 }, (_, i) => dep(`pkg-${i}`));
    // One token a minute and a 50 ms wait: the first batch goes, the other two cannot.
    const result = await scannerWith({ ...DEFAULT_RATE_LIMITS, osv: { maxPerMinute: 1 } }, 50).scan(deps, "/proj");
    expect(result.unchecked).toBe(1_500);
    expect(result.cleanCount).toBe(1_000);
    expect(result.uncheckedReason).toMatch(/query budget/);
  });

  it("a batch that fails is retried once; a second failure leaves only its dependencies unchecked", async () => {
    // Batch 0 answers; batch 1 fails twice; later ones are not sent after the outage.
    const stats = stubOsv((n) => (n === 0 ? "answer" : "503"));
    const deps = Array.from({ length: 1_200 }, (_, i) => dep(`pkg-${i}`));
    const result = await scannerWith().scan(deps, "/proj");
    expect(stats.batches).toBe(3);
    expect(result.unchecked).toBe(200);
    expect(result.cleanCount).toBe(1_000);
  });

  it("an expired cached answer stands in for a failed query, and is counted as stale, not unchecked", async () => {
    const db = new Database(":memory:");
    const cache = new LiveCache(db);
    const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
    // An answer from two hours ago, past its 1 h life.
    db.prepare(
      "INSERT INTO live_cache (cache_key, data, source, fetched_at, expires_at) VALUES (?, '[]', 'osv', datetime('now', '-2 hours'), datetime('now', '-1 hours'))",
    ).run("osv:npm:lodash:4.17.15");
    stubOsv(() => "throw");
    const result = await new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter)).scan([dep("lodash", "4.17.15"), dep("minimist", "1.2.0")], "/proj");
    expect(result.staleAnswers).toBe(1);
    expect(result.unchecked).toBe(1);
  });
});

describe("RateLimiter.acquire", () => {
  it("waits for a token instead of refusing, within the deadline", async () => {
    const limiter = new RateLimiter({ osv: { maxPerMinute: 600 } }); // one per 100 ms
    for (let i = 0; i < 600; i++) limiter.consume("osv");
    const started = Date.now();
    expect(await limiter.acquire("osv", Date.now() + 1_000)).toBe(true);
    expect(Date.now() - started).toBeGreaterThanOrEqual(50);
  });

  it("refuses when no token can arrive by the deadline", async () => {
    const limiter = new RateLimiter({ osv: { maxPerMinute: 1 } });
    limiter.consume("osv");
    expect(await limiter.acquire("osv", Date.now() + 20)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The tools: a blocked OSV.dev must read as NOT CHECKED everywhere.
// ---------------------------------------------------------------------------

describe("tools over a blocked OSV.dev", () => {
  let dir: string;
  let priorOffline: string | undefined;
  const noDb = null as unknown as FourDADatabase;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-failclosed-"));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", dependencies: { lodash: "4.17.15", minimist: "1.2.0" } }));
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: "x",
        lockfileVersion: 3,
        packages: {
          "": { name: "x", version: "1.0.0", dependencies: { lodash: "4.17.15", minimist: "1.2.0" } },
          "node_modules/lodash": { version: "4.17.15" },
          "node_modules/minimist": { version: "1.2.0" },
        },
      }),
    );
  });

  afterEach(() => {
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function intel(): LiveIntelligence {
    const li = new LiveIntelligence(new Database(":memory:"));
    li.initFromDependencyGroups([{ dir, language: "javascript", deps: ["lodash", "minimist"], devDeps: [] }]);
    li.fetchRegistryHealth = async () => [];
    return li;
  }

  /** Every way a clean-looking answer could be spelled. */
  function assertNotClean(text: string) {
    expect(text).not.toMatch(/"total_vulnerable_packages":0/);
    expect(text).not.toMatch(/"vulnerableCount":0/);
    expect(text).not.toMatch(/all healthy/);
    expect(text).not.toMatch(/"vulnerabilityDataAvailable":true/);
  }

  it.each(["throw", "503", "timeout"] as const)("vulnerability_scan (OSV %s): NOT CHECKED first, totals null", async (mode) => {
    stubOsv(() => mode);
    const result = (await executeVulnerabilityScan(null, { project_path: dir }, intel())) as Record<string, unknown>;
    expect(Object.keys(result)[0]).toBe("summary");
    expect(String(result.summary)).toMatch(/^NOT CHECKED: .* 2 of 2 dependencies have no vulnerability answer/);
    expect(result.total_vulnerable_packages).toBeNull();
    expect(result.by_severity).toBeNull();
    expect((result.coverage as { unchecked_dependencies: number }).unchecked_dependencies).toBe(2);
    assertNotClean(JSON.stringify(result));

    const detailed = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, intel())) as Record<string, unknown>;
    expect(detailed.total_vulnerable_packages).toBeNull();
    expect(detailed.clean_dependencies).toBeNull();
    assertNotClean(JSON.stringify(detailed));
  });

  it("dependency_health: no score and no vulnerable count from missing data", async () => {
    stubOsv(() => "throw");
    const result = await executeDependencyHealth(noDb, {}, intel());
    expect(result.summary).toMatch(/^NOT CHECKED: /);
    expect(result.healthScore).toBeNull();
    expect(result.vulnerableCount).toBeNull();
    expect(result.vulnerabilityCoverage?.unchecked_dependencies).toBe(2);
    assertNotClean(JSON.stringify(result));
  });

  it("upgrade_planner: never claims vulnerability data it does not have", async () => {
    stubOsv(() => "503");
    const result = (await executeUpgradePlanner(noDb, {}, intel())) as unknown as Record<string, unknown>;
    expect(result.vulnerabilityDataAvailable).toBe(false);
    expect(String(result.summary)).toMatch(/^NOT CHECKED: /);
    expect((result.vulnerabilityCoverage as { unchecked_dependencies: number }).unchecked_dependencies).toBe(2);
    assertNotClean(JSON.stringify(result));
  });

  it("with OSV answering, the same project is complete and carries no NOT CHECKED", async () => {
    stubOsv(() => "answer", (name) => (name === "lodash" ? "GHSA-p6mc-m468-83gw" : null));
    const result = (await executeVulnerabilityScan(null, { project_path: dir }, intel())) as Record<string, unknown>;
    expect(result.summary).toBeUndefined();
    expect(result.total_vulnerable_packages).toBe(1);
    expect(result.coverage).toBeUndefined();
  });
});
