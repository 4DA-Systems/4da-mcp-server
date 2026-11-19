// SPDX-License-Identifier: Apache-2.0
/**
 * A scan inside a tool call answers by the call's deadline with what it has read. The advisory
 * records it ran out of time for are NOT CHECKED in that answer, are read on after it by the
 * background queue, and the next call is answered from the cache, complete. It used to answer
 * NOT CHECKED for every dependency when the records took longer than the call had (a cold scan of a
 * 2,084-dependency tree, 2026-11-19), and only a second call read on.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { backgroundReadsDrained, OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import { RecordQueue } from "../live/record-queue.js";
import { vulnerabilityCoverage } from "../live/scan-coverage.js";
import { formatScanResult } from "../tools/vulnerability-scan-format.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { raceCallBudget, runWithCallBudget } from "../call-budget.js";
import type { ResolvedDependency } from "../live/types.js";

const dep = (name: string, version = "1.0.0"): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [],
});
const id = (n: number) => `GHSA-${String(n).padStart(4, "0")}-aaaa-bbbb`;

/** OSV stub: every dependency `pkg-<n>` has three advisories; records are counted and graded HIGH. */
function stubOsv() {
  const stats = { batches: 0, records: 0 };
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      stats.batches++;
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      return json({
        results: queries.map((q) => {
          const n = Number(q.package.name.split("-")[1]);
          return Number.isFinite(n) ? { vulns: [id(n * 3), id(n * 3 + 1), id(n * 3 + 2)].map((v) => ({ id: v })) } : {};
        }),
      });
    }
    if (url.includes("/v1/vulns/")) {
      stats.records++;
      const asked = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
      return json({ id: asked, summary: `advisory ${asked}`, database_specific: { severity: "HIGH" } });
    }
    return json({}, 404);
  });
  return stats;
}

function scannerWith(queue: RecordQueue) {
  const cache = new LiveCache(new Database(":memory:"));
  const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter, undefined, { background: queue }), { aliasBudgetMs: 50 });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("a scan with a deadline", () => {
  it("answers by it: unread records are NOT CHECKED and handed on, and the next scan is complete from the cache", async () => {
    const stats = stubOsv();
    const stop = new AbortController();
    const queue = new RecordQueue({ signal: stop.signal });
    const scanner = scannerWith(queue);
    const deps = Array.from({ length: 10 }, (_, i) => dep(`pkg-${i}`));

    // A deadline already reached: no record request is started by the scan itself.
    const first = await scanner.scan(deps, "/proj", { deadline: Date.now() });
    expect(first.unchecked).toBe(0);
    expect(first.cleanCount).toBe(0);
    expect(first.detailsUnchecked).toHaveLength(30);
    expect(first.detailsInBackground).toBe(30);
    expect(first.vulnerabilities.every((v) => v.detailUnavailable && v.detailReadingOn && v.severity === "unknown")).toBe(true);
    const coverage = vulnerabilityCoverage(first, { enabled: true });
    expect(coverage?.complete).toBe(false);
    expect(coverage?.note).toMatch(/^NOT CHECKED \(advisory details\): OSV\.dev matched 30 advisories/);
    expect(coverage?.note).toMatch(/not read in this call \(this call's time ran out first\)/);
    expect(coverage?.note).toMatch(/being read in the background now and kept in the cache, so calling again in a few seconds gives the complete answer/);
    const full = formatScanResult(first, undefined, { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true });
    expect(full.summary).toMatch(/^NOT CHECKED \(advisory details\)/);
    expect(full.total_vulnerable_packages).toBeNull();
    const row = full.vulnerabilities.find((v) => "details" in v) as { details_note?: string } | undefined;
    expect(row?.details_note).toMatch(/being read in the background now, so the next call has it/);

    await queue.drained();
    expect(stats.records).toBe(30);
    const second = await scanner.scan(deps, "/proj");
    // Every record came from the cache: no record request in the second scan.
    expect(stats.records).toBe(30);
    expect(second.detailsUnchecked).toBeUndefined();
    expect(second.detailsInBackground).toBeUndefined();
    expect(second.vulnerabilities.every((v) => v.severity === "high")).toBe(true);
    expect(vulnerabilityCoverage(second, { enabled: true })).toBeNull();
    stop.abort();
  });

  it("a scan with time to spare reads every record itself and hands nothing on", async () => {
    const stats = stubOsv();
    const stop = new AbortController();
    const queue = new RecordQueue({ signal: stop.signal });
    const result = await scannerWith(queue).scan([dep("pkg-0"), dep("pkg-1")], "/proj", { deadline: Date.now() + 60_000 });
    expect(stats.records).toBe(6);
    expect(result.detailsUnchecked).toBeUndefined();
    expect(result.detailsInBackground).toBeUndefined();
    expect(queue.size).toBe(0);
    stop.abort();
  });

  it("the per-scan limit still words its rows as before when no deadline cut the read", async () => {
    stubOsv();
    const cache = new LiveCache(new Database(":memory:"));
    const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
    const stop = new AbortController();
    const queue = new RecordQueue({ signal: stop.signal });
    const scanner = new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter, undefined, { maxDetailFetches: 1, background: queue }), { aliasBudgetMs: 50 });
    const result = await scanner.scan([dep("pkg-0")], "/proj");
    expect(result.detailsInBackground).toBeUndefined();
    expect(result.detailsUncheckedReason).toMatch(/at most 1 advisory records/);
    expect(queue.size).toBe(0);
    stop.abort();
  });
});

describe("LiveIntelligence and a cut-short scan", () => {
  it("does not keep a scan cut short by its deadline as the project's current scan", async () => {
    stubOsv();
    const li = new LiveIntelligence(new Database(":memory:"));
    (li as unknown as { auditDeps: ResolvedDependency[] }).auditDeps = [dep("pkg-0"), dep("pkg-1")];
    (li as unknown as { initialized: boolean }).initialized = true;
    const cut = await li.scanVulnerabilities("/proj", { includeDev: true, deadline: Date.now() });
    expect(cut.detailsInBackground).toBe(6);
    expect(li.getVulnerabilities()).toBeNull();
    await backgroundReadsDrained();
    const whole = await li.scanVulnerabilities("/proj", { includeDev: true });
    expect(whole.detailsUnchecked).toBeUndefined();
    expect(li.getVulnerabilities()).not.toBeNull();
  });
});

describe("vulnerability_scan inside a call", () => {
  let dir: string;
  let priorOffline: string | undefined;
  let priorBudget: string | undefined;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    priorBudget = process.env.FOURDA_CALL_BUDGET_MS;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-one-call-"));
    const deps = { "pkg-0": "1.0.0", "pkg-1": "1.0.0" };
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", dependencies: deps }));
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", version: "1.0.0", dependencies: deps }, "node_modules/pkg-0": { version: "1.0.0" }, "node_modules/pkg-1": { version: "1.0.0" } } }),
    );
  });

  afterEach(() => {
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    if (priorBudget === undefined) delete process.env.FOURDA_CALL_BUDGET_MS;
    else process.env.FOURDA_CALL_BUDGET_MS = priorBudget;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  /** A fresh layer per call, as a project_path call makes, over one cache. */
  const intel = (db: InstanceType<typeof Database>) => {
    const li = new LiveIntelligence(db);
    li.initFromDependencyGroups([{ dir, language: "javascript", deps: ["pkg-0", "pkg-1"], devDeps: [] }]);
    li.fetchRegistryHealth = async () => [];
    return li;
  };
  const call = (li: LiveIntelligence) =>
    runWithCallBudget(Date.now(), () => raceCallBudget(executeVulnerabilityScan(null, { project_path: dir }, li) as Promise<Record<string, any>>, () => ({ late: true }) as Record<string, any>));

  it("a call with too little time for the records answers NOT CHECKED (advisory details), says they are being read, and the next call is complete", async () => {
    const stats = stubOsv();
    // 8 s: the scan's share is 2 s, and records stop 1.5 s before its deadline: none are read in the call.
    process.env.FOURDA_CALL_BUDGET_MS = "8000";
    const db = new Database(":memory:");
    const first = await call(intel(db));
    expect(first.late).toBeUndefined();
    expect(first.summary).toMatch(/^NOT CHECKED \(advisory details\): OSV\.dev matched 6 advisories/);
    expect(first.summary).toMatch(/calling again in a few seconds gives the complete answer/);
    expect(first.total_vulnerable_packages).toBeNull();

    await backgroundReadsDrained();
    const records = stats.records;
    delete process.env.FOURDA_CALL_BUDGET_MS;
    const second = await call(intel(db));
    expect(second.late).toBeUndefined();
    expect(second.summary).toBeUndefined();
    expect(second.total_vulnerable_packages).toBe(2);
    expect(stats.records).toBe(records);
  });
});
