// SPDX-License-Identifier: Apache-2.0
/**
 * `force_refresh` asks OSV.dev again for what this call needs and nothing else, and a cached
 * answer is replaced only when its replacement has arrived. It used to delete every OSV row in
 * the cache first: on a 9-dependency project that emptied 927 rows of other projects' answers,
 * and with the network down nothing came back.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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

const dep = (name: string, version = "1.0.0"): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [],
});

type Mode = "answer" | "down" | "lists-down";
const net = { mode: "answer" as Mode, batches: 0, records: 0, lists: 0, severity: "HIGH" };

/** The one advisory: lodash below 4.17.21. */
const record = () => ({
  id: "GHSA-p6mc-m468-83gw",
  summary: "advisory GHSA-p6mc-m468-83gw",
  database_specific: { severity: net.severity },
  affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
});

/**
 * OSV.dev and the npm registry: lodash 4.17.15 has one advisory, fixed in 4.17.21. `net.mode`
 * "down" fails every request; "lists-down" fails only the per-package advisory list (/v1/query).
 */
function stubOsv() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (net.mode === "down") throw new TypeError("fetch failed");
    if (url.endsWith("/v1/querybatch")) {
      net.batches++;
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => (q.package.name === "lodash" && q.version === "4.17.15" ? { vulns: [{ id: "GHSA-p6mc-m468-83gw" }] } : {})) });
    }
    if (url.includes("/v1/vulns/")) {
      net.records++;
      return json(record());
    }
    if (url.endsWith("/v1/query")) {
      net.lists++;
      if (net.mode === "lists-down") return json({}, 503);
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: q.package.name === "lodash" ? [record()] : [] });
    }
    if (url.startsWith("https://registry.npmjs.org/lodash")) return json({ name: "lodash", "dist-tags": { latest: "4.17.21" }, versions: { "4.17.15": {}, "4.17.21": {} } });
    return json({}, 404);
  });
}

beforeEach(() => {
  Object.assign(net, { mode: "answer", batches: 0, records: 0, lists: 0, severity: "HIGH" });
  stubOsv();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function scannerOn(db: InstanceType<typeof Database>): OsvScanner {
  const cache = new LiveCache(db);
  const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter), { aliasBudgetMs: 50 });
}

const rows = (db: InstanceType<typeof Database>) =>
  db.prepare("SELECT cache_key, data, fetched_at FROM live_cache WHERE source = 'osv' ORDER BY cache_key").all() as Array<{ cache_key: string; data: string; fetched_at: string }>;

/** Make every cached row look ten minutes old, so a rewritten one shows. */
const age = (db: InstanceType<typeof Database>) => db.prepare("UPDATE live_cache SET fetched_at = datetime('now', '-10 minutes')").run();

describe("a refreshing scan", () => {
  const deps = [dep("lodash", "4.17.15"), dep("minimist", "1.2.0")];

  it("asks OSV.dev about every dependency and re-reads every matched record, cached or not", async () => {
    const db = new Database(":memory:");
    const s = scannerOn(db);
    await s.scan(deps, "/proj");
    expect([net.batches, net.records]).toEqual([1, 1]);
    // A plain scan answers from the cache.
    await s.scan(deps, "/proj");
    expect([net.batches, net.records]).toEqual([1, 1]);
    net.severity = "CRITICAL";
    const refreshed = await s.scan(deps, "/proj", { refresh: true });
    expect([net.batches, net.records]).toEqual([2, 2]);
    expect(refreshed.cached).toBe(false);
    expect(refreshed.vulnerabilities.map((v) => v.severity)).toEqual(["critical"]);
    // The new answer is what the cache holds now.
    expect((await s.scan(deps, "/proj")).vulnerabilities.map((v) => v.severity)).toEqual(["critical"]);
  });

  it("with OSV.dev down, keeps every cached answer and says the answer is not the refresh asked for", async () => {
    const db = new Database(":memory:");
    const s = scannerOn(db);
    await s.scan(deps, "/proj");
    const before = rows(db);
    expect(before.length).toBeGreaterThanOrEqual(3);
    net.mode = "down";
    const result = await s.scan(deps, "/proj", { refresh: true });
    // Nothing was discarded: the cache is row for row what it was.
    expect(rows(db)).toEqual(before);
    // The cached answers stand in, as stale ones: counted, with why, never as a current all-clear.
    expect(result.vulnerabilities.map((v) => `${v.package}:${v.severity}`)).toEqual(["lodash:high"]);
    expect(result.unchecked).toBe(0);
    expect(result.staleAnswers).toBe(2);
    expect(result.staleReason).toMatch(/OSV\.dev unreachable/);
    expect(result.refreshFailed).toBe(true);
    // And a plain scan afterwards still has its cache.
    net.mode = "answer";
    const plain = await s.scan(deps, "/proj");
    expect(plain.cached).toBe(true);
    expect(plain.staleAnswers).toBe(0);
  });

  it("a record that cannot be re-read keeps its cached copy; the advisory is still graded", async () => {
    const db = new Database(":memory:");
    const s = scannerOn(db);
    await s.scan(deps, "/proj");
    // querybatch answers, the record fetch fails.
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
        return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === "lodash" ? { vulns: [{ id: "GHSA-p6mc-m468-83gw" }] } : {})) }), { status: 200 });
      }
      return new Response("unavailable", { status: 503 });
    });
    const result = await s.scan(deps, "/proj", { refresh: true });
    expect(result.vulnerabilities.map((v) => `${v.vulnId}:${v.severity}:${Boolean(v.detailUnavailable)}`)).toEqual(["GHSA-p6mc-m468-83gw:high:false"]);
    expect(result.detailsUnchecked).toBeUndefined();
    expect(db.prepare("SELECT COUNT(*) AS n FROM live_cache WHERE cache_key = 'osv:detail:GHSA-p6mc-m468-83gw'").get()).toEqual({ n: 1 });
  });
});

describe("vulnerability_scan force_refresh", () => {
  let dir: string;
  let priorOffline: string | undefined;
  const OTHERS = 927;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-force-refresh-"));
    const deps = { lodash: "4.17.15", minimist: "1.2.0" };
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", dependencies: deps }));
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", version: "1.0.0", dependencies: deps }, "node_modules/lodash": { version: "4.17.15" }, "node_modules/minimist": { version: "1.2.0" } } }),
    );
  });

  afterEach(() => {
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  /** A layer over `db`, whose cache already holds other projects' OSV answers, records and advisory lists. */
  function intelWithOtherAnswers(db: InstanceType<typeof Database>): LiveIntelligence {
    const li = new LiveIntelligence(db);
    li.initFromDependencyGroups([{ dir, language: "javascript", deps: ["lodash", "minimist"], devDeps: [] }]);
    li.fetchRegistryHealth = async () => [];
    const insert = db.prepare("INSERT INTO live_cache (cache_key, data, source, fetched_at, expires_at) VALUES (?, ?, 'osv', datetime('now', '-10 minutes'), datetime('now', '+50 minutes'))");
    for (let i = 0; i < OTHERS; i++) {
      const key = i % 3 === 0 ? `osv:v9:npm:other-${i}:1.0.0` : i % 3 === 1 ? `osv:detail:GHSA-othr-${String(i).padStart(4, "0")}-zzzz` : `fixpath:v17:osv-package:npm:other-${i}`;
      insert.run(key, "[]");
    }
    return li;
  }

  const otherRows = (db: InstanceType<typeof Database>) => rows(db).filter((r) => /other-|othr-/.test(r.cache_key));

  it("refreshes this project's answers and leaves the other 927 cached rows as they were", async () => {
    const db = new Database(":memory:");
    const li = intelWithOtherAnswers(db);
    await executeVulnerabilityScan(null, { project_path: dir }, li);
    age(db);
    const others = otherRows(db);
    expect(others).toHaveLength(OTHERS);
    const [batches, records] = [net.batches, net.records];

    const forced = (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, li)) as Record<string, any>;
    expect(net.batches).toBeGreaterThan(batches);
    expect(net.records).toBeGreaterThan(records);
    expect(forced._meta.osv_cached).toBe(false);
    expect(forced.summary).toBeUndefined();
    expect(forced.total_vulnerable_packages).toBe(1);
    // Other projects' rows: still there, not rewritten.
    expect(otherRows(db)).toEqual(others);
    // This project's own answers were replaced by fresh ones: the two installed copies, and the fix target's confirmation.
    const own = rows(db).filter((r) => /^osv:v9:npm:(lodash|minimist):/.test(r.cache_key));
    expect(own.map((r) => r.cache_key)).toEqual(["osv:v9:npm:lodash:4.17.15", "osv:v9:npm:lodash:4.17.21", "osv:v9:npm:minimist:1.2.0"]);
    for (const row of own) expect(row.fetched_at > others[0].fetched_at, `${row.cache_key} was not rewritten`).toBe(true);
  });

  it("with the network down it discards nothing, and the answer is STALE, not a clean refresh", async () => {
    const db = new Database(":memory:");
    const li = intelWithOtherAnswers(db);
    await executeVulnerabilityScan(null, { project_path: dir }, li);
    const before = rows(db);
    expect(before.length).toBeGreaterThan(OTHERS);

    net.mode = "down";
    const forced = (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, li)) as Record<string, any>;
    expect(rows(db)).toEqual(before);
    expect(Object.keys(forced)[0]).toBe("summary");
    expect(forced.summary).toMatch(/^STALE: /);
    expect(forced.summary).toMatch(/could not be refreshed/);
    expect(forced.total_vulnerable_packages).toBeNull();
    expect(forced.found_in_checked_dependencies.vulnerable_packages).toBe(1);

    // The cache still answers a plain call once the forced one has failed.
    const plain = (await executeVulnerabilityScan(null, { project_path: dir }, li)) as Record<string, any>;
    expect(plain.summary).toBeUndefined();
    expect(plain.total_vulnerable_packages).toBe(1);
  });

  it("reaches the fix target too: the package's advisory list is asked for again, and the cached list stands when it does not arrive", async () => {
    const db = new Database(":memory:");
    const li = intelWithOtherAnswers(db);
    const target = (out: Record<string, any>) => out.vulnerable_packages.map((p: Record<string, unknown>) => `${p.package}:${p.fixed_version}:${p.fix_checked}`);

    const first = (await executeVulnerabilityScan(null, { project_path: dir }, li)) as Record<string, any>;
    expect(target(first)).toEqual(["lodash:4.17.21:all_advisories"]);
    expect(net.lists).toBe(1);
    // A plain call reads the list from the cache.
    await executeVulnerabilityScan(null, { project_path: dir }, li);
    expect(net.lists).toBe(1);

    const forced = (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, li)) as Record<string, any>;
    expect(net.lists).toBe(2);
    expect(target(forced)).toEqual(["lodash:4.17.21:all_advisories"]);

    // The list cannot be read this time: the one in the cache is not dropped, so the target is still worked out.
    net.mode = "lists-down";
    const again = (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, li)) as Record<string, any>;
    expect(net.lists).toBe(3);
    expect(target(again)).toEqual(["lodash:4.17.21:all_advisories"]);
    expect(db.prepare("SELECT COUNT(*) AS n FROM live_cache WHERE cache_key LIKE 'fixpath:%:osv-package:npm:lodash'").get()).toEqual({ n: 1 });
  });
});
