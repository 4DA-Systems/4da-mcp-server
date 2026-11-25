// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish audit 2026-11-25, C-3: a `proceed` could rest on an OSV.dev answer 50 minutes old from
 * the cache and say `osv_cached: false`, with no age (the guard hook then honours it for 24 h). Each
 * answer now states how old its advisory data is when it came from the cache, the summary says so
 * once past a few minutes, and `osv_cached` is true whenever a batch answer or advisory list was cached.
 * The cache is back-dated in a database of the test's own; the TTLs are unchanged.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();
const NPM: Record<string, string[]> = { lodash: ["4.17.20", "4.17.21"], ms: ["2.1.2", "2.1.3"] };
const ADVISORY = {
  id: "GHSA-35jh-r3h4-6jhm",
  aliases: [],
  summary: "lodash advisory",
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
};

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => (q.package.name === "lodash" && q.version === "4.17.20" ? { vulns: [{ id: ADVISORY.id, modified: "2026-11-01T00:00:00Z" }] } : {})) });
    }
    if (url.includes("/v1/vulns/")) return url.endsWith(ADVISORY.id) ? json(ADVISORY) : json({}, 404);
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: q.package.name === "lodash" ? [ADVISORY] : [] });
    }
    if (url.startsWith("https://api.npmjs.org/downloads/")) return json({ downloads: 50_000_000, package: "x" });
    const one = /^https:\/\/registry\.npmjs\.org\/([^/@][^/]*)\/([^/]+)$/.exec(url);
    if (one) return json({ name: one[1], version: one[2], dependencies: {} });
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const versions = NPM[name];
      if (!versions) return json({ error: "Not found" }, 404);
      return json({
        name,
        "dist-tags": { latest: versions[versions.length - 1] },
        versions: Object.fromEntries(versions.map((v) => [v, { name, version: v, dependencies: {} }])),
        time: { created: "2015-01-01T00:00:00.000Z", modified: daysAgo(1), ...Object.fromEntries(versions.map((v) => [v, daysAgo(300)])) },
      });
    }
    return json({}, 404);
  });
}

let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  clearNpmDownloadsMemo();
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

type Answer = { summary: string; results: Array<Record<string, any>>; _meta: Record<string, any> };
const ITEMS = [
  { ecosystem: "npm", package: "lodash", to: "4.17.21" },
  { ecosystem: "npm", package: "ms", to: "2.1.3" },
];
const run = async (li: LiveIntelligence, format?: "detailed") => (await executeDependencyCheck(noDb, { items: ITEMS, ...(format ? { response_format: format } : {}) } as never, li)) as unknown as Answer;
const backDate = (db: Database.Database, like: string, minutes: number) => db.prepare(`UPDATE live_cache SET fetched_at = datetime('now', '-${minutes} minutes') WHERE cache_key LIKE ?`).run(like).changes;

describe("C-3: an answer read from the cache says how old its advisory data is", () => {
  it("read live: no age, osv_cached false, no note", async () => {
    const a = await run(new LiveIntelligence(new Database(":memory:")));
    expect(a.results.map((r) => r.verdict)).toEqual(["proceed", "proceed"]);
    expect(a.results.every((r) => r.advisory_data_age_minutes === undefined)).toBe(true);
    expect(a._meta.osv_cached).toBe(false);
    expect(a.summary).not.toMatch(/local cache/);
  });

  it("a 50-minute-old cached answer: its age on the item, osv_cached true, and the summary says it once", async () => {
    const db = new Database(":memory:");
    const li = new LiveIntelligence(db);
    await run(li);
    expect(backDate(db, "osv:v9:npm:ms:2.1.3", 50)).toBe(1);
    expect(backDate(db, "osv:v9:npm:lodash:4.17.21", 2)).toBe(1);
    const a = await run(li);
    expect(a.results[1]).toMatchObject({ package: "ms", verdict: "proceed", advisory_data_age_minutes: 50 });
    expect(a.results[0].advisory_data_age_minutes).toBe(2);
    expect(a._meta.osv_cached).toBe(true);
    expect(a.summary.match(/came from the local cache/g)).toHaveLength(1);
    expect(a.summary).toMatch(/The OSV\.dev data behind 1 item came from the local cache, up to 50 minutes old/);
    const d = await run(li, "detailed");
    expect(d.results[1].advisory_data_age_minutes).toBeGreaterThanOrEqual(50);
  });

  it("only the advisory list came from the cache: osv_cached true, and no item claims an old answer", async () => {
    const db = new Database(":memory:");
    const li = new LiveIntelligence(db);
    await run(li);
    expect(backDate(db, "fixpath:%osv-package:npm:%", 10)).toBeGreaterThan(0);
    db.prepare("DELETE FROM live_cache WHERE cache_key LIKE 'osv:v9:%'").run();
    const a = await run(li);
    expect(a._meta.osv_cached).toBe(true);
    expect(a.results.every((r) => r.advisory_data_age_minutes === undefined)).toBe(true);
    expect(a.summary).not.toMatch(/local cache/);
  });
});
