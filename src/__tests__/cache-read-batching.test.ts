// SPDX-License-Identifier: Apache-2.0
/**
 * Blind audit round 4: with a 250,000-entry npm lockfile, `ping` waited 7.4 s (yarn 150k: 4.9 s,
 * pnpm 100k: 4.5 s). The scan read the cache one row per dependency, synchronously, each read
 * preparing a new statement (osv-scanner.ts, cache.ts). Statements are now prepared once per
 * connection, the reads go in batches, and the scan yields to the event loop between batches.
 */
import { describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { OsvScanner, type AdvisorySource } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import type { ResolvedDependency } from "../live/types.js";

const dep = (i: number) =>
  ({ name: `pkg-${i}`, version: "1.0.0", ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [] }) as ResolvedDependency;

describe("the cache reads a big scan's answers in batches", () => {
  it("prepares a lookup's statement once, not once per key", () => {
    const db = new Database(":memory:");
    const cache = new LiveCache(db as never);
    cache.set("a", [1], "osv", 3600);
    const prepare = vi.spyOn(db, "prepare");
    for (let i = 0; i < 500; i++) {
      cache.get(`k${i}`);
      cache.getStale(`k${i}`);
    }
    expect(cache.get("a")).toEqual([1]);
    expect(prepare.mock.calls.length).toBeLessThanOrEqual(2);
  });

  it("getMany and getStaleMany answer like get and getStale, across chunk boundaries", () => {
    const db = new Database(":memory:");
    const cache = new LiveCache(db as never);
    cache.setMany(Array.from({ length: 1_200 }, (_, i) => [`k${i}`, { i }] as [string, unknown]), "osv", 3600);
    db.prepare("INSERT INTO live_cache (cache_key, data, source, fetched_at, expires_at) VALUES ('expired', '{\"gone\":true}', 'osv', datetime('now', '-2 hours'), datetime('now', '-1 hour'))").run();
    const keys = [...Array.from({ length: 1_300 }, (_, i) => `k${i}`), "expired"];
    const live = cache.getMany<{ i: number }>(keys);
    expect(live.size).toBe(1_200);
    expect(live.get("k1199")).toEqual({ i: 1199 });
    expect(live.has("expired")).toBe(false);
    const stale = cache.getStaleMany<{ gone?: boolean }>(keys);
    expect(stale.size).toBe(1_201);
    expect(stale.get("expired")?.data).toEqual({ gone: true });
    for (const k of ["k0", "k499", "k500", "k1199", "k1250", "expired"]) {
      expect(live.get(k) ?? null, k).toEqual(cache.get(k));
      expect(stale.get(k) ?? null, k).toEqual(cache.getStale(k));
    }
  });

  it("a 20,000-dependency scan yields to the event loop while it reads the cache", async () => {
    const cache = new LiveCache(new Database(":memory:") as never);
    const deps = Array.from({ length: 20_000 }, (_, i) => dep(i));
    cache.setMany(deps.map((d) => [`osv:v9:npm:${d.name}:1.0.0`, []] as [string, unknown]), "osv", 3600);
    const source: AdvisorySource = { network: true, query: async () => ({ ids: [], failure: null }), details: async () => new Map() };
    const scanner = new OsvScanner(cache, new RateLimiter(DEFAULT_RATE_LIMITS), source);
    let turns = 0;
    let readsBeforeFirstTurn = -1;
    const getMany = vi.spyOn(cache, "getMany");
    const tick = () => {
      turns++;
      if (readsBeforeFirstTurn < 0) readsBeforeFirstTurn = getMany.mock.calls.length;
      if (turns < 1_000) setImmediate(tick);
    };
    setImmediate(tick);
    const result = await scanner.scan(deps, "/p");
    expect(result.totalScanned).toBe(20_000);
    // Read in more than one batch, and something else ran before the reads were done.
    expect(getMany.mock.calls.length).toBeGreaterThan(1);
    expect(readsBeforeFirstTurn).toBeLessThan(getMany.mock.calls.length);
    expect(getMany.mock.calls.every(([keys]) => keys.length <= 2_000)).toBe(true);
  });
});
