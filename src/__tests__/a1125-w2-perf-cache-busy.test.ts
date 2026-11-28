// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, Track F, m1: with cache.db write-locked by another process, the cache's
 * constructor purge (and every later statement) failed with "database is locked", and every tool,
 * the memory tools included, answered that bare error after about 11 s, for as long as the lock
 * lasted. A busy cache.db now moves the cache to memory for a while, says so once on stderr with the
 * file, and never fails a caller.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { _resetBusyCache, closeServerCacheDb, LiveCache } from "../live/cache.js";
import { openDatabase, type SqliteDatabase } from "../sqlite-driver.js";

let home: string;
let prior: string | undefined;
let holder: SqliteDatabase | null = null;

/** Another connection holding cache.db's write lock, as another process would. */
function lockCacheFile(): void {
  holder = openDatabase(path.join(home, "cache.db"));
  holder.exec("PRAGMA journal_mode = WAL");
  holder.exec("CREATE TABLE IF NOT EXISTS live_cache (cache_key TEXT PRIMARY KEY, data TEXT NOT NULL, source TEXT NOT NULL, fetched_at TEXT NOT NULL DEFAULT (datetime('now')), expires_at TEXT NOT NULL)");
  holder.exec("INSERT OR REPLACE INTO live_cache (cache_key, data, source, expires_at) VALUES ('old', '1', 'osv', datetime('now', '-30 days'))");
  holder.exec("BEGIN IMMEDIATE");
  holder.exec("INSERT OR REPLACE INTO live_cache (cache_key, data, source, expires_at) VALUES ('held', '1', 'osv', datetime('now', '+1 hour'))");
}

beforeEach(() => {
  closeServerCacheDb();
  _resetBusyCache();
  prior = process.env.FOURDA_MCP_HOME;
  home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-cache-busy-")));
  process.env.FOURDA_MCP_HOME = home;
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  try {
    holder?.exec("ROLLBACK");
  } catch {
    // Not in a transaction.
  }
  holder?.close();
  holder = null;
  closeServerCacheDb();
  _resetBusyCache();
  if (prior === undefined) delete process.env.FOURDA_MCP_HOME;
  else process.env.FOURDA_MCP_HOME = prior;
  fs.rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("a cache.db another process holds the write lock of (audit 2026-11-25, F-m1)", () => {
  it("the cache still works, in memory, and says so once with the file", () => {
    lockCacheFile();
    const said = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const t0 = performance.now();
    // The constructor's purge met the lock: it threw "database is locked" before.
    const cache = new LiveCache(null);
    cache.set("osv:v9:npm:x:1.0.0", { ok: true }, "osv", 3600);
    expect(cache.get("osv:v9:npm:x:1.0.0")).toEqual({ ok: true });
    cache.setMany([["osv:v9:npm:y:1.0.0", []]], "osv", 3600);
    expect(cache.getMany(["osv:v9:npm:y:1.0.0"]).size).toBe(1);
    // A second cache of the same process does not wait for the lock again.
    const second = new LiveCache(null);
    second.set("k", 1, "npm", 60);
    expect(second.get("k")).toBe(1);
    // One wait for the lock (about a second), not one per statement.
    expect(performance.now() - t0).toBeLessThan(4000);
    const lines = said.mock.calls.map((c) => String(c[0])).filter((l) => /locked by another process/.test(l));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain(path.join(home, "cache.db"));
  });

  it("goes back to the file once the lock is gone and the pause is over", () => {
    lockCacheFile();
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const cache = new LiveCache(null);
    cache.set("during", 1, "npm", 3600);
    holder!.exec("COMMIT");
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 31_000);
    cache.set("after", 2, "npm", 3600);
    // Written to the file this time: another connection sees it.
    const row = holder!.prepare("SELECT data FROM live_cache WHERE cache_key = 'after'").get() as { data: string } | undefined;
    expect(row?.data).toBe("2");
    // What was cached in memory during the lock is not in the file (it is refetched when needed).
    expect(holder!.prepare("SELECT 1 FROM live_cache WHERE cache_key = 'during'").get()).toBeUndefined();
  });
});
