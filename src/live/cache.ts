// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import { openDatabase, sqliteDriverStatus, type SqliteDatabase } from "../sqlite-driver.js";

import { serverCacheDbPath, standaloneDbPath } from "../db.js";

let serverCache: SqliteDatabase | null = null;

/**
 * The server's own cache file (serverCacheDbPath(), `cache.db`), opened once
 * per process. Falls back to an in-memory database when the file cannot be
 * created (a read-only home directory): the server then runs uncached on disk
 * rather than failing. Null when no SQLite driver is usable at all
 * (sqlite-driver.ts); LiveCache then keeps entries in a Map for the session.
 */
export function getServerCacheDb(): SqliteDatabase | null {
  if (serverCache?.open) return serverCache;
  if (!sqliteDriverStatus().driver) return null;
  const file = serverCacheDbPath();
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    serverCache = openDatabase(file);
    serverCache.pragma("journal_mode = WAL");
    // A cache, not a record: in WAL mode NORMAL never corrupts the file, and
    // a crash can only lose the last few writes, which are refetched.
    serverCache.pragma("synchronous = NORMAL");
  } catch (error) {
    console.error(
      `[4da] cannot open the cache at ${file} (${error instanceof Error ? error.message : String(error)}); caching in memory for this session`,
    );
    serverCache = openDatabase(":memory:");
  }
  return serverCache;
}

/** Close the shared cache connection (tests; the next getServerCacheDb() reopens it). */
export function closeServerCacheDb(): void {
  if (serverCache?.open) serverCache.close();
  serverCache = null;
}

/**
 * A row fetched "in the future" was written under a clock that was ahead, or the clock has
 * since gone back (an RTC reset). Its expires_at came from that clock too, so it could keep a
 * year-old "no advisories" answer live: scan 0 vulnerable, dependency_check proceed,
 * what_should_i_know safe_to_delegate (audit 6.2.5 B-3). Such a row is never an answer, fresh or
 * stale, and is purged at start. Five minutes of skew between processes is tolerated.
 */
const SANE_FETCHED_AT = "fetched_at <= datetime('now', '+5 minutes')";

interface CacheRow {
  cache_key: string;
  data: string;
  source: string;
  fetched_at: string;
  expires_at: string;
}

/** An in-memory database (tests, the no-driver fallback): the only kind a cache may live in besides cache.db. */
function inMemory(db: SqliteDatabase): boolean {
  return !db.name || db.name === ":memory:";
}

/**
 * The `live_cache` table a server before 6.3.0 left in its own `standalone.db`: disposable rows
 * nothing reads any more. Dropped once, from that file only (never from a database the server
 * does not own); a failure leaves it in place.
 */
function dropLegacyCacheTable(db: SqliteDatabase): void {
  try {
    if (path.resolve(db.name) !== path.resolve(standaloneDbPath())) return;
    db.exec("DROP TABLE IF EXISTS live_cache");
  } catch {
    // Locked or read-only after all: harmless, it is only unused space.
  }
}

/**
 * Registry, OSV and changelog responses with a TTL.
 *
 * The cache lives in its own disposable file, `cache.db` (serverCacheDbPath()), never in a
 * database that holds records: not in the desktop app's `4da.db` (until 6.0.2 the server created
 * a `live_cache` table inside it), and not in the server's own `standalone.db`, which holds the
 * user's decisions and memories (until 6.3.0 standalone mode cached there, while the README
 * said `cache.db`). Deleting cache.db costs refetches only. An in-memory database passed in
 * (tests) is used as is.
 */
export class LiveCache {
  private db: SqliteDatabase | null;
  /** True when `db` is the shared cache.db connection, which may be closed and reopened under it. */
  private readonly onServerCache: boolean;
  /** Without any SQLite driver: entries for this session only, keyed like the table. */
  private memory: Map<string, CacheRow> | null = null;

  constructor(db: SqliteDatabase | null) {
    if (db && !db.readonly && !inMemory(db)) dropLegacyCacheTable(db);
    this.onServerCache = !db || db.readonly || !inMemory(db);
    this.db = this.onServerCache ? getServerCacheDb() : db;
    if (!this.db) {
      this.memory = new Map();
      return;
    }
    this.ensureTable();
    this.purgeExpired();
  }

  /** The Map store's equivalent of datetime('now') comparisons. */
  private live(row: CacheRow): boolean {
    return Date.parse(row.expires_at) > Date.now();
  }

  /**
   * The connection to use now. The shared cache.db connection can be closed (closeServerCacheDb)
   * and reopened while this cache lives; a closed one is replaced by the current one, with its
   * table, instead of failing every lookup with "The database connection is not open".
   */
  private conn(): SqliteDatabase {
    if (this.onServerCache && this.db && !this.db.open) {
      const current = getServerCacheDb();
      if (current) {
        this.db = current;
        this.ensureTable();
      }
    }
    return this.db!;
  }

  private ensureTable(): void {
    if (!this.db) return;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS live_cache (
        cache_key TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        source TEXT NOT NULL,
        fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_live_cache_expires ON live_cache(expires_at);
      CREATE INDEX IF NOT EXISTS idx_live_cache_source ON live_cache(source);
    `);
  }

  get<T>(key: string): T | null {
    if (this.memory) {
      const hit = this.memory.get(key);
      return hit && this.live(hit) ? (JSON.parse(hit.data) as T) : null;
    }
    const row = this.conn().prepare(
      `SELECT data FROM live_cache WHERE cache_key = ? AND expires_at > datetime('now') AND ${SANE_FETCHED_AT}`,
    ).get(key) as { data: string } | undefined;

    if (!row) return null;
    try {
      return JSON.parse(row.data) as T;
    } catch {
      return null;
    }
  }

  getStale<T>(key: string): { data: T; fetchedAt: string } | null {
    if (this.memory) {
      const hit = this.memory.get(key);
      return hit ? { data: JSON.parse(hit.data) as T, fetchedAt: hit.fetched_at } : null;
    }
    const row = this.conn().prepare(
      `SELECT data, fetched_at FROM live_cache WHERE cache_key = ? AND ${SANE_FETCHED_AT}`,
    ).get(key) as { data: string; fetched_at: string } | undefined;

    if (!row) return null;
    try {
      return { data: JSON.parse(row.data) as T, fetchedAt: row.fetched_at };
    } catch {
      return null;
    }
  }

  set(key: string, data: unknown, source: string, ttlSeconds: number): void {
    if (this.memory) {
      const now = Date.now();
      const iso = (ms: number) => new Date(ms).toISOString();
      this.memory.set(key, { cache_key: key, data: JSON.stringify(data), source, fetched_at: iso(now), expires_at: iso(now + ttlSeconds * 1000) });
      return;
    }
    this.conn().prepare(`
      INSERT OR REPLACE INTO live_cache (cache_key, data, source, fetched_at, expires_at)
      VALUES (?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds'))
    `).run(key, JSON.stringify(data), source, ttlSeconds);
  }

  /**
   * Many entries in ONE transaction. A scan caches one row per dependency;
   * as separate autocommits each paid its own WAL commit, and superset's
   * 4,516 rows took about 40 s of a 55 s cold scan whose network part ended
   * at 12 s (2026-10-10).
   */
  setMany(entries: Array<[key: string, data: unknown]>, source: string, ttlSeconds: number): void {
    if (entries.length === 0) return;
    if (this.memory) {
      for (const [key, data] of entries) this.set(key, data, source, ttlSeconds);
      return;
    }
    const insert = this.conn().prepare(`
      INSERT OR REPLACE INTO live_cache (cache_key, data, source, fetched_at, expires_at)
      VALUES (?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds'))
    `);
    this.conn().transaction(() => {
      for (const [key, data] of entries) insert.run(key, JSON.stringify(data), source, ttlSeconds);
    })();
  }

  purgeExpired(): number {
    if (this.memory) {
      let purged = 0;
      for (const [key, row] of this.memory) if (!this.live(row) && this.memory.delete(key)) purged++;
      return purged;
    }
    const result = this.conn().prepare(
      `DELETE FROM live_cache WHERE expires_at <= datetime('now') OR NOT (${SANE_FETCHED_AT})`,
    ).run();
    return result.changes;
  }

  invalidateSource(source: string): void {
    if (this.memory) {
      for (const [key, row] of this.memory) if (row.source === source) this.memory.delete(key);
      return;
    }
    this.conn().prepare("DELETE FROM live_cache WHERE source = ?").run(source);
  }

  invalidateAll(): void {
    if (this.memory) {
      this.memory.clear();
      return;
    }
    this.conn().prepare("DELETE FROM live_cache").run();
  }
}
