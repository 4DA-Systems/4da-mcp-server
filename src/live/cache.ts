// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import { openDatabase, sqliteDriverStatus, type SqliteDatabase } from "../sqlite-driver.js";

import { serverCacheDbPath } from "../db.js";

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

interface CacheRow {
  cache_key: string;
  data: string;
  source: string;
  fetched_at: string;
  expires_at: string;
}

/**
 * Registry, OSV and changelog responses with a TTL.
 *
 * The cache never lives in the desktop app's database. A read-only connection
 * (the app's `4da.db`, see FourDADatabase) is replaced by the server's own
 * cache file; until 6.0.2 the server created a `live_cache` table inside the
 * app's database and filled it.
 */
export class LiveCache {
  private db: SqliteDatabase | null;
  /** Without any SQLite driver: entries for this session only, keyed like the table. */
  private memory: Map<string, CacheRow> | null = null;

  constructor(db: SqliteDatabase | null) {
    this.db = !db || db.readonly ? getServerCacheDb() : db;
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
    const row = this.db!.prepare(
      "SELECT data FROM live_cache WHERE cache_key = ? AND expires_at > datetime('now')",
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
    const row = this.db!.prepare(
      "SELECT data, fetched_at FROM live_cache WHERE cache_key = ?",
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
    this.db!.prepare(`
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
    const insert = this.db!.prepare(`
      INSERT OR REPLACE INTO live_cache (cache_key, data, source, fetched_at, expires_at)
      VALUES (?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds'))
    `);
    this.db!.transaction(() => {
      for (const [key, data] of entries) insert.run(key, JSON.stringify(data), source, ttlSeconds);
    })();
  }

  purgeExpired(): number {
    if (this.memory) {
      let purged = 0;
      for (const [key, row] of this.memory) if (!this.live(row) && this.memory.delete(key)) purged++;
      return purged;
    }
    const result = this.db!.prepare(
      "DELETE FROM live_cache WHERE expires_at <= datetime('now')",
    ).run();
    return result.changes;
  }

  invalidateSource(source: string): void {
    if (this.memory) {
      for (const [key, row] of this.memory) if (row.source === source) this.memory.delete(key);
      return;
    }
    this.db!.prepare("DELETE FROM live_cache WHERE source = ?").run(source);
  }

  invalidateAll(): void {
    if (this.memory) {
      this.memory.clear();
      return;
    }
    this.db!.prepare("DELETE FROM live_cache").run();
  }
}
