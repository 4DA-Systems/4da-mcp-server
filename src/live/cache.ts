// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import Database from "better-sqlite3";

import { serverCacheDbPath } from "../db.js";

let serverCache: Database.Database | null = null;

/**
 * The server's own cache file (serverCacheDbPath(), `cache.db`), opened once
 * per process. Falls back to an in-memory database when the file cannot be
 * created (a read-only home directory): the server then runs uncached on disk
 * rather than failing.
 */
export function getServerCacheDb(): Database.Database {
  if (serverCache?.open) return serverCache;
  const file = serverCacheDbPath();
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    serverCache = new Database(file);
    serverCache.pragma("journal_mode = WAL");
  } catch (error) {
    console.error(
      `[4da] cannot open the cache at ${file} (${error instanceof Error ? error.message : String(error)}); caching in memory for this session`,
    );
    serverCache = new Database(":memory:");
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
  private db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db.readonly ? getServerCacheDb() : db;
    this.ensureTable();
    this.purgeExpired();
  }

  private ensureTable(): void {
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
    const row = this.db.prepare(
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
    const row = this.db.prepare(
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
    this.db.prepare(`
      INSERT OR REPLACE INTO live_cache (cache_key, data, source, fetched_at, expires_at)
      VALUES (?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds'))
    `).run(key, JSON.stringify(data), source, ttlSeconds);
  }

  purgeExpired(): number {
    const result = this.db.prepare(
      "DELETE FROM live_cache WHERE expires_at <= datetime('now')",
    ).run();
    return result.changes;
  }

  invalidateSource(source: string): void {
    this.db.prepare("DELETE FROM live_cache WHERE source = ?").run(source);
  }

  invalidateAll(): void {
    this.db.prepare("DELETE FROM live_cache").run();
  }
}
