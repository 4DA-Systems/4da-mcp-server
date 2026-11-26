// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import { openDatabase, sqliteDriverStatus, type SqliteDatabase, type SqliteStatement } from "../sqlite-driver.js";

import { dataFolderWriteProblem, isOwnStorePath, serverCacheDbPath } from "../db.js";

let serverCache: SqliteDatabase | null = null;

/** Which cache this process uses, for --doctor: the file on disk, or memory and why. */
export interface ServerCacheState {
  kind: "disk" | "memory";
  path: string;
  /** Opens tried; more than 1 when a lock held by another starting server was waited out. */
  attempts: number;
  reason?: string;
}

let cacheState: ServerCacheState | null = null;

/** The cache this process opened (null before the first getServerCacheDb(), or with no SQLite driver). */
export function serverCacheState(): ServerCacheState | null {
  return cacheState;
}

/** Opens tried before a session caches in memory: a lock another starting server holds is gone in milliseconds. */
const CACHE_OPEN_ATTEMPTS = 4;
/** Pause before retry n is n times this. */
const CACHE_RETRY_PAUSE_MS = 50;
/** How long one open attempt waits for a lock on cache.db. */
const CACHE_OPEN_BUSY_TIMEOUT_MS = 250;
/**
 * How long one statement on cache.db waits for another process's write lock before the cache is
 * taken as busy (BusyCache). A server's own largest write holds it about 2 s (150,000 rows, measured
 * 2026-11-27): a writer that waits longer gives up and caches in memory, which costs refetches only.
 */
const CACHE_BUSY_TIMEOUT_MS = 1_000;

/**
 * cache.db while another process holds its write lock (another server mid-write, a tool with the
 * file open in a write transaction). The cache's constructor purged expired rows on the file, and
 * that purge, like every later statement, failed with "database is locked": every tool, the memory
 * tools included, answered that bare error for as long as the lock lasted, 11 s per call (audit
 * 2026-11-25, F-m1). A statement that meets the lock now moves the cache to an in-memory database
 * for BUSY_PAUSE_MS, then the file is tried again; this is said once on stderr, with the file.
 */
const BUSY_PAUSE_MS = 30_000;
let busyFallback: SqliteDatabase | null = null;
let diskPausedUntil = 0;
let busyTold = false;

function diskPaused(): boolean {
  return Date.now() < diskPausedUntil;
}

/** The in-memory stand-in for cache.db while it is busy, with its table. */
function busyCache(): SqliteDatabase {
  if (!busyFallback?.open) {
    busyFallback = openDatabase(":memory:");
    createCacheTable(busyFallback);
  }
  return busyFallback;
}

function noteBusy(error: unknown): void {
  diskPausedUntil = Date.now() + BUSY_PAUSE_MS;
  if (busyTold) return;
  busyTold = true;
  const reason = error instanceof Error ? error.message : String(error);
  console.error(
    `[4da] the cache at ${serverCacheDbPath()} is locked by another process (${reason}): answers are cached in memory meanwhile, and the file is tried again every ${BUSY_PAUSE_MS / 1000} s`,
  );
}

/** Tests only: forget a busy cache.db. */
export function _resetBusyCache(): void {
  diskPausedUntil = 0;
  busyTold = false;
  if (busyFallback?.open) busyFallback.close();
  busyFallback = null;
}

function createCacheTable(db: SqliteDatabase): void {
  db.exec(`
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

/** Whether an open failed on a lock (SQLITE_BUSY / SQLITE_LOCKED and their extended codes), which a retry can clear. */
export function isTransientOpenError(error: unknown): boolean {
  const code = String((error as { code?: unknown } | null)?.code ?? "");
  if (/^SQLITE_(BUSY|LOCKED)/.test(code)) return true;
  const message = error instanceof Error ? error.message : String(error);
  return /database (table )?is locked/i.test(message);
}

export interface CacheOpenResult {
  db: SqliteDatabase | null;
  attempts: number;
  error?: unknown;
}

function pauseSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Open the cache file in WAL mode, retrying a lock up to `attempts` times; any other failure is
 * final at once. Every connection a failed attempt opened is closed (on Windows a leaked handle
 * keeps the file locked).
 */
export function openCacheFile(
  file: string,
  options: { open?: (file: string) => SqliteDatabase; pause?: (ms: number) => void; attempts?: number } = {},
): CacheOpenResult {
  const open = options.open ?? ((f: string) => openDatabase(f));
  const pause = options.pause ?? pauseSync;
  const attempts = Math.max(1, options.attempts ?? CACHE_OPEN_ATTEMPTS);
  for (let attempt = 1; ; attempt++) {
    let db: SqliteDatabase | null = null;
    try {
      db = open(file);
      // SQLite's busy handler sleeps synchronously: each wait for a lock holds the event loop. A lock
      // another starting server holds is gone in milliseconds, so the open waits briefly per attempt.
      db.pragma(`busy_timeout = ${CACHE_OPEN_BUSY_TIMEOUT_MS}`);
      db.pragma("journal_mode = WAL");
      // A cache, not a record: in WAL mode NORMAL never corrupts the file, and
      // a crash can only lose the last few writes, which are refetched.
      db.pragma("synchronous = NORMAL");
      db.pragma(`busy_timeout = ${CACHE_BUSY_TIMEOUT_MS}`);
      return { db, attempts: attempt };
    } catch (error) {
      try {
        db?.close();
      } catch {
        // Nothing to close when the open itself failed.
      }
      if (attempt >= attempts || !isTransientOpenError(error)) return { db: null, attempts: attempt, error };
      pause(CACHE_RETRY_PAUSE_MS * attempt);
    }
  }
}

/**
 * The server's own cache file (serverCacheDbPath(), `cache.db`), opened once
 * per process, a lock retried (openCacheFile). Falls back to an in-memory
 * database when the file cannot be opened (a read-only home directory, a lock
 * that outlasts the retries): the server then runs uncached on disk rather
 * than failing, and serverCacheState() says so. Null when no SQLite driver is
 * usable at all (sqlite-driver.ts); LiveCache then keeps entries in a Map for
 * the session.
 */
export function getServerCacheDb(): SqliteDatabase | null {
  if (serverCache?.open) return serverCache;
  if (!sqliteDriverStatus().driver) return null;
  const file = serverCacheDbPath();
  let opened: CacheOpenResult;
  // A data folder this user cannot write to is said as that, and not tried (audit 2026-11-25, F-m3).
  const folderProblem = dataFolderWriteProblem();
  if (folderProblem) opened = { db: null, attempts: 0, error: new Error(folderProblem) };
  else {
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      opened = openCacheFile(file);
    } catch (error) {
      opened = { db: null, attempts: 0, error };
    }
  }
  if (opened.db) {
    serverCache = opened.db;
    cacheState = { kind: "disk", path: file, attempts: opened.attempts };
    return serverCache;
  }
  const reason = opened.error instanceof Error ? opened.error.message : String(opened.error);
  const tries = opened.attempts > 1 ? `, after ${opened.attempts} attempts` : "";
  console.error(`[4da] cannot open the cache at ${file} (${reason}${tries}); caching in memory for this session`);
  serverCache = openDatabase(":memory:");
  cacheState = { kind: "memory", path: file, attempts: opened.attempts, reason };
  return serverCache;
}

/** Close the shared cache connection (tests; the next getServerCacheDb() reopens it). */
export function closeServerCacheDb(): void {
  if (serverCache?.open) serverCache.close();
  serverCache = null;
  cacheState = null;
}

/**
 * A row fetched "in the future" was written under a clock that was ahead, or the clock has
 * since gone back (an RTC reset). Its expires_at came from that clock too, so it could keep a
 * year-old "no advisories" answer live: scan 0 vulnerable, dependency_check proceed,
 * what_should_i_know safe_to_delegate (audit 6.2.5 B-3). Such a row is never an answer, fresh or
 * stale, and is purged at start. Five minutes of skew between processes is tolerated.
 */
const SANE_FETCHED_AT = "fetched_at <= datetime('now', '+5 minutes')";
/** How long past its expiry an OSV answer is kept as a stale stand-in (SQLite datetime modifier; W5). */
const STALE_OSV_RETENTION = "-7 days";
/** The longest value one row may hold, in characters of JSON (about 24 MB). */
const MAX_ROW_CHARS = 24 * 1024 * 1024;
/** Keys per IN (...) query in getMany: well under SQLite's 999-variable floor of older builds. */
const MANY_CHUNK = 500;

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
    if (!isOwnStorePath(db.name)) return;
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

  /** The file connection whose table this cache has made sure of (ensureTable), or null. */
  private tableReadyOn: SqliteDatabase | null = null;

  constructor(db: SqliteDatabase | null) {
    if (db && !db.readonly && !inMemory(db)) dropLegacyCacheTable(db);
    this.onServerCache = !db || db.readonly || !inMemory(db);
    this.db = this.onServerCache ? getServerCacheDb() : db;
    if (!this.db) {
      this.memory = new Map();
      return;
    }
    this.purgeExpired();
  }

  /** The Map store's equivalent of datetime('now') comparisons. */
  private live(row: CacheRow): boolean {
    return Date.parse(row.expires_at) > Date.now();
  }

  /**
   * The connection to use now. The shared cache.db connection can be closed (closeServerCacheDb)
   * and reopened while this cache lives; a closed one is replaced by the current one, with its
   * table, instead of failing every lookup with "The database connection is not open". While
   * cache.db is busy (noteBusy) it is the in-memory stand-in.
   */
  private conn(): SqliteDatabase {
    if (this.onServerCache && diskPaused()) return busyCache();
    if (this.onServerCache && this.db && !this.db.open) {
      const current = getServerCacheDb();
      if (current) this.db = current;
    }
    if (this.tableReadyOn !== this.db) {
      try {
        createCacheTable(this.db!);
        this.tableReadyOn = this.db;
      } catch (error) {
        if (!this.onServerCache || !isTransientOpenError(error)) throw error;
        noteBusy(error);
        return busyCache();
      }
    }
    return this.db!;
  }

  /**
   * One statement or transaction on the cache. On cache.db, one that meets another process's write
   * lock is run again on the in-memory stand-in (noteBusy): a busy cache costs refetches, never a
   * failed tool (audit 2026-11-25, F-m1).
   */
  private run<T>(op: (db: SqliteDatabase) => T): T {
    const db = this.conn();
    try {
      return op(db);
    } catch (error) {
      if (!this.onServerCache || db === busyFallback || !isTransientOpenError(error)) throw error;
      noteBusy(error);
      return op(this.conn());
    }
  }

  /**
   * One prepared statement per SQL text, for as long as the connection lives. A scan read one row
   * per dependency and prepared a new statement for each: with a 250,000-entry lockfile that kept
   * the event loop for seconds, and `ping` waited 7.4 s (blind audit round 4).
   */
  private statements = new Map<string, SqliteStatement>();
  private statementsFor: SqliteDatabase | null = null;

  private statement(sql: string): SqliteStatement {
    const conn = this.conn();
    if (this.statementsFor !== conn) {
      this.statements.clear();
      this.statementsFor = conn;
    }
    let stmt = this.statements.get(sql);
    if (!stmt) {
      stmt = conn.prepare(sql);
      this.statements.set(sql, stmt);
    }
    return stmt;
  }

  /** Many live entries in one query per MANY_CHUNK keys; a key with no live, readable entry is absent from the map. */
  getMany<T>(keys: readonly string[]): Map<string, T> {
    return this.readMany(keys, true, (data) => data as T);
  }

  /** getStale for many keys at once. */
  getStaleMany<T>(keys: readonly string[]): Map<string, { data: T; fetchedAt: string }> {
    return this.readMany(keys, false, (data, fetchedAt) => ({ data: data as T, fetchedAt }));
  }

  private readMany<R>(keys: readonly string[], liveOnly: boolean, make: (data: unknown, fetchedAt: string) => R): Map<string, R> {
    const out = new Map<string, R>();
    if (this.memory) {
      for (const key of keys) {
        const hit = this.memory.get(key);
        if (hit && (!liveOnly || this.live(hit))) out.set(key, make(JSON.parse(hit.data), hit.fetched_at));
      }
      return out;
    }
    const unique = [...new Set(keys)];
    for (let at = 0; at < unique.length; at += MANY_CHUNK) {
      const chunk = unique.slice(at, at + MANY_CHUNK);
      const sql = `SELECT cache_key, data, fetched_at FROM live_cache WHERE cache_key IN (${chunk.map(() => "?").join(",")})${
        liveOnly ? " AND expires_at > datetime('now')" : ""
      } AND ${SANE_FETCHED_AT}`;
      // A full chunk's statement is reused; only the last, shorter one is prepared once more.
      const rows = this.run(() => (chunk.length === MANY_CHUNK ? this.statement(sql) : this.conn().prepare(sql)).all(...chunk)) as Array<{ cache_key: string; data: string; fetched_at: string }>;
      for (const row of rows) {
        try {
          out.set(row.cache_key, make(JSON.parse(row.data), row.fetched_at));
        } catch {
          // An unreadable row is a miss, as in get().
        }
      }
    }
    return out;
  }

  get<T>(key: string): T | null {
    if (this.memory) {
      const hit = this.memory.get(key);
      return hit && this.live(hit) ? (JSON.parse(hit.data) as T) : null;
    }
    const row = this.run(() =>
      this.statement(`SELECT data FROM live_cache WHERE cache_key = ? AND expires_at > datetime('now') AND ${SANE_FETCHED_AT}`).get(key),
    ) as { data: string } | undefined;

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
    const row = this.run(() => this.statement(`SELECT data, fetched_at FROM live_cache WHERE cache_key = ? AND ${SANE_FETCHED_AT}`).get(key)) as
      | { data: string; fetched_at: string }
      | undefined;

    if (!row) return null;
    try {
      return { data: JSON.parse(row.data) as T, fetchedAt: row.fetched_at };
    } catch {
      return null;
    }
  }

  set(key: string, data: unknown, source: string, ttlSeconds: number): void {
    const text = JSON.stringify(data);
    // One answer is never worth a row this large: it is refetched next time instead. Without the
    // limit a single oversized registry answer left a 171 MB row in cache.db for a week.
    if (text.length > MAX_ROW_CHARS) return;
    if (this.memory) {
      const now = Date.now();
      const iso = (ms: number) => new Date(ms).toISOString();
      this.memory.set(key, { cache_key: key, data: text, source, fetched_at: iso(now), expires_at: iso(now + ttlSeconds * 1000) });
      return;
    }
    this.run((db) =>
      db
        .prepare(`
      INSERT OR REPLACE INTO live_cache (cache_key, data, source, fetched_at, expires_at)
      VALUES (?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds'))
    `)
        .run(key, text, source, ttlSeconds),
    );
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
    this.run((db) => {
      const insert = db.prepare(`
        INSERT OR REPLACE INTO live_cache (cache_key, data, source, fetched_at, expires_at)
        VALUES (?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds'))
      `);
      // The row limit holds here as in set(): an oversized row is skipped, the rest are written.
      db.transaction(() => {
        for (const [key, data] of entries) {
          const text = JSON.stringify(data);
          if (text.length <= MAX_ROW_CHARS) insert.run(key, text, source, ttlSeconds);
        }
      })();
    });
  }

  purgeExpired(): number {
    if (this.memory) {
      let purged = 0;
      for (const [key, row] of this.memory) if (!this.live(row) && this.memory.delete(key)) purged++;
      return purged;
    }
    // OSV answers are kept for STALE_OSV_RETENTION past their life: they are what an offline scan, or
    // one whose lookup fails, answers from, always with their fetched_at stated (OsvScanner). Purged
    // at the life's end, a restart an hour after the last online scan left an offline scan nothing
    // (pre-publish round 10, W5). Nothing else is read past its life.
    const result = this.run((db) =>
      db
        .prepare(
          `DELETE FROM live_cache WHERE (expires_at <= datetime('now') AND (source <> 'osv' OR expires_at <= datetime('now', '${STALE_OSV_RETENTION}'))) OR NOT (${SANE_FETCHED_AT})`,
        )
        .run(),
    );
    return result.changes;
  }

  /** Remove these entries, live or expired. */
  deleteMany(keys: readonly string[]): void {
    const unique = [...new Set(keys)];
    if (this.memory) {
      for (const key of unique) this.memory.delete(key);
      return;
    }
    for (let at = 0; at < unique.length; at += MANY_CHUNK) {
      const chunk = unique.slice(at, at + MANY_CHUNK);
      this.run((db) => db.prepare(`DELETE FROM live_cache WHERE cache_key IN (${chunk.map(() => "?").join(",")})`).run(...chunk));
    }
  }

  invalidateSource(source: string): void {
    if (this.memory) {
      for (const [key, row] of this.memory) if (row.source === source) this.memory.delete(key);
      return;
    }
    this.run((db) => db.prepare("DELETE FROM live_cache WHERE source = ?").run(source));
  }

  invalidateAll(): void {
    if (this.memory) {
      this.memory.clear();
      return;
    }
    this.run((db) => db.prepare("DELETE FROM live_cache").run());
  }
}
