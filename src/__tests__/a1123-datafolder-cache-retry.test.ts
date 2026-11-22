// SPDX-License-Identifier: Apache-2.0
/**
 * Servers starting together on one data folder could each find `cache.db` locked for a moment;
 * the first failed open made that session cache in memory for its whole life (5 of 100 starts),
 * with nothing shared and no stale OSV fallback. A transient failure (a lock) is now retried a
 * bounded number of times; anything else falls back at once; and which cache is in use is known
 * (serverCacheState, shown by --doctor).
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { closeServerCacheDb, getServerCacheDb, isTransientOpenError, openCacheFile, serverCacheState } from "../live/cache.js";
import { openDatabase, type SqliteDatabase } from "../sqlite-driver.js";

const locked = () => Object.assign(new Error("database is locked"), { code: "SQLITE_BUSY" });

describe("opening cache.db", () => {
  it("a lock is retried, and the open that succeeds is used", () => {
    const pauses: number[] = [];
    let calls = 0;
    const result = openCacheFile("cache.db", {
      open: () => {
        calls++;
        if (calls < 3) throw locked();
        return openDatabase(":memory:");
      },
      pause: (ms) => pauses.push(ms),
    });
    try {
      expect(result.db).not.toBeNull();
      expect(result.attempts).toBe(3);
      expect(pauses).toHaveLength(2);
    } finally {
      result.db?.close();
    }
  });

  it("a lock that outlasts every attempt gives up after a bounded number, with the error", () => {
    let calls = 0;
    const result = openCacheFile("cache.db", {
      open: () => {
        calls++;
        throw locked();
      },
      pause: () => undefined,
    });
    expect(result.db).toBeNull();
    expect(calls).toBe(result.attempts);
    expect(result.attempts).toBeGreaterThan(1);
    expect(result.attempts).toBeLessThanOrEqual(5);
    expect(String(result.error)).toMatch(/database is locked/);
  });

  it("a failure that is not a lock is not retried", () => {
    let calls = 0;
    const result = openCacheFile("cache.db", {
      open: () => {
        calls++;
        throw Object.assign(new Error("unable to open database file"), { code: "SQLITE_CANTOPEN" });
      },
      pause: () => undefined,
    });
    expect(result.db).toBeNull();
    expect(calls).toBe(1);
  });

  it("a connection whose WAL switch fails is closed before the next attempt", () => {
    const opened: SqliteDatabase[] = [];
    let calls = 0;
    const result = openCacheFile("cache.db", {
      open: () => {
        calls++;
        const db = openDatabase(":memory:");
        opened.push(db);
        if (calls === 1) {
          return new Proxy(db, {
            get(target, key, receiver) {
              if (key === "pragma") return () => { throw locked(); };
              const value = Reflect.get(target, key, receiver);
              return typeof value === "function" ? value.bind(target) : value;
            },
          });
        }
        return db;
      },
      pause: () => undefined,
    });
    try {
      expect(result.attempts).toBe(2);
      expect(opened[0].open).toBe(false);
    } finally {
      result.db?.close();
    }
  });

  it("knows a lock from other failures", () => {
    expect(isTransientOpenError(locked())).toBe(true);
    expect(isTransientOpenError(Object.assign(new Error("x"), { code: "SQLITE_BUSY_RECOVERY" }))).toBe(true);
    expect(isTransientOpenError(Object.assign(new Error("database table is locked"), { code: "SQLITE_LOCKED" }))).toBe(true);
    expect(isTransientOpenError(Object.assign(new Error("unable to open database file"), { code: "SQLITE_CANTOPEN" }))).toBe(false);
    expect(isTransientOpenError(new Error("file is not a database"))).toBe(false);
  });
});

describe("the process's cache, and which one it is", () => {
  let home: string;
  let prior: string | undefined;

  beforeEach(() => {
    closeServerCacheDb();
    prior = process.env.FOURDA_MCP_HOME;
    home = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-cache-"));
    process.env.FOURDA_MCP_HOME = home;
  });

  afterEach(() => {
    closeServerCacheDb();
    vi.restoreAllMocks();
    if (prior === undefined) delete process.env.FOURDA_MCP_HOME;
    else process.env.FOURDA_MCP_HOME = prior;
    fs.rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("on disk, at its path", () => {
    expect(getServerCacheDb()).not.toBeNull();
    expect(serverCacheState()).toMatchObject({ kind: "disk", path: path.join(home, "cache.db") });
  });

  it("in memory when the file cannot be opened, with the reason", () => {
    // A directory where the file should be: never a lock, so no retry.
    fs.mkdirSync(path.join(home, "cache.db"));
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const db = getServerCacheDb();
    expect(db?.open).toBe(true);
    const state = serverCacheState();
    expect(state).toMatchObject({ kind: "memory", path: path.join(home, "cache.db"), attempts: 1 });
    expect(state?.reason).toBeTruthy();
  });
});
