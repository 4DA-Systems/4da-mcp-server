// SPDX-License-Identifier: Apache-2.0
/**
 * The response cache lives in `cache.db`, as the README says, in standalone mode too (audit
 * 2026-11-11 W1 M2-4: standalone mode cached registry and OSV answers inside `standalone.db`,
 * beside the user's decisions and memories, so "delete cache.db to clear the cache" cleared
 * nothing and the record file grew with disposable rows).
 */
import * as fs from "node:fs";
import * as path from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";

import { FourDADatabase, serverCacheDbPath, standaloneDbPath } from "../db.js";
import { LiveCache } from "../live/cache.js";

describe("the cache file", () => {
  it("standalone mode caches in cache.db, never in standalone.db", () => {
    const file = standaloneDbPath();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const db = new FourDADatabase(file);
    try {
      expect(db.isStandalone).toBe(true);
      new LiveCache(db.getRawDb()).set("probe:standalone", { ok: true }, "probe", 60);
    } finally {
      db.close();
    }
    const standalone = new Database(file, { readonly: true, fileMustExist: true });
    try {
      const table = standalone.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'live_cache'").get();
      expect(table).toBeUndefined();
    } finally {
      standalone.close();
    }
    const cache = new Database(serverCacheDbPath(), { readonly: true, fileMustExist: true });
    try {
      expect(cache.prepare("SELECT COUNT(*) AS c FROM live_cache WHERE cache_key = 'probe:standalone'").get()).toEqual({ c: 1 });
    } finally {
      cache.close();
    }
  });

  it("a live_cache table an older server left in standalone.db is dropped", () => {
    const file = standaloneDbPath();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const raw = new Database(file);
    raw.exec("CREATE TABLE IF NOT EXISTS live_cache (cache_key TEXT PRIMARY KEY, data TEXT, source TEXT, fetched_at TEXT, expires_at TEXT)");
    raw.close();
    const db = new FourDADatabase(file);
    try {
      new LiveCache(db.getRawDb());
      expect(db.getRawDb().prepare("SELECT name FROM sqlite_master WHERE name = 'live_cache'").get()).toBeUndefined();
    } finally {
      db.close();
    }
  });

  it("an in-memory database passed in (tests) is still used as the cache", () => {
    const memory = new Database(":memory:");
    new LiveCache(memory).set("probe:memory", { ok: true }, "probe", 60);
    expect(memory.prepare("SELECT COUNT(*) AS c FROM live_cache").get()).toEqual({ c: 1 });
    memory.close();
  });
});
