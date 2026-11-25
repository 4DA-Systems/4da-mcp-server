// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25 G-1, --doctor side: validateDatabase() answers an app database that has not
 * finished setting up with `{ standalone: true, path: <own store>, note }`. Doctor printed "a
 * database of this server's own format" for it; it prints the note (why it is not used).
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { dataFolderChecks } from "../doctor.js";
import { closeServerCacheDb } from "../live/cache.js";

const ENV = ["FOURDA_MCP_HOME", "FOURDA_DB_PATH", "FOURDA_DATA_DIR", "APPDATA", "XDG_DATA_HOME", "HOME"] as const;
let saved: Record<string, string | undefined>;
let base: string;

beforeEach(() => {
  closeServerCacheDb();
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-int-doctor-")));
  process.env.FOURDA_MCP_HOME = path.join(base, "home");
  delete process.env.FOURDA_DB_PATH;
  for (const k of ["FOURDA_DATA_DIR", "APPDATA", "XDG_DATA_HOME", "HOME"] as const) process.env[k] = path.join(base, "no-app");
});

afterEach(() => {
  closeServerCacheDb();
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/** The desktop app's first batch, before its first migration (as a1125-app-own-store builds it). */
const FIRST_RUN = `
CREATE TABLE kv_store (key TEXT PRIMARY KEY NOT NULL, value, updated_at TEXT DEFAULT (datetime('now')));
CREATE TABLE sources (id INTEGER PRIMARY KEY AUTOINCREMENT, source_type TEXT NOT NULL UNIQUE, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, config TEXT, last_fetch TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE source_items (id INTEGER PRIMARY KEY AUTOINCREMENT, source_type TEXT NOT NULL, source_id TEXT NOT NULL, url TEXT, title TEXT NOT NULL, content TEXT NOT NULL DEFAULT '', content_hash TEXT NOT NULL, embedding BLOB NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), last_seen TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(source_type, source_id));
CREATE TABLE context_chunks (id INTEGER PRIMARY KEY AUTOINCREMENT, source_file TEXT NOT NULL, content_hash TEXT NOT NULL UNIQUE, text TEXT NOT NULL, embedding BLOB NOT NULL, weight REAL NOT NULL DEFAULT 1.0, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, source_item_id INTEGER NOT NULL, relevant INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
CREATE TABLE migration_history (id INTEGER PRIMARY KEY AUTOINCREMENT, from_version INTEGER NOT NULL, to_version INTEGER NOT NULL, executed_at TEXT NOT NULL DEFAULT (datetime('now')), duration_ms INTEGER NOT NULL DEFAULT 0, success INTEGER NOT NULL DEFAULT 0);
INSERT INTO schema_version (version) VALUES (1);
`;

describe("--doctor over an app database that has not finished setting up", () => {
  it("prints why it is not used, never 'a database of this server's own format'", () => {
    const file = path.join(base, "app", "4da.db");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const raw = new Database(file);
    raw.exec(FIRST_RUN);
    raw.close();
    process.env.FOURDA_DB_PATH = file;
    const check = dataFolderChecks().find((c) => c.name === "App database")!;
    expect(check).toBeDefined();
    expect(check.detail).not.toMatch(/this server's own format, not the desktop app's/);
    expect(check.detail).toMatch(/has not finished setting up/);
    expect(check.status).toBe("warn");
  });
});
