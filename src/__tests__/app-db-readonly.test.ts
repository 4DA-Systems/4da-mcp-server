// SPDX-License-Identifier: Apache-2.0
/**
 * The desktop app's database is opened read-only, and nothing the server does
 * writes to it.
 *
 * Measured 2026-10-07: 6.0.2 opened the app's live `4da.db` read-write, created
 * a `live_cache` table in it (2,774 rows on one machine) that the app's
 * migrations do not own, and wrote decisions, agent memory and feedback into
 * app tables. The app owns that file. Everything the server writes now goes to
 * its own files: `cache.db` and `standalone.db` under FOURDA_MCP_HOME (a temp
 * directory in tests, see test-setup.ts).
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { FourDADatabase, serverCacheDbPath, standaloneDbPath } from "../db.js";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { executeAgentMemory } from "../tools/agent-memory.js";
import { executeDecisionMemory } from "../tools/decision-memory.js";
import { executeCheckDecisionAlignment } from "../tools/decision-enforcement.js";

/** An app-shaped database: no standalone marker, schema version past 100. */
function makeAppDb(file: string): void {
  const raw = new Database(file);
  raw.exec(`
    CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
    INSERT INTO schema_version (version) VALUES (124);
    CREATE TABLE source_items (
      id INTEGER PRIMARY KEY, source_type TEXT NOT NULL, source_id TEXT, url TEXT,
      title TEXT, content TEXT, created_at TEXT DEFAULT (datetime('now'))
    );
    INSERT INTO source_items (id, source_type, title) VALUES (7, 'hackernews', 'An item');
    CREATE TABLE project_dependencies (
      project_path TEXT, manifest_type TEXT, package_name TEXT, version TEXT,
      is_dev INTEGER DEFAULT 0, is_direct INTEGER DEFAULT 1, language TEXT
    );
    CREATE TABLE interactions (id INTEGER PRIMARY KEY, item_id INTEGER, action_type TEXT,
      item_source TEXT, signal_strength REAL, timestamp TEXT);
    CREATE TABLE feedback (id INTEGER PRIMARY KEY, source_item_id INTEGER NOT NULL,
      relevant INTEGER NOT NULL, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE developer_decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, decision_type TEXT NOT NULL,
      subject TEXT NOT NULL, decision TEXT NOT NULL, rationale TEXT, alternatives_rejected TEXT DEFAULT '[]',
      context_tags TEXT DEFAULT '[]', confidence REAL NOT NULL DEFAULT 0.8, status TEXT NOT NULL DEFAULT 'active',
      superseded_by INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')));
    CREATE TABLE agent_memory (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
      agent_type TEXT NOT NULL, memory_type TEXT NOT NULL, subject TEXT NOT NULL, content TEXT NOT NULL,
      context_tags TEXT DEFAULT '[]', created_at TEXT NOT NULL DEFAULT (datetime('now')), expires_at TEXT,
      promoted_to_decision_id INTEGER);
  `);
  raw.close();
}

function fingerprint(file: string): { sha: string; mtimeMs: number; siblings: string[] } {
  return {
    sha: createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
    mtimeMs: fs.statSync(file).mtimeMs,
    siblings: fs.readdirSync(path.dirname(file)).sort(),
  };
}

// Generous: these create and open SQLite files, which an on-access scanner can hold.
describe("the desktop app's database is read-only to the server", { timeout: 60_000 }, () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-app-ro-"));
    file = path.join(dir, "4da.db");
    makeAppDb(file);
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("opens it with readonly + fileMustExist, so any write is refused by SQLite", () => {
    const db = new FourDADatabase(file);
    try {
      expect(db.isStandalone).toBe(false);
      expect(db.isReadOnly).toBe(true);
      const raw = db.getRawDb();
      expect(raw.readonly).toBe(true);
      // A scanner opening the fresh temp file can make SQLite report BUSY first
      // (seen twice under load on Windows); the refusal itself is READONLY.
      let code: string | undefined;
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          raw.prepare("INSERT INTO feedback (source_item_id, relevant) VALUES (7, 1)").run();
          code = "WROTE";
        } catch (error) {
          code = (error as { code?: string }).code;
        }
        if (code !== "SQLITE_BUSY") break;
      }
      expect(code).toBe("SQLITE_READONLY");
      expect(() => db.ensureColumn("agent_memory", "embedding", "BLOB")).toThrow(/never alters/);
    } finally {
      db.close();
    }
  });

  it("caching, feedback, decisions and agent memory leave the file byte-for-byte unchanged", async () => {
    const before = fingerprint(file);
    const db = new FourDADatabase(file);
    try {
      // The live layer and its cache: the table used to be created in the app DB.
      const live = new LiveIntelligence(db.getRawDb());
      expect(live).toBeTruthy();
      const cache = new LiveCache(db.getRawDb());
      cache.set("probe:key", { ok: true }, "probe", 60);
      expect(cache.get<{ ok: boolean }>("probe:key")).toEqual({ ok: true });

      const feedback = db.recordFeedback(7, undefined, "save");
      expect(feedback.success).toBe(true);
      expect(feedback.message).toContain(standaloneDbPath());

      const recorded = (await executeDecisionMemory(db, {
        action: "record",
        decision_type: "tech_choice",
        subject: "react",
        decision: "Use React 19",
        rationale: "read-only test",
      })) as { success?: boolean };
      expect(recorded.success).toBe(true);
      const alignment = await executeCheckDecisionAlignment(db, { technology: "react" });
      expect(JSON.stringify(alignment)).toContain("React 19");

      const stored = (await executeAgentMemory(db, {
        action: "store",
        subject: "ro-test",
        content: "kept in the server's store",
      })) as { success?: boolean };
      expect(stored.success).toBe(true);
    } finally {
      db.close();
    }

    expect(fingerprint(file)).toEqual(before);

    const app = new Database(file, { readonly: true, fileMustExist: true });
    try {
      const tables = (app.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[]).map(
        (t) => t.name,
      );
      expect(tables).not.toContain("live_cache");
      expect(app.prepare("SELECT COUNT(*) AS c FROM feedback").get()).toEqual({ c: 0 });
      expect(app.prepare("SELECT COUNT(*) AS c FROM developer_decisions").get()).toEqual({ c: 0 });
      expect(app.prepare("SELECT COUNT(*) AS c FROM agent_memory").get()).toEqual({ c: 0 });
    } finally {
      app.close();
    }

    // What was recorded is in the server's own files.
    const cacheDb = new Database(serverCacheDbPath(), { readonly: true, fileMustExist: true });
    try {
      expect(cacheDb.prepare("SELECT COUNT(*) AS c FROM live_cache WHERE cache_key = 'probe:key'").get()).toEqual({ c: 1 });
    } finally {
      cacheDb.close();
    }
    const store = new Database(standaloneDbPath(), { readonly: true, fileMustExist: true });
    try {
      expect(
        (store.prepare("SELECT COUNT(*) AS c FROM developer_decisions WHERE subject = 'react'").get() as { c: number }).c,
      ).toBeGreaterThan(0);
      expect(
        (store.prepare("SELECT COUNT(*) AS c FROM agent_memory WHERE subject = 'ro-test'").get() as { c: number }).c,
      ).toBeGreaterThan(0);
      expect(
        (store.prepare("SELECT COUNT(*) AS c FROM feedback WHERE source_item_id = 7").get() as { c: number }).c,
      ).toBeGreaterThan(0);
    } finally {
      store.close();
    }
  });

  it("still opens the server's own standalone database writable", () => {
    const own = path.join(dir, "standalone.db");
    const created = new FourDADatabase(own);
    expect(created.isStandalone).toBe(true);
    expect(created.isReadOnly).toBe(false);
    created.close();
    const reopened = new FourDADatabase(own);
    try {
      expect(reopened.isStandalone).toBe(true);
      expect(reopened.isReadOnly).toBe(false);
      expect(reopened.getMemoryStore()).toBe(reopened);
    } finally {
      reopened.close();
    }
  });
});
