// SPDX-License-Identifier: Apache-2.0
/**
 * What the server may do to the desktop app's database.
 *
 * Measured 2026-10-07: 6.0.2 created a `live_cache` table inside the app's
 * live `4da.db` (2,774 rows on one machine) that the app's migrations do not
 * own. The contract now:
 * - the app's schema never changes (no table, index or column is created);
 * - the server's caches live in its own `cache.db`;
 * - the only rows the server adds are in the app-owned tables its tools exist
 *   to write: developer_decisions, agent_memory, interactions and feedback
 *   (the app's decision UI and calibration read them), through a separate
 *   write connection; everything else is read through a read-only one;
 * - a record the app's schema cannot hold goes to the server's store with a
 *   `_meta` note, never into a table the server would have to create.
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
import { changedTables, snapshotDb } from "./helpers/db-snapshot.js";

const APP_TABLES = `
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
  INSERT INTO project_dependencies VALUES ('d:/proj', 'cargo', 'tokio', '1.50.0', 0, 1, 'rust');
  CREATE TABLE interactions (id INTEGER PRIMARY KEY, item_id INTEGER, action_type TEXT,
    item_source TEXT, signal_strength REAL, timestamp TEXT);
  CREATE TABLE feedback (id INTEGER PRIMARY KEY, source_item_id INTEGER NOT NULL,
    relevant INTEGER NOT NULL, created_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE developer_decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, decision_type TEXT NOT NULL,
    subject TEXT NOT NULL, decision TEXT NOT NULL, rationale TEXT, alternatives_rejected TEXT DEFAULT '[]',
    context_tags TEXT DEFAULT '[]', confidence REAL NOT NULL DEFAULT 0.8, status TEXT NOT NULL DEFAULT 'active',
    superseded_by INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')));
`;
const AGENT_MEMORY = `
  CREATE TABLE agent_memory (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
    agent_type TEXT NOT NULL, memory_type TEXT NOT NULL, subject TEXT NOT NULL, content TEXT NOT NULL,
    context_tags TEXT DEFAULT '[]', created_at TEXT NOT NULL DEFAULT (datetime('now')), expires_at TEXT,
    promoted_to_decision_id INTEGER);
`;

/** An app-shaped database: no standalone marker, schema version past 100. */
function makeAppDb(file: string, opts: { agentMemory?: boolean } = {}): void {
  const raw = new Database(file);
  raw.exec(APP_TABLES + (opts.agentMemory === false ? "" : AGENT_MEMORY));
  raw.close();
}

const sha = (file: string) => createHash("sha256").update(fs.readFileSync(file)).digest("hex");

// Generous: these create and open SQLite files, which an on-access scanner can hold.
describe("the desktop app's database and the server", { timeout: 60_000 }, () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-app-db-"));
    file = path.join(dir, "4da.db");
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("reads through a readonly + fileMustExist connection, which SQLite refuses to write through", () => {
    makeAppDb(file);
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
          raw.prepare("INSERT INTO source_items (id, source_type) VALUES (8, 'x')").run();
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

  it("caching never touches the app's database: the file stays byte-for-byte identical", () => {
    makeAppDb(file);
    const before = sha(file);
    const db = new FourDADatabase(file);
    try {
      expect(new LiveIntelligence(db.getRawDb())).toBeTruthy();
      const cache = new LiveCache(db.getRawDb());
      cache.set("probe:key", { ok: true }, "probe", 60);
      expect(cache.get<{ ok: boolean }>("probe:key")).toEqual({ ok: true });
    } finally {
      db.close();
    }
    expect(sha(file)).toBe(before);
    const cacheDb = new Database(serverCacheDbPath(), { readonly: true, fileMustExist: true });
    try {
      expect(cacheDb.prepare("SELECT COUNT(*) AS c FROM live_cache WHERE cache_key = 'probe:key'").get()).toEqual({ c: 1 });
    } finally {
      cacheDb.close();
    }
  });

  it("decisions, agent memory and feedback reach the app's own tables; schema and every other table unchanged", async () => {
    makeAppDb(file);
    const before = snapshotDb(file);
    const db = new FourDADatabase(file);
    try {
      new LiveCache(db.getRawDb()).set("probe:key", { ok: true }, "probe", 60);

      const feedback = db.recordFeedback(7, undefined, "save");
      expect(feedback.success).toBe(true);
      expect(feedback).not.toHaveProperty("_meta");

      const recorded = (await executeDecisionMemory(db, {
        action: "record",
        decision_type: "tech_choice",
        subject: "react",
        decision: "Use React 19",
        rationale: "app-db test",
      })) as { success?: boolean; id?: number; _meta?: unknown };
      expect(recorded.success).toBe(true);
      expect(recorded._meta).toBeUndefined();
      // Read back through the read-only connection: the app sees it, and so do the tools.
      const alignment = await executeCheckDecisionAlignment(db, { technology: "react" });
      expect(JSON.stringify(alignment)).toContain("React 19");
      const updated = (await executeDecisionMemory(db, { action: "update", id: Number(recorded.id), new_status: "reconsidering" })) as {
        success?: boolean;
      };
      expect(updated.success).toBe(true);

      const stored = (await executeAgentMemory(db, { action: "store", subject: "app-db", content: "kept in the app" })) as {
        success?: boolean;
        _meta?: unknown;
      };
      expect(stored.success).toBe(true);
      expect(stored._meta).toBeUndefined();
    } finally {
      db.close();
    }

    const after = snapshotDb(file);
    expect(after.schema).toEqual(before.schema); // sqlite_master identical: nothing created or altered
    expect(changedTables(before, after)).toEqual(["agent_memory", "developer_decisions", "feedback", "interactions"]);
    expect(after.tables.feedback.rows).toBe(before.tables.feedback.rows + 1);
    expect(after.tables.interactions.rows).toBe(before.tables.interactions.rows + 1);
    expect(after.tables.developer_decisions.rows).toBe(before.tables.developer_decisions.rows + 1);
    expect(after.tables.agent_memory.rows).toBe(before.tables.agent_memory.rows + 1);
    expect(Object.keys(after.tables)).not.toContain("live_cache");

    const app = new Database(file, { readonly: true, fileMustExist: true });
    try {
      expect(app.prepare("SELECT status FROM developer_decisions WHERE subject = 'react'").get()).toEqual({ status: "reconsidering" });
      expect(app.prepare("SELECT source_item_id, relevant FROM feedback").get()).toEqual({ source_item_id: 7, relevant: 1 });
    } finally {
      app.close();
    }
  });

  it("schema drift: a table the app lacks is never created; the record goes to the server's store with a note", async () => {
    makeAppDb(file, { agentMemory: false });
    const before = snapshotDb(file);
    const db = new FourDADatabase(file);
    let note = "";
    try {
      const stored = (await executeAgentMemory(db, { action: "store", subject: "drift", content: "no app table" })) as {
        success?: boolean;
        _meta?: { written_to: string; note: string };
      };
      expect(stored.success).toBe(true);
      expect(stored._meta?.written_to).toBe("server_store");
      note = stored._meta?.note ?? "";
    } finally {
      db.close();
    }
    expect(note).toMatch(/agent_memory table does not exist/);
    expect(note).toContain(standaloneDbPath());
    expect(snapshotDb(file)).toEqual(before);
    const store = new Database(standaloneDbPath(), { readonly: true, fileMustExist: true });
    try {
      expect((store.prepare("SELECT COUNT(*) AS c FROM agent_memory WHERE subject = 'drift'").get() as { c: number }).c).toBe(1);
    } finally {
      store.close();
    }
  });

  it("still opens the server's own standalone database writable, and writes there directly", () => {
    const own = path.join(dir, "standalone.db");
    const created = new FourDADatabase(own);
    expect(created.isStandalone).toBe(true);
    expect(created.isReadOnly).toBe(false);
    created.close();
    const reopened = new FourDADatabase(own);
    try {
      expect(reopened.isStandalone).toBe(true);
      expect(reopened.isReadOnly).toBe(false);
      expect(reopened.writerFor("feedback", ["source_item_id", "relevant"])).toMatchObject({ target: "database" });
    } finally {
      reopened.close();
    }
  });
});
