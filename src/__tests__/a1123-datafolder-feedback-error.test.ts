// SPDX-License-Identifier: Apache-2.0
/**
 * record_feedback that records nothing is a failed call. Under the desktop app's write lock it
 * answered `{"success":false,"message":"... database is locked"}` with no `isError`, so a host read
 * it as done; decision_memory and agent_memory already flag the same failure. Now every
 * `success: false` carries `error` (dispatchTool sets `isError: true`), and a lock says to retry.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { FourDADatabase } from "../db.js";
import { openDatabase, type SqliteDatabase } from "../sqlite-driver.js";
import { dispatchTool } from "../tool-dispatch.js";

const APP = `
  CREATE TABLE schema_version (version INTEGER PRIMARY KEY); INSERT INTO schema_version VALUES (124);
  CREATE TABLE source_items (id INTEGER PRIMARY KEY, source_type TEXT NOT NULL, source_id TEXT, url TEXT, title TEXT, content TEXT,
    created_at TEXT DEFAULT (datetime('now')));
  INSERT INTO source_items (id, source_type, title) VALUES (7, 'hackernews', 'An item');
  CREATE TABLE interactions (id INTEGER PRIMARY KEY, item_id INTEGER, action_type TEXT, item_source TEXT, signal_strength REAL, timestamp TEXT);
  CREATE TABLE feedback (id INTEGER PRIMARY KEY, source_item_id INTEGER NOT NULL, relevant INTEGER NOT NULL, created_at TEXT DEFAULT (datetime('now')));
`;

const payload = (r: Awaited<ReturnType<typeof dispatchTool>>) => JSON.parse((r.content[0] as { text: string }).text) as Record<string, unknown>;

describe("record_feedback that records nothing is an error", { timeout: 60_000 }, () => {
  let dir: string;
  let file: string;
  let db: FourDADatabase;
  let holder: SqliteDatabase | null = null;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-feedback-"));
    file = path.join(dir, "4da.db");
    const raw = openDatabase(file, { readonly: false });
    raw.pragma("journal_mode = WAL");
    raw.exec(APP);
    raw.close();
    db = new FourDADatabase(file);
    expect(db.isStandalone).toBe(false);
  });

  afterEach(() => {
    if (holder?.open) {
      try {
        holder.exec("ROLLBACK");
      } catch {
        // no transaction open
      }
      holder.close();
    }
    holder = null;
    db.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("under the app's write lock: isError, the lock named, a retry suggested; nothing written", async () => {
    holder = openDatabase(file, { readonly: false });
    holder.exec("BEGIN IMMEDIATE");
    const result = await dispatchTool("record_feedback", db, { item_id: 7, action: "save" });
    expect(result.isError).toBe(true);
    const body = payload(result);
    expect(body.success).toBe(false);
    expect(String(body.error)).toMatch(/database is locked/);
    expect(String(body.error)).toMatch(/retry/i);
    holder.exec("ROLLBACK");
    const check = openDatabase(file, { readonly: true, fileMustExist: true });
    try {
      expect(check.prepare("SELECT COUNT(*) AS c FROM interactions").get()).toEqual({ c: 0 });
    } finally {
      check.close();
    }
  });

  it("an item that does not exist: isError with the reason", async () => {
    const result = await dispatchTool("record_feedback", db, { item_id: 6, action: "click" });
    expect(result.isError).toBe(true);
    expect(payload(result)).toMatchObject({ success: false, error: "Item 6 not found" });
  });

  it("a recorded one is not an error", async () => {
    const result = await dispatchTool("record_feedback", db, { item_id: 7, action: "save" });
    expect(result.isError).toBeFalsy();
    expect(payload(result)).toMatchObject({ success: true });
    expect(payload(result)).not.toHaveProperty("error");
  });
});
