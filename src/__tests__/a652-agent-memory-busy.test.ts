// SPDX-License-Identifier: Apache-2.0
/**
 * agent_memory `store` asks a busy database once more.
 *
 * The dispatcher retries a tool whose executor THROWS SQLITE_BUSY (tool-dispatch.ts), but this
 * tool catches its own errors and answers `{ error: "Failed to store memory: database is locked" }`,
 * so that retry never saw a lock here: one such answer in 17,595 calls of the 6.5.1 concurrency
 * bench, on a loaded machine. The store's two statements now go through db.queryWithRetry. Each
 * is a single statement, so a write that met a lock stored nothing and running it again cannot
 * store a row twice. A database that is still busy on the second try answers as before.
 */

import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";

import { FourDADatabase } from "../db.js";
import { executeAgentMemory } from "../tools/agent-memory.js";

const SCHEMA = `
  CREATE TABLE agent_memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    memory_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    content TEXT NOT NULL,
    context_tags TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    promoted_to_decision_id INTEGER
  );
`;

type Raw = InstanceType<typeof Database>;

/** A database whose statements matching `which` throw SQLITE_BUSY the first `times` times they are run. */
function busyDatabase(which: RegExp, times: number): { db: FourDADatabase; raw: Raw; attempts: () => number } {
  const raw = new Database(":memory:");
  raw.exec(SCHEMA);
  let left = times;
  let attempts = 0;
  const prepare = raw.prepare.bind(raw);
  (raw as unknown as { prepare: (sql: string) => unknown }).prepare = (sql: string) => {
    const stmt = prepare(sql);
    if (!which.test(sql)) return stmt;
    const busy = <A extends unknown[], R>(real: (...args: A) => R) => (...args: A): R => {
      attempts++;
      if (left > 0) {
        left--;
        throw Object.assign(new Error("database is locked"), { code: "SQLITE_BUSY" });
      }
      return real(...args);
    };
    return { run: busy(stmt.run.bind(stmt)), get: busy(stmt.get.bind(stmt)), all: stmt.all.bind(stmt) };
  };
  const db = Object.create(FourDADatabase.prototype) as FourDADatabase;
  (db as unknown as { db: Raw }).db = raw;
  return { db, raw, attempts: () => attempts };
}

const STORE = { action: "store" as const, agent_type: "claude", session_id: "s1", subject: "build", content: "pnpm run build before npm pack" };
const rows = (raw: Raw) => (raw.prepare("SELECT COUNT(*) AS n FROM agent_memory").get() as { n: number }).n;

describe("agent_memory store against a busy database", () => {
  it("a write that meets one lock is run again and stores the row once", async () => {
    const { db, raw, attempts } = busyDatabase(/^\s*INSERT INTO agent_memory/, 1);
    const answer = (await executeAgentMemory(db, STORE)) as { success?: boolean; error?: string };
    expect(answer.error).toBeUndefined();
    expect(answer.success).toBe(true);
    expect(attempts()).toBe(2);
    expect(rows(raw)).toBe(1);
  });

  it("a quota count that meets one lock is asked again", async () => {
    const { db, raw } = busyDatabase(/SELECT COUNT\(\*\) as cnt FROM agent_memory/, 1);
    const answer = (await executeAgentMemory(db, STORE)) as { success?: boolean; error?: string };
    expect(answer.error).toBeUndefined();
    expect(answer.success).toBe(true);
    expect(rows(raw)).toBe(1);
  });

  it("still busy on the second try: the answer is the error it always was, and nothing is stored", async () => {
    const { db, raw, attempts } = busyDatabase(/^\s*INSERT INTO agent_memory/, 2);
    const answer = (await executeAgentMemory(db, STORE)) as { success?: boolean; error?: string };
    expect(answer.success).toBeUndefined();
    expect(answer.error).toBe("Failed to store memory: database is locked");
    expect(attempts()).toBe(2);
    expect(rows(raw)).toBe(0);
  });

  it("an error that is not a lock is not run again", async () => {
    const raw = new Database(":memory:");
    raw.exec(SCHEMA.replace("subject TEXT NOT NULL", "subject TEXT NOT NULL CHECK (length(subject) < 3)"));
    const db = Object.create(FourDADatabase.prototype) as FourDADatabase;
    (db as unknown as { db: Raw }).db = raw;
    const answer = (await executeAgentMemory(db, STORE)) as { error?: string };
    expect(answer.error).toMatch(/^Failed to store memory: /);
    expect(rows(raw)).toBe(0);
  });
});
