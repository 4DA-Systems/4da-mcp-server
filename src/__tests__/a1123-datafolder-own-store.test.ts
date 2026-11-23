// SPDX-License-Identifier: Apache-2.0
/**
 * The server's own store (`standalone.db` in the data folder) is recognised by its path and always
 * has its whole schema after an open. A first start killed while it created the file left one with
 * no tables; every later session read it as the desktop app's read-only database, said the
 * lockfile "may be unsupported or corrupted", and never gave it a schema.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { FourDADatabase, standaloneDbPath } from "../db.js";
import { openDatabase } from "../sqlite-driver.js";

/** Every table of the own store's schema, and its marker. */
const OWN_TABLES = [
  "schema_version", "source_items", "user_identity", "tech_stack", "domains", "explicit_interests", "exclusions",
  "detected_tech", "active_topics", "interactions", "feedback", "project_dependencies", "developer_decisions",
  "temporal_events", "item_relationships", "agent_memory", "source_health", "sources", "briefings",
  "autophagy_cycles", "digested_intelligence", "decision_windows", "advantage_score", "mcp_standalone",
];

const ENV = ["FOURDA_MCP_HOME", "FOURDA_DB_PATH", "FOURDA_DATA_DIR", "APPDATA", "XDG_DATA_HOME", "HOME"] as const;
let saved: Record<string, string | undefined>;
let base: string;

beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  base = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-own-store-"));
  process.env.FOURDA_MCP_HOME = path.join(base, "home");
  // No desktop app anywhere: the default database is the own store.
  delete process.env.FOURDA_DB_PATH;
  process.env.FOURDA_DATA_DIR = path.join(base, "no-app");
  process.env.APPDATA = path.join(base, "no-app");
  process.env.XDG_DATA_HOME = path.join(base, "no-app");
  process.env.HOME = path.join(base, "no-app");
  fs.mkdirSync(process.env.FOURDA_MCP_HOME, { recursive: true });
});

afterEach(() => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function tablesIn(file: string): string[] {
  const raw = openDatabase(file, { readonly: true, fileMustExist: true });
  try {
    return (raw.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as { name: string }[]).map((t) => t.name);
  } finally {
    raw.close();
  }
}

function expectWholeSchema(db: FourDADatabase): void {
  expect(db.isStandalone).toBe(true);
  expect(db.isReadOnly).toBe(false);
  const present = tablesIn(db.dbPath);
  expect(OWN_TABLES.filter((t) => !present.includes(t))).toEqual([]);
}

describe("opening the own store completes whatever schema it lacks", () => {
  it("a zero-byte file (a first start killed before it wrote anything)", () => {
    fs.writeFileSync(standaloneDbPath(), "");
    const db = new FourDADatabase();
    try {
      expect(path.resolve(db.dbPath)).toBe(path.resolve(standaloneDbPath()));
      expectWholeSchema(db);
    } finally {
      db.close();
    }
  });

  it("a database with no tables (its creator's schema transaction never committed)", () => {
    const raw = openDatabase(standaloneDbPath(), { readonly: false });
    raw.pragma("journal_mode = WAL");
    raw.exec("BEGIN IMMEDIATE");
    raw.exec("CREATE TABLE schema_version (version INTEGER PRIMARY KEY)");
    raw.exec("ROLLBACK");
    raw.close();
    expect(tablesIn(standaloneDbPath())).toEqual([]);

    const db = new FourDADatabase();
    try {
      expectWholeSchema(db);
    } finally {
      db.close();
    }
    // The next session finds it whole, and as the server's own.
    const again = new FourDADatabase();
    try {
      expectWholeSchema(again);
    } finally {
      again.close();
    }
  });

  it("a database with only some of the tables keeps its rows and gains the rest", () => {
    const raw = openDatabase(standaloneDbPath(), { readonly: false });
    raw.exec(`
      CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
      INSERT INTO schema_version (version) VALUES (1);
      CREATE TABLE developer_decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, decision_type TEXT NOT NULL, subject TEXT NOT NULL,
        decision TEXT NOT NULL, rationale TEXT, alternatives_rejected TEXT DEFAULT '[]', context_tags TEXT DEFAULT '[]',
        confidence REAL NOT NULL DEFAULT 0.8, status TEXT NOT NULL DEFAULT 'active', superseded_by INTEGER,
        created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        embedding BLOB, embedding_model TEXT
      );
      INSERT INTO developer_decisions (decision_type, subject, decision) VALUES ('tech_choice', 'react', 'kept');
    `);
    raw.close();

    const db = new FourDADatabase();
    try {
      expectWholeSchema(db);
      const raw2 = db.getRawDb();
      expect(raw2.prepare("SELECT decision FROM developer_decisions").all()).toEqual([{ decision: "kept" }]);
      expect(raw2.prepare("SELECT COUNT(*) AS c FROM schema_version").get()).toEqual({ c: 1 });
    } finally {
      db.close();
    }
  });

  it("the cheap probe calls the own store's file standalone whatever its tables", () => {
    fs.writeFileSync(standaloneDbPath(), "");
    const probe = FourDADatabase.validateDatabase();
    expect(probe.standalone).toBe(true);
  });
});

describe("two servers starting on a fresh data folder, in the racing order", () => {
  it("the probe found no file, then another server created it without tables: still the own store, completed", () => {
    // Server B lists its tools before any file exists.
    expect(FourDADatabase.validateDatabase().standalone).toBe(true);
    // Server A creates standalone.db and is killed (or still inside its schema transaction) before committing.
    const a = openDatabase(standaloneDbPath(), { readonly: false });
    a.pragma("journal_mode = WAL");
    a.close();
    // B's first tool call opens it.
    const b = new FourDADatabase();
    try {
      expectWholeSchema(b);
    } finally {
      b.close();
    }
  });

  it("both open the folder's store, one after the other and both open: one schema, one version row, both writable", () => {
    const first = new FourDADatabase();
    const second = new FourDADatabase();
    try {
      expectWholeSchema(first);
      expectWholeSchema(second);
      expect(second.getRawDb().prepare("SELECT COUNT(*) AS c FROM schema_version").get()).toEqual({ c: 1 });
      first.getRawDb().prepare("INSERT INTO agent_memory (session_id, agent_type, memory_type, subject, content) VALUES ('s', 'a', 'm', 'x', 'y')").run();
      expect(second.getRawDb().prepare("SELECT COUNT(*) AS c FROM agent_memory").get()).toEqual({ c: 1 });
    } finally {
      first.close();
      second.close();
    }
  });

  it("a server that created the file late finds the schema already there and adds nothing twice", () => {
    const early = new FourDADatabase();
    early.close();
    const late = new FourDADatabase(standaloneDbPath());
    try {
      expectWholeSchema(late);
      expect(late.getRawDb().prepare("SELECT COUNT(*) AS c FROM schema_version").get()).toEqual({ c: 1 });
    } finally {
      late.close();
    }
  });
});
