// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, G-1: the server may create tables in, or treat as its own, ONLY the file at its
 * own store path (standaloneDbPath()). A database reached through FOURDA_DB_PATH or the desktop app's
 * data folder is never adopted, whatever it holds:
 * - the app's database in its first-run state (schema_version 1, before migration 1 -> 2) is left
 *   untouched and the server runs on its own store, saying why;
 * - an app database that already carries the server's `mcp_standalone` marker (left by 6.5.1) is
 *   the app's: read-only, the marker ignored, nothing created.
 * The legitimate case keeps working: an own store at the default store path opens as before.
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";

import { FourDADatabase, standaloneDbPath } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { getLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { buildAppDb, VENDORED_APP_SCHEMA } from "./helpers/a1123-appmode.js";

/** The desktop app's first batch (migrations.rs, schema_version 1), as its first start leaves it before migration 1 -> 2. */
const APP_FIRST_RUN_SQL = `
CREATE TABLE context_chunks (id INTEGER PRIMARY KEY AUTOINCREMENT, source_file TEXT NOT NULL, content_hash TEXT NOT NULL UNIQUE, text TEXT NOT NULL, embedding BLOB NOT NULL, weight REAL NOT NULL DEFAULT 1.0, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE kv_store (key TEXT PRIMARY KEY NOT NULL, value, updated_at TEXT DEFAULT (datetime('now')));
CREATE TABLE source_items (id INTEGER PRIMARY KEY AUTOINCREMENT, source_type TEXT NOT NULL, source_id TEXT NOT NULL, url TEXT, title TEXT NOT NULL, content TEXT NOT NULL DEFAULT '', content_hash TEXT NOT NULL, embedding BLOB NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), last_seen TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(source_type, source_id));
CREATE TABLE sources (id INTEGER PRIMARY KEY AUTOINCREMENT, source_type TEXT NOT NULL UNIQUE, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, config TEXT, last_fetch TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, source_item_id INTEGER NOT NULL, relevant INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
CREATE TABLE migration_history (id INTEGER PRIMARY KEY AUTOINCREMENT, from_version INTEGER NOT NULL, to_version INTEGER NOT NULL, executed_at TEXT NOT NULL DEFAULT (datetime('now')), duration_ms INTEGER NOT NULL DEFAULT 0, success INTEGER NOT NULL DEFAULT 0);
INSERT INTO schema_version (version) VALUES (1);
`;

const ENV = ["FOURDA_MCP_HOME", "FOURDA_DB_PATH", "FOURDA_DATA_DIR", "APPDATA", "XDG_DATA_HOME", "HOME", "FOURDA_PROJECT_DIR"] as const;
let saved: Record<string, string | undefined>;
let base: string;
let priorLive: ReturnType<typeof getLiveIntelligence>;

beforeAll(() => {
  priorLive = getLiveIntelligence();
});
afterAll(() => {
  setLiveIntelligence(priorLive as LiveIntelligence);
});

beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-app-own-store-")));
  process.env.FOURDA_MCP_HOME = path.join(base, "home");
  delete process.env.FOURDA_DB_PATH;
  process.env.FOURDA_DATA_DIR = path.join(base, "no-app");
  process.env.APPDATA = path.join(base, "no-app");
  process.env.XDG_DATA_HOME = path.join(base, "no-app");
  process.env.HOME = path.join(base, "no-app");
  const project = path.join(base, "project");
  fs.mkdirSync(project, { recursive: true });
  process.env.FOURDA_PROJECT_DIR = project;
  const live = new LiveIntelligence(null);
  live.initFromProjectTree(project, [], null);
  setLiveIntelligence(live);
});

afterEach(() => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  try {
    fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {
    // Windows: the live layer's response cache (cache.db) can still be open; the temp folder is left.
  }
});

function firstRunApp(file: string, marker = false): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const raw = new Database(file);
  raw.exec(APP_FIRST_RUN_SQL);
  if (marker) raw.exec("CREATE TABLE mcp_standalone (created_at TEXT DEFAULT (datetime('now')))");
  raw.close();
}

function fingerprint(file: string): { sha: string; tables: number } {
  const sha = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  const raw = new Database(file, { readonly: true, fileMustExist: true });
  const tables = (raw.prepare("SELECT COUNT(*) AS c FROM sqlite_master WHERE type='table'").get() as { c: number }).c;
  raw.close();
  return { sha, tables };
}

/** The calls the audit's repro made: get_context, agent_memory store, developer_dna. */
async function session(): Promise<FourDADatabase> {
  const db = new FourDADatabase();
  await dispatchTool("get_context", db, {});
  await dispatchTool("agent_memory", db, { action: "store", subject: "a1125", content: "probe", agent_type: "test" });
  await dispatchTool("developer_dna", db, {});
  return db;
}

describe("G-1: an app database is never adopted as the server's own store", () => {
  it.each([
    ["FOURDA_DB_PATH", false],
    ["FOURDA_DB_PATH, marker left by 6.5.1", true],
    ["the app's data folder", false],
  ] as const)("first-run app database reached through %s: byte-identical, the server runs on its own store and says why", async (how, marker) => {
    const appFile = how === "the app's data folder" ? path.join(process.env.FOURDA_DATA_DIR!, "4da.db") : path.join(base, "app", "4da.db");
    firstRunApp(appFile, marker);
    if (how !== "the app's data folder") process.env.FOURDA_DB_PATH = appFile;
    const before = fingerprint(appFile);

    const db = await session();
    try {
      expect(path.resolve(db.dbPath)).toBe(path.resolve(standaloneDbPath()));
      expect(db.isStandalone).toBe(true);
      const note = db.takeCreationNote() ?? "";
      expect(note).toContain(appFile);
      expect(note).toMatch(/has not finished setting up/);
      expect(note).toMatch(/dependency tools still read/);
      const memories = db.getRawDb().prepare("SELECT COUNT(*) AS c FROM agent_memory").get() as { c: number };
      expect(memories.c).toBe(1);
    } finally {
      db.close();
    }
    expect(fingerprint(appFile)).toEqual(before);

    // A second start finds it the same way and still changes nothing.
    const again = new FourDADatabase();
    try {
      expect(path.resolve(again.dbPath)).toBe(path.resolve(standaloneDbPath()));
    } finally {
      again.close();
    }
    expect(fingerprint(appFile)).toEqual(before);
    const probe = FourDADatabase.validateDatabase(process.env.FOURDA_DB_PATH || undefined);
    expect(probe).toMatchObject({ valid: true, standalone: true });
    expect(path.resolve(probe.path!)).toBe(path.resolve(standaloneDbPath()));
    expect(probe.note ?? "").toMatch(/has not finished setting up/);
  });

  it.skipIf(!fs.existsSync(VENDORED_APP_SCHEMA))("a set-up app database carrying the marker is the app's: read-only, nothing created, desktop tools kept", async () => {
    const appFile = path.join(base, "app", "4da.db");
    fs.mkdirSync(path.dirname(appFile), { recursive: true });
    buildAppDb(appFile, VENDORED_APP_SCHEMA, (raw) => raw.exec("CREATE TABLE mcp_standalone (created_at TEXT DEFAULT (datetime('now')))"));
    process.env.FOURDA_DB_PATH = appFile;
    const raw = new Database(appFile);
    const interestsBefore = (raw.prepare("SELECT COUNT(*) AS c FROM explicit_interests").get() as { c: number }).c;
    raw.close();
    const before = fingerprint(appFile);

    const db = new FourDADatabase();
    try {
      expect(db.isStandalone).toBe(false);
      expect(db.isReadOnly).toBe(true);
      expect(path.resolve(db.dbPath)).toBe(path.resolve(appFile));
      await dispatchTool("get_context", db, {});
      await dispatchTool("developer_dna", db, {});
    } finally {
      db.close();
    }
    expect(fingerprint(appFile).tables).toBe(before.tables);
    const after = new Database(appFile, { readonly: true });
    expect((after.prepare("SELECT COUNT(*) AS c FROM explicit_interests").get() as { c: number }).c).toBe(interestsBefore);
    after.close();
    expect(FourDADatabase.validateDatabase(appFile).standalone).toBe(false);
  });

  it("an explicit path argument never adopts an app first-run database either", () => {
    const appFile = path.join(base, "app", "4da.db");
    firstRunApp(appFile, true);
    const before = fingerprint(appFile);
    const db = new FourDADatabase(appFile);
    try {
      expect(db.isStandalone).toBe(false);
      expect(db.isReadOnly).toBe(true);
    } finally {
      db.close();
    }
    expect(fingerprint(appFile)).toEqual(before);
  });

  it("the own store at the default store path still opens with its decisions and memories", async () => {
    const own = standaloneDbPath();
    const first = new FourDADatabase();
    try {
      expect(path.resolve(first.dbPath)).toBe(path.resolve(own));
      await dispatchTool("agent_memory", first, { action: "store", subject: "kept", content: "kept memory", agent_type: "test" });
      await dispatchTool("decision_memory", first, { action: "record", subject: "kept decision", decision: "use x", rationale: "because" });
    } finally {
      first.close();
    }
    const again = new FourDADatabase();
    try {
      expect(again.isStandalone).toBe(true);
      expect(again.takeCreationNote()).toBeNull();
      const raw = again.getRawDb();
      expect((raw.prepare("SELECT COUNT(*) AS c FROM agent_memory").get() as { c: number }).c).toBe(1);
      expect((raw.prepare("SELECT COUNT(*) AS c FROM developer_decisions").get() as { c: number }).c).toBe(1);
    } finally {
      again.close();
    }
  });
});
