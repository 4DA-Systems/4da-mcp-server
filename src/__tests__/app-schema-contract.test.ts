// SPDX-License-Identifier: Apache-2.0
/**
 * App-schema contract: every tool, run against the desktop app's REAL schema.
 *
 * The desktop app (github.com/4DA-Systems/4DA) owns `4da.db`; this server
 * reads about 30 of its tables and writes none (read-only). The two live in different
 * repositories, so neither one's tests can see the other's changes. The app
 * publishes its schema as `src-tauri/contract/app-schema.sql`, generated from
 * its migrations and checked in its CI; `contract/app-schema.sql` here is a
 * copy (`pnpm run contract:sync` refreshes it, and CI also checks the app's
 * current `main`).
 *
 * The other suites build their own fixture tables, which can quietly drift
 * from what the app actually creates. This one loads the real schema, seeds a
 * row into every table, calls every tool through the same dispatcher the
 * server uses, and fails if any statement names a table or column the app
 * does not have, or if any `hasColumn` probe finds a column missing.
 *
 * `FOURDA_APP_SCHEMA=<path>` points it at another schema file (the app's CI
 * uses that to test a migration before it merges).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { DEPENDENCY_GROUP_QUERY, FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { getLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
// @ts-expect-error -- plain ESM helper shared with scripts/app-schema-contract.mjs
import { loadAppSchema, SCHEMA_ERROR } from "../../scripts/app-schema-loader.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = process.env.FOURDA_APP_SCHEMA
  ? path.resolve(process.env.FOURDA_APP_SCHEMA)
  : path.resolve(here, "..", "..", "contract", "app-schema.sql");

/**
 * `hasColumn` probes that are expected to come back false on the current
 * schema, with the reason. A probe for a column the app no longer has is how
 * a dropped column silently degrades a tool, so every entry needs a reason.
 */
const EXPECTED_MISSING_COLUMNS: Record<string, string> = {};

/** A value of the column's declared type that most columns will accept. */
function seedValue(name: string, declared: string): unknown {
  const type = declared.toUpperCase();
  const n = name.toLowerCase();
  if (type.includes("INT")) return 1;
  if (type.includes("REAL") || type.includes("FLOA") || type.includes("DOUB") || type.includes("NUM")) return 0.5;
  if (type.includes("BLOB")) return Buffer.alloc(4);
  if (/(_at|_date|date|time|timestamp|_until|_since)$/.test(n)) return "2026-10-01 00:00:00";
  if (/(json|tags|ids|data|metadata|payload|evidence|items|list|details|steps|signals|topics|keywords)$/.test(n)) {
    return "[]";
  }
  return "seed";
}

/** One row per table, so queries run past their "no rows" early returns. */
function seedEveryTable(db: Database.Database, skip: Set<string>): void {
  db.pragma("foreign_keys = OFF");
  const tables = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND sql NOT LIKE 'CREATE VIRTUAL%'")
    .all() as { name: string }[];
  for (const { name } of tables) {
    if (skip.has(name) || name.startsWith("sqlite_")) continue;
    const cols = db.pragma(`table_info("${name}")`) as {
      name: string;
      type: string;
      notnull: number;
      dflt_value: unknown;
      pk: number;
    }[];
    const attempt = (include: (c: (typeof cols)[number]) => boolean): boolean => {
      const chosen = cols.filter(include);
      if (chosen.length === 0) {
        try {
          db.prepare(`INSERT INTO "${name}" DEFAULT VALUES`).run();
          return true;
        } catch {
          return false;
        }
      }
      try {
        db.prepare(
          `INSERT INTO "${name}" (${chosen.map((c) => `"${c.name}"`).join(", ")}) VALUES (${chosen.map(() => "?").join(", ")})`,
        ).run(...chosen.map((c) => seedValue(c.name, c.type)));
        return true;
      } catch {
        return false;
      }
    };
    // Every column without a default first; then only what NOT NULL demands.
    if (!attempt((c) => c.dflt_value === null && !(c.pk && c.type.toUpperCase() === "INTEGER"))) {
      attempt((c) => c.notnull === 1 && c.dflt_value === null);
    }
  }
}

/** Every tool, with arguments that reach its database work. */
const CALLS: [string, Record<string, unknown>][] = [
  ["get_context", {}],
  ["get_relevant_content", {}],
  ["get_relevant_content", { signal_type: "security_alert", min_score: 0 }],
  ["get_actionable_signals", {}],
  ["knowledge_gaps", {}],
  ["what_should_i_know", { task: "upgrade react and axum" }],
  ["developer_dna", {}],
  ["ecosystem_pulse", {}],
  ["vulnerability_scan", {}],
  ["dependency_health", {}],
  ["upgrade_planner", {}],
  ["dependency_check", { items: [{ ecosystem: "npm", package: "react", to: "19.0.0" }] }],
  ["upgrade_impact", { package: "react", to_version: "19.0.0" }],
  ["record_feedback", { item_id: 1, action: "save" }],
  ["record_feedback", { item_id: 1, action: "dismiss" }],
  ["decision_memory", { action: "list" }],
  [
    "decision_memory",
    { action: "record", decision_type: "tech_choice", subject: "react", decision: "Use React 19", rationale: "contract" },
  ],
  ["decision_memory", { action: "check_alignment", technology: "react" }],
  ["decision_memory", { action: "update", id: 2, new_rationale: "contract update", new_status: "reconsidering" }],
  ["decision_memory", { action: "supersede", old_id: 1, new_id: 2 }],
  ["check_decision_alignment", { technology: "react" }],
  ["agent_memory", { action: "store", subject: "contract", content: "seeded by the contract test" }],
  ["agent_memory", { action: "recall", query: "contract" }],
  ["agent_memory", { action: "recall_by_tags", tags: ["contract"] }],
  ["agent_memory", { action: "get_recent" }],
];

describe.skipIf(!fs.existsSync(SCHEMA_PATH))("app-schema contract", () => {
  let dir: string;
  let db: FourDADatabase;
  const schemaErrors: { sql: string; error: string }[] = [];
  const missingProbes = new Map<string, number>();
  const restore: (() => void)[] = [];
  let priorOffline: string | undefined;
  let appFile: string;
  let appSha: string;

  beforeAll(() => {
    // Live tools must reach their database work (the cache, the
    // dependency groups), so they run ONLINE against a network that refuses
    // every request at once, instead of FOURDA_OFFLINE, which returns early.
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() => Promise.reject(new TypeError("network disabled in the app-schema contract test"))) as typeof fetch;
    restore.push(() => {
      globalThis.fetch = realFetch;
    });
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-app-contract-"));
    const file = path.join(dir, "4da.db");
    const raw = new Database(file);
    // One transaction and no fsync per row: seeding ~120 tables row by row
    // took over 10 s on Windows otherwise.
    raw.pragma("synchronous = OFF");
    raw.transaction(() => {
      const { vecTables } = loadAppSchema(raw, fs.readFileSync(SCHEMA_PATH, "utf-8")) as { vecTables: string[] };
      seedEveryTable(raw, new Set(vecTables));
    })();
    raw.close();

    // Watch every statement and probe the server makes from here on.
    const proto = Database.prototype as unknown as { prepare: (sql: string) => unknown };
    const prepare = proto.prepare;
    proto.prepare = function (this: unknown, sql: string) {
      try {
        return prepare.call(this, sql);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (SCHEMA_ERROR.test(message)) schemaErrors.push({ sql: sql.replace(/\s+/g, " ").trim(), error: message });
        throw error;
      }
    };
    restore.push(() => {
      proto.prepare = prepare;
    });
    const dbProto = FourDADatabase.prototype as unknown as { hasColumn: (t: string, c: string) => boolean };
    const hasColumn = dbProto.hasColumn;
    dbProto.hasColumn = function (this: unknown, table: string, column: string) {
      const found = hasColumn.call(this, table, column);
      if (!found) {
        const key = `${table}.${column}`;
        missingProbes.set(key, (missingProbes.get(key) ?? 0) + 1);
      }
      return found;
    };
    restore.push(() => {
      dbProto.hasColumn = hasColumn;
    });

    appFile = file;
    appSha = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    db = new FourDADatabase(file);
    const priorLive = getLiveIntelligence();
    setLiveIntelligence(new LiveIntelligence(db.getRawDb()));
    restore.push(() => setLiveIntelligence(priorLive as LiveIntelligence));
  }, 60_000);

  afterAll(() => {
    for (const undo of restore.reverse()) undo();
    db?.close();
    fs.rmSync(dir, { recursive: true, force: true });
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
  });

  it("opens the app schema as the desktop app's database, not a standalone one", () => {
    expect(db.isStandalone).toBe(false);
  });

  it("reads the dependency groups the server loads at startup", () => {
    // index.ts runs this before any tool, to seed live intelligence.
    expect(() => db.getRawDb().prepare(DEPENDENCY_GROUP_QUERY).all()).not.toThrow();
  });

  it.each(CALLS)("%s %j runs against the app schema", async (name, args) => {
    const before = schemaErrors.length;
    await dispatchTool(name, db, args).catch((error: unknown) => {
      // A tool may legitimately fail on seeded data (a JSON column holding
      // "seed"). Only a schema disagreement fails this test, and the prepare
      // hook records those whether or not the tool catches them.
      const message = error instanceof Error ? error.message : String(error);
      if (SCHEMA_ERROR.test(message)) schemaErrors.push({ sql: `(thrown by ${name})`, error: message });
    });
    expect(schemaErrors.slice(before), `${name} queried something the app schema does not have`).toEqual([]);
  });

  it("finds every column the server probes for", () => {
    const unexpected = [...missingProbes.keys()].filter((k) => !(k in EXPECTED_MISSING_COLUMNS));
    expect(unexpected, "hasColumn() found these missing from the app schema").toEqual([]);
  });

  it("leaves the app database byte-for-byte unchanged after every tool ran", () => {
    // The app owns 4da.db: the server opens it read-only and writes its cache,
    // decisions, agent memory and feedback to its own files (FOURDA_MCP_HOME).
    expect(db.isReadOnly).toBe(true);
    expect(createHash("sha256").update(fs.readFileSync(appFile)).digest("hex")).toBe(appSha);
    expect(fs.existsSync(appFile + "-wal")).toBe(false);
  });

  it("keeps the expected-missing list honest", () => {
    const stale = Object.keys(EXPECTED_MISSING_COLUMNS).filter((k) => !missingProbes.has(k));
    expect(stale, "listed as expected-missing but present (or never probed): remove them").toEqual([]);
  });
});
