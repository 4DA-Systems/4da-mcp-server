// SPDX-License-Identifier: Apache-2.0
/**
 * Every RELEASED app schema is tested, not only the app's current one.
 *
 * Users run a released app (v1.0.3 today) beside whatever server npm gives them, so the contract
 * test against the vendored `contract/app-schema.sql` (the app's main) is not enough. For each
 * schema in `contract/released/` and for the vendored one, this builds a database, seeds every
 * table, and calls every app-backed tool and the dependency tools through the real dispatcher:
 * no statement may name a table or column the schema lacks, and the compatibility status is
 * `supported` (app-compat.ts). The supported range must start at the oldest released schema here
 * and reach every one of them, so a release and its bounds move in one change (contract/README.md).
 *
 * Statements that need an SQLite extension this runtime lacks: the app's three `vec0` virtual
 * tables (`context_vec`, `source_vec`, `topic_vec`, from sqlite-vec) are created as plain stub
 * tables of the same name (scripts/app-schema-loader.mjs). The server never queries them. FTS5
 * (`source_items_fts`) is built into the runtime and loads as written.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { getLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { NodeSqliteDatabase } from "../sqlite-driver.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { appCompatibilityFor, NEWEST_TESTED_APP, OLDEST_SUPPORTED_APP } from "../app-compat.js";
import { normalizeProjectPath } from "../tools/project-scope.js";
import { buildAppDb, npmProject, RELEASED_V103_SCHEMA, seedEveryTable, VENDORED_APP_SCHEMA } from "./helpers/a1123-appmode.js";
// @ts-expect-error -- plain ESM helper shared with scripts/app-schema-contract.mjs
import { SCHEMA_ERROR } from "../../scripts/app-schema-loader.mjs";

const RELEASED_DIR = path.dirname(RELEASED_V103_SCHEMA);
const released = fs.existsSync(RELEASED_DIR) ? fs.readdirSync(RELEASED_DIR).filter((f) => f.endsWith(".sql")).sort() : [];
const schemaOf = (file: string) => Number(/^-- schema_version: (\d+)/m.exec(fs.readFileSync(file, "utf-8"))?.[1] ?? Number.NaN);

/** The app tools and the dependency tools, with arguments that reach their database work. */
const CALLS: [string, Record<string, unknown>][] = [
  ["get_context", {}],
  ["get_relevant_content", {}],
  ["get_relevant_content", { signal_type: "security_alert", min_score: 0 }],
  ["get_actionable_signals", {}],
  ["knowledge_gaps", {}],
  ["developer_dna", {}],
  ["record_feedback", { item_id: 1, action: "save" }],
  ["what_should_i_know", { task: "upgrade minimist" }],
  ["ecosystem_pulse", {}],
  ["decision_memory", { action: "list" }],
  ["decision_memory", { action: "record", decision_type: "tech_choice", subject: "minimist", decision: "Keep minimist", rationale: "released-schema test" }],
  ["check_decision_alignment", { technology: "minimist" }],
  ["agent_memory", { action: "store", subject: "released", content: "released-schema test" }],
  ["agent_memory", { action: "recall", query: "released" }],
  ["vulnerability_scan", {}],
  ["dependency_health", {}],
  ["upgrade_planner", {}],
  ["upgrade_planner", { project_path: "*" }],
  ["dependency_check", { items: [{ ecosystem: "npm", package: "minimist", to: "1.2.8" }] }],
  ["upgrade_impact", { package: "minimist", to_version: "1.2.8" }],
];

describe("contract/released: the supported range matches the released schemas", () => {
  it("v1.0.3 is here, as schema 124, and is the oldest supported", () => {
    expect(released).toContain("v1.0.3.sql");
    expect(schemaOf(RELEASED_V103_SCHEMA)).toBe(124);
    const schemas = released.map((f) => schemaOf(path.join(RELEASED_DIR, f)));
    expect(Math.min(...schemas)).toBe(OLDEST_SUPPORTED_APP.schema);
    for (const s of schemas) expect(s).toBeLessThanOrEqual(NEWEST_TESTED_APP.schema);
  });

  it("the vendored schema (the app's main) is within the range", () => {
    const vendored = schemaOf(VENDORED_APP_SCHEMA);
    expect(vendored).toBeGreaterThanOrEqual(OLDEST_SUPPORTED_APP.schema);
    expect(vendored).toBeLessThanOrEqual(NEWEST_TESTED_APP.schema);
  });
});

const SCHEMAS: Array<[string, string, number]> = [
  ...released.map((f): [string, string, number] => [`released ${f}`, path.join(RELEASED_DIR, f), schemaOf(path.join(RELEASED_DIR, f)) === 124 ? 4 : 5]),
  ["vendored app-schema.sql", VENDORED_APP_SCHEMA, 5],
];

describe.each(SCHEMAS)("every tool against the %s", (_label, schemaFile, planFormat) => {
  let dir: string;
  let db: FourDADatabase;
  let project: string;
  let vecTables: string[] = [];
  const schemaErrors: { sql: string; error: string }[] = [];
  const restore: (() => void)[] = [];
  let priorOffline: string | undefined;
  let priorProjectDir: string | undefined;

  beforeAll(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-released-"));
    project = path.join(dir, "project");
    npmProject(project, { minimist: "1.2.5" });
    priorProjectDir = process.env.FOURDA_PROJECT_DIR;
    process.env.FOURDA_PROJECT_DIR = project;
    const file = path.join(dir, "4da.db");
    const now = Date.now();
    ({ vecTables } = buildAppDb(file, schemaFile, (raw, loaded) => {
      seedEveryTable(raw, new Set([...loaded.vecTables, "schema_version", "kv_store", "osv_sync_status", "project_dependencies"]));
      raw.prepare("INSERT INTO kv_store (key, value) VALUES (?, ?)").run(
        "upgrade_plan_snapshot",
        JSON.stringify({
          schema_version: planFormat,
          generated_at: new Date(now - 3_600_000).toISOString(),
          expires_at: new Date(now + 3_600_000).toISOString(),
          source_freshness: new Date(now - 7_200_000).toISOString().replace("T", " ").slice(0, 19),
          item_count: 1,
          items: [{ id: "upgrade-plan:npm:minimist", title: "Upgrade minimist", urgency: "critical" }],
          steps: [
            {
              item_id: "upgrade-plan:npm:minimist",
              ecosystem: "npm",
              package: "minimist",
              lines: [{ installed: "1.2.5", target: "1.2.6", upgrade_type: "patch", clears_all_known: true, sites: [{ project: normalizeProjectPath(project), direct: true, dev: false }] }],
              mechanism: "manifest_bump",
              advisory_ids: ["GHSA-xvch-5gv4-984h"],
              verification: "re-run 4da plan --json",
            },
          ],
        }),
      );
      raw.prepare("INSERT INTO osv_sync_status (ecosystem, last_synced_at, advisory_count, error) VALUES ('npm', datetime('now', '-2 hours'), 10, NULL)").run();
      raw.prepare("INSERT INTO project_dependencies (project_path, manifest_type, package_name, version, language) VALUES (?, 'package.json', 'minimist', '1.2.5', 'javascript')").run(normalizeProjectPath(project));
    }));

    // Every statement the server prepares from here on, on whichever driver it uses.
    for (const Ctor of [Database, NodeSqliteDatabase]) {
      const proto = Ctor.prototype as unknown as { prepare: (sql: string) => unknown };
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
    }
    db = new FourDADatabase(file);
    // As the server's init does: the live layer on the app connection, from the walk of the project.
    const priorLive = getLiveIntelligence();
    const live = new LiveIntelligence(db.getRawDb());
    const { entries, discovery } = scanProjectTree(project);
    live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
    setLiveIntelligence(live);
    restore.push(() => setLiveIntelligence(priorLive as LiveIntelligence));
  }, 60_000);

  afterAll(() => {
    for (const undo of restore.reverse()) undo();
    db?.close();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    if (priorProjectDir === undefined) delete process.env.FOURDA_PROJECT_DIR;
    else process.env.FOURDA_PROJECT_DIR = priorProjectDir;
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  it("opens as the desktop app's database, its vec0 tables stubbed and nothing else skipped", () => {
    expect(db.isStandalone).toBe(false);
    expect(vecTables.sort()).toEqual(["context_vec", "source_vec", "topic_vec"]);
  });

  it("is a supported app", () => {
    expect(appCompatibilityFor(db)?.status).toBe("supported");
  });

  it.each(CALLS)("%s %j runs with no SQL error and no compatibility note", async (name, args) => {
    const before = schemaErrors.length;
    const result = await dispatchTool(name, db, args).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      if (SCHEMA_ERROR.test(message)) schemaErrors.push({ sql: `(thrown by ${name})`, error: message });
      return null;
    });
    expect(schemaErrors.slice(before), `${name} queried something this schema does not have`).toEqual([]);
    const meta = (result?.structuredContent as { _meta?: Record<string, unknown> } | undefined)?._meta;
    expect(meta?.app_compatibility).toBeUndefined();
  });

  it("upgrade_planner for the project compares the stored plan of this schema's format", async () => {
    const result = await dispatchTool("upgrade_planner", db, {});
    const payload = result.structuredContent as { provenance: { mode: string }; app_plan_check?: { status: string } };
    expect(payload.provenance.mode).toBe("lockfile_engine");
    expect(payload.app_plan_check?.status).toBeTypeOf("string");
    expect(payload.app_plan_check?.status).not.toBe("no_plan");
  });
});
