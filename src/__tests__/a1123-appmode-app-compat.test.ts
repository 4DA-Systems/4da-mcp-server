// SPDX-License-Identifier: Apache-2.0
/**
 * The supported range of the desktop app (app-compat.ts): released v1.0.3 (schema 124, plan
 * format 4) through the app's main (schema 131, plan format 5). An attached app outside it is
 * classified `app_older_than_supported` or `app_newer_than_tested`, and get_context and every
 * answer that reads the app's data carry `_meta.app_compatibility` saying which side to update.
 * No tool fails for it.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { getLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { APP_COMPATIBILITY_TOOLS, appCompatibilityFor, classifyAppCompatibility, NEWEST_TESTED_APP, OLDEST_SUPPORTED_APP, SUPPORTED_PLAN_FORMATS } from "../app-compat.js";
import { APP_PLAN_SCHEMA_VERSIONS } from "../tools/app-plan.js";
import { buildAppDb, VENDORED_APP_SCHEMA } from "./helpers/a1123-appmode.js";

describe("classifyAppCompatibility", () => {
  it("names the released bounds: v1.0.3 is schema 124 / plan format 4, main is schema 131 / plan format 5", () => {
    expect(OLDEST_SUPPORTED_APP).toMatchObject({ release: "4DA v1.0.3", schema: 124, planFormat: 4 });
    expect(NEWEST_TESTED_APP).toMatchObject({ schema: 131, planFormat: 5 });
    expect(SUPPORTED_PLAN_FORMATS).toEqual([4, 5]);
    expect(APP_PLAN_SCHEMA_VERSIONS).toEqual(SUPPORTED_PLAN_FORMATS);
  });

  it.each([
    [124, 4, "supported"],
    [124, null, "supported"],
    [130, 5, "supported"],
    [131, 5, "supported"],
    [123, 4, "app_older_than_supported"],
    [124, 3, "app_older_than_supported"],
    [null, null, "app_older_than_supported"],
    [132, 5, "app_newer_than_tested"],
    [131, 6, "app_newer_than_tested"],
  ] as const)("schema %s, plan format %s: %s", (schema, format, status) => {
    expect(classifyAppCompatibility(schema, format).status).toBe(status);
  });

  it("each note says in plain words which side to update", () => {
    expect(classifyAppCompatibility(120, 4).note).toContain("Update the 4DA app");
    expect(classifyAppCompatibility(140, 5).note).toContain("Update @4da/mcp-server");
    expect(classifyAppCompatibility(140, 5).note).toContain("schema 140");
    expect(classifyAppCompatibility(140, 5).supported).toMatchObject({ app_schema: { min: 124, max: 131 }, plan_format: { min: 4, max: 5 } });
  });
});

describe.skipIf(!fs.existsSync(VENDORED_APP_SCHEMA))("_meta.app_compatibility on the answers that read the app's data", () => {
  let root: string;
  let priorLive: ReturnType<typeof getLiveIntelligence>;
  let priorProjectDir: string | undefined;
  const opened: FourDADatabase[] = [];

  /** An app database at `schema` (the vendored DDL, its schema_version row replaced), with a stored plan of `planFormat`. */
  function appAt(name: string, schema: number | null, planFormat: number | null): FourDADatabase {
    const file = path.join(root, `${name}.db`);
    buildAppDb(file, VENDORED_APP_SCHEMA, (raw) => {
      raw.exec("DELETE FROM schema_version");
      if (schema !== null) raw.prepare("INSERT INTO schema_version (version) VALUES (?)").run(schema);
      if (planFormat !== null) {
        const now = Date.now();
        const plan = { schema_version: planFormat, generated_at: new Date(now - 60_000).toISOString(), expires_at: new Date(now + 3_600_000).toISOString(), items: [], steps: [], item_count: 0 };
        raw.prepare("INSERT INTO kv_store (key, value) VALUES (?, ?)").run("upgrade_plan_snapshot", JSON.stringify(plan));
      }
    });
    const db = new FourDADatabase(file);
    opened.push(db);
    return db;
  }

  const CALLS: Array<[string, Record<string, unknown>]> = [
    ["get_context", {}],
    ["get_relevant_content", {}],
    ["get_actionable_signals", {}],
    ["knowledge_gaps", {}],
    ["developer_dna", {}],
    ["record_feedback", { item_id: 999_999, action: "save" }],
    ["decision_memory", { action: "list" }],
    ["check_decision_alignment", { technology: "react" }],
    ["agent_memory", { action: "get_recent" }],
    ["upgrade_planner", { project_path: "*" }],
  ];

  async function callAll(db: FourDADatabase) {
    const out: Array<{ name: string; isError: boolean; meta: Record<string, unknown> | undefined }> = [];
    for (const [name, args] of CALLS) {
      const r = await dispatchTool(name, db, args);
      const payload = (r.structuredContent ?? JSON.parse((r.content[0] as { text: string }).text)) as { _meta?: Record<string, unknown> };
      out.push({ name, isError: r.isError === true, meta: payload._meta });
    }
    return out;
  }

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-compat-"));
    const project = path.join(root, "project");
    fs.mkdirSync(project, { recursive: true });
    priorProjectDir = process.env.FOURDA_PROJECT_DIR;
    process.env.FOURDA_PROJECT_DIR = project;
    priorLive = getLiveIntelligence();
    const live = new LiveIntelligence(null);
    live.initFromProjectTree(project, [], null);
    setLiveIntelligence(live);
  });

  afterAll(() => {
    setLiveIntelligence(priorLive as LiveIntelligence);
    if (priorProjectDir === undefined) delete process.env.FOURDA_PROJECT_DIR;
    else process.env.FOURDA_PROJECT_DIR = priorProjectDir;
    for (const db of opened) db.close();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  it("covers get_context and every app-backed tool", () => {
    for (const name of ["get_context", "get_relevant_content", "get_actionable_signals", "knowledge_gaps", "developer_dna", "record_feedback"]) {
      expect(APP_COMPATIBILITY_TOOLS.has(name)).toBe(true);
    }
  });

  it("a supported app adds nothing", async () => {
    const db = appAt("supported", 130, 5);
    expect(appCompatibilityFor(db)?.status).toBe("supported");
    for (const r of await callAll(db)) expect(r.meta?.app_compatibility, r.name).toBeUndefined();
  });

  it("an app newer than tested: every answer says so and names the server as the side to update, and none fails for it", async () => {
    const supported = await callAll(appAt("baseline", 130, 5));
    const newer = await callAll(appAt("newer", 140, 5));
    for (const [i, r] of newer.entries()) {
      const compat = r.meta?.app_compatibility as { status: string; app_schema: number; supported: unknown; note: string } | undefined;
      expect(compat?.status, r.name).toBe("app_newer_than_tested");
      expect(compat?.app_schema).toBe(140);
      expect(compat?.supported).toBeTypeOf("object");
      expect(compat?.note).toContain("Update @4da/mcp-server");
      expect(r.isError, r.name).toBe(supported[i].isError);
    }
  });

  it("an app older than supported: the note names the app as the side to update", async () => {
    const older = await callAll(appAt("older", 120, 4));
    for (const r of older) {
      const compat = r.meta?.app_compatibility as { status: string; note: string } | undefined;
      expect(compat?.status, r.name).toBe("app_older_than_supported");
      expect(compat?.note).toContain("Update the 4DA app");
    }
  });

  it("a plan format newer than this server reads is the newer side too", async () => {
    const db = appAt("newer-plan", 131, 6);
    expect(appCompatibilityFor(db)).toMatchObject({ status: "app_newer_than_tested", app_schema: 131, app_plan_format: 6 });
  });

  it("the dependency tools that read only the disk carry no app note", async () => {
    const db = appAt("deps-only", 140, 5);
    const r = await dispatchTool("dependency_check", db, { items: [{ ecosystem: "npm", package: "left-pad", to: "1.3.0" }] });
    const payload = (r.structuredContent ?? {}) as { _meta?: Record<string, unknown> };
    expect(payload._meta?.app_compatibility).toBeUndefined();
  });
});
