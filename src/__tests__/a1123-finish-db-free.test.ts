// SPDX-License-Identifier: Apache-2.0
/**
 * With no database to use (FOURDA_DB_PATH naming a missing or table-less file, or no SQLite
 * driver), the tools whose answer comes from the project's files still answer: the planner, the
 * briefing (without its stored decisions, memories and feed rows, which it says are absent) and
 * the ecosystem pulse, beside the four dependency tools. The app-backed tools return the error.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { DATABASE_FREE_TOOLS, dispatchTool } from "../tool-dispatch.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { deriveTechStackForHeadlines } from "../tools/ecosystem-pulse.js";
import { resultText, serverEntry, stdioSession, type ToolResult } from "./helpers/stdio-session.js";

const SPAWN_TIMEOUT_MS = 180_000;
const parse = (r: ToolResult) => JSON.parse(resultText(r)) as Record<string, any>;

describe("the tools that answer without a database", () => {
  it("include upgrade_planner, what_should_i_know and ecosystem_pulse; the app-backed tools are not among them", () => {
    for (const tool of ["vulnerability_scan", "dependency_health", "dependency_check", "upgrade_impact", "upgrade_planner", "what_should_i_know", "ecosystem_pulse"]) {
      expect(DATABASE_FREE_TOOLS.has(tool), tool).toBe(true);
    }
    for (const tool of ["get_relevant_content", "get_actionable_signals", "knowledge_gaps", "developer_dna", "record_feedback", "get_context", "decision_memory", "agent_memory", "check_decision_alignment"]) {
      expect(DATABASE_FREE_TOOLS.has(tool), tool).toBe(false);
    }
  });

  it("an app-backed tool dispatched with no database is still refused", async () => {
    await expect(dispatchTool("developer_dna", null, {})).rejects.toThrow(/needs a database/);
  });
});

describe("what_should_i_know with no database", () => {
  const live = {
    isEnabled: () => false,
    getProjectRoot: () => "/work/app",
    getResolvedDeps: () => [{ name: "lodash", version: "4.17.21", ecosystem: "npm", isDirect: true, isDev: false }],
    getAuditDeps: () => [],
    wasLockfileRead: () => true,
  };

  it("answers, with no stored decisions, memories or feed rows, and says they are absent", async () => {
    const result = await executeWhatShouldIKnow(null, { task: "upgrade lodash" }, live as never);
    expect(result.task_dependencies.map((d) => d.package)).toEqual(["lodash"]);
    expect(result.decision_windows).toEqual([]);
    expect(result.decision_conflicts).toEqual([]);
    expect(result.relevant_wisdom).toEqual([]);
    expect(result.related_reading).toEqual([]);
    expect(result.stored_data_note).toMatch(/No 4DA database is open/);
    expect(result.stored_data_note).toMatch(/decisions/);
    expect(result.summary).toContain(result.stored_data_note);
  });

  it("with a database the note is absent", async () => {
    const { FourDADatabase } = await import("../db.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-finish-wsik-"));
    const db = new FourDADatabase(path.join(dir, "standalone.db"));
    try {
      const result = await executeWhatShouldIKnow(db, { task: "upgrade lodash" }, live as never);
      expect(result.stored_data_note).toBeUndefined();
    } finally {
      db.close();
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});

describe("ecosystem_pulse's search terms come from the project on disk", () => {
  it("with no database: the live layer's direct dependencies, never a name its rules call private", () => {
    const live = {
      getProjectRoot: () => path.join(os.tmpdir(), "a1123-finish-no-such-project"),
      getResolvedDeps: () => [
        { name: "express", version: "4.18.2", ecosystem: "npm", isDirect: true, isDev: false },
        { name: "acme-ledger", version: "1.0.0", ecosystem: "npm", isDirect: true, isDev: false },
        { name: "debug", version: "4.4.2", ecosystem: "npm", isDirect: false, isDev: false },
      ],
      privateReason: (_eco: string, name: string) => (name === "acme-ledger" ? "private" : null),
    };
    const terms = deriveTechStackForHeadlines(null, live as never);
    expect(terms).toContain("express");
    expect(terms).not.toContain("acme-ledger");
    expect(terms).not.toContain("debug");
  });

  it("with the app's database: rows the app stored for this project are not the inventory", async () => {
    const { FourDADatabase } = await import("../db.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-finish-pulse-"));
    const db = new FourDADatabase(path.join(dir, "standalone.db"));
    try {
      const raw = db.getRawDb();
      raw.prepare("INSERT INTO project_dependencies (project_path, manifest_type, package_name, version, is_dev, language) VALUES (?, 'package.json', 'stale-row-only', '1.0.0', 0, 'javascript')").run(dir);
      const live = {
        getProjectRoot: () => dir,
        getResolvedDeps: () => [{ name: "express", version: "4.18.2", ecosystem: "npm", isDirect: true, isDev: false }],
        privateReason: () => null,
      };
      const terms = deriveTechStackForHeadlines(db, live as never);
      expect(terms).toContain("express");
      expect(terms).not.toContain("stale-row-only");
    } finally {
      db.close();
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});

describe.skipIf(!fs.existsSync(serverEntry))("through the built server, FOURDA_DB_PATH naming no file", () => {
  let scratch: string;
  const project = () => path.join(scratch, "clone");

  beforeAll(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-finish-db-free-"));
    fs.mkdirSync(project(), { recursive: true });
    fs.writeFileSync(path.join(project(), "package.json"), JSON.stringify({ name: "clone", dependencies: { lodash: "4.17.21" } }));
    fs.writeFileSync(
      path.join(project(), "package-lock.json"),
      JSON.stringify({ name: "clone", lockfileVersion: 3, packages: { "": { name: "clone", dependencies: { lodash: "4.17.21" } }, "node_modules/lodash": { version: "4.17.21" } } }),
    );
  });

  afterAll(() => {
    try {
      fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      // left for the OS temp cleaner
    }
  });

  it("upgrade_planner, what_should_i_know and ecosystem_pulse answer from disk with the database note", async () => {
    const { results } = await stdioSession(
      project(),
      [
        ["upgrade_planner", {}],
        ["what_should_i_know", { task: "upgrade lodash" }],
        ["ecosystem_pulse", {}],
        ["get_relevant_content", {}],
      ],
      { FOURDA_DB_PATH: "./data/4da.db" },
    );
    const [plan, brief, pulse, feed] = results;
    for (const r of [plan, brief, pulse]) {
      expect(r.isError, resultText(r).slice(0, 300)).toBeFalsy();
      expect(parse(r)._meta?.database_note).toMatch(/was not found/);
    }
    expect(parse(plan).provenance.mode).toBe("lockfile_engine");
    expect(parse(plan).app_plan_check).toBeUndefined();
    expect(parse(brief).task_dependencies.map((d: { package: string }) => d.package)).toEqual(["lodash"]);
    expect(parse(brief).stored_data_note).toMatch(/No 4DA database is open/);
    expect(feed.isError).toBe(true);
    expect(fs.existsSync(path.join(project(), "data", "4da.db"))).toBe(false);
  }, SPAWN_TIMEOUT_MS);
});
