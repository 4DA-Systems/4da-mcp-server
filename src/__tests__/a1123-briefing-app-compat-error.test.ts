// SPDX-License-Identifier: Apache-2.0
/**
 * An attached 4DA app database outside the supported range that also lacks a table a tool reads:
 * get_context failed with the bare "no such table: user_identity" and no `_meta.app_compatibility`,
 * though the changelog promises nothing fails without a word of which side to update. The error
 * answer now carries the compatibility note (the app's schema and which side to update). Inside the
 * supported range, and for errors that are not about the app's tables, the error is as it was.
 *
 * Stand-in databases (schema_version and kv_store only) are built in a temporary folder.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";

import { FourDADatabase } from "../db.js";
import { appCompatibilityError } from "../app-compat.js";
import { dispatchTool } from "../tool-dispatch.js";
import { clearLiveIntelligence } from "../live-singleton.js";

let root: string;
const opened: FourDADatabase[] = [];

/** A two-table stand-in for the app's database at `schema`. */
function standIn(name: string, schema: number): FourDADatabase {
  const file = path.join(root, `${name}.db`);
  const raw = new Database(file);
  raw.exec("CREATE TABLE schema_version (version INTEGER NOT NULL); CREATE TABLE kv_store (key TEXT PRIMARY KEY, value TEXT);");
  raw.prepare("INSERT INTO schema_version (version) VALUES (?)").run(schema);
  raw.prepare("INSERT INTO kv_store (key, value) VALUES (?, ?)").run("upgrade_plan_snapshot", JSON.stringify({ schema_version: 5, steps: [] }));
  raw.close();
  const db = new FourDADatabase(file);
  opened.push(db);
  return db;
}

/** The answer's JSON, or the thrown error's message. */
async function answer(tool: string, db: FourDADatabase, args: Record<string, unknown> = {}): Promise<{ isError?: boolean; body: Record<string, any> } | { thrown: string }> {
  try {
    const result = (await dispatchTool(tool, db, args)) as { isError?: boolean; content: Array<{ text: string }> };
    return { isError: result.isError, body: JSON.parse(result.content[0].text) };
  } catch (error) {
    return { thrown: error instanceof Error ? error.message : String(error) };
  }
}

beforeAll(() => {
  clearLiveIntelligence();
  root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-appcompat-"));
});
afterAll(() => {
  for (const db of opened) db.close();
  try {
    fs.rmSync(root, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

describe("a tool that cannot read an app outside the supported range says which side to update", () => {
  it.each([
    ["newer", 140, "app_newer_than_tested", "Update @4da/mcp-server"],
    ["older", 100, "app_older_than_supported", "Update the 4DA app"],
  ] as const)("app %s (schema %i): get_context is an error carrying _meta.app_compatibility", async (label, schema, status, side) => {
    const db = standIn(`${label}-${schema}`, schema);
    expect(db.isStandalone).toBe(false);
    const got = await answer("get_context", db);
    expect("thrown" in got ? got.thrown : null).toBeNull();
    if ("thrown" in got) return;
    expect(got.isError).toBe(true);
    expect(got.body.error).toContain("no such table: user_identity");
    expect(got.body.error).toContain(`schema ${schema}`);
    expect(got.body.error).toContain(side);
    expect(got.body._meta.app_compatibility).toMatchObject({ status, app_schema: schema, supported: { app_schema: { min: 124, max: 131 } } });
  });

  it("decision_memory over the same database says it too", async () => {
    const db = standIn("newer-decisions", 140);
    const got = await answer("decision_memory", db, { action: "list" });
    expect("thrown" in got).toBe(false);
    if ("thrown" in got) return;
    expect(got.isError).toBe(true);
    expect(got.body._meta?.app_compatibility?.status).toBe("app_newer_than_tested");
  });

  it("the stand-in is never written to", async () => {
    const db = standIn("newer-untouched", 140);
    await answer("get_context", db);
    const raw = new Database(path.join(root, "newer-untouched.db"), { readonly: true });
    const tables = (raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all() as Array<{ name: string }>).map((t) => t.name);
    raw.close();
    expect(tables).toEqual(["kv_store", "schema_version"]);
  });

  it("inside the supported range, or for an error that is not about the app's tables, nothing is added", () => {
    const supported = standIn("supported-130", 130);
    expect(appCompatibilityError("get_context", supported, new Error("no such table: user_identity"))).toBeNull();
    const newer = standIn("newer-other", 140);
    expect(appCompatibilityError("get_context", newer, new Error("database is locked"))).toBeNull();
    expect(appCompatibilityError("vulnerability_scan", newer, new Error("no such table: user_identity"))).toBeNull();
    expect(appCompatibilityError("get_context", newer, new Error("no such column: role"))?._meta.app_compatibility.status).toBe("app_newer_than_tested");
  });
});
