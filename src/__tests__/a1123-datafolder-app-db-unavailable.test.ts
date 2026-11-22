// SPDX-License-Identifier: Apache-2.0
/**
 * FOURDA_DB_PATH names the desktop app's database. When it names no file (a fresh clone of a
 * repository whose committed `.mcp.json` says `./data/4da.db`), or a file with no tables, the
 * tools that need no database still answer from the project's files and say why the app's data
 * is missing; the tools that read the app's data return the error. Nothing is created or changed
 * at that path. Before: every tool returned the error, and a file with no tables was taken for the
 * app's database (`developer_dna` answered an empty profile).
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { DatabaseUnavailableError, FourDADatabase } from "../db.js";
import { startupToolsLine } from "../schema-registry.js";
import { openDatabase } from "../sqlite-driver.js";
import { resultText, serverEntry, stdioSession, type ToolResult } from "./helpers/stdio-session.js";

const SPAWN_TIMEOUT_MS = 180_000;
const sha = (file: string) => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const meta = (r: ToolResult) => (JSON.parse(resultText(r)) as { _meta?: { database_note?: string } })._meta ?? {};

describe("in process: a table-less file at FOURDA_DB_PATH is not an app database", () => {
  let dir: string;
  let prior: string | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-tableless-"));
    prior = process.env.FOURDA_DB_PATH;
  });

  afterEach(() => {
    if (prior === undefined) delete process.env.FOURDA_DB_PATH;
    else process.env.FOURDA_DB_PATH = prior;
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  for (const shape of ["a zero-byte file", "a SQLite file with no tables"]) {
    it(`${shape}: the open is refused with the path, nothing in the file changes`, () => {
      const file = path.join(dir, "4da.db");
      if (shape === "a zero-byte file") fs.writeFileSync(file, "");
      else {
        const raw = openDatabase(file, { readonly: false });
        raw.exec("CREATE TABLE t (x INTEGER); DROP TABLE t;");
        raw.close();
      }
      const before = sha(file);
      process.env.FOURDA_DB_PATH = file;
      let thrown: unknown;
      try {
        new FourDADatabase().close();
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(DatabaseUnavailableError);
      expect((thrown as Error).message).toContain(file);
      expect((thrown as Error).message).toMatch(/not a 4DA database/);
      expect((thrown as DatabaseUnavailableError).note).toMatch(/not a 4DA database.*project's files/);
      const probe = FourDADatabase.validateDatabase(file);
      expect(probe).toMatchObject({ valid: false, standalone: false });
      expect(probe.error).toMatch(/not a 4DA database/);
      expect(sha(file)).toBe(before);
      expect(fs.existsSync(`${file}-wal`)).toBe(false);
    });
  }

  it("the startup line says the dependency tools run, not that no tool can", () => {
    const line = startupToolsLine({ valid: false, standalone: false }, true, 4);
    expect(line).toMatch(/^4 dependency tools answer from the project's files/);
    expect(line).not.toMatch(/no tool can run/);
  });
});

describe.skipIf(!fs.existsSync(serverEntry))("through the built server", () => {
  let scratch: string;
  const project = () => path.join(scratch, "clone");

  beforeAll(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-app-db-"));
    fs.mkdirSync(path.join(project(), "data"), { recursive: true });
    fs.writeFileSync(path.join(project(), "data", "README.md"), "tracked files, no 4da.db\n");
    fs.writeFileSync(path.join(project(), "package.json"), JSON.stringify({ name: "clone", dependencies: { lodash: "4.17.21" } }));
    fs.writeFileSync(
      path.join(project(), "package-lock.json"),
      JSON.stringify({ name: "clone", lockfileVersion: 3, packages: { "": { name: "clone" }, "node_modules/lodash": { version: "4.17.21" } } }),
    );
  });

  afterAll(() => {
    try {
      fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      // left for the OS temp cleaner
    }
  });

  const CALLS: Array<[string, Record<string, unknown>]> = [
    ["vulnerability_scan", {}],
    ["dependency_health", {}],
    ["dependency_check", { items: [{ ecosystem: "npm", package: "lodash", to: "4.17.21" }] }],
    ["developer_dna", {}],
    ["get_context", {}],
  ];

  it("FOURDA_DB_PATH=./data/4da.db in a fresh clone: dependency tools answer with one note, the rest return the error, nothing is created", async () => {
    const { results, stderr } = await stdioSession(project(), CALLS, { FOURDA_DB_PATH: "./data/4da.db" });
    const [scan, health, check, dna, context] = results;
    for (const r of [scan, health, check]) {
      expect(r.isError, resultText(r).slice(0, 300)).toBeFalsy();
      expect(meta(r).database_note).toMatch(/app database named by FOURDA_DB_PATH .*4da\.db\) was not found/);
    }
    expect(JSON.parse(resultText(scan)).total_dependencies_scanned).toBe(1);
    for (const r of [dna, context]) {
      expect(r.isError).toBe(true);
      expect((JSON.parse(resultText(r)) as { error: string }).error).toMatch(/FOURDA_DB_PATH is set to "\.\/data\/4da\.db", but there is no database at/);
    }
    expect(fs.existsSync(path.join(project(), "data", "4da.db"))).toBe(false);
    expect(stderr).toMatch(/dependency tools answer from the project's files/);
    expect(stderr).not.toMatch(/no tool can run/);
  }, SPAWN_TIMEOUT_MS);

  it("FOURDA_DB_PATH naming a zero-byte file: developer_dna is an error naming it, the scan answers, the file is untouched", async () => {
    const file = path.join(scratch, "empty.db");
    fs.writeFileSync(file, "");
    const { results } = await stdioSession(project(), CALLS, { FOURDA_DB_PATH: file });
    const [scan, , , dna] = results;
    expect(dna.isError).toBe(true);
    const error = (JSON.parse(resultText(dna)) as { error: string }).error;
    expect(error).toContain(file);
    expect(error).toMatch(/not a 4DA database/);
    expect(scan.isError).toBeFalsy();
    expect(meta(scan).database_note).toMatch(/has no tables, so it is not a 4DA database/);
    expect(fs.statSync(file).size).toBe(0);
  }, SPAWN_TIMEOUT_MS);
});
