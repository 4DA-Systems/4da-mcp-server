// SPDX-License-Identifier: Apache-2.0
/**
 * `--doctor` names the data folder, the server's own store, the cache and the app's database, each
 * with its state, and fails on a store the tools cannot use. It used to say "4DA database: Found
 * with 0 tables ... All clear" over a data folder every tool answered wrongly from, and named no
 * path at all. The app's database is only read: a `live_cache` table an old version of this server
 * left there is mentioned and left alone.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { dataFolderChecks } from "../doctor.js";
import { closeServerCacheDb } from "../live/cache.js";
import { openDatabase } from "../sqlite-driver.js";
import { serverEntry } from "./helpers/stdio-session.js";

const ENV = ["FOURDA_MCP_HOME", "FOURDA_DB_PATH", "FOURDA_DATA_DIR", "APPDATA", "XDG_DATA_HOME", "HOME"] as const;
const sha = (file: string) => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
/** The colour codes --doctor prints around its icons. */
const ANSI_COLOUR = new RegExp(`${String.fromCharCode(27)}\\[\\d+m`, "g");
let saved: Record<string, string | undefined>;
let base: string;
let home: string;

beforeEach(() => {
  closeServerCacheDb();
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  base = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-doctor-"));
  home = path.join(base, "home");
  process.env.FOURDA_MCP_HOME = home;
  delete process.env.FOURDA_DB_PATH;
  for (const k of ["FOURDA_DATA_DIR", "APPDATA", "XDG_DATA_HOME", "HOME"] as const) process.env[k] = path.join(base, "no-app");
});

afterEach(() => {
  closeServerCacheDb();
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

const byName = () => Object.fromEntries(dataFolderChecks().map((c) => [c.name, c]));

describe("the data folder lines", () => {
  it("a fresh folder: every path named, the own store made whole, the cache on disk, no app database", () => {
    const checks = byName();
    expect(checks["Data folder"]).toMatchObject({ status: "pass" });
    expect(checks["Data folder"].detail).toContain(home);
    expect(checks["Own database"]).toMatchObject({ status: "pass" });
    expect(checks["Own database"].detail).toContain(path.join(home, "standalone.db"));
    expect(checks["Cache"]).toMatchObject({ status: "pass" });
    expect(checks["Cache"].detail).toContain(path.join(home, "cache.db"));
    expect(checks["Cache"].detail).toMatch(/on disk/);
    expect(checks["App database"]).toMatchObject({ status: "pass" });
    expect(checks["App database"].detail).toMatch(/none attached/);
  });

  it("an own store a killed first start left with no tables is completed by the check, which says so", () => {
    fs.mkdirSync(home, { recursive: true });
    fs.writeFileSync(path.join(home, "standalone.db"), "");
    expect(byName()["Own database"]).toMatchObject({ status: "warn", detail: expect.stringMatching(/completed it in place/) });
    const raw = openDatabase(path.join(home, "standalone.db"), { readonly: true, fileMustExist: true });
    try {
      expect((raw.prepare("SELECT COUNT(*) AS c FROM sqlite_master WHERE type='table'").get() as { c: number }).c).toBeGreaterThan(20);
    } finally {
      raw.close();
    }
  });

  it("an own store that cannot be opened fails, naming it", () => {
    fs.mkdirSync(home, { recursive: true });
    fs.writeFileSync(path.join(home, "standalone.db"), "not a sqlite database at all, " + "x".repeat(200));
    const own = byName()["Own database"];
    expect(own.status).toBe("fail");
    expect(own.detail).toContain(path.join(home, "standalone.db"));
    expect(own.detail).toMatch(/cannot be opened/);
  });

  it("FOURDA_DB_PATH naming no file fails, and nothing is created", () => {
    const missing = path.join(base, "clone", "data", "4da.db");
    process.env.FOURDA_DB_PATH = missing;
    const app = byName()["App database"];
    expect(app.status).toBe("fail");
    expect(app.detail).toContain(missing);
    expect(fs.existsSync(path.dirname(missing))).toBe(false);
  });

  it("FOURDA_DB_PATH naming a file with no tables fails as not a 4DA database, and the file is untouched", () => {
    const empty = path.join(base, "empty.db");
    fs.writeFileSync(empty, "");
    process.env.FOURDA_DB_PATH = empty;
    const checks = byName();
    expect(checks["App database"].status).toBe("fail");
    expect(checks["App database"].detail).toMatch(/not a 4DA database/);
    expect(fs.statSync(empty).size).toBe(0);
    // The own store is not what the tools use then: it is not created for this check.
    expect(fs.existsSync(path.join(home, "standalone.db"))).toBe(false);
  });

  it("an app database is read only; a live_cache table an old version left there is named and kept", () => {
    const appDb = path.join(base, "app", "4da.db");
    fs.mkdirSync(path.dirname(appDb), { recursive: true });
    const raw = openDatabase(appDb, { readonly: false });
    raw.exec(`
      CREATE TABLE schema_version (version INTEGER PRIMARY KEY); INSERT INTO schema_version VALUES (131);
      CREATE TABLE source_items (id INTEGER PRIMARY KEY, source_type TEXT, title TEXT);
      CREATE TABLE live_cache (cache_key TEXT PRIMARY KEY, data TEXT, source TEXT, fetched_at TEXT, expires_at TEXT);
      INSERT INTO live_cache VALUES ('k', '{}', 'osv', '2026-10-02', '2026-10-03');
    `);
    raw.close();
    const before = sha(appDb);
    process.env.FOURDA_DB_PATH = appDb;
    const app = byName()["App database"];
    expect(app.status).toBe("pass");
    expect(app.detail).toContain(appDb);
    expect(app.detail).toMatch(/read-only/);
    expect(app.detail).toMatch(/live_cache/);
    expect(app.detail).toMatch(/old version of this server/);
    expect(sha(appDb)).toBe(before);
    const check = openDatabase(appDb, { readonly: true, fileMustExist: true });
    try {
      expect(check.prepare("SELECT COUNT(*) AS c FROM live_cache").get()).toEqual({ c: 1 });
    } finally {
      check.close();
    }
  });
});

describe.skipIf(!fs.existsSync(serverEntry))("--doctor through the built server", () => {
  const run = (env: Record<string, string>) => {
    const childEnv: NodeJS.ProcessEnv = { ...process.env, FOURDA_OFFLINE: "1", HTTPS_PROXY: "http://127.0.0.1:9", HTTP_PROXY: "http://127.0.0.1:9", ...env };
    delete childEnv.FOURDA_DB_PATH;
    const r = spawnSync(process.execPath, [serverEntry, "--doctor"], { cwd: base, env: childEnv, encoding: "utf8", timeout: 120_000 });
    return { status: r.status, text: (r.stdout + r.stderr).replace(ANSI_COLOUR, "") };
  };

  it("names the data folder, the own store and the cache on a fresh folder", () => {
    const { text } = run({ FOURDA_MCP_HOME: home });
    expect(text).toMatch(new RegExp(`✓ Data folder: .*${path.basename(home)}`));
    expect(text).toMatch(/✓ Own database: .*standalone\.db/);
    expect(text).toMatch(/✓ Cache: .*cache\.db/);
    expect(text).toMatch(/✓ App database: none attached/);
  }, 150_000);

  it("a store the tools cannot use: exits non-zero and never says All clear", () => {
    fs.mkdirSync(home, { recursive: true });
    fs.writeFileSync(path.join(home, "standalone.db"), "not a sqlite database at all, " + "x".repeat(200));
    const { status, text } = run({ FOURDA_MCP_HOME: home });
    expect(status).not.toBe(0);
    expect(text).toMatch(/✗ Own database: .*standalone\.db.*cannot be opened/);
    expect(text).not.toMatch(/All clear|All checks passed/);
  }, 150_000);
});
