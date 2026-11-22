// SPDX-License-Identifier: Apache-2.0
/**
 * --doctor opens the server's own store the way a tool call does, which completes a store found
 * with no tables (a zero-byte file, or a database with no tables: a first start stopped while it
 * created it). The store is usable afterwards, so the check does not fail; but it says what it
 * found and what it did, instead of a plain "ready" that hides that anything happened.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { dataFolderChecks } from "../doctor.js";
import { closeServerCacheDb } from "../live/cache.js";
import { openDatabase } from "../sqlite-driver.js";

const ENV = ["FOURDA_MCP_HOME", "FOURDA_DB_PATH", "FOURDA_DATA_DIR", "APPDATA", "XDG_DATA_HOME", "HOME"] as const;
let saved: Record<string, string | undefined>;
let base: string;
let home: string;

beforeEach(() => {
  closeServerCacheDb();
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  base = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-triage-doctor-"));
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

const own = () => dataFolderChecks().find((c) => c.name === "Own database")!;

describe("--doctor over an own store with no tables", () => {
  it("a zero-byte standalone.db: completed in place, and the line says it found it with no tables", () => {
    fs.mkdirSync(home, { recursive: true });
    fs.writeFileSync(path.join(home, "standalone.db"), "");
    const check = own();
    expect(check.status).toBe("warn");
    expect(check.detail).toMatch(/was empty \(0 bytes\)/);
    expect(check.detail).toMatch(/completed it in place/);
    expect(check.detail).toMatch(/\d+ tables, ready/);
  });

  it("a zero-table standalone.db: the same", () => {
    fs.mkdirSync(home, { recursive: true });
    const db = openDatabase(path.join(home, "standalone.db"));
    db.exec("PRAGMA user_version = 1");
    db.close();
    const check = own();
    expect(check.status).toBe("warn");
    expect(check.detail).toMatch(/had no tables/);
    expect(check.detail).toMatch(/completed it in place/);
  });

  it("a store that already had its tables: a plain pass, nothing said about completing it", () => {
    expect(own().status).toBe("pass"); // first check creates it
    closeServerCacheDb();
    const again = own();
    expect(again.status).toBe("pass");
    expect(again.detail).not.toMatch(/completed it in place/);
  });
});
