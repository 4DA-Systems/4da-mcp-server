// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, Track F, m3: with a data folder this user cannot write to, every call paid about
 * 3 s (SQLite's own retries on opening the store, then the cache) and answered "Failed to open 4DA
 * database ... unable to open database file", which names nothing useful. The folder is now judged
 * once per process, said plainly, and the store and cache are not tried there again.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { closeServerCacheDb, getServerCacheDb, serverCacheState } from "../live/cache.js";
import { createDatabase, DatabaseUnavailableError } from "../db.js";
import { dataFolderChecks } from "../doctor.js";

let base: string;
let prior: string | undefined;
let priorDb: string | undefined;
let undo: (() => void) | null = null;

beforeEach(() => {
  closeServerCacheDb();
  prior = process.env.FOURDA_MCP_HOME;
  priorDb = process.env.FOURDA_DB_PATH;
  delete process.env.FOURDA_DB_PATH;
  base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-rofolder-")));
});

afterEach(() => {
  undo?.();
  undo = null;
  closeServerCacheDb();
  vi.restoreAllMocks();
  if (prior === undefined) delete process.env.FOURDA_MCP_HOME;
  else process.env.FOURDA_MCP_HOME = prior;
  if (priorDb !== undefined) process.env.FOURDA_DB_PATH = priorDb;
  fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/** Open the store three times; each must fail at once, with the folder named. */
function expectRefusedFast(home: string, words: RegExp): void {
  const t0 = performance.now();
  for (let i = 0; i < 3; i++) {
    let caught: unknown = null;
    try {
      createDatabase();
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(DatabaseUnavailableError);
    expect((caught as Error).message).toMatch(words);
    expect((caught as Error).message).toContain(home);
    expect((caught as DatabaseUnavailableError).note).toMatch(words);
  }
  expect(performance.now() - t0).toBeLessThan(1500);
}

/** Make `dir` unwritable for this user; null when this platform or user cannot be denied (root). */
function denyWrites(dir: string): (() => void) | null {
  if (process.platform === "win32") {
    const user = process.env.USERNAME;
    if (!user) return null;
    try {
      execFileSync("icacls", [dir, "/deny", `${user}:(OI)(CI)(W,D,DC)`], { stdio: "ignore" });
    } catch {
      return null;
    }
    return () => execFileSync("icacls", [dir, "/remove:d", user], { stdio: "ignore" });
  }
  if (typeof process.getuid === "function" && process.getuid() === 0) return null;
  fs.chmodSync(dir, 0o555);
  return () => fs.chmodSync(dir, 0o755);
}

describe("a data folder the server cannot use (audit 2026-11-25, F-m3)", () => {
  it("a file where the folder should be: said plainly, at once, every time", () => {
    const home = path.join(base, "not-a-folder");
    fs.writeFileSync(home, "x");
    process.env.FOURDA_MCP_HOME = home;
    expectRefusedFast(home, /is not a folder/);
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(getServerCacheDb()?.open).toBe(true);
    expect(serverCacheState()).toMatchObject({ kind: "memory" });
    expect(serverCacheState()?.reason).toMatch(/is not a folder/);
  });

  it("a folder this user cannot write to: said plainly, at once, every time, with the cache in memory", ({ skip }) => {
    const home = path.join(base, "ro");
    fs.mkdirSync(home);
    // A store from an earlier session, which the folder still holds.
    fs.writeFileSync(path.join(home, "keep.txt"), "x");
    undo = denyWrites(home);
    if (!undo) return skip("this user cannot be denied writes here (root)");
    process.env.FOURDA_MCP_HOME = home;
    expectRefusedFast(home, /is not writable/);
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const t0 = performance.now();
    expect(getServerCacheDb()?.open).toBe(true);
    expect(performance.now() - t0).toBeLessThan(500);
    expect(serverCacheState()?.reason).toMatch(/is not writable/);
    // Nothing was written there.
    undo();
    undo = null;
    expect(fs.readdirSync(home)).toEqual(["keep.txt"]);
  });

  it("--doctor's Data folder line fails on a folder this user cannot write to, and passes on one it can", ({ skip }) => {
    const ro = path.join(base, "doctor-ro");
    fs.mkdirSync(ro);
    undo = denyWrites(ro);
    if (!undo) return skip("this user cannot be denied writes here (root)");
    process.env.FOURDA_MCP_HOME = ro;
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const line = dataFolderChecks().find((c) => c.name === "Data folder");
    expect(line?.status).toBe("fail");
    expect(line?.detail).toMatch(/the data folder .*doctor-ro is not writable .*: the server cannot keep its files there/);
    undo();
    undo = null;
    closeServerCacheDb();
    process.env.FOURDA_MCP_HOME = path.join(base, "doctor-rw");
    expect(dataFolderChecks().find((c) => c.name === "Data folder")?.status).toBe("pass");
  });

  it("a writable folder is used as before", () => {
    const home = path.join(base, "rw");
    process.env.FOURDA_MCP_HOME = home;
    const db = createDatabase();
    try {
      expect(db.isStandalone).toBe(true);
      // The check leaves nothing behind.
      expect(fs.readdirSync(home).filter((f) => f.startsWith(".write-check"))).toEqual([]);
    } finally {
      db.close();
    }
  });
});
