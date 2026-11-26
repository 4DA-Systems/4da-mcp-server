// SPDX-License-Identifier: Apache-2.0
/**
 * firstrun-together, 2026-11-26: six servers opening a new data folder at the same instant. The
 * one that puts standalone.db in WAL mode needs a lock the others' reads hold for milliseconds,
 * and SQLite answers that journal-mode change with SQLITE_BUSY at once, without its busy handler
 * (measured 0-1 ms with busy_timeout = 5000). The open failed, and the tool calls that opened the
 * store with it (a decision being recorded among them) answered "database is locked". The open now
 * waits for that lock like any other statement, and says so plainly when it never comes.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { createDatabase, enableWal, WAL_LOCK_WAIT_MS } from "../db.js";
import { openDatabase, type SqliteDatabase } from "../sqlite-driver.js";

let dir: string;
const open: SqliteDatabase[] = [];
const conn = (file: string) => {
  const db = openDatabase(file);
  db.pragma("busy_timeout = 5000");
  open.push(db);
  return db;
};

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1125-wal-"));
});
afterEach(() => {
  for (const db of open.splice(0)) {
    try {
      db.close();
    } catch {
      // Closed by the test.
    }
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * A new, empty store file whose write lock another starting server holds (it is writing the file's
 * first page). A reader's lock is waited on by the busy handler; this one is not (measured: 1 ms).
 */
function fileWithReader(): { file: string; reader: SqliteDatabase } {
  const file = path.join(dir, "standalone.db");
  const reader = conn(file);
  reader.exec("BEGIN IMMEDIATE");
  return { file, reader };
}

describe("the own store's WAL switch waits for a lock another server holds", () => {
  it("SQLite itself refuses the switch at once, busy timeout or not (the defect's mechanism)", () => {
    const { file } = fileWithReader();
    const db = conn(file);
    const started = Date.now();
    expect(() => db.pragma("journal_mode = WAL")).toThrow(/locked|busy/i);
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it("enableWal waits, and switches once the other server's write ends", () => {
    const { file, reader } = fileWithReader();
    const db = conn(file);
    let pauses = 0;
    enableWal(db, 5_000, () => {
      pauses++;
      if (pauses === 3) reader.exec("COMMIT");
    });
    expect(pauses).toBe(3);
    expect(String(db.pragma("journal_mode", { simple: true })).toLowerCase()).toBe("wal");
  });

  it("a lock that never goes is said plainly, inside the wait, and stays a lock error", () => {
    const { file } = fileWithReader();
    const db = conn(file);
    const started = Date.now();
    let error: unknown;
    try {
      enableWal(db, 150);
    } catch (e) {
      error = e;
    }
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(String((error as Error).message)).toMatch(/another process held this store's lock .* nothing was read or stored: call again/);
    expect((error as { code?: string }).code).toBe("SQLITE_BUSY");
  });

  it("the own store opens on a new folder while another process is writing its first page", async () => {
    const prior = process.env.FOURDA_MCP_HOME;
    process.env.FOURDA_MCP_HOME = dir;
    const file = path.join(dir, "standalone.db");
    // Another server: takes the new file's write lock, holds it 400 ms, then lets go.
    const holder = spawn(
      process.execPath,
      [
        "--no-warnings",
        "-e",
        "const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync(process.argv[1]);d.exec('BEGIN IMMEDIATE');console.log('held');setTimeout(()=>{d.exec('COMMIT');d.close();},400);",
        file,
      ],
      { stdio: ["ignore", "pipe", "inherit"] },
    );
    const done = new Promise((resolve) => holder.on("close", resolve));
    await new Promise<void>((resolve) => holder.stdout.on("data", () => resolve()));
    try {
      const started = Date.now();
      const db = createDatabase();
      expect(db.isStandalone).toBe(true);
      expect(Date.now() - started).toBeLessThan(WAL_LOCK_WAIT_MS);
      db.close();
    } finally {
      await done;
      if (prior === undefined) delete process.env.FOURDA_MCP_HOME;
      else process.env.FOURDA_MCP_HOME = prior;
    }
  });

  it("any other failure is not waited on", () => {
    let calls = 0;
    const fake = {
      pragma: () => {
        calls++;
        throw Object.assign(new Error("disk I/O error"), { code: "SQLITE_IOERR" });
      },
    } as unknown as SqliteDatabase;
    expect(() => enableWal(fake, 5_000, () => undefined)).toThrow(/disk I\/O/);
    expect(calls).toBe(1);
  });
});
