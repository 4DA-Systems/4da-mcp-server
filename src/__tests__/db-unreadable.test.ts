// SPDX-License-Identifier: Apache-2.0
/**
 * What the server says when its database cannot help: a file that is not a
 * SQLite database used to answer every call with the bare "file is not a
 * database", and a desktop-only tool called without the desktop app's
 * database answered `[]`, which reads as "nothing relevant".
 */
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { FourDADatabase, isUnreadableDbError, unreadableDbMessage } from "../db.js";
import { dispatchTool } from "../tool-dispatch.js";

describe("an unreadable database file", () => {
  let dir: string;
  let file: string;
  const garbage = "this is not a sqlite database, " + "x".repeat(200);

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "4da-unreadable-"));
    file = path.join(dir, "4da.db");
    writeFileSync(file, garbage);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("opening it names the file and a way out, and touches nothing", () => {
    let message = "";
    try {
      new FourDADatabase(file);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain(file);
    expect(message).toContain("file is not a database");
    expect(message).toMatch(/damaged or is not a SQLite database/);
    expect(message).toContain("--doctor");
    expect(readFileSync(file, "utf-8")).toBe(garbage);
    expect(existsSync(`${file}-wal`)).toBe(false);
  });

  it("the handle is closed, so the file can be moved aside while the server runs", () => {
    expect(() => new FourDADatabase(file)).toThrow();
    // On Windows a leaked handle makes this rename fail with EBUSY/EPERM.
    const moved = path.join(dir, "4da.db.aside");
    expect(() => renameSync(file, moved)).not.toThrow();
  });

  it("validateDatabase reports the same guidance", () => {
    const result = FourDADatabase.validateDatabase(file);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/damaged or is not a SQLite database/);
  });

  it("never advises deleting the desktop app's database", () => {
    const prior = process.env.FOURDA_DB_PATH;
    delete process.env.FOURDA_DB_PATH;
    try {
      const message = unreadableDbMessage(file, new Error("file is not a database"));
      expect(message).toContain("Do not delete it");
      expect(message).not.toMatch(/try deleting/i);
    } finally {
      if (prior !== undefined) process.env.FOURDA_DB_PATH = prior;
    }
  });

  it("recognises SQLite's codes and messages", () => {
    expect(isUnreadableDbError(Object.assign(new Error("x"), { code: "SQLITE_NOTADB" }))).toBe(true);
    expect(isUnreadableDbError(Object.assign(new Error("x"), { code: "SQLITE_CORRUPT" }))).toBe(true);
    expect(isUnreadableDbError(new Error("database disk image is malformed"))).toBe(true);
    expect(isUnreadableDbError(new Error("SQLITE_BUSY: database is locked"))).toBe(false);
  });
});

describe("a desktop-only tool in standalone mode", () => {
  let dir: string;
  let db: FourDADatabase;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "4da-standalone-"));
    db = new FourDADatabase(path.join(dir, "standalone.db"));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("says it needs the desktop app instead of answering a bare []", async () => {
    expect(db.isStandalone).toBe(true);
    const result = await dispatchTool("get_relevant_content", db, {});
    const payload = JSON.parse((result.content[0] as { text: string }).text);
    expect(payload.items).toEqual([]);
    expect(payload.item_count).toBe(0);
    expect(payload.desktop_app_note).toMatch(/get_relevant_content reads the 4DA desktop app's database/);
    expect(payload.desktop_app_note).toContain("FOURDA_DB_PATH");
  });

  it("a standalone tool carries no such note", async () => {
    const result = await dispatchTool("decision_memory", db, { action: "list" });
    const text = (result.content[0] as { text: string }).text;
    expect(text).not.toContain("desktop_app_note");
  });
});
