// SPDX-License-Identifier: Apache-2.0
/**
 * B-3 / B-4 / B-5 (audit 2026-10-12): the server never adopts configuration or
 * a database from the directory it was started in. A cloned repository could
 * plant `data/settings.json` (redirecting semantic recall, and with it stored
 * agent memory and decisions, to any host) or `data/4da.db` (rows read back as
 * the user's own "decisions", and the file reopened writable).
 *
 * Only these are read: FOURDA_SETTINGS_PATH; the settings.json beside an
 * explicit FOURDA_DB_PATH; the desktop app's own data directory; the server's
 * own home. A FOURDA_DB_PATH that names a missing file is refused, never
 * created.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getEmbeddingConfig } from "../embeddings.js";
import { FourDADatabase, standaloneDbPath } from "../db.js";

const ENV = ["FOURDA_SETTINGS_PATH", "FOURDA_DB_PATH", "FOURDA_DATA_DIR", "APPDATA", "XDG_DATA_HOME", "HOME", "USERPROFILE", "FOURDA_MCP_HOME", "FOURDA_EMBED_PROVIDER", "FOURDA_OFFLINE"];
let saved: Record<string, string | undefined>;
let base: string;
let repo: string;

const plantSettings = (dir: string) => {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "settings.json"), JSON.stringify({ embedding: { provider: "ollama", url: "http://127.0.0.1:47123" } }));
};

beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  base = fs.mkdtempSync(path.join(os.tmpdir(), "sec-discovery-"));
  repo = path.join(base, "cloned", "repo");
  fs.mkdirSync(repo, { recursive: true });
  for (const k of ["FOURDA_SETTINGS_PATH", "FOURDA_DB_PATH", "FOURDA_EMBED_PROVIDER", "FOURDA_OFFLINE"]) delete process.env[k];
  // The desktop app's data directory, and the user's home, are empty temp dirs.
  const fakeHome = path.join(base, "home");
  fs.mkdirSync(fakeHome);
  process.env.FOURDA_DATA_DIR = path.join(base, "appdata-dir");
  process.env.APPDATA = path.join(fakeHome, "Roaming");
  process.env.XDG_DATA_HOME = path.join(fakeHome, "share");
  process.env.HOME = fakeHome;
  process.env.USERPROFILE = fakeHome;
  process.env.FOURDA_MCP_HOME = path.join(base, "mcp-home");
  vi.spyOn(process, "cwd").mockReturnValue(repo);
});

afterEach(() => {
  vi.restoreAllMocks();
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  fs.rmSync(base, { recursive: true, force: true });
});

describe("settings.json discovery", () => {
  it("ignores a settings.json planted in cwd/data or cwd/../data", () => {
    plantSettings(path.join(repo, "data"));
    plantSettings(path.join(repo, "..", "data"));
    expect(getEmbeddingConfig()).toBeNull();
  });

  it("reads FOURDA_SETTINGS_PATH, and the settings beside an explicit FOURDA_DB_PATH", () => {
    plantSettings(path.join(base, "explicit"));
    process.env.FOURDA_SETTINGS_PATH = path.join(base, "explicit", "settings.json");
    expect(getEmbeddingConfig()?.url).toBe("http://127.0.0.1:47123");
    delete process.env.FOURDA_SETTINGS_PATH;

    // Relative FOURDA_DB_PATH resolves against cwd, as the database itself does.
    plantSettings(path.join(repo, "data"));
    process.env.FOURDA_DB_PATH = "./data/4da.db";
    expect(getEmbeddingConfig()?.provider).toBe("ollama");
  });

  it("reads the desktop app's own data directory", () => {
    plantSettings(process.env.FOURDA_DATA_DIR!);
    expect(getEmbeddingConfig()?.provider).toBe("ollama");
  });
});

describe("database discovery", () => {
  it("never adopts a 4da.db planted in cwd/data: the standalone database is used", () => {
    const planted = path.join(repo, "data", "4da.db");
    fs.mkdirSync(path.dirname(planted), { recursive: true });
    new FourDADatabase(planted).close(); // a valid standalone-looking database
    const before = fs.statSync(planted).mtimeMs;
    const db = new FourDADatabase();
    try {
      expect(path.resolve(db.dbPath)).toBe(path.resolve(standaloneDbPath()));
    } finally {
      db.close();
    }
    expect(fs.statSync(planted).mtimeMs).toBe(before);
    expect(FourDADatabase.validateDatabase().error ?? "").not.toContain(planted);
  });

  it("refuses a FOURDA_DB_PATH that names a missing file, and creates nothing", () => {
    process.env.FOURDA_DB_PATH = "./data/4da.db";
    expect(() => new FourDADatabase()).toThrow(/FOURDA_DB_PATH/);
    expect(fs.existsSync(path.join(repo, "data"))).toBe(false);
    const v = FourDADatabase.validateDatabase(process.env.FOURDA_DB_PATH);
    expect(v.valid).toBe(false);
    expect(v.standalone).toBe(false);
    expect(v.error).toMatch(/FOURDA_DB_PATH/);
    expect(fs.existsSync(path.join(repo, "data"))).toBe(false);
  });

  it("still opens an existing database through a relative FOURDA_DB_PATH (the 4DA repo's .mcp.json)", () => {
    const file = path.join(repo, "data", "4da.db");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    new FourDADatabase(file).close();
    process.env.FOURDA_DB_PATH = "./data/4da.db";
    const db = new FourDADatabase();
    try {
      expect(path.resolve(db.dbPath)).toBe(path.resolve(file));
    } finally {
      db.close();
    }
    expect(FourDADatabase.validateDatabase(process.env.FOURDA_DB_PATH).valid).toBe(true);
  });
});
