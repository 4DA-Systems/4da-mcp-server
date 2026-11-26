// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, H-6: a config that is a symbolic link to a file not made yet (a dotfiles checkout)
 * was replaced by a plain file with no backup, and a config with a second hard link was given a new
 * file, so the other name kept the old content. Both said only "Written". Now a link is written
 * through to where it points (the file is created when its folder exists), a hard-linked file is
 * written in place after its backup, and setup says which it did. Also: temp files that a run stopped
 * mid-write left beside a config (each a full copy of it) are removed by the next run.
 */
import { existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { configTarget, editorTargets, runSetup, writeConfig, type SetupContext } from "../setup.js";

let home: string;
let ctx: SetupContext;
let lines: string[];
const log = (line: string) => lines.push(line);
const output = () => lines.join("\n");

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "4da-w2-links-"));
  ctx = { platform: process.platform, env: { APPDATA: path.join(home, "Roaming"), XDG_CONFIG_HOME: path.join(home, ".config") }, home };
  lines = [];
});
afterEach(() => rmSync(home, { recursive: true, force: true }));

/** A symlink, or false where this host does not allow one (Windows without the privilege). */
function trySymlink(target: string, at: string): boolean {
  try {
    symlinkSync(target, at, "file");
    return true;
  } catch {
    return false;
  }
}

function cursorConfig(): string {
  const t = editorTargets(ctx).find((x) => x.name === "Cursor")!;
  mkdirSync(t.detectDir, { recursive: true });
  return t.configPath;
}

describe("a symbolic link is written through to where it points", () => {
  it("a link to a file not made yet: the file is created there, the link stays a link, and setup says so", () => {
    const config = cursorConfig();
    const dot = path.join(home, "dotfiles");
    mkdirSync(dot);
    const where = path.join(dot, "cursor-mcp.json");
    if (!trySymlink(where, config)) return;
    const result = runSetup({}, ctx, log);
    expect(result.exitCode).toBe(0);
    expect(lstatSync(config).isSymbolicLink()).toBe(true);
    expect(readlinkSync(config)).toBe(where);
    expect(JSON.parse(readFileSync(where, "utf8")).mcpServers["4da"].command).toBe("npx");
    expect(output()).toContain(`It is a symbolic link: created ${where}, where it points; the link is kept.`);
    expect(readdirSync(dot)).toEqual(["cursor-mcp.json"]);
  });

  it("a relative link, and a chain of two links, end at the same file", () => {
    const config = cursorConfig();
    const dot = path.join(home, "dotfiles");
    mkdirSync(dot);
    const middle = path.join(dot, "middle.json");
    if (!trySymlink("final.json", middle)) return;
    if (!trySymlink(path.relative(path.dirname(config), middle), config)) return;
    expect(configTarget(config)).toEqual({ target: path.join(dot, "final.json"), viaLink: true });
    runSetup({}, ctx, log);
    expect(lstatSync(config).isSymbolicLink()).toBe(true);
    expect(lstatSync(middle).isSymbolicLink()).toBe(true);
    expect(JSON.parse(readFileSync(path.join(dot, "final.json"), "utf8")).mcpServers["4da"]).toBeDefined();
  });

  it("a link into a folder that does not exist: nothing is created, the link is left, exit 1", () => {
    const config = cursorConfig();
    const where = path.join(home, "not-mounted", "dotfiles", "cursor-mcp.json");
    if (!trySymlink(where, config)) return;
    const result = runSetup({}, ctx, log);
    expect(result.exitCode).toBe(1);
    expect(lstatSync(config).isSymbolicLink()).toBe(true);
    expect(existsSync(path.join(home, "not-mounted"))).toBe(false);
    expect(output()).toContain("whose folder does not exist");
    expect(output()).toContain("Add this by hand:");
  });

  it("a link loop is refused, and both links are left", () => {
    const config = cursorConfig();
    const other = path.join(path.dirname(config), "loop.json");
    if (!trySymlink(other, config) || !trySymlink(config, other)) return;
    const result = runSetup({}, ctx, log);
    expect(result.exitCode).toBe(1);
    expect(lstatSync(config).isSymbolicLink()).toBe(true);
    expect(lstatSync(other).isSymbolicLink()).toBe(true);
    expect(output()).toContain("symbolic links");
  });

  it("a link to an existing file: written there with its backup beside it, the link kept", () => {
    const config = cursorConfig();
    const where = path.join(home, "dotfiles-mcp.json");
    writeFileSync(where, '{ "mcpServers": { "other": { "command": "x" } } }\n');
    if (!trySymlink(where, config)) return;
    runSetup({}, ctx, log);
    expect(lstatSync(config).isSymbolicLink()).toBe(true);
    expect(readFileSync(`${where}.bak`, "utf8")).toContain('"other"');
    expect(output()).toContain(`It is a symbolic link: written ${where}, where it points; the link is kept.`);
  });
});

describe("a hard-linked config is written in place", () => {
  it("every name sees the new content, the link count stays, the backup holds the old one", () => {
    const config = cursorConfig();
    const dot = path.join(home, "dotfiles-cursor.json");
    const original = '{ "mcpServers": { "other": { "command": "x", "args": ["a", "b", "c", "d", "e", "f", "g", "h"] } } }\n';
    writeFileSync(dot, original);
    linkSync(dot, config);
    expect(statSync(config).nlink).toBe(2);
    const result = runSetup({}, ctx, log);
    expect(result.exitCode).toBe(0);
    expect(statSync(config).nlink).toBe(2);
    const fromDotfiles = JSON.parse(readFileSync(dot, "utf8"));
    expect(fromDotfiles.mcpServers["4da"]).toBeDefined();
    expect(fromDotfiles.mcpServers.other.command).toBe("x");
    expect(readFileSync(config, "utf8")).toBe(readFileSync(dot, "utf8"));
    expect(readFileSync(`${config}.bak`, "utf8")).toBe(original);
    expect(output()).toContain("It has 2 hard links: written in place so each of them keeps naming it.");
  });

  it("a shorter new content leaves no tail of the old one", () => {
    const dir = path.join(home, "h");
    mkdirSync(dir);
    const a = path.join(dir, "a.json");
    writeFileSync(a, "x".repeat(5000));
    linkSync(a, path.join(dir, "b.json"));
    writeConfig(a, "{}\n");
    expect(readFileSync(path.join(dir, "b.json"), "utf8")).toBe("{}\n");
  });
});

describe("temp files left by a run stopped mid-write", () => {
  it("one whose process is gone is removed and named; a live run's, our own, and a directory are left", () => {
    const dir = path.join(home, "t");
    mkdirSync(dir);
    const file = path.join(dir, "mcp.json");
    writeFileSync(file, "{}\n");
    const dead = `${file}.4da-4294967.tmp`;
    const live = `${file}.4da-${process.ppid}.tmp`;
    writeFileSync(dead, "a full copy of the config");
    writeFileSync(live, "a write in progress");
    mkdirSync(`${file}.4da-4294968.tmp`);
    const outcome = writeConfig(file, '{ "a": 1 }\n');
    expect(outcome.removedLeftovers).toEqual([dead]);
    expect(existsSync(dead)).toBe(false);
    expect(existsSync(live)).toBe(true);
    expect(existsSync(`${file}.4da-4294968.tmp`)).toBe(true);
  });
});
