// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, H-7: below Node.js 22 the server started and served with no word of its own (npm's
 * EBADENGINE warning is hidden by MCP clients; a cold start on Node 20.20.2 took 30 s and then ran an
 * untested server). The entry's first import now stops it with one stderr line and exit code 1;
 * `--version` and `--help` still answer. Checked by hand on real Node 18.20.8, 20.20.2 and 22.12.0
 * (on 18, undici does not even load, so the gate answers those two itself).
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { asksOnlyForVersionOrHelp, nodeTooOldLine } from "../node-gate.js";

const root = path.resolve(".");
const entry = path.join(root, "dist", "index.js");
const VERSION = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).version as string;

describe("the gate's rule", () => {
  it("22 and later pass; below, one line naming both versions", () => {
    for (const v of ["22.0.0", "22.12.0", "23.0.0", "24.15.0", "30.1.2"]) expect(nodeTooOldLine(v), v).toBeNull();
    for (const v of ["20.20.2", "18.20.8", "21.7.3", "16.0.0"]) {
      const line = nodeTooOldLine(v)!;
      expect(line).toBe(`[4DA] Node.js 22 or newer is needed; this is Node.js ${v}. Install Node.js 22.13 or later (its built-in SQLite driver needs nothing built), then start the server again.`);
      expect(line).not.toContain("\n");
    }
    expect(nodeTooOldLine("garbage")).not.toBeNull();
  });

  it("only a request for the version or the usage is answered on an old Node", () => {
    expect(asksOnlyForVersionOrHelp(["--version"])).toBe(true);
    expect(asksOnlyForVersionOrHelp(["-h"])).toBe(true);
    expect(asksOnlyForVersionOrHelp(["--version", "--help"])).toBe(true);
    expect(asksOnlyForVersionOrHelp([])).toBe(false);
    expect(asksOnlyForVersionOrHelp(["--version", "--http"])).toBe(false);
    expect(asksOnlyForVersionOrHelp(["--setup"])).toBe(false);
  });

  it("it is the entry's first import, so it runs before any other module", () => {
    const source = readFileSync(path.join(root, "src", "index.ts"), "utf8");
    const imports = source.split("\n").filter((l) => /^import\s/.test(l));
    expect(imports[0]).toBe('import "./node-gate.js";');
  });
});

describe.skipIf(!existsSync(entry))("the built server under an old Node.js version", () => {
  let dir: string;
  let preload: string;
  beforeAll(() => {
    dir = mkdtempSync(path.join(tmpdir(), "4da-w2-gate-"));
    preload = path.join(dir, "node20.cjs");
    // process.versions reports another Node: what the gate reads, the rest of this Node unchanged.
    writeFileSync(preload, "Object.defineProperty(process, 'versions', { value: { ...process.versions, node: '20.20.2' } });\n");
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  const run = (args: string[]) =>
    spawnSync(process.execPath, ["--require", preload, entry, ...args], {
      input: "",
      encoding: "utf8",
      timeout: 30_000,
      env: { ...process.env, FOURDA_MCP_HOME: path.join(dir, "home"), FOURDA_OFFLINE: "1", HOME: dir, USERPROFILE: dir, APPDATA: path.join(dir, "Roaming") },
    });

  it("serving, --doctor and --setup stop with one stderr line and exit 1, and print nothing on stdout", () => {
    for (const args of [[], ["--doctor"], ["--setup", "--dry-run"], ["--http"]]) {
      const r = run(args);
      expect(r.status, args.join(" ")).toBe(1);
      expect(r.stdout).toBe("");
      expect(r.stderr.trim().split("\n")).toEqual([nodeTooOldLine("20.20.2")]);
    }
  });

  it("--version and --help still answer", () => {
    const v = run(["--version"]);
    expect(v.status).toBe(0);
    expect(v.stdout.trim()).toBe(`@4da/mcp-server ${VERSION}`);
    const h = run(["--help"]);
    expect(h.status).toBe(0);
    expect(h.stdout).toContain("Usage:");
    expect(h.stderr).toContain("Node.js 22 or newer is needed");
  });
});
