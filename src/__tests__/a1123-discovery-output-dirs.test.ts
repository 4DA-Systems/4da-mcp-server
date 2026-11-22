// SPDX-License-Identifier: Apache-2.0
/**
 * A lockfile in a directory the repository does not ignore is read, whatever the directory is
 * called: microsoft/vscode keeps real projects under `build/npm/gyp/`, `build/win32/` and
 * `.vscode/extensions/*`, none of them gitignored, and those lockfiles were dropped without a word
 * (minimatch 9.0.5, CVSS 8.7, absent from every answer). A directory that stays excluded by its
 * name (installed code, a tool's build output or cache, agent worktrees) is never scanned, and
 * every lockfile found inside it is listed with a reason. Nothing is dropped silently.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { discoveryNote, MAX_DEPTH, MAX_EXCLUDED_WALK_DIRS, MAX_PROJECTS, scanProjectTree } from "../project-tree.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

const VULNERABLE = new Set(["minimatch", "time", "glob"]);

describe("a1123 discovery: lockfiles under build/ and .vscode/", () => {
  let dir: string;
  let priorOffline: string | undefined;
  let asked: string[];

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-outdirs-"));
    asked = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version?: string }> };
        for (const q of queries) asked.push(`${q.package.name}@${q.version}`);
        return new Response(JSON.stringify({ results: queries.map((q) => (VULNERABLE.has(q.package.name) ? { vulns: [{ id: `GHSA-${q.package.name}` }] } : {})) }), { status: 200 });
      }
      if (url.includes("/v1/vulns/")) {
        const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
        return new Response(JSON.stringify({ id, summary: id, database_specific: { severity: "HIGH" } }), { status: 200 });
      }
      throw new TypeError(`fetch failed (${url})`);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const write = (rel: string, content: string) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  };
  const npmLock = (deps: Record<string, string>) =>
    JSON.stringify({
      name: "x",
      lockfileVersion: 3,
      packages: {
        "": { name: "x", dependencies: deps },
        ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` }])),
      },
    });
  const npmProject = (rel: string, deps: Record<string, string>) => {
    write(`${rel}/package.json`, JSON.stringify({ dependencies: deps }));
    write(`${rel}/package-lock.json`, npmLock(deps));
  };
  const cargoLock = (name: string, version: string) =>
    `version = 3\n\n[[package]]\nname = "${name}"\nversion = "${version}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`;
  const scan = async () =>
    (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
  const rels = () => scanProjectTree(dir).entries.map((e) => path.relative(dir, e.dir).replace(/\\/g, "/") || ".").sort();

  it("the vscode layout: build/<sub>/ and .vscode/extensions/* lockfiles are read when the repository does not ignore them", async () => {
    write(".gitignore", "node_modules/\nout/\n");
    npmProject(".", { "left-pad": "1.3.0" });
    npmProject("build", { "left-pad": "1.3.0" });
    npmProject("build/npm/gyp", { minimatch: "9.0.5", glob: "10.4.2" });
    write("build/win32/Cargo.toml", '[package]\nname = "inno"\nversion = "0.1.0"\n\n[dependencies]\ntime = "0.3"\n');
    write("build/win32/Cargo.lock", `${cargoLock("inno", "0.1.0").replace(/source = .*\n/, "")}\n[[package]]\nname = "time"\nversion = "0.3.11"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`);
    npmProject(".vscode/extensions/vscode-selfhost-import-aid", { "left-pad": "1.3.0" });
    npmProject(".vscode/extensions/vscode-selfhost-test-provider", { minimatch: "9.0.5" });

    expect(rels()).toEqual([".", ".vscode/extensions/vscode-selfhost-import-aid", ".vscode/extensions/vscode-selfhost-test-provider", "build", "build/npm/gyp", "build/win32"]);
    const result = await scan();
    expect(asked).toEqual(expect.arrayContaining(["minimatch@9.0.5", "glob@10.4.2", "time@0.3.11"]));
    expect(result.vulnerable_packages.map((p: any) => `${p.package} ${[...p.source_dirs].sort().join(",")}`).sort()).toEqual([
      "glob build/npm/gyp",
      "minimatch .vscode/extensions/vscode-selfhost-test-provider,build/npm/gyp",
      "time build/win32",
    ]);
    expect(result.coverage?.not_scanned?.lockfiles ?? []).toEqual([]);
  });

  it("a gitignored build/ is listed lockfile by lockfile, deep ones included", () => {
    write(".gitignore", "build/\n");
    npmProject(".", { "left-pad": "1.3.0" });
    npmProject("build", { "left-pad": "1.3.0" });
    npmProject("build/npm/gyp", { minimatch: "9.0.5" });
    const { entries, discovery } = scanProjectTree(dir);
    expect(entries).toHaveLength(1);
    expect(discovery.skipped.sort((a, b) => a.path.localeCompare(b.path))).toEqual([
      { path: "build/npm/gyp/package-lock.json", reason: "gitignored_directory" },
      { path: "build/package-lock.json", reason: "gitignored_directory" },
    ]);
  });

  it("a directory excluded by its name is not scanned, and each lockfile in it is listed with a reason", async () => {
    npmProject(".", { "left-pad": "1.3.0" });
    write("node_modules/x/package-lock.json", npmLock({ minimatch: "9.0.5" }));
    write(".venv/lib/site-packages/y/requirements.txt", "django==3.2.0\n");
    write("target/package/z-0.1.0/Cargo.lock", cargoLock("time", "0.3.11"));
    write(".claude/worktrees/agent-1/package-lock.json", npmLock({ minimatch: "9.0.5" }));
    // Version-control data is never searched.
    write(".git/package-lock.json", npmLock({ minimatch: "9.0.5" }));

    const { entries, discovery } = scanProjectTree(dir);
    expect(entries).toHaveLength(1);
    expect(discovery.skipped.sort((a, b) => a.path.localeCompare(b.path))).toEqual([
      { path: ".claude/worktrees/agent-1/package-lock.json", reason: "excluded_directory" },
      { path: ".venv/lib/site-packages/y/requirements.txt", reason: "excluded_directory" },
      { path: "node_modules/x/package-lock.json", reason: "excluded_directory" },
      { path: "target/package/z-0.1.0/Cargo.lock", reason: "excluded_directory" },
    ]);
    expect(discoveryNote(discovery)).toMatch(/4 lockfiles were found but NOT scanned \(inside installed code, a tool's build output or cache, or an editor's or agent's state/);
    const result = await scan();
    expect(asked).toEqual(["left-pad@1.3.0"]);
    expect(result.coverage).toMatchObject({ complete: false, lockfiles_not_scanned: 4 });
    expect(result.coverage.not_scanned.lockfiles).toEqual(expect.arrayContaining([{ path: "node_modules/x/package-lock.json", reason: "excluded_directory" }]));
  });

  it("the same directories, gitignored, are left out as the repository says, without listing what they hold", () => {
    write(".gitignore", "node_modules/\n.venv/\n/target\n.claude/\n");
    npmProject(".", { "left-pad": "1.3.0" });
    write("node_modules/x/package-lock.json", npmLock({ minimatch: "9.0.5" }));
    write(".venv/lib/site-packages/y/requirements.txt", "django==3.2.0\n");
    write("target/package/z-0.1.0/Cargo.lock", cargoLock("time", "0.3.11"));
    write(".claude/worktrees/agent-1/package-lock.json", npmLock({ minimatch: "9.0.5" }));
    const { entries, discovery } = scanProjectTree(dir);
    expect(entries).toHaveLength(1);
    expect(discovery.skipped).toEqual([]);
    expect(discoveryNote(discovery)).toBeNull();
  });

  it("the search inside excluded directories is bounded, and says when it stopped", () => {
    npmProject(".", { "left-pad": "1.3.0" });
    for (let i = 0; i < 12; i++) fs.mkdirSync(path.join(dir, "node_modules", `p${i}`), { recursive: true });
    const { discovery } = scanProjectTree(dir, { maxDepth: MAX_DEPTH, maxProjects: MAX_PROJECTS, maxExcludedDirs: 10 });
    expect(discovery.excludedWalkTruncated).toBe(true);
    expect(discoveryNote(discovery)).toMatch(new RegExp(`the search of directories excluded by name .* stopped after ${MAX_EXCLUDED_WALK_DIRS} directories`));
    expect(scanProjectTree(dir).discovery.excludedWalkTruncated).toBeUndefined();
  });
});
