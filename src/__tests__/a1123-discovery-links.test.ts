// SPDX-License-Identifier: Apache-2.0
/**
 * Workspace members that are junctions or symbolic links. A directory listing reports a link as a
 * link, not a directory, so the walk passed over every one of them and the answer read complete
 * (a monorepo with a junction to flask and a symlink to json-server answered 1/214, no coverage).
 * A link whose real path is inside the project root, and not walked already, is followed; any
 * other is not scanned, and each lockfile behind it is listed (reason `symlink_outside_root`).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { discoveryNote, scanProjectTree } from "../project-tree.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

/** A directory link of the kind the platform makes without privileges: a junction on Windows. */
function linkDir(target: string, link: string): boolean {
  try {
    fs.symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir");
    return true;
  } catch {
    return false;
  }
}

/** Whether this machine lets a test create a directory symbolic link (Windows needs developer mode or elevation). */
function canSymlink(): boolean {
  const probe = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-symprobe-"));
  try {
    fs.mkdirSync(path.join(probe, "t"));
    fs.symlinkSync(path.join(probe, "t"), path.join(probe, "l"), "dir");
    return true;
  } catch {
    return false;
  } finally {
    fs.rmSync(probe, { recursive: true, force: true });
  }
}

describe("a1123 discovery: workspace members behind junctions and symlinks", () => {
  let base: string;
  let dir: string;
  let outside: string;
  let priorOffline: string | undefined;
  let asked: string[];

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    base = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-links-"));
    dir = path.join(base, "repo");
    outside = path.join(base, "elsewhere");
    fs.mkdirSync(dir);
    fs.mkdirSync(outside);
    asked = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version?: string }> };
        for (const q of queries) asked.push(`${q.package.name}@${q.version}`);
        return new Response(JSON.stringify({ results: queries.map(() => ({})) }), { status: 200 });
      }
      throw new TypeError(`fetch failed (${url})`);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    fs.rmSync(base, { recursive: true, force: true });
  });

  const npmProject = (at: string, deps: Record<string, string>) => {
    fs.mkdirSync(at, { recursive: true });
    fs.writeFileSync(path.join(at, "package.json"), JSON.stringify({ dependencies: deps }));
    fs.writeFileSync(
      path.join(at, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { dependencies: deps },
          ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` }])),
        },
      }),
    );
  };
  const rels = () => scanProjectTree(dir).entries.map((e) => path.relative(dir, e.dir).replace(/\\/g, "/") || ".").sort();

  it("a junction to a directory inside the root is followed once; one that leads outside is listed, not scanned", async () => {
    npmProject(path.join(dir, "packages", "real"), { "left-pad": "1.3.0" });
    // Inside the root: walked once, under the path reached first (libs/ sorts before packages/).
    npmProject(path.join(dir, "libs", "core"), { "is-odd": "3.0.1" });
    expect(linkDir(path.join(dir, "libs", "core"), path.join(dir, "packages", "core-link"))).toBe(true);
    // Outside the root.
    npmProject(path.join(outside, "flask-like"), { "is-even": "1.0.0" });
    fs.mkdirSync(path.join(outside, "flask-like", "sub"));
    fs.writeFileSync(path.join(outside, "flask-like", "sub", "requirements.txt"), "django==3.2.0\n");
    expect(linkDir(path.join(outside, "flask-like"), path.join(dir, "packages", "junction-out"))).toBe(true);

    expect(rels()).toEqual([".", "libs/core", "packages/real"]);
    const { discovery } = scanProjectTree(dir);
    expect(discovery.skipped.sort((a, b) => a.path.localeCompare(b.path))).toEqual([
      { path: "packages/junction-out/package-lock.json", reason: "symlink_outside_root" },
      { path: "packages/junction-out/sub/requirements.txt", reason: "symlink_outside_root" },
    ]);
    expect(discoveryNote(discovery)).toMatch(/2 lockfiles were found but NOT scanned \(behind a link .*that leads outside the project\)/);

    const result = (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
    expect(asked.sort()).toEqual(["is-odd@3.0.1", "left-pad@1.3.0"]);
    expect(result.coverage).toMatchObject({ complete: false, lockfiles_not_scanned: 2 });
    expect(result.coverage.not_scanned.lockfiles).toEqual(expect.arrayContaining([{ path: "packages/junction-out/package-lock.json", reason: "symlink_outside_root" }]));
  });

  it("a directory reached both directly and through a link is walked once", () => {
    npmProject(path.join(dir, "libs", "core"), { "left-pad": "1.3.0" });
    expect(linkDir(path.join(dir, "libs", "core"), path.join(dir, "zz-link"))).toBe(true);
    expect(linkDir(path.join(dir, "libs", "core"), path.join(dir, "aa-link"))).toBe(true);
    const found = rels();
    expect(found.filter((r) => r !== ".")).toHaveLength(1);
  });

  it("a link back to the root or an ancestor does not loop", () => {
    npmProject(path.join(dir, "packages", "a"), { "left-pad": "1.3.0" });
    expect(linkDir(dir, path.join(dir, "packages", "a", "loop"))).toBe(true);
    expect(linkDir(base, path.join(dir, "packages", "up"))).toBe(true);
    npmProject(path.join(outside, "x"), { "is-even": "1.0.0" });
    const { entries, discovery } = scanProjectTree(dir);
    expect(entries.map((e) => path.relative(dir, e.dir).replace(/\\/g, "/") || ".").sort()).toEqual([".", "packages/a"]);
    // `up` leads outside the root (to its parent): what is behind it is listed, never the root's own lockfiles again.
    expect(discovery.skipped).toEqual([{ path: "packages/up/elsewhere/x/package-lock.json", reason: "symlink_outside_root" }]);
    expect(discovery.walkTruncated).toBe(false);
  });

  it("a scan started in a directory that is itself a junction reads its target", () => {
    npmProject(path.join(outside, "proj"), { "left-pad": "1.3.0" });
    const linked = path.join(base, "proj-link");
    expect(linkDir(path.join(outside, "proj"), linked)).toBe(true);
    const { entries } = scanProjectTree(linked);
    expect(entries).toHaveLength(1);
    expect(entries[0].scan.dependencies).toContain("left-pad");
  });

  it.skipIf(!canSymlink())("a directory symbolic link (mklink /D) is treated as a junction is", () => {
    npmProject(path.join(outside, "json-server-like"), { "is-even": "1.0.0" });
    fs.symlinkSync(path.join(outside, "json-server-like"), path.join(dir, "symlink-out"), "dir");
    npmProject(path.join(dir, "lib"), { "left-pad": "1.3.0" });
    fs.symlinkSync(path.join(dir, "lib"), path.join(dir, "a-symlink-in"), "dir");
    const { entries, discovery } = scanProjectTree(dir);
    expect(entries.map((e) => path.relative(dir, e.dir).replace(/\\/g, "/") || ".").sort()).toEqual([".", "a-symlink-in"]);
    expect(discovery.skipped).toEqual([{ path: "symlink-out/package-lock.json", reason: "symlink_outside_root" }]);
  });
});
