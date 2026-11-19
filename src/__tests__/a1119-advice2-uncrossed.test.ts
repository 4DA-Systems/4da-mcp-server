// SPDX-License-Identifier: Apache-2.0
/**
 * A lockfile is cross-checked against the package.json beside it: a declared dependency with no
 * entry means the file is older than the manifest or cut short. A name a workspace member answers
 * needs no entry, so when the member list cannot be read whole that check is not made for the
 * names it would flag. The answer then says the lockfile was not cross-checked and why, in the
 * place the partial-lockfile notes go, without calling the lockfile damaged or partial.
 * yarn and pnpm gate the check on the member list; bun lists its members as entries and does not.
 */

import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { lockfileProblemNotes } from "../project-tree.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { removeProject, scanProject, stubOsv, tempProject } from "./helpers/a1119-readers.js";

const YARN = `# yarn lockfile v1\n\n\nms@2.1.3:\n  version "2.1.3"\n  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz"\n  integrity sha512-AAAA\n`;
const member = (name: string) => JSON.stringify({ name, version: "1.0.0" });
const ROOT = JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"], dependencies: { ms: "2.1.3", "ws-b": "^1.0.0" } });

/** packages/b's package.json cannot be read: ws-b may be that member. */
const YARN_UNREAD = { "package.json": ROOT, "packages/a/package.json": member("ws-a"), "packages/b/package.json": "{ not json", "yarn.lock": YARN };

const PNPM_LOCK = [
  "lockfileVersion: '9.0'",
  "",
  "importers:",
  "",
  "  .:",
  "    dependencies:",
  "      ms:",
  "        specifier: 2.1.3",
  "        version: 2.1.3",
  "",
  "packages:",
  "",
  "  ms@2.1.3:",
  "    resolution: {integrity: sha512-AAAA}",
  "",
  "snapshots:",
  "",
  "  ms@2.1.3: {}",
  "",
].join("\n");
const PNPM_UNREAD = {
  "package.json": JSON.stringify({ name: "root", private: true, dependencies: { ms: "2.1.3", "ws-b": "^1.0.0" } }),
  "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n",
  "packages/a/package.json": member("ws-a"),
  "packages/b/package.json": "{ not json",
  "pnpm-lock.yaml": PNPM_LOCK,
};

const problemsOf = (dir: string) => resolveVersionSource(dir, "npm").problems ?? [];
const NOT_DAMAGE = /truncated|damaged|partial|corrupt|older than/i;

describe("a lockfile not cross-checked against its manifests says so", () => {
  let dirs: string[];
  let priorOffline: string | undefined;
  const project = (files: Record<string, string>) => {
    const dir = tempProject(files);
    dirs.push(dir);
    return dir;
  };
  beforeEach(() => {
    dirs = [];
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    dirs.forEach(removeProject);
  });

  it("yarn: an unreadable member manifest: one note, why, never damage", () => {
    const problems = problemsOf(project(YARN_UNREAD));
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatchObject({ notCrossChecked: true });
    expect(problems[0].partial).toBeUndefined();
    expect(problems[0].skipped).toBeUndefined();
    expect(problems[0].error).toMatch(/ws-b \(dependencies\) has no entry in it/);
    expect(problems[0].error).toMatch(/packages\/b\/package\.json could not be read/);
    expect(problems[0].error).not.toMatch(NOT_DAMAGE);
    const notes = lockfileProblemNotes(problems, () => "yarn.lock");
    expect(notes).toEqual([expect.stringMatching(/^NOT CROSS-CHECKED: 1 lockfile was not cross-checked against the package\.json files: yarn\.lock \(/)]);
    expect(notes[0]).not.toMatch(/UNREADABLE|PARTIAL/);
  });

  it("yarn: a workspaces pattern that cannot be expanded is named as the reason", () => {
    const dir = project({ ...YARN_UNREAD, "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/[ab]"], dependencies: { ms: "2.1.3", "ws-b": "^1.0.0" } }), "packages/b/package.json": member("ws-b") });
    const [problem] = problemsOf(dir);
    expect(problem).toMatchObject({ notCrossChecked: true });
    expect(problem.error).toMatch(/a workspaces pattern could not be expanded/);
  });

  it("nothing is said when every declared name has an entry, or the member list is whole", () => {
    expect(problemsOf(project({ ...YARN_UNREAD, "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"], dependencies: { ms: "2.1.3" } }) }))).toEqual([]);
    expect(problemsOf(project({ ...YARN_UNREAD, "packages/b/package.json": member("ws-b") }))).toEqual([]);
  });

  it("pnpm: the same gate, the same note", () => {
    const problems = problemsOf(project(PNPM_UNREAD));
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatchObject({ notCrossChecked: true });
    expect(problems[0].error).toMatch(/ws-b \(dependencies\) has no entry in it/);
    expect(problems[0].error).toMatch(/packages\/b\/package\.json could not be read/);
    expect(problems[0].error).not.toMatch(NOT_DAMAGE);
  });

  it("pnpm: a lockfile that records no importer for the project says it was not compared, never nothing", () => {
    const lock = ["lockfileVersion: '6.0'", "", "packages:", "", "  /ms@2.1.3:", "    resolution: {integrity: sha512-AAAA}", "    dev: false", ""].join("\n");
    const problems = problemsOf(project({ "package.json": JSON.stringify({ name: "root", dependencies: { ms: "2.1.3", lodash: "^4.17.21" } }), "pnpm-lock.yaml": lock }));
    expect(problems).toEqual([expect.objectContaining({ notCrossChecked: true, error: expect.stringMatching(/records no importer for the project itself, so what it holds for ms \(dependencies\) and 1 more/) })]);
    expect(problems[0].error).not.toMatch(NOT_DAMAGE);
  });

  it("bun lists its members as entries: the check runs whatever a member's manifest holds", () => {
    const lock = {
      lockfileVersion: 1,
      workspaces: { "": { name: "root", dependencies: { ms: "2.1.3" } }, "packages/a": { name: "ws-a" } },
      packages: { "ws-a": ["ws-a@workspace:packages/a"], ms: ["ms@2.1.3", "", {}, "sha512-AAAA=="] },
    };
    const dir = project({
      "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"], dependencies: { ms: "2.1.3", "ws-b": "^1.0.0" } }),
      "packages/a/package.json": member("ws-a"),
      "packages/b/package.json": "{ not json",
      "bun.lock": JSON.stringify(lock, null, 2),
    });
    const [problem] = problemsOf(dir);
    expect(problem.notCrossChecked).toBeUndefined();
    expect(problem.error).toMatch(/package\.json declares ws-b \(dependencies\), but this lockfile has no entry for it/);
  });

  it("vulnerability_scan, dependency_health and upgrade_planner carry the note, apart from damage", async () => {
    stubOsv([]);
    const dir = project(YARN_UNREAD);
    const scan = await scanProject(dir);
    expect(scan.coverage.note).toMatch(/NOT CROSS-CHECKED: 1 lockfile was not cross-checked against the package\.json files: yarn\.lock \(/);
    expect(scan.coverage.not_cross_checked_lockfiles).toEqual([{ path: "yarn.lock", reason: expect.stringMatching(/ws-b \(dependencies\)/) }]);
    expect(scan.coverage.partial_lockfiles).toBeUndefined();
    expect(scan.coverage.unreadable_lockfiles).toBeUndefined();
    const concise = await scanProject(dir, { response_format: "concise" });
    expect(concise.coverage.not_cross_checked_lockfiles).toHaveLength(1);

    const live = new LiveIntelligence(new Database(":memory:"));
    const { entries, discovery } = scanProjectTree(dir);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    const health = JSON.stringify(await executeDependencyHealth(null as never, { project_path: dir } as never, live));
    expect(health).toMatch(/NOT CROSS-CHECKED: 1 lockfile/);
    expect(health).not.toMatch(/UNREADABLE/);
    const plan = JSON.stringify(await executeUpgradePlanner(null as never, { project_path: dir } as never, live));
    expect(plan).toMatch(/NOT CROSS-CHECKED: 1 lockfile/);
  });
});
