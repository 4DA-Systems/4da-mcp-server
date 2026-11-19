// SPDX-License-Identifier: Apache-2.0
/**
 * npm-shrinkwrap.json beside package-lock.json: npm installs from the
 * shrinkwrap and ignores package-lock.json, so the shrinkwrap is what is
 * read, and the answer says the other file was ignored and why.
 *
 * The fixture pins lodash 4.17.15 in npm-shrinkwrap.json (what `npm ls`
 * shows) and 4.18.1 in package-lock.json.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { fixtureProject, npmAdvisory, removeProject, scanProject, stubOsv, tempProject, vulnerableCopies } from "./helpers/a1119-readers.js";

const LODASH = npmAdvisory("GHSA-35jh-r3h4-6jhm", "lodash", "4.17.21", "HIGH");

const lockOf = (lodash: string) =>
  JSON.stringify({
    name: "x",
    lockfileVersion: 3,
    packages: { "": { name: "x", dependencies: { lodash: "^4.17.15" } }, "node_modules/lodash": { version: lodash } },
  });
const MANIFEST = JSON.stringify({ name: "x", dependencies: { lodash: "^4.17.15" } });

describe("npm-shrinkwrap.json takes precedence over package-lock.json", () => {
  let dirs: string[];
  let priorOffline: string | undefined;
  const project = (dir: string) => {
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

  it("reads the shrinkwrap and says package-lock.json is the one npm ignores", () => {
    const dir = project(fixtureProject("npm-shrinkwrap-precedence"));
    const read = resolveVersionSource(dir, "npm");
    expect(path.basename(read.source ?? "")).toBe("npm-shrinkwrap.json");
    expect(read.versions.get("lodash")).toBe("4.17.15");
    expect(read.instances.map((i) => `${i.name}@${i.version}`)).toEqual(["lodash@4.17.15"]);
    expect(read.problems).toHaveLength(1);
    const problem = read.problems![0];
    expect(path.basename(problem.file)).toBe("package-lock.json");
    expect(problem.conflict).toBe(true);
    expect(problem.error).toMatch(/npm-shrinkwrap\.json was read instead: npm installs from npm-shrinkwrap\.json and ignores package-lock\.json when both are present/);
    expect(problem.error).toMatch(/lodash 4\.18\.1 here, 4\.17\.15 in npm-shrinkwrap\.json/);
    // Which file is stale is known here: nothing says it cannot be told.
    expect(problem.error).not.toMatch(/cannot tell which/);
  });

  it("the scan reports the version npm installs", async () => {
    stubOsv([LODASH]);
    const answer = await scanProject(project(fixtureProject("npm-shrinkwrap-precedence")));
    expect(vulnerableCopies(answer)).toEqual(["lodash@4.17.15"]);
    expect(answer.coverage.note).toMatch(/npm installs from npm-shrinkwrap\.json and ignores package-lock\.json/);
    expect(answer.coverage.conflicting_lockfiles).toEqual([expect.objectContaining({ path: "package-lock.json" })]);
  });

  it("says nothing when both files pin the same set", () => {
    const dir = project(tempProject({ "package.json": MANIFEST, "package-lock.json": lockOf("4.17.15"), "npm-shrinkwrap.json": lockOf("4.17.15") }));
    const read = resolveVersionSource(dir, "npm");
    expect(path.basename(read.source ?? "")).toBe("npm-shrinkwrap.json");
    expect(read.problems ?? []).toEqual([]);
  });

  it("a shrinkwrap that cannot be parsed is named, and package-lock.json is read", () => {
    const dir = project(tempProject({ "package.json": MANIFEST, "package-lock.json": lockOf("4.18.1"), "npm-shrinkwrap.json": '{ "name": "x", "packages": {' }));
    const read = resolveVersionSource(dir, "npm");
    expect(path.basename(read.source ?? "")).toBe("package-lock.json");
    expect(read.problems).toHaveLength(1);
    expect(path.basename(read.problems![0].file)).toBe("npm-shrinkwrap.json");
    expect(read.problems![0].error).toMatch(/invalid JSON/);
  });

  it("package-lock.json alone is read as before", () => {
    const dir = project(tempProject({ "package.json": MANIFEST, "package-lock.json": lockOf("4.18.1") }));
    const read = resolveVersionSource(dir, "npm");
    expect(path.basename(read.source ?? "")).toBe("package-lock.json");
    expect(read.problems ?? []).toEqual([]);
    expect(fs.existsSync(path.join(dir, "npm-shrinkwrap.json"))).toBe(false);
  });

  it("another package manager's lockfile beside package-lock.json is still a conflict that cannot be settled", () => {
    const pnpm = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.15\n        version: 4.17.15\n\npackages:\n\n  lodash@4.17.15:\n    resolution: {integrity: sha512-AAAA}\n\nsnapshots:\n\n  lodash@4.17.15: {}\n";
    const dir = project(tempProject({ "package.json": MANIFEST, "package-lock.json": lockOf("4.18.1"), "pnpm-lock.yaml": pnpm }));
    const read = resolveVersionSource(dir, "npm");
    expect(path.basename(read.source ?? "")).toBe("package-lock.json");
    expect(read.problems![0].error).toMatch(/package-lock\.json was read instead.*One of the two is stale and the scan cannot tell which/);
  });
});
