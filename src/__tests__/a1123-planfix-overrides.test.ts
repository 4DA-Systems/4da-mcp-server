// SPDX-License-Identifier: Apache-2.0
/**
 * An override row whose snippet a plain command writes exactly is in run_order: `npm pkg set
 * "overrides.<name>=<version>"` (its scope kept), then the install, in the lockfile's directory.
 * The candidate run of 2026-11-23 left every override out (http-server 82 -> 44, where 6.4.0's rows
 * applied by hand had reached 31). One that crosses a major of what its parents declare, or that a
 * command cannot write exactly, stays a hand step, and run_order_note counts and names the hand
 * steps so the script is not read as the whole job.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { overrideCommandsOf, recordOverrideCommands } from "../tools/upgrade-plan-overrides.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const runs = (result: Record<string, any>) => (result.run_order as Array<{ dir: string; run: string }>).map((s) => s.run);

function stuck(childTarget: string, extraTree: Record<string, { version: string; dependencies?: Record<string, string> }> = {}, extraDirect: Record<string, string> = {}) {
  h.ADVISORIES = { child: [adv("GHSA-cccc-0003", "child", fixedIn(childTarget))] };
  h.NPM = {
    par: { latest: "1.0.0", versions: { "1.0.0": { dependencies: { child: "1.0.0" } } } },
    other: { latest: "1.0.0", versions: { "1.0.0": { dependencies: { child: "^2.0.0" } } } },
    child: { latest: childTarget, versions: { "1.0.0": {}, "1.0.2": {}, "2.0.0": {}, "2.0.1": {} } },
  };
  h.npmProject({ par: "1.0.0", ...extraDirect }, {}, { par: { version: "1.0.0", dependencies: { child: "1.0.0" } }, child: { version: "1.0.0" }, ...extraTree });
}

describe("an npm override as commands", () => {
  it("within the parent's major: the snippet as `npm pkg set`, then `npm install`, in run_order", async () => {
    stuck("1.0.2");
    const { result, step } = await h.plan();
    const row = step("child");
    expect(row.action).toBe("override_or_replace");
    expect(row.commands).toEqual([
      { dir: ".", run: 'npm pkg set "overrides.child=1.0.2"' },
      { dir: ".", run: "npm install" },
    ]);
    expect(runs(result)).toEqual(['npm pkg set "overrides.child=1.0.2"', "npm install"]);
    expect(result.run_order[0].fixes).toEqual(["npm:child"]);
  });

  it("scoped to the copy's parent when the lockfile holds another version", async () => {
    stuck("1.0.2", { other: { version: "1.0.0", dependencies: { child: "^2.0.0" } }, "other/node_modules/child": { version: "2.0.0" } }, { other: "1.0.0" });
    const { step } = await h.plan();
    expect(step("child", "1.0.0").commands).toEqual([
      { dir: ".", run: 'npm pkg set "overrides.par.child=1.0.2"' },
      { dir: ".", run: "npm install" },
    ]);
  });

  it("across a major of what the parent declares: a hand step, counted in the note", async () => {
    stuck("2.0.1");
    const { result, step } = await h.plan();
    const row = step("child");
    expect(row.breaking).toBe(true);
    expect(row.commands).toEqual([]);
    expect(result.run_order).toEqual([]);
    expect(result.run_order_note).toMatch(/1 row is a hand edit and is not in this script: child 1\.0\.0/);
  });
});

describe("what a command can write exactly", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });
  const project = (pkg: Record<string, unknown>) => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "4da-planfix-ov-"));
    dirs.push(d);
    fs.writeFileSync(path.join(d, "package.json"), JSON.stringify(pkg));
    return d;
  };
  const record = (root: string, format: Parameters<typeof recordOverrideCommands>[1][number]["format"], name: string, parents: string[] | null = null) => {
    const row = {};
    recordOverrideCommands(row, [{ format, dir: "." }], root, name, "1.0.2", parents);
    return overrideCommandsOf(row).map((c) => c.command);
  };

  it("pnpm and Yarn classic keep their scope syntax; Yarn's install follows", () => {
    const root = project({ name: "x" });
    expect(record(root, "pnpm", "child", ["par"])).toEqual(['npm pkg set "pnpm.overrides.par>child=1.0.2"', "pnpm install"]);
    expect(record(root, "yarn", "child", ["par"])).toEqual(['npm pkg set "resolutions.par/child=1.0.2"', "yarn install"]);
    expect(record(root, "yarn-berry", "child")).toEqual(['npm pkg set "resolutions.child=1.0.2"', "yarn install"]);
  });

  it("is none when package.json already has an entry there, a name has a dot, or Yarn Berry would force every copy", () => {
    expect(record(project({ overrides: { child: "1.0.1" } }), "package-lock", "child")).toEqual([]);
    expect(record(project({ overrides: { par: "1.0.0" } }), "package-lock", "child", ["par"])).toEqual([]);
    expect(record(project({ name: "x" }), "package-lock", "lodash.pick")).toEqual([]);
    expect(record(project({ name: "x" }), "yarn-berry", "child", ["par"])).toEqual([]);
  });
});

describe("an override row whose only commands are a parent's lever", () => {
  it("is not in run_order: the lever covers some paths, the override is the fix, and it crosses a major (http-server cross-spawn 5.1.0)", async () => {
    const { buildRunOrder } = await import("../tools/upgrade-plan-sequence.js");
    const row = {
      package: "cross-spawn",
      ecosystem: "npm",
      currentVersion: "5.1.0",
      targetVersion: "6.0.6",
      action: "override_or_replace",
      breaking: true,
      reasons: ["Transitive dependency: eslint 4.19.1 requires \"^5.1.0\". Force cross-spawn to 6.0.6: npm: add ..."],
      commands: [{ dir: ".", run: 'npm install "eslint@^5.0.0"' }],
      parentUpgrades: [{ parent: "eslint", levers: [{ name: "eslint", version: "4.19.1", to: "5.0.0", commands: [{ dir: ".", command: 'npm install "eslint@^5.0.0"' }] }] }],
    };
    const out = buildRunOrder({ rows: [row], totalRows: 1, heldUnclean: () => false });
    expect(out.run_order).toEqual([]);
    expect(out.run_order_note).toMatch(/1 row is a hand edit and is not in this script: cross-spawn 5\.1\.0/);
  });
});
