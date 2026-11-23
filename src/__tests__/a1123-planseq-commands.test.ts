// SPDX-License-Identifier: Apache-2.0
/**
 * Every instruction upgrade_planner gives a developer to run is also data: `commands` on the row,
 * `{ dir, run }`, from the same fields the row's words are built from. A hand edit (yarn.lock or
 * bun.lock entries, an override, a manifest edit) is never a command.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { manualRefreshSteps } from "../live/fix-paths.js";
import { isManualStep, rowCommands, type CommandRow } from "../tools/upgrade-plan-sequence.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const row = (fields: Partial<CommandRow>): CommandRow => ({ package: "p", ecosystem: "npm", currentVersion: "1.0.0", targetVersion: "1.0.1", ...fields });
const ctx = { root: "/proj" };

describe("rowCommands: one entry per command, per route and tool", () => {
  it.each([
    ["npm install", "npm install a@1.2.3 --save-exact"],
    ["npm caret", 'npm install "a@^1.2.3"'],
    ["pnpm up", 'pnpm up "a@^1.2.3"'],
    ["Yarn classic", 'yarn upgrade "a@^1.2.3"'],
    ["Yarn Berry", 'yarn up "a@^1.2.3"'],
    ["Yarn workspace member", 'yarn workspace web add "a@^1.2.3" --dev'],
    ["cargo add", 'cargo add "serde@^1.0.200"'],
    ["go get", "go get golang.org/x/text@v0.41.0"],
  ])("a direct upgrade (%s) is its command", (_, command) => {
    expect(rowCommands(row({ upgradeCommands: [{ dir: "packages/a", command }] }), ctx)).toEqual([{ dir: "packages/a", run: command }]);
  });

  it.each([
    ["npm", "npm update minimist"],
    ["pnpm", "pnpm update -r minimist --depth Infinity"],
    ["Yarn Berry", "yarn up -R minimist"],
    ["uv", "uv lock --upgrade-package certifi"],
    ["Poetry", "poetry update certifi"],
  ])("a lockfile refresh (%s) is its command", (_, command) => {
    expect(rowCommands(row({ refreshCommands: [{ dir: ".", command }] }), ctx)).toEqual([{ dir: ".", run: command }]);
  });

  it("a Cargo refresh that pre-updates crates is two commands, in order", () => {
    const command = "cargo update -p either@1.6.1 -p log@0.4.14 && cargo update -p url@2.2.2 --precise 2.5.9";
    expect(rowCommands(row({ ecosystem: "crates.io", refreshCommands: [{ dir: ".", command }] }), ctx)).toEqual([
      { dir: ".", run: "cargo update -p either@1.6.1 -p log@0.4.14" },
      { dir: ".", run: "cargo update -p url@2.2.2 --precise 2.5.9" },
    ]);
  });

  it("a Go raise keeps both of its entries", () => {
    const refreshCommands = [
      { dir: ".", command: "go get golang.org/x/crypto@v0.59.0" },
      { dir: ".", command: "go mod tidy" },
    ];
    expect(rowCommands(row({ ecosystem: "Go", refreshCommands }), ctx).map((c) => c.run)).toEqual(["go get golang.org/x/crypto@v0.59.0", "go mod tidy"]);
  });

  it("a parent upgrade gives every lever's command, then the refreshes that follow them", () => {
    const parentUpgrades = [
      { levers: [{ commands: [{ dir: ".", command: "npm install mkdirp@0.5.5 --save-exact" }] }], refreshCommands: [{ dir: ".", command: "npm update minimist" }] },
      { levers: [{ commands: [{ dir: ".", command: "npm install mocha@7.1.2 --save-exact" }] }, {}] },
    ];
    expect(rowCommands(row({ parentUpgrades }), ctx).map((c) => c.run)).toEqual([
      "npm install mkdirp@0.5.5 --save-exact",
      "npm install mocha@7.1.2 --save-exact",
      "npm update minimist",
    ]);
  });

  it("a reinstall runs in every directory whose node_modules drifted", () => {
    expect(rowCommands(row({ installFix: "npm ci" }), { root: "/proj", installDirs: ["web", "api"] })).toEqual([
      { dir: "web", run: "npm ci" },
      { dir: "api", run: "npm ci" },
    ]);
  });

  it("the hand-edit refresh of Yarn classic and Bun is no command", () => {
    for (const steps of [manualRefreshSteps("yarn", "minimist"), manualRefreshSteps("bun", "minimist"), manualRefreshSteps("yarn", "a b")]) {
      expect(isManualStep(steps)).toBe(true);
      expect(rowCommands(row({ refreshCommands: [{ dir: "examples/demo", command: steps }] }), ctx)).toEqual([]);
    }
  });

  it("a manifest edit is no command", () => {
    const upgradeInstructions = [{ dir: ".", instruction: "change `django==3.2.1` to `django==3.2.25` in requirements.txt" }];
    expect(rowCommands(row({ ecosystem: "PyPI", upgradeInstructions }), ctx)).toEqual([]);
  });

  it("the same command named twice on one row is one entry", () => {
    const parentUpgrades = [
      { levers: [{ commands: [{ dir: ".", command: 'pnpm up "vitest@^4.1.12"' }] }] },
      { levers: [{ commands: [{ dir: ".", command: 'pnpm up "vitest@^4.1.12"' }] }] },
    ];
    expect(rowCommands(row({ parentUpgrades }), ctx)).toEqual([{ dir: ".", run: 'pnpm up "vitest@^4.1.12"' }]);
  });
});

describe("upgrade_planner rows carry `commands`", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
  });
  afterEach(() => h.dispose());

  function project() {
    h.ADVISORIES = {
      minimist: [adv("GHSA-vh95-rmgr-6w4m", "minimist", fixedIn("0.2.1")), adv("GHSA-xvch-5gv4-984h", "minimist", fixedIn("0.2.4"))],
      lodash: [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21"))],
      ms: [adv("GHSA-w9mr-4mfr-499f", "ms", fixedIn("2.0.0"))],
    };
    h.NPM = {
      mkdirp: { latest: "0.5.5", versions: { "0.5.1": { dependencies: { minimist: "0.0.8" } }, "0.5.5": { dependencies: { minimist: "^1.2.5" } } } },
      minimist: { latest: "1.2.8", versions: { "0.0.8": {}, "0.2.4": {}, "1.2.8": {} } },
      mocha: { latest: "7.1.2", versions: { "7.1.0": { dependencies: { mkdirp: "0.5.1" } }, "7.1.2": { dependencies: { mkdirp: "0.5.5" } } } },
      lodash: { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } },
      debug: { latest: "2.6.9", versions: { "2.6.9": { dependencies: { ms: "^2.0.0" } } } },
      ms: { latest: "2.1.3", versions: { "0.7.1": {}, "2.0.0": {}, "2.1.3": {} } },
    };
    h.npmProject({ mkdirp: "0.5.1", lodash: "4.17.20", debug: "^2.6.9" }, { mocha: "7.1.0" }, {
      mkdirp: { version: "0.5.1", dependencies: { minimist: "0.0.8" } },
      minimist: { version: "0.0.8" },
      mocha: { version: "7.1.0", dev: true, dependencies: { mkdirp: "0.5.1" } },
      lodash: { version: "4.17.20" },
      debug: { version: "2.6.9", dependencies: { ms: "^2.0.0" } },
      ms: { version: "0.7.1" },
    });
  }

  it("each route's commands are the row's own command fields, in order", async () => {
    project();
    const { result, step } = await h.plan();
    for (const r of result.recommendations) expect(Array.isArray(r.commands)).toBe(true);
    expect(step("lodash")).toMatchObject({ action: "upgrade_direct", commands: [{ dir: ".", run: "npm install lodash@4.17.21 --save-exact" }] });
    expect(step("ms")).toMatchObject({ action: "lockfile_refresh", commands: [{ dir: ".", run: "npm update ms" }] });
    expect(step("minimist")).toMatchObject({
      action: "upgrade_parent",
      commands: [
        { dir: ".", run: "npm install mkdirp@0.5.5 --save-exact" },
        { dir: ".", run: "npm install mocha@7.1.2 --save-exact" },
      ],
    });
  });

  it("a command on a row is one its words name", async () => {
    project();
    const { result } = await h.plan();
    for (const r of result.recommendations) {
      const said = [JSON.stringify(r.upgradeCommands ?? []), JSON.stringify(r.refreshCommands ?? []), JSON.stringify(r.parentUpgrades ?? []), r.installFix ?? ""].join(" ");
      for (const c of r.commands as Array<{ run: string }>) expect(said).toContain(JSON.stringify(c.run).slice(1, -1));
    }
  });
});
