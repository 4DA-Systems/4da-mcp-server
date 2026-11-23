// SPDX-License-Identifier: Apache-2.0
/**
 * A plan's command installs the release the plan checked. A command written with a range installs
 * the release the package manager picks for it: on uptime-kuma 1.23.0 `npm install "mssql@~10.0.3"`
 * installed mssql 10.0.6, whose tedious "^16.4.0" left @azure/identity on an affected 3.x, and
 * `npm install "@actions/github@~6.0.0"` installed 6.0.1, which declares undici "^5.28.5" itself.
 * That release is now checked as the target was; when it fails a check, or cannot be established,
 * the command names the target exactly.
 *
 * What each command form leaves, measured 2026-11-23 on a project declaring ms "~2.0.0" locked at
 * 2.0.0, moved to ms 2.1.1 ("~2.1.1" also admits 2.1.3, the latest), scripts off:
 *
 *   manager             command                              package.json   lockfile
 *   npm 10.9.2          npm install "ms@~2.1.1"              ~2.1.1         2.1.3
 *   npm 10.9.2          npm install ms@2.1.1 --save-exact    2.1.1          2.1.1
 *   pnpm 9.3.0, 10.34.6 pnpm up "ms@~2.1.1"                  ~2.1.3         2.1.3
 *   pnpm 9.3.0, 10.34.6 pnpm up ms@2.1.1                     ~2.1.1         2.1.1
 *   yarn 1.22.22        yarn upgrade "ms@~2.1.1"             ~2.1.1         2.1.3
 *   yarn 1.22.22        yarn upgrade ms@2.1.1                2.1.1          2.1.1
 *   yarn 4.9.1, 3.2.4   yarn up "ms@~2.1.1"                  ~2.1.1         2.1.3
 *   yarn 4.9.1, 3.2.4   yarn up ms@2.1.1                     2.1.1          2.1.1
 *   yarn 1.22.22, 4.9.1 yarn workspace api add ms@2.1.1      member 2.1.1   2.1.1 (root ~2.0.0 kept)
 *   yarn 4.9.1          yarn add ms@2.1.1 (workspace root)   root 2.1.1     2.1.1 (member ~2.0.0 kept)
 *   pnpm 9.3.0          pnpm add -D "ms@^2.1.1"              ~2.1.3         2.1.3
 *   pnpm 9.3.0          pnpm add -D ms@2.1.1                 ~2.1.1         2.1.1
 *   cargo 1.97.0        cargo add itoa@1.0.1 (from 0.4.1)    "1.0.1"        1.0.19
 *   cargo 1.97.0        cargo add "itoa@~1.0.1"              "~1.0.1"       1.0.19
 *   cargo 1.97.0        cargo add "itoa@=1.0.1"              "=1.0.1"       1.0.1
 *
 * Every exact form leaves exactly the target in the lockfile; pnpm keeps the declared operator in
 * package.json, the others write the exact version.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";
import { readRangeCommand } from "../tools/upgrade-planner-installs.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");
const runs = (result: Record<string, any>) => (result.run_order as Array<{ run: string }>).map((s) => s.run);

/** mssql 8.1.4 -> tedious 14.7.0 -> @azure/identity 2.1.0; mssql 10.0.3 brings tedious 18, 10.0.4 to 10.0.6 go back to tedious 16. */
function mssqlProject() {
  h.ADVISORIES = { "@azure/identity": [adv("GHSA-m5vv-6r4h-3vj9", "@azure/identity", fixedIn("4.2.1"))] };
  h.NPM = {
    mssql: {
      latest: "12.0.0",
      versions: {
        "8.1.4": { dependencies: { tedious: "^14.7.0" } },
        "10.0.3": { dependencies: { tedious: "^18.2.1" } },
        "10.0.4": { dependencies: { tedious: "^16.4.0" } },
        "10.0.5": { dependencies: { tedious: "^16.4.0" } },
        "10.0.6": { dependencies: { tedious: "^16.4.0" } },
        "12.0.0": { dependencies: { tedious: "^19.0.0" } },
      },
    },
    tedious: {
      latest: "19.0.0",
      versions: {
        "14.7.0": { dependencies: { "@azure/identity": "^2.0.4" } },
        "16.7.1": { dependencies: { "@azure/identity": "^3.4.1" } },
        "18.2.1": { dependencies: { "@azure/identity": "^4.2.1" } },
        "18.6.2": { dependencies: { "@azure/identity": "^4.2.1" } },
        "19.0.0": { dependencies: { "@azure/identity": "^4.2.1" } },
      },
    },
    "@azure/identity": { latest: "4.14.1", versions: { "2.1.0": {}, "3.4.2": {}, "4.2.1": {}, "4.14.1": {} } },
  };
  h.npmProject({ mssql: "~8.1.4" }, {}, {
    mssql: { version: "8.1.4", dependencies: { tedious: "^14.7.0" } },
    tedious: { version: "14.7.0", dependencies: { "@azure/identity": "^2.0.4" } },
    "@azure/identity": { version: "2.1.0" },
  });
}

describe("a lever whose range admits a release that does not bring the fix in", () => {
  it("names the checked release exactly, says why, and every row and the script agree", async () => {
    mssqlProject();
    const { result, step } = await h.plan();
    const row = step("@azure/identity");
    expect(row).toMatchObject({ action: "upgrade_parent", targetVersion: "4.2.1" });
    const lever = row.parentUpgrades[0].levers[0];
    expect(lever).toMatchObject({ name: "mssql", to: "10.0.3" });
    expect(lever.commands).toEqual([{ dir: ".", command: "npm install mssql@10.0.3 --save-exact" }]);
    const why = reasonsOf(row);
    expect(why).toContain(
      '`npm install mssql@10.0.3 --save-exact`, not `npm install "mssql@~10.0.3"`: npm installs mssql 10.0.6 for "~10.0.3" (it is the highest release "~10.0.3" admits that is not deprecated), and mssql 10.0.4 to 10.0.6, which "~10.0.3" also admits, do not bring this fix in (mssql 10.0.6 requires tedious "^16.4.0"); the exact form installs 10.0.3, the release this plan checked',
    );
    // The move's own words name the command the row gives.
    expect(why).toContain("upgrade mssql to 10.0.3 (a major upgrade) (`npm install mssql@10.0.3 --save-exact`)");
    expect(why).not.toContain('"mssql@~10.0.3"`)');
    expect(row.commands).toEqual([{ dir: ".", run: "npm install mssql@10.0.3 --save-exact" }]);
    // mssql's own row moves to the same release with the same command.
    expect(step("mssql").upgradeCommands).toEqual([{ dir: ".", command: "npm install mssql@10.0.3 --save-exact" }]);
    expect(runs(result)).toContain("npm install mssql@10.0.3 --save-exact");
    expect(runs(result).some((r) => r.includes("mssql@~"))).toBe(false);
  });

  it("vulnerability_scan's fix target gives the same command", async () => {
    mssqlProject();
    const scan = await h.scan({ response_format: "detailed" });
    const target = scan.fix_targets["@azure/identity@2.1.0"];
    expect(target.action).toBe("upgrade_parent");
    expect(target.commands).toEqual([{ dir: ".", command: "npm install mssql@10.0.3 --save-exact" }]);
  });
});

/** @actions/github 5.0.3 -> @octokit/plugin-paginate-rest 2.21.3; 6.0.1 also requires undici "^5.28.5", every 5.x of which is affected. */
function actionsProject() {
  h.ADVISORIES = {
    "@octokit/plugin-paginate-rest": [adv("GHSA-h5c3-5r3r-rr8q", "@octokit/plugin-paginate-rest", fixedIn("9.2.2"))],
    undici: [adv("GHSA-c76h-2ccp-4975", "undici", fixedIn("6.0.0"))],
  };
  h.NPM = {
    "@actions/github": {
      latest: "7.0.0",
      versions: {
        "5.0.3": { dependencies: { "@octokit/plugin-paginate-rest": "^2.17.0" } },
        "6.0.0": { dependencies: { "@octokit/plugin-paginate-rest": "^9.0.0" } },
        "6.0.1": { dependencies: { "@octokit/plugin-paginate-rest": "^9.2.2", undici: "^5.28.5" } },
        "7.0.0": { dependencies: { "@octokit/plugin-paginate-rest": "^9.2.2" } },
      },
    },
    "@octokit/plugin-paginate-rest": { latest: "9.2.2", versions: { "2.21.3": {}, "9.2.2": {} } },
    undici: { latest: "7.0.0", versions: { "5.28.5": {}, "5.29.0": {}, "7.0.0": {} } },
  };
  h.npmProject({ "@actions/github": "~5.0.1" }, {}, {
    "@actions/github": { version: "5.0.3", dependencies: { "@octokit/plugin-paginate-rest": "^2.17.0" } },
    "@octokit/plugin-paginate-rest": { version: "2.21.3" },
  });
}

describe("a lever whose range admits a release that brings in a new vulnerable copy", () => {
  it("names the checked release exactly, and says what the other release holds", async () => {
    actionsProject();
    const { result, step } = await h.plan();
    const row = step("@octokit/plugin-paginate-rest");
    expect(row).toMatchObject({ action: "upgrade_parent" });
    const lever = row.parentUpgrades[0].levers[0];
    expect(lever).toMatchObject({ name: "@actions/github", to: "6.0.0" });
    expect(lever.commands).toEqual([{ dir: ".", command: "npm install @actions/github@6.0.0 --save-exact" }]);
    expect(reasonsOf(row)).toContain(
      '`npm install @actions/github@6.0.0 --save-exact`, not `npm install "@actions/github@~6.0.0"`: npm installs @actions/github 6.0.1 for "~6.0.0" (it is the highest release "~6.0.0" admits that is not deprecated), and @actions/github 6.0.1 requires undici "^5.28.5", whose newest admitted release 5.29.0 is affected (GHSA-c76h-2ccp-4975), which 6.0.0 does not bring',
    );
    // A pinned command is still a fix of the row: the release it installs is the one checked.
    expect(result.parentUpgradeSteps).toBe(1);
    expect(runs(result)).toContain("npm install @actions/github@6.0.0 --save-exact");
  });
});

describe("a direct upgrade whose range installs a newer release", () => {
  function tarProject() {
    h.ADVISORIES = { tar: [adv("GHSA-r6q2-hw4h-h46w", "tar", fixedIn("7.5.21"))] };
    h.NPM = { tar: { latest: "7.5.23", versions: { "6.1.15": {}, "7.5.21": {}, "7.5.22": {}, "7.5.23": {} } } };
    h.npmProject({ tar: "~6.1.11" }, {}, { tar: { version: "6.1.15" } });
  }

  it("keeps the range when that release passes the target's checks, and says which release installs", async () => {
    tarProject();
    const { step } = await h.plan();
    const row = step("tar");
    expect(row).toMatchObject({ action: "upgrade_direct", targetVersion: "7.5.21" });
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: 'npm install "tar@~7.5.21"', installs: "7.5.23" }]);
    expect(reasonsOf(row)).toContain(
      '`npm install "tar@~7.5.21"` installs tar 7.5.23, not 7.5.21: it is the "latest" dist-tag, which "~7.5.21" admits; 7.5.23 was checked as 7.5.21 was: no advisory of tar affects it, and it holds no affected dependency 7.5.21 does not',
    );
    expect(row.commands).toEqual([{ dir: ".", run: 'npm install "tar@~7.5.21"' }]);
  });

  it("names the target exactly when an advisory affects the release the range installs", async () => {
    tarProject();
    h.ADVISORIES.tar.push(adv("GHSA-7f2w-3x4c-9q5m", "tar", [{ introduced: "7.5.22" }]));
    const { step } = await h.plan();
    const row = step("tar");
    expect(row.targetVersion).toBe("7.5.21");
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: "npm install tar@7.5.21 --save-exact" }]);
    expect(reasonsOf(row)).toContain('npm installs tar 7.5.23 for "~7.5.21" (it is the "latest" dist-tag, which "~7.5.21" admits), and GHSA-7f2w-3x4c-9q5m affects 7.5.23, not 7.5.21');
  });

  it("changes nothing when the range's release is the target", async () => {
    h.ADVISORIES = { tar: [adv("GHSA-r6q2-hw4h-h46w", "tar", fixedIn("7.5.23"))] };
    h.NPM = { tar: { latest: "7.5.23", versions: { "6.1.15": {}, "7.5.23": {} } } };
    h.npmProject({ tar: "~6.1.11" }, {}, { tar: { version: "6.1.15" } });
    const { step } = await h.plan();
    const row = step("tar");
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: 'npm install "tar@~7.5.23"' }]);
    expect(reasonsOf(row)).not.toMatch(/installs tar 7\.5\.23, not|the exact form installs/);
  });
});

describe("a Yarn project whose range npm and Yarn may resolve differently", () => {
  it("names the target exactly: which release Yarn installs is not established", async () => {
    h.ADVISORIES = { tar: [adv("GHSA-r6q2-hw4h-h46w", "tar", fixedIn("7.5.21"))] };
    // "latest" is 7.5.22 while 7.5.23 is published: npm takes the tag, Yarn can take the highest.
    h.NPM = { tar: { latest: "7.5.22", versions: { "6.1.15": {}, "7.5.21": {}, "7.5.22": {}, "7.5.23": {} } } };
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { tar: "~6.1.11" } }));
    h.write("yarn.lock", '# yarn lockfile v1\n\n\ntar@~6.1.11:\n  version "6.1.15"\n  resolved "https://registry.yarnpkg.com/tar/-/tar-6.1.15.tgz"\n  integrity sha512-AAAA\n');
    const { step } = await h.plan();
    const row = step("tar");
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: "yarn upgrade tar@7.5.21" }]);
    expect(reasonsOf(row)).toContain(
      '`yarn upgrade tar@7.5.21`, not `yarn upgrade "tar@~7.5.21"`: which release "~7.5.21" installs was not established (npm would install 7.5.22 for it and Yarn can install 7.5.23, the highest release it admits); the exact form installs 7.5.21, the release this plan checked',
    );
  });
});

describe("readRangeCommand", () => {
  it("reads the range forms the plan writes and gives each one's exact form", () => {
    expect(readRangeCommand('npm install "mssql@~10.0.3"')).toMatchObject({ tool: "npm", name: "mssql", spec: "~10.0.3", target: "10.0.3", exact: "npm install mssql@10.0.3 --save-exact" });
    expect(readRangeCommand('pnpm up "@scope/x@^1.2.3"')?.exact).toBe("pnpm up @scope/x@1.2.3");
    expect(readRangeCommand('yarn upgrade "x@^1.2.3"')?.exact).toBe("yarn upgrade x@1.2.3");
    expect(readRangeCommand('yarn up "x@~1.2.3"')?.exact).toBe("yarn up x@1.2.3");
    expect(readRangeCommand('yarn add "x@~1.2.3"')?.exact).toBe("yarn add x@1.2.3");
    expect(readRangeCommand('yarn workspace api add "x@^1.2.3" --dev')?.exact).toBe("yarn workspace api add x@1.2.3 --dev");
    expect(readRangeCommand("cargo add itoa@1.0.1 --dev")).toMatchObject({ tool: "cargo", spec: "^1.0.1", exact: 'cargo add "itoa@=1.0.1" --dev' });
    expect(readRangeCommand('cargo add "itoa@~1.0.1" --target "cfg(windows)"')?.exact).toBe('cargo add "itoa@=1.0.1" --target "cfg(windows)"');
    // Exact forms and refreshes are not range commands.
    for (const c of ["npm install mssql@10.0.3 --save-exact", 'cargo add "itoa@=1.0.1"', "npm update tar", "yarn upgrade x@1.2.3", "cargo update -p itoa@0.4.1 --precise 0.4.8"]) {
      expect(readRangeCommand(c)).toBeNull();
    }
  });
});
