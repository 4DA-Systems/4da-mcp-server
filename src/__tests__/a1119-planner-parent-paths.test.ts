// SPDX-License-Identifier: Apache-2.0
/**
 * A parent upgrade is claimed as the fix only when it covers every path to the vulnerable copy.
 *
 * minimist 0.0.8 is pinned by mkdirp 0.5.1. The project declares mkdirp itself, and mocha 7.1.0
 * pins mkdirp "0.5.1" too. `npm install mkdirp@0.5.5` moves the project's copy; mocha keeps its
 * own mkdirp 0.5.1, and minimist 0.0.8 with it. The step names both paths and what moves each,
 * and is counted as fixed only when every path has a release to move to.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");
const leversOf = (step: Record<string, any>) => (step.parentUpgrades as Array<{ levers: Array<Record<string, any>> }>).flatMap((u) => u.levers);

/** mochaMkdirp: what mocha 7.1.0 requires of mkdirp; mochaReleases: mocha's later releases and their mkdirp requirement. */
function project(mochaMkdirp: string, mochaReleases: Record<string, string>) {
  h.ADVISORIES = {
    minimist: [
      adv("GHSA-vh95-rmgr-6w4m", "minimist", [{ introduced: "0" }, { fixed: "0.2.1" }]),
      adv("GHSA-xvch-5gv4-984h", "minimist", [{ introduced: "0" }, { fixed: "0.2.4" }]),
    ],
  };
  h.NPM = {
    mkdirp: { latest: "0.5.5", versions: { "0.5.1": { dependencies: { minimist: "0.0.8" } }, "0.5.5": { dependencies: { minimist: "^1.2.5" } } } },
    minimist: { latest: "1.2.8", versions: { "0.0.8": {}, "0.2.4": {}, "1.2.8": {} } },
    mocha: {
      latest: Object.keys(mochaReleases).pop() ?? "7.1.0",
      versions: { "7.1.0": { dependencies: { mkdirp: mochaMkdirp } }, ...Object.fromEntries(Object.entries(mochaReleases).map(([v, req]) => [v, { dependencies: { mkdirp: req } }])) },
    },
  };
  h.npmProject({ mkdirp: "0.5.1" }, { mocha: "7.1.0" }, {
    mkdirp: { version: "0.5.1", dependencies: { minimist: "0.0.8" } },
    minimist: { version: "0.0.8" },
    mocha: { version: "7.1.0", dev: true, dependencies: { mkdirp: mochaMkdirp } },
  });
}

describe("a vulnerable copy reachable through more than one holder of its parent", () => {
  it("names every path and the move for each, and counts the step as fixed only with all of them", async () => {
    project("0.5.1", { "7.1.2": "0.5.5" });
    const { result, step } = await h.plan();
    const row = step("minimist");
    expect(row).toMatchObject({ scope: "transitive", action: "upgrade_parent" });
    // Both moves are on the step, each with its command.
    expect(leversOf(row)).toMatchObject([
      { name: "mkdirp", version: "0.5.1", to: "0.5.5", commands: [{ dir: ".", command: "npm install mkdirp@0.5.5 --save-exact" }] },
      { name: "mocha", version: "7.1.0", to: "7.1.2", brings: "0.5.5", commands: [{ dir: ".", command: "npm install mocha@7.1.2 --save-exact" }] },
    ]);
    const why = reasonsOf(row);
    expect(why).toMatch(/upgrade mkdirp to 0\.5\.5/);
    expect(why).toMatch(/1 of 2 paths to minimist 0\.0\.8/);
    expect(why).toMatch(/mocha 7\.1\.0, which requires mkdirp "0\.5\.1"/);
    expect(why).toMatch(/upgrade mocha to 7\.1\.2/);
    expect(result.parentUpgradeSteps).toBe(1);
  });

  it("vulnerability_scan gives both commands with its 'resolves' claim", async () => {
    project("0.5.1", { "7.1.2": "0.5.5" });
    const concise = await h.scan();
    const line = (concise.recommendations as string[]).find((r) => r.includes("minimist 0.0.8"))!;
    expect(line).toMatch(/resolves 2 CVEs/);
    expect(line).toMatch(/npm install mkdirp@0\.5\.5 --save-exact/);
    expect(line).toMatch(/npm install mocha@7\.1\.2 --save-exact/);
  });

  it("does not claim the fix when the other holder has no release that brings a fixed parent in", async () => {
    project("0.5.1", { "7.1.1": "0.5.1" });
    const { result, step } = await h.plan();
    const row = step("minimist");
    // mocha, at its newest release, still pins mkdirp 0.5.1: upgrading mkdirp alone leaves that copy.
    expect(row.action).not.toBe("upgrade_parent");
    expect(result.parentUpgradeSteps).toBe(0);
    const why = reasonsOf(row);
    expect(why).toMatch(/1 of 2 paths to minimist 0\.0\.8/);
    expect(why).toMatch(/mocha 7\.1\.0, which requires mkdirp "0\.5\.1"/);
    const concise = await h.scan();
    const line = (concise.recommendations as string[]).find((r) => r.includes("minimist 0.0.8"))!;
    expect(line).not.toMatch(/^Upgrade the parent .* resolves/);
  });

  it("one upgrade is the whole step when the other holder's requirement admits the new parent release", async () => {
    project("^0.5.1", { "7.1.2": "^0.5.1" });
    const { step } = await h.plan();
    const row = step("minimist");
    expect(row).toMatchObject({ action: "upgrade_parent" });
    expect(leversOf(row)).toMatchObject([{ name: "mkdirp", to: "0.5.5" }]);
    expect(leversOf(row)).toHaveLength(1);
    expect(reasonsOf(row)).not.toMatch(/of 2 paths/);
  });
});
