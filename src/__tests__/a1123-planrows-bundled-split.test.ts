// SPDX-License-Identifier: Apache-2.0
/**
 * One version of a package installed twice, once bundled inside another package and once on its
 * own: nodemon's brace-expansion 1.1.11 sits in node_modules/npm (bundled by npm 7.24.2) and in
 * node_modules/brace-expansion (required by minimatch "^1.1.7"). The whole version was labelled
 * waiting on upstream ("npm 7.24.2 ships it bundled"), while `npm update brace-expansion` moves
 * the unbundled copy to the fix. Each copy now gets its own verdict: the refresh for the copy that
 * is not bundled, and waiting on its owner for the bundled one.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness, type LockEntry } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");

function nodemon(minimatchRange = "^1.1.7") {
  h.ADVISORIES = { "brace-expansion": [adv("GHSA-v6h2-p8h4-qcjw", "brace-expansion", fixedIn("1.1.12"))] };
  h.NPM = {
    "brace-expansion": { latest: "1.1.12", versions: { "1.1.11": {}, "1.1.12": {} } },
    minimatch: { latest: "3.0.4", versions: { "3.0.4": { dependencies: { "brace-expansion": minimatchRange } } } },
    npm: { latest: "7.24.2", versions: { "7.24.2": { dependencies: { "brace-expansion": "^1.1.11" } } } },
  };
  h.npmProject({ npm: "^7.24.2", minimatch: "^3.0.4" }, {}, {
    npm: { version: "7.24.2", dependencies: { "brace-expansion": "^1.1.11" } },
    "npm/node_modules/brace-expansion": { version: "1.1.11", inBundle: true } as LockEntry,
    minimatch: { version: "3.0.4", dependencies: { "brace-expansion": minimatchRange } },
    "brace-expansion": { version: "1.1.11" },
  });
}

describe("a version installed both bundled and on its own", () => {
  it("the copy that is not bundled is refreshed; the bundled one waits on its owner, and both are said", async () => {
    nodemon();
    const { step } = await h.plan();
    const row = step("brace-expansion");
    expect(row).toMatchObject({ scope: "transitive", action: "lockfile_refresh", targetVersion: "1.1.12" });
    expect(row.refreshCommands).toEqual([{ dir: ".", command: "npm update brace-expansion" }]);
    expect(row.bundledCopies).toEqual([{ owner: "npm", ownerVersion: "7.24.2", action: "waiting_on_upstream" }]);
    const why = reasonsOf(row);
    expect(why).toMatch(/not bundled/);
    expect(why).toMatch(/npm 7\.24\.2 ships it bundled/);
    expect(why).toMatch(/npm must release a version that ships brace-expansion >= 1\.1\.12, or be replaced/);
  });

  it("stays waiting on upstream when the unbundled copy's parents block the fix too", async () => {
    nodemon("~1.1.7 <1.1.12");
    const { step } = await h.plan();
    const row = step("brace-expansion");
    expect(row.action).not.toBe("lockfile_refresh");
    expect(row.refreshCommands).toBeUndefined();
  });
});
