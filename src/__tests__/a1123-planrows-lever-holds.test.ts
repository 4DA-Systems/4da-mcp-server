// SPDX-License-Identifier: Apache-2.0
/**
 * A parent upgrade names a release of what the project declares (the lever). That release is
 * judged by what it holds, as dependency_check and the planner's direct targets are: nodemon's
 * uuid row named `npm install "nyc@^18.0.0"`, and nyc 18.0.0 requires glob "^13.0.6", every 13.x
 * of which GHSA-3g3m-2fjr-6pw4 affects, so the step brought in a new vulnerable glob.
 *
 * The smallest lever release that still brings the fix in and holds nothing affected is named;
 * when none is found, the lever's release is kept and the row says what it brings, and the step is
 * not counted as fixed.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");

function nycProject(nyc1801Glob = "^14.0.0") {
  h.ADVISORIES = {
    uuid: [adv("GHSA-w5hq-g745-h8pq", "uuid", fixedIn("11.1.1"))],
    glob: [adv("GHSA-3g3m-2fjr-6pw4", "glob", [{ introduced: "13.0.0" }, { fixed: "14.0.0" }])],
  };
  h.NPM = {
    nyc: {
      latest: "18.0.1",
      versions: {
        "15.1.0": { dependencies: { "istanbul-lib-processinfo": "^2.0.2", glob: "^7.1.6" } },
        "18.0.0": { dependencies: { "istanbul-lib-processinfo": "^3.0.0", glob: "^13.0.6" } },
        "18.0.1": { dependencies: { "istanbul-lib-processinfo": "^3.0.0", glob: nyc1801Glob } },
      },
    },
    "istanbul-lib-processinfo": { latest: "3.0.0", versions: { "2.0.2": { dependencies: { uuid: "^8.3.2" } }, "3.0.0": { dependencies: { uuid: "^11.1.1" } } } },
    uuid: { latest: "11.1.1", versions: { "8.3.2": {}, "11.1.1": {} } },
    glob: { latest: "14.0.2", versions: { "7.2.3": {}, "13.0.7": {}, "14.0.2": {} } },
  };
  h.npmProject({}, { nyc: "^15.1.0" }, {
    nyc: { version: "15.1.0", dev: true, dependencies: { "istanbul-lib-processinfo": "^2.0.2", glob: "^7.1.6" } },
    "istanbul-lib-processinfo": { version: "2.0.2", dev: true, dependencies: { uuid: "^8.3.2" } },
    uuid: { version: "8.3.2", dev: true },
    glob: { version: "7.2.3", dev: true },
  });
}

describe("the release of the declared dependency a parent upgrade names", () => {
  it("is the smallest one that brings the fix in and holds nothing affected", async () => {
    nycProject();
    const { step } = await h.plan();
    const row = step("uuid");
    expect(row).toMatchObject({ scope: "transitive", action: "upgrade_parent", targetVersion: "11.1.1" });
    const lever = row.parentUpgrades[0].levers[0];
    expect(lever).toMatchObject({ name: "nyc", version: "15.1.0", to: "18.0.1" });
    expect(JSON.stringify(lever.commands)).toContain("nyc@^18.0.1");
    const why = reasonsOf(row);
    expect(why).toMatch(/nyc 18\.0\.1, not 18\.0\.0: 18\.0\.0 requires glob "\^13\.0\.6", whose newest admitted release 13\.0\.7 is affected \(GHSA-3g3m-2fjr-6pw4\)/);
    expect(why).not.toMatch(/upgrade nyc to 18\.0\.0/);
  });

  it("when every release that brings the fix in holds something affected: kept, said, and not counted as fixed", async () => {
    nycProject("^13.0.6");
    const { result, step } = await h.plan();
    const row = step("uuid");
    const why = reasonsOf(row);
    expect(why).toMatch(/nyc 18\.0\.0 requires glob "\^13\.0\.6", whose newest admitted release 13\.0\.7 is affected \(GHSA-3g3m-2fjr-6pw4\)/);
    expect(why).toMatch(/is NOT a clean fix: confirm a release with dependency_check before pinning it/);
    expect(result.parentUpgradeSteps).toBe(0);
  });
});
