// SPDX-License-Identifier: Apache-2.0
/**
 * A planner row whose unbundled copies a lockfile refresh fixes while a bundled copy waits on its
 * owner (`bundledCopies`) is not fully fixed: it counts in `lockfileRefreshes` (the refresh is a
 * real step) and in `waitingOnUpstream` (a vulnerable copy stays), and the summary says a bundled
 * copy remains. A row with no bundled copy is counted as before.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness, type LockEntry } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

function nodemon(bundled: boolean) {
  h.ADVISORIES = { "brace-expansion": [adv("GHSA-v6h2-p8h4-qcjw", "brace-expansion", fixedIn("1.1.12"))] };
  h.NPM = {
    "brace-expansion": { latest: "1.1.12", versions: { "1.1.11": {}, "1.1.12": {} } },
    minimatch: { latest: "3.0.4", versions: { "3.0.4": { dependencies: { "brace-expansion": "^1.1.7" } } } },
    npm: { latest: "7.24.2", versions: { "7.24.2": { dependencies: { "brace-expansion": "^1.1.11" } } } },
  };
  h.npmProject({ npm: "^7.24.2", minimatch: "^3.0.4" }, {}, {
    npm: { version: "7.24.2", dependencies: bundled ? { "brace-expansion": "^1.1.11" } : {} },
    ...(bundled ? { "npm/node_modules/brace-expansion": { version: "1.1.11", inBundle: true } as LockEntry } : {}),
    minimatch: { version: "3.0.4", dependencies: { "brace-expansion": "^1.1.7" } },
    "brace-expansion": { version: "1.1.11" },
  });
}

describe("a refresh row that leaves a bundled copy", () => {
  it("counts as a refresh and as waiting on upstream, and the summary says the bundled copy remains", async () => {
    nodemon(true);
    const { result, step } = await h.plan();
    expect(step("brace-expansion").bundledCopies).toHaveLength(1);
    expect(result.lockfileRefreshes).toBe(1);
    expect(result.waitingOnUpstream).toBe(1);
    expect(result.summary).toMatch(/1 transitive, fixed by a lockfile refresh[^.]*1 of them only partly: a bundled copy stays/);
    expect(result.summary).toMatch(/1 transitive, waiting on upstream \(1 a bundled copy beside a refresh/);
  });

  it("control: with no bundled copy the row is a refresh only", async () => {
    nodemon(false);
    const { result, step } = await h.plan();
    expect(step("brace-expansion").action).toBe("lockfile_refresh");
    expect(step("brace-expansion").bundledCopies).toBeUndefined();
    expect(result.lockfileRefreshes).toBe(1);
    expect(result.waitingOnUpstream).toBe(0);
    expect(result.summary).not.toMatch(/bundled/);
  });
});
