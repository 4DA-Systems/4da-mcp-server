// SPDX-License-Identifier: Apache-2.0
/**
 * An answer that starts with NOT CHECKED or STALE is incomplete: the server's instructions tell
 * agents so. The planner's summary therefore starts with its NOT CHECKED sentence whenever its
 * vulnerability data is unavailable or incomplete, or no lockfile was read. Before, a lockfile with
 * merge-conflict markers gave "1 recommendation. 1 upgradable directly ..." with the NOT CHECKED
 * sentence last, and a manifest with no lockfile gave no NOT CHECKED sentence at all.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.ADVISORIES = { tar: [adv("GHSA-r6q2-hw4h-h46w", "tar", fixedIn("7.5.21"))] };
  h.NPM = { tar: { latest: "7.5.21", versions: { "6.1.15": {}, "7.5.21": {} } } };
});
afterEach(() => h.dispose());

describe("the planner's summary when its vulnerability data is not complete", () => {
  it("a lockfile with merge-conflict markers: NOT CHECKED comes first", async () => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { tar: "~6.1.11" } }));
    h.write(
      "package-lock.json",
      '{\n  "name": "x",\n<<<<<<< HEAD\n  "lockfileVersion": 3,\n=======\n  "lockfileVersion": 2,\n>>>>>>> other\n  "packages": {}\n}\n',
    );
    const { result } = await h.plan();
    expect(result.vulnerabilityDataAvailable).toBe(false);
    expect(result.summary).toMatch(/^NOT CHECKED \(merge conflict\): 1 file holds git merge-conflict markers/);
    expect(result.summary.match(/NOT CHECKED \(merge conflict\)/g)).toHaveLength(1);
  });

  it("a manifest and no lockfile: the summary says NOT CHECKED, first", async () => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { tar: "~6.1.11" } }));
    const { result } = await h.plan();
    expect(result.vulnerabilityDataAvailable).toBe(false);
    expect(result.summary).toMatch(
      /^NOT CHECKED: no lockfile was read, so no installed version is known and none was checked for advisories \(a declared range is not an install\); generate the lockfile, then plan again\. 1 recommendation\./,
    );
  });

  it("complete data: the summary does not start with NOT CHECKED", async () => {
    h.npmProject({ tar: "~6.1.11" }, {}, { tar: { version: "6.1.15" } });
    const { result } = await h.plan();
    expect(result.vulnerabilityDataAvailable).toBe(true);
    expect(result.summary).not.toMatch(/NOT CHECKED/);
  });
});
