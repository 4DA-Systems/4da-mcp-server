// SPDX-License-Identifier: Apache-2.0
/**
 * The rows a plan shows are decided by the rows, never by the order the lookups happened to return
 * them in: two identical calls showed different subsets of tied rows in 7 of 15 projects. The plan
 * order is total, with a final tiebreak of ecosystem, package, directory and version.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness, type LockEntry } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

/** Five tied rows (same grade, all transitive runtime refreshes), with the lockfile listing them in `order`. */
function project(order: string[]) {
  const names = ["delta", "alpha", "echo", "charlie", "bravo"];
  h.ADVISORIES = Object.fromEntries(names.map((n) => [n, [adv(`GHSA-${n}-0001`, n, fixedIn("1.0.1"))]]));
  h.NPM = {
    host: { latest: "1.0.0", versions: { "1.0.0": { dependencies: Object.fromEntries(names.map((n) => [n, "^1.0.0"])) } } },
    ...Object.fromEntries(names.map((n) => [n, { latest: "1.0.1", versions: { "1.0.0": {}, "1.0.1": {} } }])),
  };
  const tree: Record<string, LockEntry> = { host: { version: "1.0.0", dependencies: Object.fromEntries(names.map((n) => [n, "^1.0.0"])) } };
  for (const n of order) tree[n] = { version: "1.0.0" };
  h.npmProject({ host: "1.0.0" }, {}, tree);
}

const shown = (result: Record<string, any>) => (result.recommendations as Array<{ package: string }>).map((r) => r.package);

describe("the default slice of tied rows", () => {
  it("is the same rows in the same order whatever order the lockfile lists them in", async () => {
    project(["delta", "alpha", "echo", "charlie", "bravo"]);
    const first = shown((await h.plan({ max_recommendations: 3 })).result);
    project(["bravo", "echo", "alpha", "delta", "charlie"]);
    const second = shown((await h.plan({ max_recommendations: 3 })).result);
    expect(first).toEqual(["alpha", "bravo", "charlie"]);
    expect(second).toEqual(first);
  });

  it("two identical calls give the same rows and the same run_order", async () => {
    project(["delta", "alpha", "echo", "charlie", "bravo"]);
    const a = (await h.plan({ max_recommendations: 3 })).result;
    const b = (await h.plan({ max_recommendations: 3 })).result;
    expect(shown(b)).toEqual(shown(a));
    expect(b.run_order).toEqual(a.run_order);
  });
});
