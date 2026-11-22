// SPDX-License-Identifier: Apache-2.0
/**
 * What the plan-execution harness calls a lowering and a step without effect, from what the
 * candidate run of 2026-11-23 showed:
 * - eslint-config `pnpm update -r semver --depth Infinity` moved semver 5.7.1, 6.3.0 and 7.3.x up
 *   their own lines and was reported as lowering 6.3.0 and 7.3.x to 5.7.3: only 5.7.3 was a new
 *   version, the 6.x and 7.x copies landed on versions the lockfile already held;
 * - nodemon `npm update brace-expansion` moved the hoisted 1.1.11 to 1.1.22 and was reported
 *   without effect, because npm's bundled 1.1.11 (which nothing can move) is still there;
 * - bat's Cargo pre-update moved six crates so the `--precise` steps after it could run, and was
 *   reported without effect because its rows' copies move in those later steps.
 */
import { describe, expect, it } from "vitest";
import { lockfileCopies, lowerings, movedTargets, releaseLine, stepOutcome, type CopyInventory, type Inventory } from "../../bench/plan-exec/lib.mjs";

const inv = (entries: Record<string, string[]>): Inventory => new Map(Object.entries(entries).map(([k, v]) => [k, new Set(v)]));
const copies = (entries: Record<string, Record<string, number>>): CopyInventory => new Map(Object.entries(entries).map(([k, v]) => [k, new Map(Object.entries(v))]));

describe("a lowering", () => {
  it("is not several copies moving up their own release lines onto versions already held", () => {
    const before = inv({ "npm|.|semver": ["5.7.1", "6.3.0", "6.3.2", "7.3.5", "7.3.7", "7.3.8", "7.8.6"] });
    const after = inv({ "npm|.|semver": ["5.7.3", "6.3.2", "7.8.6"] });
    expect(lowerings(before, after, new Map(), before)).toEqual([]);
  });

  it("is still a copy that leaves its line for a lower one (vite 8.3.8 set by an earlier step, then 6.4.6)", () => {
    const before = inv({ "npm|.|vite": ["8.3.8"] });
    const after = inv({ "npm|.|vite": ["6.4.6"] });
    expect(lowerings(before, after, inv({ "npm|.|vite": ["8.3.8"] }), inv({ "npm|.|vite": ["3.0.4"] }))).toEqual([{ key: "npm|.|vite", from: "8.3.8", to: "6.4.6", set_by: "earlier_step" }]);
  });

  it("reads 0.x minors as lines", () => {
    expect(releaseLine("0.59.0")).toBe("0.59");
    expect(releaseLine("v1.2.3")).toBe("1");
    const before = inv({ "Go|.|golang.org/x/crypto": ["v0.59.0"] });
    const after = inv({ "Go|.|golang.org/x/crypto": ["v0.51.0"] });
    expect(lowerings(before, after, before, new Map())).toHaveLength(1);
  });
});

describe("a step's effect", () => {
  it("counts copies: the hoisted copy moved while the bundled one of the same version stayed", () => {
    const lock = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        "": { name: "x" },
        "node_modules/brace-expansion": { version: "1.1.11" },
        "node_modules/npm/node_modules/brace-expansion": { version: "1.1.11", inBundle: true },
      },
    });
    expect(lockfileCopies("package-lock.json", lock).get("brace-expansion")).toEqual(new Map([["1.1.11", 2]]));
    const before = copies({ "npm|.|brace-expansion": { "1.1.11": 2 } });
    const after = copies({ "npm|.|brace-expansion": { "1.1.11": 1, "1.1.22": 1 } });
    const target = { ecosystem: "npm", package: "brace-expansion", version: "1.1.11" };
    expect(movedTargets(before, after, [target])).toEqual([target]);
    expect(stepOutcome({ cmds: [{ exit: 0 }], targets: [target], moved: [target], changed: true, laterServesSame: false })).toBe("worked");
  });

  it("is without effect when nothing moved and no later step serves the same rows", () => {
    const target = { ecosystem: "npm", package: "@babel/core", version: "7.19.6" };
    expect(stepOutcome({ cmds: [{ exit: 0 }], targets: [target], moved: [], changed: true, laterServesSame: false })).toBe("without_effect");
    expect(stepOutcome({ cmds: [{ exit: 0 }], targets: [target], moved: [], changed: false, laterServesSame: true })).toBe("without_effect");
  });

  it("is not without effect for a pre-update that changed the lockfile ahead of the steps that move its rows' copies", () => {
    const target = { ecosystem: "crates.io", package: "url", version: "2.2.2" };
    expect(stepOutcome({ cmds: [{ exit: 0 }], targets: [target], moved: [], changed: true, laterServesSame: true })).toBe("worked");
  });
});
