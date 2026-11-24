// SPDX-License-Identifier: Apache-2.0
/**
 * "Safe" is said only of a release judged at every level. Re-check of 0d30b40 (2026-11-24, live
 * twolevel85): the openapi-ts row said "0.97.3 is the smallest safe release ...; 0.99.0 is the
 * newest safe release" while dependency_check answered avoid for both (js-yaml two levels down).
 * deadLineText now says "safe" only when the target was checked whole (targetCheckedAll), names a
 * target that holds an affected copy as NOT a clean fix, and words the newest release by what was
 * judged: its own advisories.
 */

import { describe, expect, it } from "vitest";
import { deadLineText } from "../live/fix-paths.js";

const base = { target: "0.97.3", basis: "advisory_fixes" as const, floor: "0.97.3", floorAffectedBy: [], stillAffectedBy: [], unfixable: [], withheld: [], lineDead: true as const, newestSafe: "0.99.0" };

describe("dead-line words", () => {
  it("a target that holds an affected copy two levels down is never called safe", () => {
    const text = deadLineText("0.85.0", { ...base, heldBlocked: { affected: [{ name: "js-yaml", version: "4.1.1", advisories: ["GHSA-x"] }] as never, searched: ["0.97.3"] } }) ?? "";
    expect(text).not.toMatch(/safe/);
    expect(text).toContain("0.97.3 is the smallest release its own advisories leave clean");
    expect(text).toContain("NOT a clean fix");
    expect(text).toContain("0.99.0 is the newest release its own advisories leave clean (what it installs was not judged)");
  });
  it("a target checked whole is the smallest safe release; the newest is worded by what was judged", () => {
    const text = deadLineText("0.85.0", base) ?? "";
    expect(text).toContain("0.97.3 is the smallest safe release");
    expect(text).not.toContain("newest safe release");
  });
});
