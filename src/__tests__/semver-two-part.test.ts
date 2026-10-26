// SPDX-License-Identifier: Apache-2.0
/**
 * PyPI and Go write two-part versions (`4.2`, `1.23`). computeSemverDistance
 * required three parts, so Django 4.2 -> 5.2.17 and urllib3 1.23 -> 2.8.0 came
 * back unknown and upgrade_planner counted them non-breaking (audit 6.2.5 A-3 / D-9).
 */
import { describe, expect, it } from "vitest";
import { computeSemverDistance } from "../live/semver-utils.js";

describe("computeSemverDistance with two-part versions", () => {
  it("labels a major jump from a two-part version major", () => {
    expect(computeSemverDistance("4.2", "5.2.17")?.label).toBe("major");
    expect(computeSemverDistance("1.23", "2.8.0")?.label).toBe("major");
  });
  it("labels minor and patch moves from two-part versions", () => {
    expect(computeSemverDistance("4.2", "4.3")?.label).toBe("minor");
    expect(computeSemverDistance("4.2", "4.2.5")?.label).toBe("patch");
    expect(computeSemverDistance("4.2", "4.2.0")?.label).toBe("up-to-date");
  });
});
