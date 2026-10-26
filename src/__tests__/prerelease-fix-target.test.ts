// SPDX-License-Identifier: Apache-2.0
/**
 * An advisory whose fix event is a prerelease (docker/distribution: fixed in
 * v2.8.2-beta.1) let prereleases in as candidates, and the beta was named the
 * target while v2.8.2+incompatible, a clean stable release, existed (audit 6.2.5 A-7).
 */
import { describe, expect, it } from "vitest";
import { advisoryRanges, smallestCleanVersion } from "../live/osv-ranges.js";
import type { OsvVulnerability } from "../live/types.js";

const vuln = {
  id: "GHSA-hqxw-f8mx-cpmw",
  affected: [{ package: { name: "dist", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.8.2-beta.1" }] }] }],
} as unknown as OsvVulnerability;

describe("smallestCleanVersion with a prerelease fix event", () => {
  it("names the smallest clean stable release when there is one", () => {
    const advisories = [advisoryRanges(vuln, "dist", "npm")!];
    const out = smallestCleanVersion({ ecosystem: "npm", fixes: ["2.8.2-beta.1"], advisories, published: ["2.8.1", "2.8.2-beta.1", "2.8.2", "2.8.3"], installed: "2.8.1" });
    expect(out?.target).toBe("2.8.2");
  });

  it("still names the prerelease when no stable release is clean", () => {
    const advisories = [advisoryRanges(vuln, "dist", "npm")!];
    const out = smallestCleanVersion({ ecosystem: "npm", fixes: ["2.8.2-beta.1"], advisories, published: ["2.8.1", "2.8.2-beta.1"], installed: "2.8.1" });
    expect(out?.target).toBe("2.8.2-beta.1");
  });
});
