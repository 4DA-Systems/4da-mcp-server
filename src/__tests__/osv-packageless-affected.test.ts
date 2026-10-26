// SPDX-License-Identifier: Apache-2.0
/**
 * An OSV `affected[]` entry may carry no `package`: the schema allows an entry
 * with only GIT ranges. EEF-CVE-2026-56812 (npm `phoenix`) has one, and every
 * walker read `a.package.ecosystem` unguarded. The TypeError was caught as an
 * OSV outage, so a whole scan containing `phoenix` came back NOT CHECKED
 * (1,024 of 1,024 on vite 4.0.0's lockfile) and a dependency_check batch with
 * one `phoenix` item turned every item to `unknown`. Audit 6.2.5 finding D-2.
 */
import { describe, it, expect } from "vitest";
import { extractFixedVersion } from "../live/osv-scanner.js";
import { advisoryRanges, collectAffectedSpans } from "../live/osv-ranges.js";
import { PinnedRecordsSource } from "../live/pinned-advisories.js";
import type { OsvVulnerability } from "../live/types.js";

/** The EEF record's shape: a package-less GIT entry beside the npm one. */
const record = {
  id: "EEF-TEST-PACKAGELESS",
  affected: [
    { ranges: [{ type: "GIT", repo: "https://github.com/phoenixframework/phoenix", events: [{ introduced: "0" }, { fixed: "abc123" }] }] },
    { package: { name: "phoenix", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.7.21" }] }] },
  ],
} as unknown as OsvVulnerability;

describe("a package-less affected[] entry", () => {
  it("is skipped when collecting spans, and the package's own range still counts", () => {
    expect(() => collectAffectedSpans(record.affected, "phoenix", "npm")).not.toThrow();
    expect(collectAffectedSpans(record.affected, "phoenix", "npm").length).toBeGreaterThan(0);
  });

  it("does not break advisoryRanges or the fixed-version pick", () => {
    expect(advisoryRanges(record, "phoenix", "npm")).not.toBeNull();
    expect(extractFixedVersion(record.affected, "phoenix", "npm", "1.7.0")).toBe("1.7.21");
  });

  it("does not break the pinned-record index", () => {
    const source = new PinnedRecordsSource([record]);
    expect(source.affecting("npm", "phoenix", "1.7.0")).toEqual(["EEF-TEST-PACKAGELESS"]);
    expect(source.affecting("npm", "phoenix", "1.7.21")).toEqual([]);
  });
});
