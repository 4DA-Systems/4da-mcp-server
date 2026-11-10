// SPDX-License-Identifier: Apache-2.0
/**
 * Range bounds that are not semver, read the way OSV.dev reads them (osv-ranges.ts coerceBound).
 *
 * GHSA-92cp-5422-2mw7 (go-redis v9) opens one range at `9.6.0b1`. For an installed v9.5.1,
 * vulnerability_scan said "no published version clears every advisory (9.6.3 is still affected by
 * GHSA-92cp-5422-2mw7)" (the bound unreadable, so the advisory undecidable) while dependency_check
 * said the smallest safe release is v9.6.3 (the bound read as 0, which also called 9.5.5 affected).
 * OSV.dev answers per version: 9.6.0 to 9.6.2 affected and 9.5.5 and 9.6.3 not, which is the
 * bound read as the prerelease 9.6.0-b1. Both tools now read it so, and agree on v9.6.3.
 * Records: api.osv.dev 2026-11-10, verbatim but for `affected[].database_specific`.
 */

import { describe, expect, it } from "vitest";
import { advisoryAffects, advisoryRanges, coerceBound, readableAdvisory, smallestCleanVersion } from "../live/osv-ranges.js";
import type { OsvVulnerability } from "../live/types.js";
import type { PackageReleaseIndex, ReleaseRecord } from "../live/release-metadata.js";
import { checkRange } from "../tools/dependency-check-versions.js";

const MODULE = "github.com/redis/go-redis/v9";
const spans = (...ranges: Array<{ type: string; events: Array<Record<string, string>> }>) => ranges.map((r) => ({ package: { name: MODULE, ecosystem: "Go" }, ranges: [r] }));

const GHSA = {
  id: "GHSA-92cp-5422-2mw7",
  aliases: ["CVE-2025-29923", "GO-2025-3540"],
  summary: "go-redis allows potential out of order responses when `CLIENT SETINFO` times out during connection establishment",
  database_specific: { severity: "LOW" },
  affected: spans(
    { type: "SEMVER", events: [{ introduced: "9.7.0-beta.1" }, { fixed: "9.7.3" }] },
    { type: "ECOSYSTEM", events: [{ introduced: "9.6.0b1" }, { fixed: "9.6.3" }] },
    { type: "SEMVER", events: [{ introduced: "9.5.1" }, { fixed: "9.5.5" }] },
  ),
} as unknown as OsvVulnerability;

const GO = {
  id: "GO-2025-3540",
  aliases: ["CVE-2025-29923", "GHSA-92cp-5422-2mw7"],
  summary: "Potential out of order responses in github.com/redis/go-redis",
  affected: spans(
    { type: "SEMVER", events: [{ introduced: "9.5.1" }, { fixed: "9.5.5" }] },
    { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.6.3" }] },
    { type: "SEMVER", events: [{ introduced: "9.7.0-beta.1" }, { fixed: "9.7.3" }] },
  ),
} as unknown as OsvVulnerability;

/** api.osv.dev /v1/query per version, 2026-11-10: the GHSA record's answer. */
const OSV_SAYS_GHSA: Record<string, boolean> = {
  "9.5.0": false, "9.5.1": true, "9.5.4": true, "9.5.5": false, "9.6.0": true, "9.6.1": true, "9.6.2": true, "9.6.3": false, "9.7.0": true, "9.7.3": false,
};

describe("coerceBound: OSV's reading of a bound that is not semver", () => {
  it("a bare prerelease suffix and missing parts, for npm, crates.io and Go", () => {
    expect(coerceBound("9.6.0b1", "Go")).toBe("9.6.0-b1");
    expect(coerceBound("v1.2.0rc1", "Go")).toBe("v1.2.0-rc1");
    expect(coerceBound("3", "crates.io")).toBe("3.0.0");
    // Already readable here (the npm comparator pads it): left as written.
    expect(coerceBound("1.2", "npm")).toBe("1.2");
    expect(coerceBound("1.2.3beta.2", "npm")).toBe("1.2.3-beta.2");
  });

  it("leaves valid bounds, other ecosystems and unparseable text alone", () => {
    for (const v of ["0", "9.6.0", "9.7.0-beta.1", "v0.23.0", "1.0.0+build.1"]) expect(coerceBound(v, "Go")).toBe(v);
    expect(coerceBound("2.0b1", "PyPI")).toBe("2.0b1");
    expect(coerceBound("deadbeef", "npm")).toBe("deadbeef");
    expect(coerceBound("", "npm")).toBe("");
  });
});

describe("GHSA-92cp-5422-2mw7: one reading, the one OSV.dev answers with", () => {
  const ghsa = advisoryRanges(GHSA, MODULE, "Go")!;
  const go = advisoryRanges(GO, MODULE, "Go")!;

  it("the record is readable and affects exactly the versions OSV.dev says", () => {
    expect(readableAdvisory(ghsa, "Go")).toBe(true);
    for (const [v, affected] of Object.entries(OSV_SAYS_GHSA)) expect(advisoryAffects(ghsa, v, "Go"), v).toBe(affected);
  });

  const published = ["v9.5.0", "v9.5.1", "v9.5.4", "v9.5.5", "v9.6.0", "v9.6.1", "v9.6.2", "v9.6.3", "v9.7.0", "v9.7.3", "v9.8.0"];

  it("vulnerability_scan's fix target from v9.5.1 is v9.6.3, clear of both records", () => {
    const clean = smallestCleanVersion({ ecosystem: "Go", fixes: ["9.5.5", "9.6.3"], advisories: [ghsa, go], published, installed: "v9.5.1" });
    expect(clean).toMatchObject({ target: "v9.6.3", stillAffectedBy: [] });
    expect(clean?.unreadable).toBeUndefined();
  });

  it("dependency_check's safe releases on v9 agree: smallest above v9.5.1 is v9.6.3", () => {
    const rec = (version: string): ReleaseRecord => ({ version, publishedAt: "2025-01-01T00:00:00Z", trust: "unknown", trustEvidence: "", installScripts: null, deprecated: null, withdrawn: null, dependencies: null }) as unknown as ReleaseRecord;
    const index: PackageReleaseIndex = { ecosystem: "Go", name: MODULE, createdAt: null, releases: Object.fromEntries(published.map((v) => [v, rec(v)])) };
    const rc = checkRange({ ecosystem: "Go", index, range: "v9", basis: "requested", advisories: [ghsa, go], from: "v9.5.1" });
    expect(rc.smallest_safe_upgrade).toBe("v9.6.3");
    // 9.5.5 is still affected, by GO-2025-3540 (0 to 9.6.3), not by the GHSA record.
    expect(rc.safe_versions).not.toContain("v9.5.5");
    expect(advisoryAffects(ghsa, "v9.5.5", "Go")).toBe(false);
  });
});
