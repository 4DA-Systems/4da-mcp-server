// SPDX-License-Identifier: Apache-2.0
/**
 * CPU budget for a PyPI range check (pre-publish audit 2026-11-12, S1). dependency_check of
 * {PyPI, django, 4.2.0} took 25-30 s of pure CPU: every one of ~400 releases was compared against
 * every version each of ~100 advisories lists (OSV lists every affected PyPI release), each compare
 * re-parsing both strings with the PEP 440 regex, and "advisories affecting every release in range"
 * re-ran that per advisory id. The event loop was blocked, so the 20 s call budget could not fire.
 *
 * Synthetic data of Django's shape (lines 1.0 to 5.2, each advisory listing its whole affected
 * line(s) as OSV does, plus ECOSYSTEM ranges). The budget is generous for a slow CI runner and
 * still orders of magnitude below the old cost.
 */

import { describe, expect, it } from "vitest";
import { checkRange } from "../tools/dependency-check-versions.js";
import { advisoryRanges, type AdvisoryRanges } from "../live/osv-ranges.js";
import type { PackageReleaseIndex, ReleaseRecord } from "../live/release-metadata.js";
import type { OsvVulnerability } from "../live/types.js";

function djangoShape(): { index: PackageReleaseIndex; advisories: AdvisoryRanges[]; versions: string[] } {
  const versions: string[] = [];
  for (const [maj, min, patches] of [[1, 11, 29], [2, 0, 13], [2, 1, 15], [2, 2, 28], [3, 0, 14], [3, 1, 14], [3, 2, 25], [4, 0, 10], [4, 1, 13], [4, 2, 26], [5, 0, 14], [5, 1, 14], [5, 2, 17]] as const) {
    versions.push(`${maj}.${min}`);
    for (let p = 1; p <= patches; p++) versions.push(`${maj}.${min}.${p}`);
  }
  const record = (version: string): ReleaseRecord => ({ version, publishedAt: "2024-01-01T00:00:00Z", trust: "none", trustEvidence: "", installScripts: null, deprecated: null } as unknown as ReleaseRecord);
  const index: PackageReleaseIndex = { ecosystem: "PyPI", name: "django", createdAt: null, releases: Object.fromEntries(versions.map((v) => [v, record(v)])) };
  const advisories: AdvisoryRanges[] = [];
  for (let i = 0; i < 150; i++) {
    // Each advisory affects a stretch of releases ending at a fix, and lists every version it affects
    // (in OSV's own spelling, "4.2.0" for the registry's "4.2"), as OSV's PyPI records do.
    const end = 20 + ((i * 37) % (versions.length - 20));
    const fixed = versions[end];
    const listed = versions.slice(Math.max(0, end - 120), end).map((v) => (v.split(".").length === 2 ? `${v}.0` : v));
    const vuln: OsvVulnerability = {
      id: `PYSEC-2026-${1000 + i}`,
      aliases: [`GHSA-xxxx-xxxx-${String(i).padStart(4, "0")}`],
      affected: [{ package: { name: "django", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed }] }], versions: listed }],
    } as OsvVulnerability;
    advisories.push(advisoryRanges(vuln, "django", "PyPI")!);
  }
  return { index, advisories, versions };
}

describe("a PyPI range check of Django's size stays within a CPU budget (S1)", () => {
  it("the 4.2 line of ~210 releases against 150 advisories listing every affected release: well under a second", () => {
    const { index, advisories } = djangoShape();
    const started = performance.now();
    const rc = checkRange({ ecosystem: "PyPI", index, range: ">=4.2,<4.3", basis: "same_line", advisories });
    const ms = performance.now() - started;
    expect(rc.releases_in_range).toBeGreaterThan(20);
    expect(ms).toBeLessThan(1500);
  });

  it("every release of the package (the newest-safe-outside search): within the same budget", () => {
    const { index, advisories } = djangoShape();
    const started = performance.now();
    // Nothing in this range is safe, so the check walks every installable release looking outside it.
    const rc = checkRange({ ecosystem: "PyPI", index, range: ">=1.0,<5.0", basis: "requested", advisories });
    const ms = performance.now() - started;
    expect(rc.smallest_safe_in_range).toBeNull();
    expect(ms).toBeLessThan(1500);
  });
});
