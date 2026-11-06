// SPDX-License-Identifier: Apache-2.0
/**
 * The advisories signal's prose must never undercount. It used to name three of the
 * high/critical advisories and append "and N more", where N counted only the high and
 * critical ones: axios 1.7.4 read "affected by A (high), B (high), C (high) and 10 more"
 * (13) while `affecting_to` held 33 ids, so an agent reading the prose alone saw 13.
 * The prose now states the total and how many of them are high or critical.
 */
import { describe, expect, it } from "vitest";
import { advisoriesSignal, type AdvisoryRef, type CheckItem } from "../tools/dependency-check-signals.js";
import { checkRange } from "../tools/dependency-check-versions.js";
import { advisoryRanges } from "../live/osv-ranges.js";
import type { PackageReleaseIndex } from "../live/release-metadata.js";
import type { OsvVulnerability } from "../live/types.js";

const item: CheckItem = { ecosystem: "npm", package: "widget", from: "1.0.0", to: "1.7.4" };

function adv(n: number, severity: AdvisoryRef["severity"]): AdvisoryRef {
  return { id: `GHSA-${severity}-${String(n).padStart(4, "0")}`, severity, summary: "", maintenance: false };
}
const many = (count: number, severity: AdvisoryRef["severity"]) => Array.from({ length: count }, (_, i) => adv(i, severity));

describe("advisories signal prose counts every advisory", () => {
  it("13 high among 33: the total, the high/critical share, and 'more' qualified as high or critical", () => {
    const to = [...many(13, "high"), ...many(20, "medium")];
    const s = advisoriesSignal(item, { available: true, from: [], to });
    expect(s.effect).toBe("avoid");
    expect((s.value as { affecting_to: string[] }).affecting_to).toHaveLength(33);
    expect(s.evidence).toBe(
      "1.7.4 is affected by 33 known advisories, 13 of them high or critical: GHSA-high-0000 (high), GHSA-high-0001 (high), GHSA-high-0002 (high) and 10 more high or critical.",
    );
  });

  it("every advisory high or critical reads 'all of them'", () => {
    const s = advisoriesSignal(item, { available: true, from: [], to: [adv(0, "critical"), adv(1, "high")] });
    expect(s.effect).toBe("avoid");
    expect(s.evidence).toBe("1.7.4 is affected by 2 known advisories, all of them high or critical: GHSA-critical-0000 (critical), GHSA-high-0001 (high).");
  });

  it("one high among several lower ones still counts all of them", () => {
    const s = advisoriesSignal(item, { available: true, from: [], to: [adv(0, "low"), adv(1, "high"), adv(2, "medium")] });
    expect(s.effect).toBe("avoid");
    expect(s.evidence).toBe("1.7.4 is affected by 3 known advisories, 1 of them high or critical: GHSA-high-0001 (high).");
  });

  it("no high or critical: the total, and 'and N more' adds up to it", () => {
    const s = advisoriesSignal(item, { available: true, from: [], to: many(5, "medium") });
    expect(s.effect).toBe("review");
    expect(s.evidence).toBe(
      "1.7.4 is affected by 5 known advisories: GHSA-medium-0000 (medium), GHSA-medium-0001 (medium), GHSA-medium-0002 (medium) and 2 more.",
    );
  });

  it("a single advisory is named without a count", () => {
    const s = advisoriesSignal(item, { available: true, from: [], to: [adv(0, "high")] });
    expect(s.evidence).toBe("1.7.4 is affected by GHSA-high-0000 (high).");
  });

  it("maintenance notices are not counted as advisories", () => {
    const notice: AdvisoryRef = { id: "RUSTSEC-2024-0375", severity: "unknown", summary: "", maintenance: true };
    const s = advisoriesSignal(item, { available: true, from: [], to: [notice, adv(0, "high"), adv(1, "low")] });
    expect(s.evidence).toMatch(/^1\.7\.4 is affected by 2 known advisories, 1 of them high or critical: GHSA-high-0000 \(high\)\./);
  });
});

describe("range_check.affecting_all_total", () => {
  it("counts every advisory affecting the whole range although affecting_all names at most 10", () => {
    const versions = ["1.0.0", "1.0.1", "1.0.2"];
    const index: PackageReleaseIndex = {
      ecosystem: "npm",
      name: "widget",
      createdAt: null,
      releases: Object.fromEntries(
        versions.map((v) => [v, { version: v, publishedAt: null, trust: 0 as const, trustEvidence: "", installScripts: null, deprecated: null, withdrawn: null, dependencies: null }]),
      ),
    };
    const osv: OsvVulnerability[] = Array.from({ length: 14 }, (_, i) => ({
      id: `GHSA-all-${String(i).padStart(4, "0")}`,
      summary: "",
      affected: [{ package: { ecosystem: "npm", name: "widget" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }],
    })) as unknown as OsvVulnerability[];
    const advisories = osv.map((v) => advisoryRanges(v, "widget", "npm")).filter((a) => a !== null);
    const rc = checkRange({ ecosystem: "npm", index, range: "1.x", basis: "requested", advisories });
    expect(rc.smallest_safe_in_range).toBeNull();
    expect(rc.affecting_all).toHaveLength(10);
    expect(rc.affecting_all_total).toBe(14);
  });

  it("a GHSA record and its PYSEC twin are one advisory (pyjwt 2.9.* read 32 for 17)", () => {
    const index: PackageReleaseIndex = {
      ecosystem: "PyPI",
      name: "pyjwt",
      createdAt: null,
      releases: { "2.9.0": { version: "2.9.0", publishedAt: null, trust: 0 as const, trustEvidence: "", installScripts: null, deprecated: null, withdrawn: null, dependencies: null } },
    };
    const rec = (id: string, aliases: string[]) =>
      ({ id, aliases, summary: "", affected: [{ package: { ecosystem: "PyPI", name: "pyjwt" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }] }] }) as unknown as OsvVulnerability;
    const osv = [
      rec("GHSA-aaaa-aaaa-aaaa", ["CVE-2026-1", "PYSEC-2026-1"]),
      rec("PYSEC-2026-1", ["CVE-2026-1", "GHSA-aaaa-aaaa-aaaa"]),
      rec("GHSA-bbbb-bbbb-bbbb", ["CVE-2026-2", "PYSEC-2026-2"]),
      rec("PYSEC-2026-2", ["CVE-2026-2", "GHSA-bbbb-bbbb-bbbb"]),
      rec("PYSEC-2025-9", ["CVE-2025-9"]),
    ];
    const advisories = osv.map((v) => advisoryRanges(v, "pyjwt", "PyPI")).filter((a) => a !== null);
    const rc = checkRange({ ecosystem: "PyPI", index, range: "==2.9.*", basis: "same_line", advisories });
    expect(rc.affecting_all).toEqual(["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb", "PYSEC-2025-9"]);
    expect(rc.affecting_all_total).toBe(3);
  });
});
