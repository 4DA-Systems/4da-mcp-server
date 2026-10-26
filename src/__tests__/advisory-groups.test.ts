// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { distinctAdvisoryCount, groupAdvisories } from "../live/advisory-groups.js";
import type { VulnerabilityEntry } from "../live/types.js";

const rec = (vulnId: string, aliases: string[], severity = "medium"): VulnerabilityEntry => ({
  package: "django", currentVersion: "3.2.0", ecosystem: "PyPI", isDev: false, isDirect: true, devScopeKnown: true, vulnId,
  aliases, severity, cvssScore: null, summary: vulnId, fixedVersion: null, published: null, references: [], target: null,
  platformActive: true, sourceDirs: [],
} as unknown as VulnerabilityEntry);

describe("advisory groups (one issue, many OSV records)", () => {
  it("a GHSA and a PYSEC record naming each other are one advisory, kept at the worse severity", () => {
    const groups = groupAdvisories([rec("GHSA-a", ["PYSEC-1", "CVE-1"], "medium"), rec("PYSEC-1", ["GHSA-a", "CVE-1"], "high")]);
    expect(groups).toHaveLength(1);
    expect(groups[0].best.severity).toBe("high");
  });

  it("is transitive: a record naming ids of two groups joins them", () => {
    const entries = [rec("GHSA-a", ["CVE-1"]), rec("PYSEC-2", ["CVE-2"]), rec("GO-3", ["CVE-1", "CVE-2"])];
    expect(distinctAdvisoryCount(entries)).toBe(1);
  });

  it("unrelated records stay separate", () => {
    expect(distinctAdvisoryCount([rec("GHSA-a", []), rec("GHSA-b", [])])).toBe(2);
    expect(distinctAdvisoryCount([])).toBe(0);
  });
});
