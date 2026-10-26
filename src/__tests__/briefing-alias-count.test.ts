// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know listed every OSV record of one advisory as its own
 * vulnerability: django read 96 confirmed vulnerabilities where
 * vulnerability_scan, dependency_health and upgrade_planner said 51 (audit 6.2.5 D-7).
 */
import { describe, expect, it } from "vitest";
import { advisoriesFor } from "../tools/briefing-task-scope.js";

const record = (vulnId: string, aliases: string[], fixedVersion: string) => ({
  package: "django", currentVersion: "4.2", ecosystem: "PyPI" as const, isDev: false, isDirect: true, devScopeKnown: true,
  vulnId, aliases, severity: "high" as const, cvssScore: null, summary: "django advisory", fixedVersion, published: "", references: [],
  target: null, platformActive: true, sourceDirs: ["."],
});

describe("advisoriesFor counts an advisory once, whatever its aliases", () => {
  it("GHSA, PYSEC and CVE records of one advisory are one row", () => {
    const rows = advisoriesFor({ name: "django", ecosystem: "PyPI" } as never, [
      record("GHSA-aaaa-bbbb-cccc", ["CVE-2024-0001", "PYSEC-2024-1"], "4.2.10"),
      record("PYSEC-2024-1", ["CVE-2024-0001", "GHSA-aaaa-bbbb-cccc"], "4.2.10"),
      record("GHSA-dddd-eeee-ffff", ["CVE-2024-0002"], "4.2.11"),
    ] as never);
    expect(rows).toHaveLength(2);
  });
});
