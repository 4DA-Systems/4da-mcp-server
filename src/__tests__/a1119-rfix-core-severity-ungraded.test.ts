// SPDX-License-Identifier: Apache-2.0
/**
 * `severity_filter` never hides an advisory whose record was read but carries
 * no grade: its severity is unknown, not below the floor. The filter applies to
 * the advisories only, after maintenance notices and platform-inactive rows are
 * split off, so those lists and their counts describe the whole result.
 */
import { describe, expect, it } from "vitest";
import { formatScanResult, type ScanContext } from "../tools/vulnerability-scan-format.js";
import type { VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";

const entry = (pkg: string, id: string, severity: VulnerabilityEntry["severity"], extra: Partial<VulnerabilityEntry> = {}): VulnerabilityEntry => ({
  package: pkg, currentVersion: "1.0.0", ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, vulnId: id, aliases: [], severity, cvssScore: null,
  summary: `${id} summary`, fixedVersion: null, published: "2026-01-01T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: ["/proj"], ...extra,
});
const scanOf = (vulnerabilities: VulnerabilityEntry[]): VulnerabilityScanResult => ({
  scannedAt: "2026-11-19T00:00:00.000Z", projectPath: "/proj", ecosystemsScanned: ["npm"], totalScanned: 10,
  totalVulnerable: new Set(vulnerabilities.map((v) => v.package)).size, platformInactiveVulnerable: vulnerabilities.filter((v) => v.platformActive === false).length,
  bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities,
  cleanCount: 5, scanDurationMs: 1, cached: false, offline: false, unchecked: 0, uncheckedReason: null, staleAnswers: 0,
});
const ctx: ScanContext = { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true };

describe("severity_filter and ungraded advisories", () => {
  it("an advisory read with no grade is kept, not hidden, and the note says so", () => {
    const full = formatScanResult(scanOf([entry("mystery", "GHSA-unkn-0000-0001", "unknown"), entry("ws", "GHSA-3h5v-q93c-6h6q", "medium"), entry("minimist", "GHSA-xvch-5gv4-984h", "critical")]), "high", ctx);
    expect(full.vulnerabilities.map((v) => v.package).sort()).toEqual(["minimist", "mystery"]);
    expect(full.severity_filter).toMatchObject({ minimum: "high", shown: 2, hidden: 1, hidden_by_severity: { medium: 1 } });
    expect(full.severity_filter?.note).toMatch(/1 advisory with no known severity is kept/);
  });

  it("maintenance notices and platform-inactive rows are not filtered, and their counts describe the whole result", () => {
    const notice = entry("old", "RUSTSEC-2020-0001", "low", { ecosystem: "crates.io", maintenance: true } as Partial<VulnerabilityEntry>);
    const offHost = entry("winonly", "GHSA-wino-0000-0001", "low", { platformActive: false });
    const full = formatScanResult(scanOf([notice, offHost, entry("minimist", "GHSA-xvch-5gv4-984h", "critical"), entry("ws", "GHSA-3h5v-q93c-6h6q", "medium")]), "critical", ctx);
    expect(full.vulnerabilities.map((v) => v.package)).toEqual(["minimist"]);
    expect(full.platform_inactive_vulnerabilities.map((v) => v.package)).toEqual(["winonly"]);
    expect(full.platform_inactive_counts).toBeDefined();
    expect(full.maintenance_notices.map((v) => v.package)).toEqual(["old"]);
    // Only the advisories were filtered: ws is the one row hidden.
    expect(full.severity_filter).toMatchObject({ shown: 1, hidden: 1, hidden_by_severity: { medium: 1 } });
  });
});
