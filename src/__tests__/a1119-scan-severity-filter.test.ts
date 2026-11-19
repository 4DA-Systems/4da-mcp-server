// SPDX-License-Identifier: Apache-2.0
/**
 * `severity_filter` keeps a row when the advisory's own severity OR the presented (scope-adjusted)
 * grade meets the floor, and the answer says how many rows it left out. A critical advisory on a
 * transitive copy is presented as high: filtering on "critical" by the presented grade alone
 * dropped it and said nothing.
 */

import { describe, expect, it } from "vitest";
import { conciseScanResult } from "../tools/vulnerability-scan-concise.js";
import { formatScanResult, type ScanContext } from "../tools/vulnerability-scan-format.js";
import { vulnerabilityScanTool } from "../tools/vulnerability-scan.js";
import type { VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";

const entry = (pkg: string, version: string, id: string, severity: VulnerabilityEntry["severity"], extra: Partial<VulnerabilityEntry> = {}): VulnerabilityEntry => ({
  package: pkg, currentVersion: version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, vulnId: id, aliases: [], severity, cvssScore: null,
  summary: `${id} summary`, fixedVersion: null, published: "2026-01-01T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: ["/proj"], ...extra,
});

const scanOf = (vulnerabilities: VulnerabilityEntry[], total = 14): VulnerabilityScanResult => ({
  scannedAt: "2026-11-19T00:00:00.000Z", projectPath: "/proj", ecosystemsScanned: ["npm"], totalScanned: total,
  totalVulnerable: new Set(vulnerabilities.map((v) => v.package)).size, platformInactiveVulnerable: 0,
  bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities,
  cleanCount: total - new Set(vulnerabilities.map((v) => `${v.package}@${v.currentVersion}`)).size, scanDurationMs: 1, cached: false, offline: false, unchecked: 0, uncheckedReason: null, staleAnswers: 0,
});

const ctx: ScanContext = { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true };

/** The audited tree: the same critical advisory on a direct copy and on a transitive one, plus lesser findings. */
const TREE = [
  entry("minimist", "1.2.5", "GHSA-xvch-5gv4-984h", "critical"),
  entry("minimist", "0.2.3", "GHSA-xvch-5gv4-984h", "critical", { isDirect: false }),
  entry("lodash", "4.17.20", "GHSA-35jh-r3h4-6jhm", "high", { isDirect: false }),
  entry("ws", "7.5.9", "GHSA-3h5v-q93c-6h6q", "medium"),
  entry("devtool", "1.0.0", "GHSA-dev0-0000-0001", "critical", { isDev: true }),
  entry("mystery", "1.0.0", "GHSA-unkn-0000-0001", "unknown"),
];

describe("severity_filter: the advisory's own severity counts as much as the presented grade", () => {
  it("critical: a transitive copy carrying a critical advisory is kept (it is presented as high)", () => {
    const full = formatScanResult(scanOf(TREE), "critical", ctx);
    const rows = full.vulnerabilities.map((v) => `${v.package}@${v.current_version}:${v.severity}/${v.advisory_severity}`);
    expect(rows).toEqual(["minimist@1.2.5:critical/critical", "devtool@1.0.0:high/critical", "minimist@0.2.3:high/critical"]);
    expect(full.advisory_by_severity).toMatchObject({ critical: 3 });
  });

  it("says how many rows it left out, and that an unknown severity is among them", () => {
    const full = formatScanResult(scanOf(TREE), "critical", ctx);
    expect(full.severity_filter).toMatchObject({ minimum: "critical", shown: 3, hidden: 3, hidden_by_severity: { high: 1, medium: 1, unknown: 1 } });
    expect(full.severity_filter?.note).toMatch(/3 advisor(y|ies) .*below critical.*not shown/);
    expect(full.severity_filter?.note).toMatch(/1 of them has no known severity/);
  });

  it("high: keeps rows at high or above by either grade, hides the rest and counts them", () => {
    const full = formatScanResult(scanOf(TREE), "high", ctx);
    expect(full.vulnerabilities.map((v) => v.package).sort()).toEqual(["devtool", "lodash", "minimist", "minimist"]);
    expect(full.severity_filter).toMatchObject({ minimum: "high", shown: 4, hidden: 2 });
  });

  it("a filter that hides nothing still says so (hidden: 0)", () => {
    const full = formatScanResult(scanOf([entry("minimist", "1.2.5", "GHSA-xvch-5gv4-984h", "critical")]), "low", ctx);
    expect(full.severity_filter).toMatchObject({ minimum: "low", shown: 1, hidden: 0 });
    expect(full.severity_filter?.note).toMatch(/nothing was left out/i);
  });

  it("an advisory whose record was not read is never filtered out, and is not counted as hidden", () => {
    const unread = entry("ghost", "1.0.0", "GHSA-ghst-0000-0001", "unknown", { detailUnavailable: true });
    const full = formatScanResult(scanOf([unread, entry("ws", "7.5.9", "GHSA-3h5v-q93c-6h6q", "medium")]), "critical", ctx);
    expect(full.vulnerabilities.map((v) => v.package)).toEqual(["ghost"]);
    expect(full.severity_filter).toMatchObject({ shown: 1, hidden: 1 });
  });

  it("without a filter the answer carries no severity_filter block", () => {
    const full = formatScanResult(scanOf(TREE), undefined, ctx);
    expect(full.severity_filter).toBeUndefined();
    expect(full.vulnerabilities).toHaveLength(6);
  });

  it("concise: the kept transitive copy is a row, and the hidden count is stated", () => {
    const concise = conciseScanResult(formatScanResult(scanOf(TREE), "critical", ctx));
    expect(concise.vulnerable_packages.map((p) => `${p.package}@${p.current_version}`)).toEqual(["minimist@1.2.5", "devtool@1.0.0", "minimist@0.2.3"]);
    expect(concise.severity_filter).toMatchObject({ minimum: "critical", hidden: 3 });
  });

  it("the input schema describes the rule", () => {
    expect(vulnerabilityScanTool.inputSchema.properties.severity_filter.description).toMatch(/advisory's own severity or the presented/);
  });
});
