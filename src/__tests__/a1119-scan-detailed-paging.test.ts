// SPDX-License-Identifier: Apache-2.0
/**
 * The detailed vulnerability_scan answer is bounded: 200 advisory rows by default, most severe
 * first and direct before transitive, with `limit` (at most 1,000) and `offset` to read the rest
 * and a `truncated` block saying what is shown, what there is and how to get it. Totals describe
 * the whole result, never the page. It was unbounded: 495,000 characters on a 562-advisory tree.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { TOOL_REGISTRY } from "../schema-registry.js";
import { validateToolArgs } from "../tool-args.js";
import { conciseScanResult } from "../tools/vulnerability-scan-concise.js";
import { formatScanResult, type ScanContext } from "../tools/vulnerability-scan-format.js";
import { DEFAULT_DETAILED_ROWS, MAX_DETAILED_ROWS, pageScanResult } from "../tools/vulnerability-scan-page.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import type { FourDADatabase } from "../db.js";
import type { ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";

const SEVERITIES = ["low", "critical", "medium", "high"] as const;

const entry = (i: number, extra: Partial<VulnerabilityEntry> = {}): VulnerabilityEntry => ({
  package: `pkg-${Math.floor(i / 3)}`, currentVersion: "1.0.0", ecosystem: "npm", isDev: false, isDirect: i % 2 === 0, devScopeKnown: true,
  vulnId: `GHSA-${String(i).padStart(4, "0")}-aaaa-bbbb`, aliases: [], severity: SEVERITIES[i % 4], cvssScore: null, summary: `advisory ${i}`,
  fixedVersion: "2.0.0", published: "2026-01-01T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: ["/proj"], ...extra,
});

function scanOf(vulnerabilities: VulnerabilityEntry[]): VulnerabilityScanResult {
  return {
    scannedAt: "2026-11-19T00:00:00.000Z", projectPath: "/proj", ecosystemsScanned: ["npm"], totalScanned: 2_000,
    totalVulnerable: new Set(vulnerabilities.map((v) => v.package)).size, platformInactiveVulnerable: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities, cleanCount: 1_000, scanDurationMs: 1, cached: false, offline: false,
    unchecked: 0, uncheckedReason: null, staleAnswers: 0,
  };
}

const ctx: ScanContext = { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true };

/** 562 advisories: 500 counted, 40 on a crate this host does not build, 22 unmaintained notices. */
const TREE = [
  ...Array.from({ length: 500 }, (_, i) => entry(i)),
  ...Array.from({ length: 40 }, (_, i) => entry(1_000 + i, { platformActive: false, target: "cfg(unix)" })),
  ...Array.from({ length: 22 }, (_, i) => entry(2_000 + i, { maintenance: true, summary: "unmaintained" })),
];

const full = () => formatScanResult(scanOf(TREE), undefined, ctx);
const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

describe("the detailed answer is a bounded page of the whole result", () => {
  it("by default shows 200 rows of 562 and says how to get the rest", () => {
    const page = pageScanResult(full());
    expect(DEFAULT_DETAILED_ROWS).toBe(200);
    expect(page.vulnerabilities).toHaveLength(200);
    expect(page.platform_inactive_vulnerabilities).toEqual([]);
    expect(page.maintenance_notices).toEqual([]);
    expect(page.truncated).toMatchObject({
      shown: 200,
      total: 562,
      offset: 0,
      limit: 200,
      next_offset: 200,
      lists: {
        vulnerabilities: { shown: 200, total: 500 },
        platform_inactive_vulnerabilities: { shown: 0, total: 40 },
        maintenance_notices: { shown: 0, total: 22 },
      },
    });
    expect(page.truncated?.how).toMatch(/offset: 200/);
    expect(page.truncated?.how).toMatch(/limit/);
  });

  it("totals describe the whole result on every page", () => {
    const whole = full();
    for (const offset of [0, 200, 400]) {
      const page = pageScanResult(whole, undefined, offset);
      expect(page.total_vulnerable_packages).toBe(whole.total_vulnerable_packages);
      expect(page.by_severity).toEqual(whole.by_severity);
      expect(page.advisory_by_severity).toEqual(whole.advisory_by_severity);
      expect(page.clean_dependencies).toBe(whole.clean_dependencies);
      expect(Object.values(page.by_severity ?? {}).reduce((a, b) => a + b, 0)).toBe(500);
    }
  });

  it("the pages are disjoint and together hold every row exactly once, in the three lists' order", () => {
    const whole = full();
    const seen: string[] = [];
    const lists: string[] = [];
    for (let offset = 0; ; ) {
      const page = pageScanResult(whole, undefined, offset);
      for (const [name, rows] of [["v", page.vulnerabilities], ["p", page.platform_inactive_vulnerabilities], ["m", page.maintenance_notices]] as const) {
        for (const row of rows) {
          seen.push(row.vuln_id);
          lists.push(name);
        }
      }
      if (page.truncated?.next_offset === undefined) break;
      offset = page.truncated.next_offset;
    }
    expect(seen).toHaveLength(562);
    expect(new Set(seen).size).toBe(562);
    // vulnerabilities first, then platform-inactive advisories, then maintenance notices.
    expect(lists.join("")).toMatch(/^v{500}p{40}m{22}$/);
  });

  it("the last page has no next_offset and still says it is a part", () => {
    const page = pageScanResult(full(), undefined, 400);
    expect(page.vulnerabilities).toHaveLength(100);
    expect(page.platform_inactive_vulnerabilities).toHaveLength(40);
    expect(page.maintenance_notices).toHaveLength(22);
    expect(page.truncated).toMatchObject({ shown: 162, total: 562, offset: 400 });
    expect(page.truncated?.next_offset).toBeUndefined();
  });

  it("rows are ordered most severe first, and direct before transitive at the same grade", () => {
    const rows = full().vulnerabilities;
    for (let i = 1; i < rows.length; i++) {
      const [a, b] = [rows[i - 1], rows[i]];
      expect(RANK[a.severity]).toBeGreaterThanOrEqual(RANK[b.severity]);
      if (a.severity === b.severity) expect(Number(a.is_direct === true)).toBeGreaterThanOrEqual(Number(b.is_direct === true));
    }
    // So the first page holds the most severe rows there are.
    const page = pageScanResult(full());
    const worstLeftOut = Math.max(...full().vulnerabilities.slice(200).map((v) => RANK[v.severity]));
    expect(Math.min(...page.vulnerabilities.map((v) => RANK[v.severity]))).toBeGreaterThanOrEqual(worstLeftOut);
  });

  it("limit: up to 1,000 rows; a result that fits carries no truncated block", () => {
    expect(MAX_DETAILED_ROWS).toBe(1_000);
    const page = pageScanResult(full(), 1_000);
    expect(page.vulnerabilities).toHaveLength(500);
    expect(page.platform_inactive_vulnerabilities).toHaveLength(40);
    expect(page.maintenance_notices).toHaveLength(22);
    expect(page.truncated).toBeUndefined();
    // A limit past the maximum is held to it, never read as "everything".
    const huge = formatScanResult(scanOf(Array.from({ length: 1_200 }, (_, i) => entry(i))), undefined, ctx);
    expect(pageScanResult(huge, 5_000).vulnerabilities).toHaveLength(1_000);
    expect(pageScanResult(huge, 5_000).truncated).toMatchObject({ shown: 1_000, total: 1_200, limit: 1_000 });
  });

  it("fix_targets and recommendations are those of the page", () => {
    const whole = full();
    const page = pageScanResult(whole, 30);
    const copies = new Set(page.vulnerabilities.map((v) => `${v.package}@${v.current_version}`));
    expect(Object.keys(page.fix_targets).sort()).toEqual([...copies].sort());
    expect(Object.keys(page.fix_targets).length).toBeLessThan(Object.keys(whole.fix_targets).length);
    expect(page.recommendations).toHaveLength(30);
    expect(page.truncated?.recommendations).toEqual({ shown: 30, total: whole.recommendations.length });
  });

  it("an offset past the end shows no rows and says where the result ends", () => {
    const page = pageScanResult(full(), undefined, 9_999);
    expect(page.vulnerabilities).toEqual([]);
    expect(page.truncated).toMatchObject({ shown: 0, total: 562, offset: 9_999 });
    expect(page.truncated?.how).toMatch(/562/);
  });

  it("a small result is returned whole and unchanged", () => {
    const small = formatScanResult(scanOf([entry(1), entry(2)]), undefined, ctx);
    expect(pageScanResult(small)).toEqual(small);
  });

  it("the concise answer keeps its own caps whatever the page", () => {
    const concise = conciseScanResult(full());
    expect(concise.vulnerable_packages).toHaveLength(40);
    expect(concise.recommendations).toHaveLength(25);
    expect(concise.by_severity).toEqual(full().by_severity);
  });
});

describe("vulnerability_scan: limit and offset", () => {
  const schema = TOOL_REGISTRY.vulnerability_scan.definition.inputSchema;

  it("are declared, with their bounds", () => {
    expect(schema.properties).toMatchObject({ limit: { type: "integer", minimum: 1, maximum: 1_000 }, offset: { type: "integer", minimum: 0 } });
    expect(validateToolArgs("vulnerability_scan", schema, { response_format: "detailed", limit: 1_000, offset: 200 })).toBeNull();
    expect(validateToolArgs("vulnerability_scan", schema, { limit: 1_001 })).toMatch(/"limit" must be <= 1000/);
    expect(validateToolArgs("vulnerability_scan", schema, { limit: 0 })).toMatch(/"limit" must be >= 1/);
    expect(validateToolArgs("vulnerability_scan", schema, { offset: -1 })).toMatch(/"offset" must be >= 0/);
    expect(validateToolArgs("vulnerability_scan", schema, { limit: "200" })).toMatch(/"limit" must be a integer/);
  });

  describe("through the tool", () => {
    let dir: string;
    afterEach(() => {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
    });

    async function scan(params: Record<string, unknown>): Promise<Record<string, any>> {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-scan-paging-"));
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", dependencies: { "pkg-0": "1.0.0" } }));
      fs.writeFileSync(
        path.join(dir, "package-lock.json"),
        JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", version: "1.0.0", dependencies: { "pkg-0": "1.0.0" } }, "node_modules/pkg-0": { version: "1.0.0" } } }),
      );
      const prior = process.env.FOURDA_OFFLINE;
      delete process.env.FOURDA_OFFLINE;
      const li = new LiveIntelligence(new Database(":memory:"));
      if (prior !== undefined) process.env.FOURDA_OFFLINE = prior;
      const stub = async (deps: ResolvedDependency[], projectPath: string) => ({ ...scanOf(Array.from({ length: 450 }, (_, i) => entry(i))), projectPath, totalScanned: deps.length });
      (li as unknown as { osvScanner: { scan: typeof stub } }).osvScanner = { scan: stub } as never;
      li.initFromDependencyGroups([{ dir, language: "javascript", deps: ["pkg-0"], devDeps: [] }]);
      // The scan is stubbed; nothing else may reach the network.
      vi.stubGlobal("fetch", async () => {
        throw new Error("offline test");
      });
      return (await executeVulnerabilityScan(null as unknown as FourDADatabase, { project_path: dir, ...params }, li)) as Record<string, any>;
    }

    it("detailed with no limit is the first 200 rows; limit and offset read on", async () => {
      const first = await scan({ response_format: "detailed" });
      expect(first.vulnerabilities).toHaveLength(200);
      expect(first.truncated).toMatchObject({ shown: 200, total: 450, next_offset: 200 });
      expect(Object.values(first.by_severity as Record<string, number>).reduce((a, b) => a + b, 0)).toBe(450);
      const rest = await scan({ response_format: "detailed", limit: 1_000, offset: 200 });
      expect(rest.vulnerabilities).toHaveLength(250);
      expect(rest.truncated).toMatchObject({ shown: 250, total: 450, offset: 200 });
      expect(rest.truncated.next_offset).toBeUndefined();
      expect(new Set([...first.vulnerabilities, ...rest.vulnerabilities].map((v: { vuln_id: string }) => v.vuln_id)).size).toBe(450);
    });

    it("the concise answer is not paged", async () => {
      const concise = await scan({ limit: 5, offset: 3 });
      expect(concise.vulnerable_packages).toHaveLength(40);
      expect(concise.truncated).toBeUndefined();
    });
  });
});
