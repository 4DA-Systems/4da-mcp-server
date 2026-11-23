// SPDX-License-Identifier: Apache-2.0
/**
 * The detailed answer's rows have one order, whatever part of the scan came from the cache.
 * Paging through react 18.2.0 (1,465 rows claimed) read 1,441 unique rows: 24 were never shown
 * and 24 shown twice, two package versions lost entirely, because page 1 was answered partly live
 * and page 2 from the cache, the scanner put cached answers first, and the sort had no final
 * tiebreak. Rows are now ordered by grade, then ecosystem, package, version, directory and
 * advisory id, so pages read over the same scan state, concatenated, are the unpaged list.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import type { OsvEcosystem, ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { conciseScanResult } from "../tools/vulnerability-scan-concise.js";
import { formatScanResult, type ScanContext } from "../tools/vulnerability-scan-format.js";
import { pageScanResult } from "../tools/vulnerability-scan-page.js";

const ctx: ScanContext = { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true };

const entry = (pkg: string, version: string, id: string, extra: Partial<VulnerabilityEntry> = {}): VulnerabilityEntry => ({
  package: pkg, currentVersion: version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true,
  vulnId: id, aliases: [], severity: "high", cvssScore: null, summary: `${id} summary`, fixedVersion: "9.0.0",
  published: "2026-01-01T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: ["/proj"], ...extra,
});

function scanOf(vulnerabilities: VulnerabilityEntry[]): VulnerabilityScanResult {
  return {
    scannedAt: "2026-11-23T00:00:00.000Z", projectPath: "/proj", ecosystemsScanned: ["npm", "PyPI"], totalScanned: 3_000,
    totalVulnerable: new Set(vulnerabilities.map((v) => v.package)).size, platformInactiveVulnerable: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities, cleanCount: 2_000, scanDurationMs: 1, cached: false, offline: false,
    unchecked: 0, uncheckedReason: null, staleAnswers: 0,
  };
}

/**
 * Many rows that tie on grade and directness: several versions and directories per package,
 * alias pairs whose records are equally rich (either could represent the advisory), one name in
 * two ecosystems, rows this host does not build and maintenance notices.
 */
function tree(): VulnerabilityEntry[] {
  const rows: VulnerabilityEntry[] = [];
  for (let p = 0; p < 40; p++) {
    const versions = p % 3 === 0 ? ["1.9.0", "1.10.0"] : ["1.2.3"];
    for (const version of versions) {
      const dirs = p % 4 === 0 ? ["/proj/b", "/proj/a"] : p % 4 === 1 ? ["/proj/a"] : ["/proj"];
      rows.push(entry(`pkg-${p}`, version, `GHSA-${p}-0001`, { sourceDirs: dirs }));
      rows.push(entry(`pkg-${p}`, version, `GHSA-${p}-0002`, { sourceDirs: dirs, isDirect: p % 2 === 0 }));
      if (p % 5 === 0) {
        // One advisory, two records naming each other, equally rich.
        rows.push(entry(`pkg-${p}`, version, `GHSA-${p}-0003`, { aliases: [`CVE-2026-${p}`], sourceDirs: dirs }));
        rows.push(entry(`pkg-${p}`, version, `CVE-2026-${p}`, { aliases: [`GHSA-${p}-0003`], sourceDirs: dirs }));
      }
    }
  }
  for (const ecosystem of ["npm", "PyPI"] as OsvEcosystem[]) rows.push(entry("shared", "2.0.0", `GHSA-shared-${ecosystem}`, { ecosystem }));
  for (let i = 0; i < 10; i++) rows.push(entry(`linux-only-${i % 3}`, `0.${i}.0`, `RUSTSEC-2026-${1000 + i}`, { ecosystem: "crates.io", platformActive: false, target: "cfg(unix)" }));
  for (let i = 0; i < 6; i++) rows.push(entry(`old-${i % 2}`, `0.${i}.0`, `RUSTSEC-2025-${2000 + i}`, { ecosystem: "crates.io", maintenance: true, summary: "unmaintained" }));
  return rows;
}

/** A fixed shuffle (mulberry32), so a failure reproduces. */
function shuffled<T>(items: T[], seed: number): T[] {
  let s = seed;
  const rand = () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

type Full = ReturnType<typeof formatScanResult>;
const allRows = (f: Full) => [...f.vulnerabilities, ...f.platform_inactive_vulnerabilities, ...f.maintenance_notices];

/** Read every page, page n from `answers[n % answers.length]`: the answers stand for calls over the same scan state. */
function readPages(answers: Full[], limit: number) {
  const rows: unknown[] = [];
  const recommendations: string[] = [];
  for (let offset = 0, n = 0; ; n++) {
    const page = pageScanResult(answers[n % answers.length], limit, offset);
    rows.push(...page.vulnerabilities, ...page.platform_inactive_vulnerabilities, ...page.maintenance_notices);
    recommendations.push(...page.recommendations);
    if (page.truncated?.next_offset === undefined) break;
    offset = page.truncated.next_offset;
  }
  return { rows, recommendations };
}

describe("one row order, whatever order the scan's answers arrived in", () => {
  const rows = tree();
  const cachedFirst = [...rows.filter((_, i) => i % 2 === 0), ...rows.filter((_, i) => i % 2 === 1)];
  const liveFirst = [...rows.filter((_, i) => i % 2 === 1), ...rows.filter((_, i) => i % 2 === 0)];
  const orders = [rows, cachedFirst, liveFirst, [...rows].reverse(), shuffled(rows, 7), shuffled(rows, 1123)];
  const answers = orders.map((o) => formatScanResult(scanOf(o), undefined, ctx));

  it("formats the same answer from any input order", () => {
    for (const other of answers.slice(1)) {
      expect(allRows(other)).toEqual(allRows(answers[0]));
      expect(other.recommendations).toEqual(answers[0].recommendations);
      expect(other.fix_targets).toEqual(answers[0].fix_targets);
      expect(conciseScanResult(other)).toEqual(conciseScanResult(answers[0]));
    }
  });

  it("pages read from answers built in different orders, concatenated, are the unpaged list exactly", () => {
    const unpaged = allRows(answers[0]);
    for (const limit of [1, 7, 50]) {
      for (const pair of [[answers[1], answers[2]], [answers[2], answers[1]], [answers[3], answers[4], answers[5]]]) {
        const read = readPages(pair, limit);
        expect(read.rows).toEqual(unpaged);
        expect(read.recommendations).toEqual(answers[0].recommendations);
      }
    }
  });

  it("the order is grade, directness, then ecosystem, package, version, directory and advisory id", () => {
    const list = answers[0].vulnerabilities;
    const v19 = list.findIndex((r) => r.package === "pkg-0" && r.current_version === "1.9.0" && r.is_direct);
    const v110 = list.findIndex((r) => r.package === "pkg-0" && r.current_version === "1.10.0" && r.is_direct);
    // Versions by the ecosystem's order, not by their text.
    expect(v19).toBeGreaterThanOrEqual(0);
    expect(v19).toBeLessThan(v110);
    // One name in two ecosystems: two rows, npm before PyPI.
    const shared = list.filter((r) => r.package === "shared").map((r) => r.ecosystem);
    expect(shared).toEqual(["npm", "PyPI"]);
    // Within one copy, advisory ids in order; an alias pair keeps one representative, the same each time.
    const ids = list.filter((r) => r.package === "pkg-5" && r.is_direct).map((r) => r.vuln_id);
    expect(ids).toEqual([...ids].sort());
    expect(list.filter((r) => r.package === "pkg-5" && r.aliases.length > 0)).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// The scanner: part of a scan from the cache, the rest live
// ---------------------------------------------------------------------------

const dep = (name: string): ResolvedDependency => ({
  name, version: "1.0.0", ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: ["/proj"],
});

/** OSV.dev stub: every package has two advisories, HIGH, fixed in 2.0.0. */
function stubOsv() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      return new Response(JSON.stringify({ results: queries.map((q) => ({ vulns: [{ id: `GHSA-${q.package.name}-0001` }, { id: `GHSA-${q.package.name}-0002` }] })) }), { status: 200 });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const name = id.replace(/^GHSA-/, "").replace(/-000\d$/, "");
      return new Response(
        JSON.stringify({
          id,
          summary: `advisory ${id}`,
          database_specific: { severity: "HIGH" },
          affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }],
        }),
        { status: 200 },
      );
    }
    throw new TypeError(`fetch failed (${url})`);
  });
}

function scanner(): OsvScanner {
  const cache = new LiveCache(new Database(":memory:"));
  const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter));
}

describe("the scanner's answer does not depend on which dependencies were cached", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const deps = Array.from({ length: 24 }, (_, i) => dep(`pkg-${String.fromCharCode(97 + i)}`));

  /** Warm the cache with `warm`, then scan every dependency: `warm` is answered from the cache, the rest live. */
  async function scanWithWarm(warm: ResolvedDependency[]) {
    const s = scanner();
    await s.scan(warm, "/proj");
    const result = await s.scan(deps, "/proj");
    expect(result.offline).toBe(false);
    return result;
  }

  it("gives the same rows, in the same order, in both cache orders", async () => {
    const prior = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    try {
      stubOsv();
      const front = await scanWithWarm(deps.slice(0, 12));
      const back = await scanWithWarm(deps.slice(12));
      expect(front.vulnerabilities).toHaveLength(48);
      expect(back.vulnerabilities).toEqual(front.vulnerabilities);

      // Pages over the two, alternating, concatenated: the unpaged list.
      const answers = [formatScanResult(front, undefined, ctx), formatScanResult(back, undefined, ctx)];
      const unpaged = allRows(answers[0]);
      expect(unpaged).toHaveLength(48);
      for (const limit of [5, 20]) expect(readPages(answers, limit).rows).toEqual(unpaged);
      expect(readPages([answers[1], answers[0]], 20).rows).toEqual(unpaged);
    } finally {
      if (prior !== undefined) process.env.FOURDA_OFFLINE = prior;
    }
  });
});
