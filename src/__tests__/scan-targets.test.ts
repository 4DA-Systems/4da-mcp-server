// SPDX-License-Identifier: Apache-2.0
/**
 * vulnerability_scan and what_should_i_know recommend an upgrade target too,
 * and it was the highest per-advisory fix: "Upgrade openssl 0.10.38 →
 * 0.10.79", which GHSA-phqj-4mhp-q6mq affects (0.10.50 up to 0.10.80). Both
 * now check the target against every advisory of the package (the same check
 * upgrade_planner runs), within a time budget, and say when they could not.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { advisoryRanges, type AdvisoryRanges } from "../live/osv-ranges.js";
import { restampDepContext } from "../live/osv-scanner.js";
import type { FixPathSources } from "../live/fix-paths.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeWhatShouldIKnow, type BriefingLiveIntel } from "../tools/what-should-i-know.js";
import type { FourDADatabase } from "../db.js";
import type { OsvVulnerability, ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";

const noDb = null as unknown as FourDADatabase;
const adv = (id: string, introduced: string, fixed: string): OsvVulnerability => ({
  id,
  affected: [{ package: { name: "openssl", ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events: [{ introduced }, { fixed }] }] }],
});
// The two that decide it (real ranges, OSV 2026-10-10): the installed 0.10.38's highest fix is 0.10.79,
// and phqj, which 0.10.38 predates, affects 0.10.50 up to 0.10.80.
const OPENSSL: AdvisoryRanges[] = [adv("GHSA-xp3w-r5p5-63rr", "0.9.7", "0.10.79"), adv("GHSA-xcf7-rvmh-g6q4", "0.10.0", "0.10.55"), adv("GHSA-phqj-4mhp-q6mq", "0.10.50", "0.10.80")]
  .map((v) => advisoryRanges(v, "openssl", "crates.io")!);
const VERSIONS = ["0.10.38", "0.10.55", "0.10.78", "0.10.79", "0.10.80", "0.10.81"];

const sources = (ok = true) =>
  ({
    packageAdvisories: async () => (ok ? OPENSSL : null),
    publishedVersions: async () => (ok ? VERSIONS : null),
  }) as unknown as FixPathSources;

function entry(dep: ResolvedDependency, id: string, fixed: string): VulnerabilityEntry {
  return restampDepContext(
    {
      package: "", currentVersion: "", ecosystem: "crates.io", isDev: false, isDirect: false, devScopeKnown: true,
      vulnId: id, aliases: [], severity: "high", cvssScore: 7.5, summary: `${id} summary`, fixedVersion: fixed,
      published: "2026-01-01T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: [],
    } as VulnerabilityEntry,
    dep,
  );
}

let root: string;
beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-scan-targets-"));
  fs.writeFileSync(path.join(root, "Cargo.lock"), ['[[package]]', 'name = "openssl"', 'version = "0.10.38"', 'source = "registry+https://github.com/rust-lang/crates.io-index"', ""].join("\n"));
});
afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
afterEach(() => vi.restoreAllMocks());

async function scan(params: Record<string, unknown>, fixSources: FixPathSources | null): Promise<Record<string, any>> {
  const prior = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  const li = new LiveIntelligence(new Database(":memory:"));
  if (prior !== undefined) process.env.FOURDA_OFFLINE = prior;
  const scanOf = async (deps: ResolvedDependency[], projectPath: string): Promise<VulnerabilityScanResult> => {
    const vulnerabilities = deps.flatMap((d) =>
      d.name === "openssl" ? [entry(d, "GHSA-xp3w-r5p5-63rr", "0.10.79"), entry(d, "GHSA-xcf7-rvmh-g6q4", "0.10.55")] : [],
    );
    return {
      scannedAt: new Date().toISOString(), projectPath, ecosystemsScanned: ["crates.io"], totalScanned: deps.length, totalVulnerable: 1,
      platformInactiveVulnerable: 0, bySeverity: { critical: 0, high: 2, medium: 0, low: 0, unknown: 0 }, vulnerabilities,
      cleanCount: deps.length - 1, scanDurationMs: 1, cached: false, offline: false,
    };
  };
  (li as unknown as { osvScanner: { scan: typeof scanOf } }).osvScanner = { scan: scanOf } as never;
  li.initFromDependencyGroups([{ dir: root, language: "rust", deps: [], devDeps: [] }]);
  vi.spyOn(li, "getFixPathSources").mockReturnValue(fixSources);
  vi.spyOn(process, "cwd").mockReturnValue(root);
  return (await executeVulnerabilityScan(noDb, params, li)) as Record<string, any>;
}

describe("vulnerability_scan upgrade targets", () => {
  it("recommends 0.10.80, not the affected 0.10.79, in both formats", async () => {
    const concise = await scan({}, sources());
    expect(concise.vulnerable_packages[0]).toMatchObject({ package: "openssl", fixed_version: "0.10.80", fix_checked: "all_advisories" });
    expect(concise.recommendations[0]).toMatch(/^Upgrade openssl 0\.10\.38 → 0\.10\.80 .*0\.10\.79, the highest per-advisory fix, is itself affected by GHSA-phqj-4mhp-q6mq/);
    const detailed = await scan({ response_format: "detailed" }, sources());
    expect(detailed.fix_targets["openssl@0.10.38"]).toMatchObject({ target: "0.10.80", checked: "all_advisories" });
    // Each advisory row keeps its own fix: that is still true of that advisory.
    expect(detailed.vulnerabilities.map((v: { fixed_version: string }) => v.fixed_version).sort()).toEqual(["0.10.55", "0.10.79"]);
  });

  it("when the check cannot run, the answer says the target is unverified", async () => {
    const concise = await scan({}, sources(false));
    expect(concise.vulnerable_packages[0]).toMatchObject({ fixed_version: "0.10.79", fix_checked: "installed_advisories_only" });
    const offline = await scan({ response_format: "detailed" }, null);
    expect(offline.fix_targets["openssl@0.10.38"]).toEqual({ target: "0.10.79", checked: "installed_advisories_only" });
  });
});

describe("what_should_i_know upgrade targets", () => {
  it("the task advisory names the target that clears every advisory", async () => {
    const dep: ResolvedDependency = { name: "openssl", version: "0.10.38", ecosystem: "crates.io", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [root] };
    const scanned: VulnerabilityScanResult = {
      scannedAt: new Date().toISOString(), projectPath: root, ecosystemsScanned: ["crates.io"], totalScanned: 5, totalVulnerable: 1,
      platformInactiveVulnerable: 0, bySeverity: { critical: 0, high: 2, medium: 0, low: 0, unknown: 0 },
      vulnerabilities: [entry(dep, "GHSA-xp3w-r5p5-63rr", "0.10.79"), entry(dep, "GHSA-xcf7-rvmh-g6q4", "0.10.55")],
      cleanCount: 4, scanDurationMs: 1, cached: false, offline: false,
    };
    const raw = new Database(":memory:");
    raw.exec("CREATE TABLE source_items (id INTEGER PRIMARY KEY, title TEXT, url TEXT, source_type TEXT, content TEXT, created_at TEXT, relevance_score REAL, signal_type TEXT, signal_priority TEXT)");
    const { FourDADatabase } = await import("../db.js");
    const db = Object.create(FourDADatabase.prototype) as FourDADatabase;
    (db as unknown as { db: unknown }).db = raw;
    const intel: BriefingLiveIntel = {
      isEnabled: () => true,
      getProjectRoot: () => root,
      getVulnerabilities: () => scanned,
      ensureVulnerabilities: async () => scanned,
      getResolvedDeps: () => [dep],
      getFixPathSources: () => sources(),
    };
    const result = await executeWhatShouldIKnow(db, { task: "Upgrade openssl in the TLS layer" }, intel);
    const row = result.advisories.find((a) => a.title.startsWith("openssl"));
    expect(row?.action).toMatch(/^Upgrade openssl to 0\.10\.80 \(the smallest version that fixes all 2; 0\.10\.80 is the smallest version clear of every advisory a release fixes; 0\.10\.79/);
  });
});
