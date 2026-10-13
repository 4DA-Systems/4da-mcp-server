// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_health must count "vulnerable" the way vulnerability_scan does.
 *
 * Live 2026-09-07: over one scan, vulnerability_scan reported 5 vulnerable
 * packages (with the rest filed under platform_inactive_vulnerabilities and
 * maintenance_notices) while dependency_health said 11 — it counted every
 * advisory row. Two tools, one scan, two numbers.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import type { FourDADatabase } from "../db.js";
import type { VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";

let root: string;
let webDir: string;
let priorOffline: string | undefined;

const noDb = null as unknown as FourDADatabase;

function makeEntry(over: Partial<VulnerabilityEntry>): VulnerabilityEntry {
  return {
    package: "react",
    currentVersion: "19.2.6",
    ecosystem: "npm",
    isDev: false,
    isDirect: true,
    devScopeKnown: true,
    vulnId: "GHSA-test-0001",
    aliases: [],
    severity: "high",
    cvssScore: 7.5,
    summary: "test advisory",
    fixedVersion: "19.2.7",
    published: "2026-01-01T00:00:00Z",
    references: [],
    target: null,
    platformActive: true,
    sourceDirs: [],
    ...over,
  };
}

function makeScan(entries: VulnerabilityEntry[]): VulnerabilityScanResult {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const e of entries) bySeverity[e.severity]++;
  return {
    scannedAt: new Date().toISOString(),
    projectPath: webDir,
    ecosystemsScanned: ["npm"],
    totalScanned: 10,
    totalVulnerable: new Set(entries.map((e) => e.package)).size,
    platformInactiveVulnerable: 0,
    bySeverity,
    vulnerabilities: entries,
    cleanCount: 10 - entries.length,
    scanDurationMs: 5,
    cached: true,
    // A complete scan: every dependency answered. (These stubs said offline:
    // true and were counted as complete; 6.2.5 withholds counts from an
    // offline scan, which is what the fail-closed tests below pin.)
    offline: false,
    unchecked: 0,
  };
}

function makeIntel(scan: VulnerabilityScanResult): LiveIntelligence {
  delete process.env.FOURDA_OFFLINE;
  const li = new LiveIntelligence(new Database(":memory:"));
  process.env.FOURDA_OFFLINE = "true";
  li.initFromDependencyGroups([{ dir: webDir, language: "javascript", deps: ["react"], devDeps: [] }]);
  li.fetchRegistryHealth = async () => [];
  (li as unknown as { lastVulnScan: VulnerabilityScanResult }).lastVulnScan = scan;
  return li;
}

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  process.env.FOURDA_OFFLINE = "true";
  root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-dep-health-"));
  webDir = path.join(root, "web");
  fs.mkdirSync(webDir);
  fs.writeFileSync(
    path.join(webDir, "package-lock.json"),
    JSON.stringify({ packages: { "node_modules/react": { version: "19.2.6" } } }),
  );
});

afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(root, { recursive: true, force: true });
});

describe("dependency_health — vulnerable means the actionable set", () => {
  const scan = makeScan([
    makeEntry({}),
    makeEntry({ package: "nix", currentVersion: "0.29.0", ecosystem: "crates.io", vulnId: "GHSA-inactive", severity: "critical", platformActive: false, target: "cfg(unix)" }),
    makeEntry({ package: "paste", currentVersion: "1.0.15", ecosystem: "crates.io", vulnId: "RUSTSEC-2024-0436", severity: "unknown", summary: "paste - no longer maintained", fixedVersion: null }),
  ]);

  it("counts distinct packages that are built on this host and not maintenance notices", async () => {
    const result = await executeDependencyHealth(noDb, {}, makeIntel(scan));

    expect(result.vulnerableCount).toBe(1);
    expect(result.advisoryCount).toBe(3);
    expect(result.summary).toContain("1 vulnerable");
    expect(result.summary).toContain("2 advisories not counted");
  });

  it("breaks severity down over the same set", async () => {
    const result = await executeDependencyHealth(noDb, {}, makeIntel(scan));

    expect(result.vulnerabilitySummary).toEqual({ critical: 0, high: 1, medium: 0, low: 0 });
  });

  it("keys a vulnerable package by ecosystem and name, not name alone", async () => {
    // Same name, two registries: two vulnerable packages, never one.
    const twoRegistries = makeScan([
      makeEntry({}),
      makeEntry({ ecosystem: "crates.io", vulnId: "RUSTSEC-react", currentVersion: "0.1.0" }),
    ]);
    const result = await executeDependencyHealth(noDb, {}, makeIntel(twoRegistries));

    expect(result.vulnerableCount).toBe(2);
    expect(result.summary).toContain("2 vulnerable");
  });

  it("reports all healthy when every advisory is inactive or a maintenance notice", async () => {
    const quiet = makeScan([
      makeEntry({ package: "nix", vulnId: "GHSA-inactive", severity: "critical", platformActive: false, target: "cfg(unix)" }),
      makeEntry({ package: "paste", vulnId: "RUSTSEC-2024-0436", severity: "unknown", summary: "paste - no longer maintained", fixedVersion: null }),
    ]);
    const result = await executeDependencyHealth(noDb, {}, makeIntel(quiet));

    expect(result.vulnerableCount).toBe(0);
    expect(result.advisoryCount).toBe(2);
    expect(result.summary).toContain("all healthy");
    expect(result.healthScore).toBe(100);
  });
});

// 2026-10-03 agent eval: the first health check of a session answered "run
// vulnerability_scan first" instead of loading the scan it needed.
describe("dependency_health loads its own vulnerability data", () => {
  it("runs the scan when none has run, at the requested scope", async () => {
    delete process.env.FOURDA_OFFLINE;
    const li = new LiveIntelligence(new Database(":memory:"));
    process.env.FOURDA_OFFLINE = "true";
    li.initFromDependencyGroups([{ dir: webDir, language: "javascript", deps: ["react"], devDeps: [] }]);
    const calls: Array<{ includeDev?: boolean }> = [];
    (li as unknown as { osvScanner: unknown }).osvScanner = {
      scan: async () => ({ ...makeScan([makeEntry({})]), offline: false, cached: false }),
    };
    li.fetchRegistryHealth = async () => [];
    const scan = li.scanVulnerabilities.bind(li);
    li.scanVulnerabilities = (p, o) => (calls.push(o ?? {}), scan(p, o));

    const result = await executeDependencyHealth(noDb, { include_dev: true }, li);
    expect(calls).toEqual([{ includeDev: true }]);
    expect(result.vulnerableCount).toBe(1);
    expect(result.summary).not.toContain("CVE data not loaded");
  });

  it("says why there is no CVE data offline", async () => {
    const li = new LiveIntelligence(new Database(":memory:"));
    li.initFromDependencyGroups([{ dir: webDir, language: "javascript", deps: ["react"], devDeps: [] }]);
    const result = await executeDependencyHealth(noDb, {}, li);
    expect(result.summary).toMatch(/^NOT CHECKED: live lookups are disabled \(FOURDA_OFFLINE=true\)/);
    expect(result.healthScore).toBeNull();
    expect(result.vulnerableCount).toBeNull();
    expect(result.vulnerabilityCoverage?.unchecked_dependencies).toBe(1);
  });
});

/**
 * 2026-10-07 eval: dependency_health labelled sqlx 0.8 -> 0.9, reqwest
 * 0.12 -> 0.13, lopdf 0.42 -> 0.45 and tower-http 0.6 -> 0.7 "minor". Under
 * the caret rules npm and Cargo apply, a 0.x minor bump is breaking.
 */
describe("version distance below 1.0", () => {
  it.each([
    ["0.8.6", "0.9.0", "major"],
    ["0.12.28", "0.13.5", "major"],
    ["0.42.0", "0.45.0", "major"],
    ["0.6.8", "0.7.0", "major"],
    ["0.0.3", "0.0.4", "major"],
    ["0.8.6", "0.8.7", "patch"],
    ["1.26.1", "1.27.0", "minor"],
    ["2.0.0", "3.1.0", "major"],
    ["1.2.3", "1.2.3", "up-to-date"],
  ])("%s -> %s is %s", async (from, to, label) => {
    const { computeSemverDistance } = await import("../live/semver-utils.js");
    expect(computeSemverDistance(from, to)?.label).toBe(label);
  });

  it("agrees with upgrade_impact's upgrade type", async () => {
    const { computeSemverDistance } = await import("../live/semver-utils.js");
    const { upgradeType } = await import("../tools/upgrade-impact-report.js");
    for (const [from, to] of [["0.8.6", "0.9.0"], ["0.0.3", "0.0.4"], ["1.2.0", "1.3.0"], ["0.4.1", "0.4.2"], ["22.3.0", "23.0.0"]]) {
      expect(computeSemverDistance(from, to)?.label, `${from} -> ${to}`).toBe(upgradeType(from, to));
    }
  });
});

/**
 * 2026-10-13 review (also in 6.2.4): navcal read "Health: 19/100. 18
 * dependencies scanned, 26 vulnerable": 18 was the direct runtime
 * dependencies checked against the registry (25 devDependencies left out),
 * 26 the vulnerable packages among the 633 installed. Each number now says
 * which population it counts, and the score says how it was built.
 */
describe("dependency_health — direct and tree counts are named, the score explains itself", () => {
  const tree = (scan: VulnerabilityScanResult): LiveIntelligence => {
    delete process.env.FOURDA_OFFLINE;
    const li = new LiveIntelligence(new Database(":memory:"));
    process.env.FOURDA_OFFLINE = "true";
    li.initFromDependencyGroups([{ dir: webDir, language: "javascript", deps: ["react"], devDeps: ["vitest"] }]);
    li.fetchRegistryHealth = async (deps) =>
      deps.map((d) => ({
        name: d.name, ecosystem: d.ecosystem, currentVersion: d.version, latestVersion: "20.0.0", latestStableVersion: "20.0.0",
        versionsBehind: { major: 1, minor: 0, patch: 0, label: "major" as const }, deprecated: false, deprecationMessage: null,
        lastPublished: null, license: null, weeklyDownloads: null, isDev: d.isDev, fetchError: null,
      }));
    (li as unknown as { lastVulnScan: VulnerabilityScanResult }).lastVulnScan = scan;
    return li;
  };
  const scan = { ...makeScan([
    makeEntry({}),
    makeEntry({ package: "semver", currentVersion: "5.7.1", isDirect: false, vulnId: "GHSA-semver", severity: "medium" }),
    makeEntry({ package: "ws", currentVersion: "7.4.0", isDirect: false, vulnId: "GHSA-ws", severity: "high" }),
  ]), totalScanned: 633 };

  it("vulnerable can exceed the direct count, and the summary says why", async () => {
    const result = await executeDependencyHealth(noDb, {}, tree(scan));
    expect(result.totalDeps).toBe(1);
    expect(result.vulnerableCount).toBe(3);
    expect(result.vulnerableDirectCount).toBe(1);
    expect(result.treeDeps).toBe(633);
    expect(result.summary).toContain("1 direct dependency checked against its registry (1 devDependency left out; include_dev: true adds them)");
    expect(result.summary).toContain("3 vulnerable packages in the full tree of 633 installed (1 direct, 2 transitive)");
    expect(result.summary).toContain("1 outdated (direct)");
    expect(result.summary).not.toMatch(/\d+ dependencies scanned/);
  });

  it("the score is 100 minus the penalties it lists", async () => {
    const result = await executeDependencyHealth(noDb, {}, tree(scan));
    const basis = result.healthScoreBasis!;
    // react high direct 10 + semver medium transitive 4/3 + ws high transitive 10/3 = 14.67 -> 15
    expect(basis.vulnerabilities).toBe(15);
    expect(basis.outdated).toBe(30);
    expect(result.healthScore).toBe(100 - basis.vulnerabilities - basis.outdated - basis.deprecated);
    expect(result.summary).toMatch(/^Health: 55\/100 \(100 minus 15 for vulnerabilities, 30 for outdated, 0 for deprecated; see healthScoreBasis\)/);
    expect(basis.note).toMatch(/full installed tree/);
  });

  it("ecosystem_filter narrows the vulnerability counts as well as the rows", async () => {
    const mixed = { ...scan, vulnerabilities: [...scan.vulnerabilities, makeEntry({ package: "rsa", ecosystem: "crates.io", currentVersion: "0.9.6", isDirect: false, vulnId: "RUSTSEC-2023-0071" })] };
    const result = await executeDependencyHealth(noDb, { ecosystem_filter: "npm" }, tree(mixed));
    expect(result.vulnerableCount).toBe(3);
  });
});
