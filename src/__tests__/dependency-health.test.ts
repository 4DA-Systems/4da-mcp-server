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

    expect(result.vulnerabilitySummary).toEqual({ critical: 0, high: 1, medium: 0, low: 0, unknown: 0 });
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

/**
 * Readiness audit M1 (2026-10-16): advisoryCount and the per-advisory penalty
 * counted OSV records, not advisories. One issue published as GHSA, PYSEC and
 * CVE records was counted two or three times: pygoat read advisoryCount 348
 * beside the scan's 187, xsv 31 beside 13. Records are grouped per installed
 * copy by shared ids (groupAdvisories), each group penalised once at its worst
 * severity, the way vulnerability_scan counts its rows.
 */
describe("dependency_health — advisories, not OSV records (M1)", () => {
  const scan = makeScan([
    // One django issue as three records naming each other; the PYSEC record is the most severe.
    makeEntry({ package: "django", ecosystem: "PyPI", currentVersion: "3.2.0", vulnId: "GHSA-dj01", aliases: ["CVE-2024-0001", "PYSEC-2024-1"], severity: "high" }),
    makeEntry({ package: "django", ecosystem: "PyPI", currentVersion: "3.2.0", vulnId: "PYSEC-2024-1", aliases: ["CVE-2024-0001"], severity: "critical" }),
    makeEntry({ package: "django", ecosystem: "PyPI", currentVersion: "3.2.0", vulnId: "CVE-2024-0001", aliases: [], severity: "unknown" }),
    // A second, separate django issue.
    makeEntry({ package: "django", ecosystem: "PyPI", currentVersion: "3.2.0", vulnId: "GHSA-dj02", aliases: ["PYSEC-2024-2"], severity: "medium" }),
    makeEntry({ package: "django", ecosystem: "PyPI", currentVersion: "3.2.0", vulnId: "PYSEC-2024-2", aliases: ["GHSA-dj02"], severity: "medium" }),
    // The same id on another installed copy is a separate finding, as in the scan.
    makeEntry({ package: "django", ecosystem: "PyPI", currentVersion: "4.2.0", vulnId: "GHSA-dj02", aliases: ["PYSEC-2024-2"], severity: "medium" }),
  ]);

  it("advisoryCount is distinct advisories per installed copy (3), not records (6)", async () => {
    const result = await executeDependencyHealth(noDb, {}, makeIntel(scan));
    expect(result.advisoryCount).toBe(3);
    expect(result.vulnerableCount).toBe(1);
  });

  it("each advisory is penalised once, at its group's worst severity", async () => {
    const result = await executeDependencyHealth(noDb, {}, makeIntel(scan));
    // critical 20 + medium 4 + medium 4 (all direct); records would give 20+10+2+4+4+4 = 44.
    expect(result.healthScoreBasis?.vulnerabilities).toBe(28);
    expect(result.vulnerabilitySummary).toEqual({ critical: 1, high: 0, medium: 2, low: 0, unknown: 0 });
  });
});

/**
 * Readiness audit M5 (2026-10-16): with a merge-conflicted or invalid-JSON
 * package-lock.json, the score was 32/100, built from package.json's pins
 * alone while the lockfile's tree went unchecked. A lockfile (or include)
 * that could not be read withholds the score and the counts, as an OSV gap
 * does, and the answer leads with what was not checked.
 */
describe("dependency_health — an unreadable lockfile withholds the score (M5)", () => {
  const conflicted = (body: string): LiveIntelligence => {
    const dir = fs.mkdtempSync(path.join(root, "m5-"));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "repro", dependencies: { lodash: "4.17.20" } }));
    fs.writeFileSync(path.join(dir, "package-lock.json"), body);
    delete process.env.FOURDA_OFFLINE;
    const li = new LiveIntelligence(new Database(":memory:"));
    process.env.FOURDA_OFFLINE = "true";
    li.initFromDependencyGroups([{ dir, language: "javascript", deps: ["lodash"], devDeps: [] }]);
    li.fetchRegistryHealth = async () => [];
    (li as unknown as { lastVulnScan: VulnerabilityScanResult }).lastVulnScan = makeScan([
      makeEntry({ package: "lodash", currentVersion: "4.17.20", vulnId: "GHSA-lodash", severity: "high" }),
    ]);
    return li;
  };

  it.each([
    ["merge-conflict markers", `{\n<<<<<<< HEAD\n  "lockfileVersion": 3,\n=======\n  "lockfileVersion": 2,\n>>>>>>> branch\n}\n`, /merge-conflict/],
    ["invalid JSON", "{\n  not json\n", /invalid JSON/],
  ])("%s: no score, no counts, NOT CHECKED first", async (_label, body, reason) => {
    const result = await executeDependencyHealth(noDb, {}, conflicted(body));
    expect(result.healthScore).toBeNull();
    expect(result.healthScoreBasis).toBeUndefined();
    expect(result.vulnerableCount).toBeNull();
    expect(result.vulnerabilitySummary).toBeNull();
    expect(result.summary).toMatch(/^NOT CHECKED: /);
    expect(result.summary).toMatch(/package-lock\.json/);
    expect(result.summary).toMatch(reason);
    expect(result.summary).toMatch(/Health score withheld/);
    expect(result.summary).toMatch(/at least 1 vulnerable package/);
  });
});
/**
 * Readiness audit L2 (2026-10-16): navcal's health said "4 direct" vulnerable,
 * three of them devDependencies (vitest, sharp, vite), beside "18 direct
 * dependencies checked ... 25 devDependencies left out". dependency_health
 * reused the stored vulnerability_scan, which includes devDependencies by
 * default. Without include_dev, both populations now leave direct
 * devDependencies out, and the summary says which scope it counts.
 */
describe("dependency_health — one population for the registry rows and the vulnerable counts (L2)", () => {
  const withDev = (): LiveIntelligence => {
    const dir = fs.mkdtempSync(path.join(root, "l2-"));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "l2", dependencies: { react: "19.2.6" }, devDependencies: { vitest: "3.2.4" } }));
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: "l2",
        lockfileVersion: 3,
        packages: {
          "": { name: "l2", dependencies: { react: "19.2.6" }, devDependencies: { vitest: "3.2.4" } },
          "node_modules/react": { version: "19.2.6" },
          "node_modules/vitest": { version: "3.2.4", dev: true },
        },
      }),
    );
    delete process.env.FOURDA_OFFLINE;
    const li = new LiveIntelligence(new Database(":memory:"));
    process.env.FOURDA_OFFLINE = "true";
    li.initFromDependencyGroups([{ dir, language: "javascript", deps: ["react"], devDeps: ["vitest"] }]);
    li.fetchRegistryHealth = async () => [];
    // The stored scan is vulnerability_scan's: devDependencies included.
    (li as unknown as { lastVulnScan: VulnerabilityScanResult }).lastVulnScan = {
      ...makeScan([
        makeEntry({}),
        makeEntry({ package: "vitest", currentVersion: "3.2.4", isDev: true, vulnId: "GHSA-vitest", severity: "critical" }),
      ]),
      totalScanned: 2,
    };
    (li as unknown as { lastVulnScanIncludesDev: boolean }).lastVulnScanIncludesDev = true;
    return li;
  };

  it("without include_dev, a direct devDependency is not counted as vulnerable, direct or penalised", async () => {
    const result = await executeDependencyHealth(noDb, {}, withDev());
    expect(result.vulnerableCount).toBe(1);
    expect(result.vulnerableDirectCount).toBe(1);
    expect(result.treeDeps).toBe(1);
    expect(result.vulnerabilitySummary).toEqual({ critical: 0, high: 1, medium: 0, low: 0, unknown: 0 });
    expect(result.summary).toContain("1 vulnerable package in the full tree of 1 installed (1 direct, 0 transitive; 1 dev-only copy left out)");
  });

  it("with include_dev, both populations include them", async () => {
    const result = await executeDependencyHealth(noDb, { include_dev: true }, withDev());
    expect(result.vulnerableCount).toBe(2);
    expect(result.vulnerableDirectCount).toBe(2);
    expect(result.treeDeps).toBe(2);
    expect(result.summary).toContain("2 vulnerable packages in the full tree of 2 installed (2 direct, 0 transitive; dev-only copies included)");
  });
});
/**
 * Review of M5/M4/L5 (2026-10-18): a withheld score says why in a field;
 * ecosystem_filter narrows the lockfile problems too; a refused include or a
 * partial read scores the checked part, marked partial, instead of
 * withholding forever (a refusal is permanent by design); and the wording is
 * the scan's (UNREADABLE / PARTIAL / REFUSED).
 */
describe("dependency_health — why a score is withheld, and what a partial one rests on", () => {
  const intel = (files: Record<string, string>, groups: Array<{ language: string; deps: string[] }>) => {
    const dir = fs.mkdtempSync(path.join(root, "r3-"));
    for (const [rel, body] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), body);
    }
    delete process.env.FOURDA_OFFLINE;
    const li = new LiveIntelligence(new Database(":memory:"));
    process.env.FOURDA_OFFLINE = "true";
    li.initFromDependencyGroups(groups.map((g) => ({ dir, devDeps: [], ...g })));
    li.fetchRegistryHealth = async () => [];
    (li as unknown as { lastVulnScan: VulnerabilityScanResult }).lastVulnScan = makeScan([makeEntry({ package: "requests", ecosystem: "PyPI", currentVersion: "2.19.0", vulnId: "GHSA-req", severity: "high" })]);
    return { li, dir };
  };
  const conflicted = `{\n<<<<<<< HEAD\n  "lockfileVersion": 3,\n=======\n  "lockfileVersion": 2,\n>>>>>>> branch\n}\n`;

  it("an unreadable lockfile: withheldReason lockfile_unreadable", async () => {
    const { li } = intel({ "package.json": JSON.stringify({ dependencies: { lodash: "4.17.20" } }), "package-lock.json": conflicted }, [{ language: "javascript", deps: ["lodash"] }]);
    const r = await executeDependencyHealth(noDb, {}, li);
    expect(r.healthScore).toBeNull();
    expect(r.withheldReason).toBe("lockfile_unreadable");
    expect(r.summary).toMatch(/^NOT CHECKED: UNREADABLE: 1 lockfile could not be read/);
  });

  it("ecosystem_filter: an npm lockfile problem does not withhold a PyPI-only answer", async () => {
    const { li } = intel(
      { "package.json": JSON.stringify({ dependencies: { lodash: "4.17.20" } }), "package-lock.json": conflicted, "requirements.txt": "requests==2.19.0\n" },
      [{ language: "javascript", deps: ["lodash"] }, { language: "python", deps: ["requests"] }],
    );
    const r = await executeDependencyHealth(noDb, { ecosystem_filter: "PyPI" }, li);
    expect(r.healthScore).not.toBeNull();
    expect(r.withheldReason).toBeUndefined();
    expect(r.summary).not.toMatch(/package-lock/);
  });

  it("a refused include: the checked part is scored, marked partial, worded REFUSED", async () => {
    const { li } = intel({ "requirements.txt": "requests==2.19.0\n-r ../base.txt\n" }, [{ language: "python", deps: ["requests"] }]);
    const r = await executeDependencyHealth(noDb, {}, li);
    expect(r.healthScore).not.toBeNull();
    expect(r.withheldReason).toBeUndefined();
    expect(r.scoreCoverage).toEqual({ complete: false, basis: "checked_part", notes: [expect.stringMatching(/^REFUSED: 1 requirements include was not read: .*base\.txt/)] });
    expect(r.summary).toMatch(/^Health: \d+\/100 over the checked part only \(see scoreCoverage\)/);
    expect(r.summary).toMatch(/at least 1 vulnerable package/);
    expect(r.summary).not.toMatch(/UNREADABLE|all healthy/);
  });

  it("nothing resolved: withheldReason nothing_checked", async () => {
    const empty = new LiveIntelligence(new Database(":memory:"));
    empty.initFromProjectTree(fs.mkdtempSync(path.join(root, "r3-empty-")), [], null);
    expect((await executeDependencyHealth(noDb, {}, empty)).withheldReason).toBe("nothing_checked");
  });
});