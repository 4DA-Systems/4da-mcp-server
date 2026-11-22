// SPDX-License-Identifier: Apache-2.0
/**
 * The scan shows the advisory's own grade beside the scope-adjusted one. `severity` and
 * `by_severity` stay the presented grade (transitive caps critical at high, dev-only drops a
 * level: the rule shared with the desktop app); the advisory's own grade is counted in
 * `by_advisory_severity`, carried on every concise row where it differs (`advisory_severity`),
 * named in each recommendation's brackets, and the summary says first how many advisories are
 * critical by their own grade. zip 8.6.0 (transitive; two advisories rated critical by the
 * advisory, CVSS 9.4 and 9.1) read `critical: 0` and two models told the developer "nothing
 * rated critical".
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import type { ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { conciseScanResult } from "../tools/vulnerability-scan-concise.js";
import { formatScanResult, type ScanContext } from "../tools/vulnerability-scan-format.js";
import { pageScanResult } from "../tools/vulnerability-scan-page.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import type { FourDADatabase } from "../db.js";

const entry = (pkg: string, version: string, id: string, severity: VulnerabilityEntry["severity"], extra: Partial<VulnerabilityEntry> = {}): VulnerabilityEntry => ({
  package: pkg, currentVersion: version, ecosystem: "crates.io", isDev: false, isDirect: true, devScopeKnown: true,
  vulnId: id, aliases: [], severity, cvssScore: null, summary: `${id} summary`, fixedVersion: "99.0.0",
  published: "2026-01-01T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: ["/proj/src-tauri"], ...extra,
});

function scanOf(vulnerabilities: VulnerabilityEntry[], extra: Partial<VulnerabilityScanResult> = {}): VulnerabilityScanResult {
  return {
    scannedAt: "2026-11-23T00:00:00.000Z", projectPath: "/proj", ecosystemsScanned: ["crates.io"], totalScanned: 400,
    totalVulnerable: new Set(vulnerabilities.map((v) => v.package)).size, platformInactiveVulnerable: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities, cleanCount: 390, scanDurationMs: 1, cached: false, offline: false,
    unchecked: 0, uncheckedReason: null, staleAnswers: 0, ...extra,
  };
}

const ctx: ScanContext = { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true };

/** The audit's shape: zip transitive with two critical advisories, one direct high, one dev-only direct critical, one crate this host does not build. */
const ZIP = [
  entry("zip", "8.6.0", "RUSTSEC-2026-0546", "critical", { isDirect: false, cvssScore: 9.4, fixedVersion: "9.0.5" }),
  entry("zip", "8.6.0", "RUSTSEC-2026-0547", "critical", { isDirect: false, cvssScore: 9.1, fixedVersion: "9.0.5" }),
  entry("zip", "8.6.0", "RUSTSEC-2026-0001", "high", { isDirect: false, fixedVersion: "9.0.5" }),
  entry("rsa", "0.9.10", "RUSTSEC-2023-0071", "medium"),
  entry("sqlx", "0.8.6", "RUSTSEC-2026-0100", "high"),
  entry("devtool", "1.0.0", "RUSTSEC-2026-0200", "critical", { isDev: true, fixedVersion: "1.0.1" }),
  entry("glib", "0.15.0", "RUSTSEC-2024-0429", "high", { platformActive: false, target: "cfg(unix)" }),
];

describe("detailed: the advisory's own grade is counted and said first", () => {
  it("keeps by_severity scope-adjusted and adds by_advisory_severity beside it", () => {
    const full = formatScanResult(scanOf(ZIP), undefined, ctx);
    // The presented grade: zip's criticals are high (transitive), devtool's is high (dev-only).
    expect(full.by_severity).toEqual({ critical: 0, high: 5, medium: 1, low: 0, unknown: 0 });
    expect(full.by_advisory_severity).toEqual({ critical: 3, high: 2, medium: 1, low: 0, unknown: 0 });
    // The earlier name stays, with the same counts.
    expect(full.advisory_by_severity).toEqual(full.by_advisory_severity);
    for (const row of full.vulnerabilities) expect(row).toHaveProperty("advisory_severity");
  });

  it("the summary begins with how many advisories are critical by their own grade, and why they are presented lower", () => {
    const full = formatScanResult(scanOf(ZIP), undefined, ctx);
    expect(full.summary).toBeDefined();
    expect(full.summary).toMatch(/^3 advisories on 2 package versions are rated critical by the advisory itself \(zip@8\.6\.0, devtool@1\.0\.0\)/);
    expect(full.summary).toMatch(/2 are presented as high \(transitive-only dependency\)/);
    expect(full.summary).toMatch(/1 as high \(dev-only dependency\)/);
    expect(full.summary).toMatch(/by_advisory_severity/);
    expect(full.summary).toMatch(/severity_filter: "critical"/);
  });

  it("every recommendation shows the advisory's own grade in its brackets where it differs", () => {
    const full = formatScanResult(scanOf(ZIP), undefined, ctx);
    const zip = full.recommendations.find((r) => r.includes("zip 8.6.0"));
    expect(zip).toMatch(/\[3 high \(2 critical by the advisory\)\]/);
    const dev = full.recommendations.find((r) => r.includes("devtool 1.0.0"));
    expect(dev).toMatch(/\[1 high \(1 critical by the advisory\)\]/);
    // Where the grades agree, the brackets are as before.
    const sqlx = full.recommendations.find((r) => r.includes("sqlx 0.8.6"));
    expect(sqlx).toMatch(/\[1 high\]/);
  });

  it("says nothing extra when no advisory is critical by its own grade", () => {
    const full = formatScanResult(scanOf(ZIP.filter((v) => v.severity !== "critical")), undefined, ctx);
    expect(full.summary).toBeUndefined();
    expect(full.by_advisory_severity).toEqual(full.by_severity);
  });

  it("criticals presented as critical are said as such", () => {
    const full = formatScanResult(scanOf([entry("openssl", "0.10.38", "RUSTSEC-2026-0300", "critical")]), undefined, ctx);
    expect(full.summary).toMatch(/^1 advisory on 1 package version is rated critical by the advisory itself \(openssl@0\.10\.38\); it is presented as critical\./);
  });

  it("an incomplete scan still leads with NOT CHECKED, then the criticals among what was checked", () => {
    const full = formatScanResult(scanOf(ZIP, { unchecked: 3, uncheckedReason: "OSV.dev timed out", offline: true, uncheckedDependencies: ["a", "b", "c"].map((n) => `crates.io\u0000${n}\u00001.0.0`) }), undefined, ctx);
    expect(full.summary).toMatch(/^NOT CHECKED/);
    expect(full.summary).toMatch(/In the dependencies that were checked, 3 advisories on 2 package versions are rated critical by the advisory itself/);
    expect(full.summary!.indexOf("NOT CHECKED")).toBeLessThan(full.summary!.indexOf("rated critical"));
    expect(full.by_severity).toBeNull();
    expect(full.by_advisory_severity).toBeNull();
    expect(full.found_in_checked_dependencies).toMatchObject({ by_advisory_severity: { critical: 3 } });
  });

  it("every page carries the whole result's counts and summary", () => {
    const full = formatScanResult(scanOf(ZIP), undefined, ctx);
    const page = pageScanResult(full, 2, 2);
    expect(page.by_advisory_severity).toEqual(full.by_advisory_severity);
    expect(page.summary).toBe(full.summary);
  });

  it("the policy note in _meta stays and names the new count", () => {
    const full = formatScanResult(scanOf(ZIP), undefined, ctx);
    expect(full._meta.severity_rule).toMatch(/transitive-only dependency caps critical at high/);
    expect(full._meta.severity_rule).toMatch(/by_advisory_severity/);
  });
});

describe("concise: the default answer never reads `critical: 0` alone", () => {
  it("counts by the advisory's own grade, and each row says its own grade where it differs", () => {
    const concise = conciseScanResult(formatScanResult(scanOf(ZIP), undefined, ctx));
    expect(concise.by_severity).toMatchObject({ critical: 0 });
    expect(concise.by_advisory_severity).toMatchObject({ critical: 3, high: 2 });
    const zip = concise.vulnerable_packages.find((r) => r.package === "zip")!;
    expect(zip).toMatchObject({ severity: "high", advisory_severity: "critical" });
    const dev = concise.vulnerable_packages.find((r) => r.package === "devtool")!;
    expect(dev).toMatchObject({ severity: "high", advisory_severity: "critical" });
    // Where the grades agree the row carries no second grade.
    const sqlx = concise.vulnerable_packages.find((r) => r.package === "sqlx")!;
    expect(sqlx.advisory_severity).toBeUndefined();
    expect(concise._meta.severity_rule).toMatch(/by_advisory_severity/);
  });

  it("the summary begins with the criticals, before the platform-inactive note", () => {
    const concise = conciseScanResult(formatScanResult(scanOf(ZIP), undefined, ctx));
    expect(concise.summary).toMatch(/^3 advisories on 2 package versions are rated critical by the advisory itself/);
    expect(concise.summary).toMatch(/not built on this host/);
    expect(concise.summary!.indexOf("rated critical")).toBeLessThan(concise.summary!.indexOf("not built on this host"));
  });

  it("at an equal presented grade, a row critical by its own grade ranks before one that is not", () => {
    // 45 transitive highs by their own grade, then one transitive critical (presented high): it is within the 40 shown.
    const many = Array.from({ length: 45 }, (_, i) => entry(`crate-${String(i).padStart(2, "0")}`, "1.0.0", `RUSTSEC-2026-${1000 + i}`, "high", { isDirect: false }));
    const concise = conciseScanResult(formatScanResult(scanOf([...many, entry("zz-last", "1.0.0", "RUSTSEC-2026-0546", "critical", { isDirect: false })]), undefined, ctx));
    expect(concise.vulnerable_packages).toHaveLength(40);
    expect(concise.vulnerable_packages[0]).toMatchObject({ package: "zz-last", severity: "high", advisory_severity: "critical" });
  });
});

describe("through the tool: the default answer", () => {
  let dir: string;
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("carries by_advisory_severity and the critical sentence", async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-grade-"));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", dependencies: { a: "1.0.0" } }));
    fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", version: "1.0.0", dependencies: { a: "1.0.0" } }, "node_modules/a": { version: "1.0.0" } } }));
    const prior = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    const li = new LiveIntelligence(new Database(":memory:"));
    if (prior !== undefined) process.env.FOURDA_OFFLINE = prior;
    const stub = async (deps: ResolvedDependency[], projectPath: string) => ({ ...scanOf(ZIP.map((v) => ({ ...v, sourceDirs: [dir] }))), projectPath, totalScanned: deps.length });
    (li as unknown as { osvScanner: { scan: typeof stub } }).osvScanner = { scan: stub } as never;
    li.initFromDependencyGroups([{ dir, language: "javascript", deps: ["a"], devDeps: [] }]);
    vi.stubGlobal("fetch", async () => {
      throw new Error("offline test");
    });
    const out = (await executeVulnerabilityScan(null as unknown as FourDADatabase, { project_path: dir }, li)) as Record<string, any>;
    expect(out.by_severity).toMatchObject({ critical: 0 });
    expect(out.by_advisory_severity).toMatchObject({ critical: 3 });
    expect(out.summary).toMatch(/^3 advisories on 2 package versions are rated critical by the advisory itself/);
  });
});
