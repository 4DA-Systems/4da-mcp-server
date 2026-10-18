// SPDX-License-Identifier: Apache-2.0
/**
 * The final release-readiness audit of 6.2.5 (2026-10-18). Each block names its finding; every
 * test fails on 59081cc and passes after the fix. Registry and OSV shapes are the real ones
 * (registry.npmjs.org abbreviated documents, index.crates.io sparse lines, api.osv.dev records),
 * cut down to the versions that matter.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { checkParentRelease, planParentReleaseLine } from "./helpers/parent-release-vectors.js";
import { smallestCleanVersion } from "../live/osv-ranges.js";
import { introducesText } from "../live/fix-paths.js";

const noDb = null as unknown as FourDADatabase;

type Ev = Record<string, string>;
const adv = (id: string, name: string, events: Ev[], opts: { aliases?: string[]; severity?: string; summary?: string; cvss?: string; ecosystem?: string } = {}): OsvVulnerability => ({
  id,
  aliases: opts.aliases ?? [],
  summary: opts.summary ?? `${name} advisory ${id}`,
  ...(opts.severity ? { database_specific: { severity: opts.severity } } : {}),
  ...(opts.cvss ? { severity: [{ type: "CVSS_V3", score: opts.cvss }] } : {}),
  affected: [{ package: { name, ecosystem: opts.ecosystem ?? "npm" }, ranges: [{ type: "SEMVER", events }] }],
});
const fixedIn = (v: string): Ev[] => [{ introduced: "0" }, { fixed: v }];

let ADVISORIES: Record<string, OsvVulnerability[]> = {};
type VersionDoc = { deprecated?: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> };
let NPM: Record<string, { versions: Record<string, VersionDoc>; latest: string }> = {};
/** crates.io sparse index: crate -> version -> { deps: crate -> req, yanked } */
let CRATES: Record<string, Record<string, { deps?: Record<string, string>; yanked?: boolean }>> = {};
let QUERY_DOWN = false;
let REGISTRY_DOWN = false;

/** Semver-ish order for the stubbed OSV matcher (numeric parts; a prerelease sorts below its release). */
function cmp(a: string, b: string): number {
  const [ma, pa] = a.split("-");
  const [mb, pb] = b.split("-");
  const x = ma.split(".").map(Number);
  const y = mb.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  if (pa && !pb) return -1;
  if (!pa && pb) return 1;
  return 0;
}
function affects(v: OsvVulnerability, version: string): boolean {
  if (!v.affected?.[0]?.ranges?.[0]) return false;
  return v.affected![0].ranges[0].events.reduce<boolean | null>((hit, _e, i, ev) => {
    if (hit !== null || ev[i].introduced === undefined) return hit;
    const intro = ev[i].introduced!;
    const close = ev[i + 1];
    if (intro !== "0" && cmp(version, intro) < 0) return null;
    if (close?.fixed) return cmp(version, close.fixed) < 0 ? true : null;
    if (close?.last_affected) return cmp(version, close.last_affected) <= 0 ? true : null;
    return true;
  }, null) === true;
}

function stubNetwork() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (ADVISORIES[q.package.name] ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(ADVISORIES).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      if (QUERY_DOWN) return new Response("unavailable", { status: 503 });
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: ADVISORIES[q.package.name] ?? [] });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      if (REGISTRY_DOWN) throw new TypeError("fetch failed (simulated registry outage)");
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({}, 404);
      if (npm[2]) return json(doc.versions[decodeURIComponent(npm[2])] ?? {});
      return json({ name, "dist-tags": { latest: doc.latest }, versions: doc.versions, time: {} });
    }
    const crate = /^https:\/\/index\.crates\.io\/.*\/([^/]+)$/.exec(url);
    if (crate) {
      const versions = CRATES[crate[1]];
      if (!versions) return new Response("", { status: 404 });
      const lines = Object.entries(versions).map(([vers, v]) =>
        JSON.stringify({ name: crate[1], vers, yanked: v.yanked === true, deps: Object.entries(v.deps ?? {}).map(([name, req]) => ({ name, req, kind: "normal", optional: false })) }),
      );
      return new Response(lines.join("\n"), { status: 200 });
    }
    return json({}, 404);
  });
}

let dir: string;
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-final-625-"));
  ADVISORIES = {};
  NPM = {};
  CRATES = {};
  QUERY_DOWN = false;
  REGISTRY_DOWN = false;
  stubNetwork();
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

type LockEntry = { version: string; dev?: boolean; dependencies?: Record<string, string> };
/** A package-lock v3 project: `direct` / `devDirect` are declared; `tree` adds each installed entry. */
function project(direct: Record<string, string>, devDirect: Record<string, string>, tree: Record<string, LockEntry> = {}) {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: direct, devDependencies: devDirect }));
  const packages: Record<string, unknown> = { "": { name: "x", dependencies: direct, devDependencies: devDirect } };
  for (const [n, v] of Object.entries(direct)) packages[`node_modules/${n}`] = { version: v };
  for (const [n, v] of Object.entries(devDirect)) packages[`node_modules/${n}`] = { version: v, dev: true };
  for (const [n, e] of Object.entries(tree)) packages[n.includes("/") && !n.startsWith("@") ? n : `node_modules/${n}`] = e;
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
}

function intel(): LiveIntelligence {
  return new LiveIntelligence(new Database(":memory:"));
}

async function initialised(): Promise<LiveIntelligence> {
  const li = intel();
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

async function plan(params: Record<string, unknown> = {}) {
  const li = await initialised();
  const result = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50, ...params }, li)) as Record<string, any>;
  const step = (name: string, version?: string) =>
    result.recommendations.find((s: { package: string; currentVersion: string }) => s.package === name && (!version || s.currentVersion === version));
  return { result, step };
}

async function health(params: Record<string, unknown> = {}) {
  const li = await initialised();
  return (await executeDependencyHealth(null, params, li)) as unknown as Record<string, any>;
}

const scan = async (params: Record<string, unknown> = {}) =>
  (await executeVulnerabilityScan(null, { project_path: dir, ...params }, intel())) as Record<string, any>;

// ---------------------------------------------------------------------------
// H1: no tool offers a known-affected release
// ---------------------------------------------------------------------------

/**
 * crossenv: npm's placeholder 0.0.2-security; 1.0.0 and 1.0.1 are the malware. The REAL record,
 * api.osv.dev/v1/vulns/GHSA-c2m4-w5hm-vqjw read 2026-10-18 (fixtures/osv/): aliases only
 * CVE-2017-16074, no MAL- id; it is malware by database_specific.cwe_ids ["CWE-506"].
 */
const CROSSENV = JSON.parse(fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, "$1")), "fixtures", "osv", "GHSA-c2m4-w5hm-vqjw.json"), "utf8")) as OsvVulnerability;
function crossenvProject() {
  ADVISORIES.crossenv = [CROSSENV];
  NPM.crossenv = { latest: "0.0.2-security", versions: { "0.0.1-security": {}, "1.0.0": {}, "1.0.1": {}, "0.0.2-security": {} } };
  project({ crossenv: "0.0.2-security" }, {});
}

describe("H1: every release a tool offers passes the advisory check dependency_check decides proceed by", () => {
  it("upgrade_planner: crossenv 0.0.2-security gets NO target, and says to remove it", async () => {
    crossenvProject();
    const { result, step } = await plan();
    const row = step("crossenv");
    expect(row.targetVersion).toBeNull();
    expect(row.action).toBe("remove_dependency");
    const text = row.reasons.join(" ");
    expect(text).toMatch(/crossenv 1\.0\.0 and 1\.0\.1 are malware \(GHSA-c2m4-w5hm-vqjw\)/);
    expect(text).toMatch(/remove it/);
    expect(text).not.toMatch(/major version behind/);
    expect(result.summary).toMatch(/1 to remove/);
  });

  it("dependency_health: crossenv's latest stable is not offered; it is not counted outdated", async () => {
    crossenvProject();
    const h = await health();
    const row = h.dependencies.find((d: { name: string }) => d.name === "crossenv");
    expect(row.latestStableVersion).toBe("1.0.1");
    expect(row.latestSafeVersion).toBeNull();
    expect(row.versionsBehind).toBeNull();
    expect(row.latestStableNote).toMatch(/remove it/);
    expect(h.outdatedCount).toBe(0);
  });

  it("a newer release an advisory affects is never the freshness target: the newest clean one is", async () => {
    ADVISORIES.widget = [adv("GHSA-widget-12", "widget", [{ introduced: "1.2.0" }, { fixed: "1.3.0" }], { severity: "HIGH" })];
    NPM.widget = { latest: "1.2.0", versions: { "1.0.0": {}, "1.1.0": {}, "1.2.0": {} } };
    project({ widget: "1.0.0" }, {});
    const { step } = await plan();
    const row = step("widget");
    expect(row).toMatchObject({ targetVersion: "1.1.0", action: "upgrade_direct" });
    expect(row.reasons.join(" ")).toMatch(/widget 1\.2\.0 is affected by GHSA-widget-12, so it is not offered: 1\.1\.0 is the newest release/);
    const h = await health();
    expect(h.dependencies.find((d: { name: string }) => d.name === "widget")).toMatchObject({ latestSafeVersion: "1.1.0" });
  });
});

// ---------------------------------------------------------------------------
// M2: one severity per advisory
// ---------------------------------------------------------------------------

describe("M2: within an alias group, every tool grades the advisory by its most severe record", () => {
  function aliasProject() {
    // CVE-2026-4277's shape: the record with the most detail (a CVSS vector) grades it LOW; its
    // alias grades it critical. The scan kept the detailed record's grade.
    ADVISORIES.tmpl = [
      adv("GHSA-pwjp-ccjc-ghwg", "tmpl", fixedIn("2.0.0"), { severity: "LOW", aliases: ["CVE-2026-4277", "OSV-2026-52"], cvss: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" }),
      adv("OSV-2026-52", "tmpl", fixedIn("2.0.0"), { aliases: ["CVE-2026-4277", "GHSA-pwjp-ccjc-ghwg"], severity: "CRITICAL" }),
    ];
    NPM.tmpl = { latest: "2.0.0", versions: { "1.0.0": {}, "2.0.0": {} } };
    project({ tmpl: "1.0.0" }, {});
  }

  it("vulnerability_scan keeps one row at critical and names the record the grade came from", async () => {
    aliasProject();
    const s = await scan({ response_format: "detailed" });
    expect(s.vulnerabilities).toHaveLength(1);
    const row = s.vulnerabilities[0];
    expect(row.advisory_severity).toBe("critical");
    if (row.vuln_id === "GHSA-pwjp-ccjc-ghwg") expect(row.severity_from).toBe("OSV-2026-52");
    expect(s.advisory_by_severity.critical).toBe(1);
  });

  it("dependency_check, dependency_health and the scan agree", async () => {
    aliasProject();
    const dc = (await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "tmpl", to: "1.0.0" }] }, intel())) as Record<string, any>;
    expect(dc.results[0].reason).toMatch(/\(critical/);
    const h = await health();
    expect(h.vulnerabilitySummary).toEqual({ critical: 1, high: 0, medium: 0, low: 0, unknown: 0 });
    const s = await scan({ response_format: "detailed" });
    expect(s.advisory_by_severity).toEqual({ ...h.vulnerabilitySummary });
  });
});

// ---------------------------------------------------------------------------
// #981 re-review: one predicate for every clean-release decision (malware, unreadable, unfixed)
// ---------------------------------------------------------------------------

describe("#981: one clean-release predicate on the planner paths", () => {
  it("malware-installed parent: the row names no release, and says to remove or replace it", async () => {
    parentProject([adv("GHSA-par-0000-0099", "par", [{ introduced: "0" }], { summary: "par advisory", aliases: ["MAL-2026-0099"] })], { "1.1.0": { dependencies: { leaf: "^1.1.0" } } });
    const { step } = await plan();
    const leaf = step("leaf");
    expect(leaf.targetVersion).toBeNull();
    expect(leaf.reasons.join(" ")).toContain("par is flagged malicious (GHSA-par-0000-0099): remove or replace par");
    expect(JSON.stringify(leaf)).not.toMatch(/npm install/);
  });

  it("unreadable ranges on a parent: undecided, no release and no command", async () => {
    parentProject([{ id: "GHSA-par-0000-0098", summary: "no ranges", affected: [{ package: { name: "par", ecosystem: "npm" }, ranges: [] }] }], { "1.1.0": { dependencies: { leaf: "^1.1.0" } } });
    const { step } = await plan();
    const leaf = step("leaf");
    expect(leaf.reasons.join(" ")).toMatch(/the affected ranges of GHSA-par-0000-0098 cannot be read/);
    expect(JSON.stringify(leaf.parentUpgrades ?? [])).not.toContain("\"to\":\"1.1.0\"");
    expect(JSON.stringify(leaf)).not.toMatch(/npm install/);
  });

  /** leaf 1.0.0 pinned by par 1.0.0; par's own advisories are what each case varies. */
  function parentProject(parAdvisories: OsvVulnerability[], parVersions: Record<string, VersionDoc>) {
    ADVISORIES.leaf = [adv("GHSA-leaf-0000-0001", "leaf", fixedIn("1.1.0"), { severity: "HIGH" })];
    ADVISORIES.par = parAdvisories;
    NPM.leaf = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    NPM.par = { latest: Object.keys(parVersions).pop()!, versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } }, ...parVersions } };
    project({ par: "1.0.0" }, {}, { par: { version: "1.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } });
  }

  it("(a) a release a malware advisory affects is never the parent release, even when it affects the newest", async () => {
    parentProject(
      [adv("MAL-2026-0001", "par", [{ introduced: "1.1.0" }], { summary: "Malicious code in par (npm)" })],
      { "1.1.0": { dependencies: { leaf: "^1.1.0" } }, "1.2.0": { dependencies: { leaf: "^1.1.0" } } },
    );
    const { step } = await plan();
    const leaf = step("leaf");
    expect(JSON.stringify(leaf.parentUpgrades ?? [])).not.toMatch(/"to":"1\.[12]\.0"/);
    expect(leaf.action).not.toBe("upgrade_parent");
  });

  it("(a) a malware package with no clean release: no target, remove it", async () => {
    ADVISORIES.evil = [adv("MAL-2026-0002", "evil", [{ introduced: "0" }], { summary: "Malicious code in evil (npm)" })];
    NPM.evil = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    project({ evil: "1.0.0" }, {});
    const { step } = await plan();
    const row = step("evil");
    expect(row.targetVersion).toBeNull();
    expect(row.action).toBe("remove_dependency");
    expect(row.reasons.join(" ")).toMatch(/evil is flagged malicious \(MAL-2026-0002\): remove or replace evil/);
    expect(row.upgradeCommands).toBeUndefined();
  });

  it("(b) an advisory whose ranges cannot be read leaves the decision unknown: no release, no command, the reason stated", async () => {
    ADVISORIES.odd = [
      adv("GHSA-odd-0000-0001", "odd", fixedIn("1.1.0"), { severity: "HIGH" }),
      { id: "GHSA-odd-0000-0002", summary: "odd advisory with no ranges", database_specific: { severity: "HIGH" }, affected: [{ package: { name: "odd", ecosystem: "npm" }, ranges: [] }] },
    ];
    NPM.odd = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    project({ odd: "1.0.0" }, {});
    const { step } = await plan();
    const row = step("odd");
    expect(row.targetVersion).toBeNull();
    expect(row.upgradeCommands).toBeUndefined();
    expect(row.reasons.join(" ")).toMatch(/the affected ranges of GHSA-odd-0000-0002 cannot be read, so whether any release clears it is unknown: no release is named/);
  });

  it("(c) a genuinely unfixed advisory may be skipped, and the chosen release says it remains affected", async () => {
    ADVISORIES.gap = [
      adv("GHSA-gap-0000-0001", "gap", fixedIn("1.1.0"), { severity: "HIGH" }),
      adv("GHSA-gap-0000-0002", "gap", [{ introduced: "0" }], { severity: "MODERATE" }),
    ];
    NPM.gap = { latest: "1.2.0", versions: { "1.0.0": {}, "1.1.0": {}, "1.2.0": {} } };
    project({ gap: "1.0.0" }, {});
    const { step } = await plan();
    const row = step("gap");
    expect(row.targetVersion).toBe("1.1.0");
    expect(row.reasons.join(" ")).toMatch(/1\.1\.0 remains affected by GHSA-gap-0000-0002 \(no fix published\)/);
  });

  it("(c) on a parent: the parent release that admits a clean copy says it remains affected by an unfixed advisory of its own", async () => {
    parentProject([adv("GHSA-par-0000-0001", "par", [{ introduced: "0" }], { severity: "LOW" })], { "1.1.0": { dependencies: { leaf: "^1.1.0" } } });
    const { step } = await plan();
    const leaf = step("leaf");
    expect(leaf.parentUpgrades[0]).toMatchObject({ parent: "par", to: "1.1.0" });
    expect(leaf.reasons.join(" ")).toMatch(/, though par 1\.1\.0 remains affected by GHSA-par-0000-0001 \(no fix published\)/);
    expect(leaf.reasons.join(" ")).not.toMatch(/no advisory of par affects it/);
  });
});

// ---------------------------------------------------------------------------
// 8a / 8b (the 4DA H1 review): candidates and "newest" follow the fix-target rules
// ---------------------------------------------------------------------------

describe("8a/8b: parent candidates and newest", () => {
  it("8b: a parent's newest release is the highest one no advisory of it affects, not its latest tag", async () => {
    ADVISORIES.leaf = [adv("GHSA-leaf-0000-0001", "leaf", fixedIn("1.1.0"), { severity: "HIGH" })];
    // par 1.2.0 (the latest) is malware: never "newest", so the newest release to name is 1.1.0.
    ADVISORIES.par = [adv("MAL-2026-0012", "par", [{ introduced: "1.2.0" }], { summary: "Malicious code in par (npm)" })];
    NPM.leaf = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    NPM.par = { latest: "1.2.0", versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } }, "1.1.0": { dependencies: { leaf: "1.0.0" } }, "1.2.0": { dependencies: { leaf: "^1.1.0" } } } };
    project({ par: "1.0.0" }, {}, { par: { version: "1.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } });
    const { step } = await plan();
    const text = step("leaf").reasons.join(" ");
    expect(text).toMatch(/no par release up to 1\.1\.0 both admits a clean leaf/);
    expect(text).not.toMatch(/up to 1\.2\.0/);
  });

  it("8a: a package retired whole (latest deprecated) is the app's Deprecated standing, said, never a release (pr-006)", async () => {
    ADVISORIES.leaf = [adv("GHSA-leaf-0000-0001", "leaf", fixedIn("1.1.0"), { severity: "HIGH" })];
    NPM.leaf = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    NPM.par = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } }, "1.1.0": { deprecated: "retired", dependencies: { leaf: "^1.1.0" } } } };
    project({ par: "1.0.0" }, {}, { par: { version: "1.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } });
    const { step } = await plan();
    const leaf = step("leaf");
    expect(leaf.action).toBe("override_or_replace");
    expect(leaf.parentUpgrades ?? []).toEqual([]);
    expect(leaf.reasons.join(" ")).toContain('par is deprecated ("retired")');
  });
});

// ---------------------------------------------------------------------------
// M3: devDependencies in the lever walk; a workspace member's own declaration
// ---------------------------------------------------------------------------

describe("M3: the root's and every workspace member's devDependencies are declarations", () => {
  it("a dev-only transitive's lever is the declared devDependency (navcal: @vitest/mocker -> vitest)", async () => {
    ADVISORIES.mocker = [adv("GHSA-mock-0000-0001", "mocker", fixedIn("3.2.5"), { severity: "HIGH" })];
    NPM.mocker = { latest: "3.2.5", versions: { "3.2.4": {}, "3.2.5": {} } };
    NPM.vitest = { latest: "3.2.5", versions: { "3.2.4": { dependencies: { mocker: "3.2.4" } }, "3.2.5": { dependencies: { mocker: "3.2.5" } } } };
    project({}, { vitest: "3.2.4" }, { vitest: { version: "3.2.4", dev: true, dependencies: { mocker: "3.2.4" } }, mocker: { version: "3.2.4", dev: true } });
    const { step } = await plan();
    const row = step("mocker");
    expect(row.parentUpgrades[0]).toMatchObject({ parent: "vitest", to: "3.2.5", levers: [{ name: "vitest", to: "3.2.5", commands: [{ dir: ".", command: "npm install vitest@3.2.5 --save-exact" }] }] });
    expect(row.action).toBe("upgrade_parent");
  });

  it("an npm workspace member's devDependency is declared there, and moves in the member's directory", async () => {
    ADVISORIES.minimist = [adv("GHSA-xvch-5gv4-984h", "minimist", fixedIn("1.2.6"), { severity: "CRITICAL" })];
    NPM.minimist = { latest: "1.2.8", versions: { "1.2.5": {}, "1.2.6": {}, "1.2.8": {} } };
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }));
    fs.mkdirSync(path.join(dir, "packages", "a"), { recursive: true });
    fs.writeFileSync(path.join(dir, "packages", "a", "package.json"), JSON.stringify({ name: "a", version: "1.0.0", devDependencies: { minimist: "^1.2.5" } }));
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: "root",
        lockfileVersion: 3,
        packages: {
          "": { name: "root", workspaces: ["packages/*"] },
          "node_modules/a": { resolved: "packages/a", link: true },
          "node_modules/minimist": { version: "1.2.5", dev: true },
          "packages/a": { version: "1.0.0", devDependencies: { minimist: "^1.2.5" } },
        },
      }),
    );
    const { step } = await plan();
    const row = step("minimist");
    expect(row.reasons.join(" ")).not.toMatch(/not declared in your manifest/);
    expect(row.reasons.join(" ")).toMatch(/Declared by workspace member packages\/a\/package\.json \(devDependencies "\^1\.2\.5"\)/);
    // ^1.2.5 admits 1.2.6: the in-range refresh, run in the member's directory (npm 10.9.2 moves a
    // member's own copy there, on lockfiles npm wrote; the 4DA app's rule).
    expect(row).toMatchObject({ action: "upgrade_direct", scope: "direct", upgradeCommands: [{ dir: "packages/a", command: "npm update minimist", refresh: true }] });
  });
});

// ---------------------------------------------------------------------------
// M4 + 7b: one release per dependency, and everything derived from it recomputed
// ---------------------------------------------------------------------------

describe("M4/7b: one release per dependency across every row", () => {
  /** NodeGoat's express-session shape: cookie needs 1.18.1, on-headers 1.18.2, its own row is 1.19.0. */
  function sessionProject() {
    ADVISORIES.cookie = [adv("GHSA-pxg6-pf52-xh8x", "cookie", fixedIn("0.7.0"), { severity: "LOW" })];
    ADVISORIES["on-headers"] = [adv("GHSA-76c9-3jph-rj3q", "on-headers", fixedIn("1.1.0"), { severity: "LOW" })];
    NPM.cookie = { latest: "0.7.2", versions: { "0.3.1": {}, "0.7.0": {}, "0.7.2": {} } };
    NPM["on-headers"] = { latest: "1.1.0", versions: { "1.0.1": {}, "1.0.2": {}, "1.1.0": {} } };
    NPM["express-session"] = {
      latest: "1.19.0",
      versions: {
        "1.15.6": { dependencies: { cookie: "0.3.1", "on-headers": "~1.0.1" } },
        "1.18.1": { dependencies: { cookie: "0.7.2", "on-headers": "~1.0.2" } },
        "1.18.2": { dependencies: { cookie: "0.7.2", "on-headers": "~1.1.0" } },
        "1.19.0": { dependencies: { cookie: "0.7.2", "on-headers": "~1.1.0" } },
      },
    };
    project({ "express-session": "1.15.6" }, {}, {
      "express-session": { version: "1.15.6", dependencies: { cookie: "0.3.1", "on-headers": "~1.0.1" } },
      cookie: { version: "0.3.1" },
      "on-headers": { version: "1.0.1" },
    });
  }

  it("express-session: every row names one release and one command", async () => {
    sessionProject();
    const { step } = await plan();
    const releases = new Set<string>();
    const commands = new Set<string>();
    for (const name of ["cookie", "on-headers"]) {
      for (const u of step(name).parentUpgrades) {
        releases.add(u.to);
        for (const l of u.levers) for (const c of l.commands ?? []) commands.add(c.command);
      }
    }
    const own = step("express-session");
    releases.add(own.targetVersion);
    for (const c of own.upgradeCommands ?? []) commands.add(c.command);
    // The highest release a row NEEDS (on-headers: 1.18.2); its own freshness row follows it, the
    // newest release kept as latestVersion (the app's row_target: a freshness target is not a need).
    expect([...releases]).toEqual(["1.18.2"]);
    expect([...commands]).toEqual(["npm install express-session@1.18.2 --save-exact"]);
    expect(own).toMatchObject({ targetVersion: "1.18.2", latestVersion: "1.19.0" });
    // The cookie row is lifted from 1.18.1 to 1.18.2, with the requirement at 1.18.2.
    expect(step("cookie").parentUpgrades[0]).toMatchObject({ to: "1.18.2", smallest: "1.18.1", requirement: "0.7.2" });
    expect(step("cookie").reasons.join(" ")).not.toMatch(/upgrade express-session to 1\.18\.1/);
  });

  it("7b: a lifted release whose requirement no longer admits the installed copy drops the refresh", async () => {
    ADVISORIES["path-to-regexp"] = [adv("GHSA-rhx6-c78j-4q9w", "path-to-regexp", fixedIn("0.1.13"), { severity: "HIGH" })];
    // qs needs express 4.22.3 (NodeGoat's shape), so path-to-regexp's 4.22.0 is lifted to it.
    ADVISORIES.qs = [adv("GHSA-qs00-0000-0001", "qs", fixedIn("6.16.0"), { severity: "HIGH" })];
    NPM["path-to-regexp"] = { latest: "0.1.13", versions: { "0.1.12": {}, "0.1.13": {} } };
    NPM.qs = { latest: "6.16.0", versions: { "6.5.2": {}, "6.15.1": {}, "6.16.0": {} } };
    const deps = (ptr: string, qs: string) => ({ dependencies: { "path-to-regexp": ptr, qs } });
    NPM.express = { latest: "4.22.3", versions: { "4.21.2": deps("0.1.12", "6.5.2"), "4.22.0": deps("~0.1.12", "~6.15.1"), "4.22.3": deps("~0.1.13", "~6.16.0") } };
    project({ express: "4.21.2" }, {}, { express: { version: "4.21.2", ...deps("0.1.12", "6.5.2") }, "path-to-regexp": { version: "0.1.12" }, qs: { version: "6.5.2" } });
    const { step } = await plan();
    const ptr = step("path-to-regexp");
    expect(ptr.parentUpgrades[0]).toMatchObject({ parent: "express", to: "4.22.3", smallest: "4.22.0", requirement: "~0.1.13" });
    expect(ptr.parentUpgrades[0].refreshCommands).toBeUndefined();
    expect(JSON.stringify(ptr)).not.toMatch(/npm update path-to-regexp/);
  });

  it("7b: no refresh is named while another parent's requirement keeps the copy below the target (micromatch ^3 vs 4.0.8)", async () => {
    ADVISORIES.micromatch = [adv("GHSA-952p-6rrq-rcjv", "micromatch", fixedIn("4.0.8"), { severity: "MODERATE" })];
    NPM.micromatch = { latest: "4.0.8", versions: { "3.1.10": {}, "4.0.8": {} } };
    NPM.anymatch = { latest: "3.0.0", versions: { "2.0.0": { dependencies: { micromatch: "^3.1.4" } }, "3.0.0": {} } };
    NPM.readdirp = { latest: "2.2.1", versions: { "2.2.1": { dependencies: { micromatch: "^3.1.10" } } } };
    project({ anymatch: "2.0.0", readdirp: "2.2.1" }, {}, {
      anymatch: { version: "2.0.0", dependencies: { micromatch: "^3.1.4" } },
      readdirp: { version: "2.2.1", dependencies: { micromatch: "^3.1.10" } },
      micromatch: { version: "3.1.10" },
    });
    const { step } = await plan();
    expect(JSON.stringify(step("micromatch"))).not.toMatch(/npm update micromatch/);
  });
});

// ---------------------------------------------------------------------------
// M5: a declared bump that drops the vulnerable package from the path, before an override
// ---------------------------------------------------------------------------

describe("M5: 'goes away with' before an override or a fork", () => {
  it("the lever's release no longer brings the stuck parent in: the step names it, not an override", async () => {
    ADVISORIES.leaf = [adv("GHSA-leaf-0000-0001", "leaf", fixedIn("2.0.0"), { severity: "HIGH" })];
    NPM.leaf = { latest: "2.0.0", versions: { "1.0.0": {}, "2.0.0": {} } };
    // mid will not move (its only release pins leaf 1.0.0); top 2.0.0 no longer depends on mid.
    NPM.mid = { latest: "1.0.0", versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } } } };
    NPM.top = { latest: "2.0.0", versions: { "1.0.0": { dependencies: { mid: "1.0.0" } }, "2.0.0": { dependencies: {} } } };
    project({ top: "1.0.0" }, {}, { top: { version: "1.0.0", dependencies: { mid: "1.0.0" } }, mid: { version: "1.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } });
    const { step } = await plan();
    const row = step("leaf");
    expect(row.action).toBe("upgrade_parent");
    expect(row.reasons.join(" ")).not.toMatch(/overrides/);
    expect(row.reasons.join(" ")).toMatch(/goes away from that path with top 2\.0\.0: upgrade top to 2\.0\.0/);
    expect(row.parentUpgrades[0]).toMatchObject({ parent: "mid", goesAway: true, levers: [{ name: "top", to: "2.0.0" }] });
  });
});

// ---------------------------------------------------------------------------
// M6: one meaning of include_dev: false
// ---------------------------------------------------------------------------

describe("M6: include_dev: false leaves out exactly the dev-only copies, in every tool", () => {
  it("scan, health and planner count the same population in both modes", async () => {
    ADVISORIES.rt = [adv("GHSA-rt00-0000-0001", "rt", fixedIn("1.1.0"), { severity: "HIGH" })];
    ADVISORIES.devt = [adv("GHSA-devt-0000-0001", "devt", fixedIn("1.1.0"), { severity: "HIGH" })];
    NPM.rt = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    NPM.devt = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    NPM.tool = { latest: "1.0.0", versions: { "1.0.0": { dependencies: { devt: "1.0.0" } } } };
    project({ rt: "1.0.0" }, { tool: "1.0.0" }, { devt: { version: "1.0.0", dev: true } });
    for (const include_dev of [true, false]) {
      const s = await scan({ include_dev });
      const h = await health({ include_dev });
      const { result } = await plan({ include_dev });
      const want = include_dev ? 2 : 1;
      expect(s.total_vulnerable_packages).toBe(want);
      expect(h.vulnerableCount).toBe(want);
      expect(result.summary).toMatch(new RegExp(`Planned over ${want} vulnerable packages?`));
      if (!include_dev) {
        expect(s.dev_scope).toMatch(/2 dev-only copies left out/);
        expect(h.summary).toMatch(/2 dev-only copies left out/);
        expect(result.summary).toMatch(/2 dev-only copies left out/);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// L: 7a, 7d, 7e, 7f, 7g, and the severity rank
// ---------------------------------------------------------------------------

describe("L: the smaller findings", () => {
  it("7a: OSV /v1/query and the registry both down: the target says the withdrawal check did not run", async () => {
    QUERY_DOWN = true;
    REGISTRY_DOWN = true;
    ADVISORIES.lodash = [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.18.0"), { severity: "HIGH" })];
    project({ lodash: "4.17.20" }, {});
    const { step } = await plan();
    expect(step("lodash").reasons.join(" ")).toMatch(/the registry could not be read, so whether it yanked or deprecated this release was not checked/);
    const s = await scan({ response_format: "detailed" });
    expect(JSON.stringify(s.fix_targets)).toMatch(/whether it yanked or deprecated this release was not checked/);
  });

  it("7d: a requirement that does not admit the target is not said to admit it", async () => {
    ADVISORIES.leaf = [adv("GHSA-leaf-0000-0001", "leaf", fixedIn("2.68.0"), { severity: "HIGH" })];
    NPM.leaf = { latest: "2.75.0", versions: { "2.67.0": {}, "2.68.0": {}, "2.75.0": {} } };
    NPM.par = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { leaf: "2.67.0" } }, "1.1.0": { dependencies: { leaf: "~2.75" } } } };
    project({ par: "1.0.0" }, {}, { par: { version: "1.0.0", dependencies: { leaf: "2.67.0" } }, leaf: { version: "2.67.0" } });
    const { step } = await plan();
    const text = step("leaf").reasons.join(" ");
    expect(text).not.toMatch(/"~2\.75" admits leaf 2\.68\.0/);
    expect(text).toMatch(/"~2\.75" resolves leaf to 2\.75\.0/);
  });

  it("7e: Go versions keep their v in every target field", async () => {
    const { inEcosystemForm } = await import("../live/version-compare.js");
    expect(inEcosystemForm("Go", "0.60.0")).toBe("v0.60.0");
    expect(inEcosystemForm("Go", "v0.60.0")).toBe("v0.60.0");
    expect(inEcosystemForm("npm", "0.60.0")).toBe("0.60.0");
    const { formatScanResult } = await import("../tools/vulnerability-scan-format.js");
    const entry = {
      package: "golang.org/x/net", currentVersion: "v0.20.0", ecosystem: "Go" as const, isDev: false, isDirect: true, devScopeKnown: true,
      vulnId: "GO-2024-3333", aliases: [], severity: "high" as const, cvssScore: null, summary: "x", fixedVersion: "0.33.0", published: "", references: [],
      target: null, platformActive: true, sourceDirs: [dir],
    };
    const result = {
      scannedAt: "", projectPath: dir, ecosystemsScanned: ["Go"], totalScanned: 1, totalVulnerable: 1, platformInactiveVulnerable: 0,
      bySeverity: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 }, vulnerabilities: [entry], cleanCount: 0, scanDurationMs: 0, cached: false, offline: false,
    };
    const out = formatScanResult(result as never, undefined, { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true }) as Record<string, any>;
    expect(out.vulnerabilities[0].fixed_version).toBe("v0.33.0");
    expect(out.fix_targets["golang.org/x/net@v0.20.0"].target).toBe("v0.33.0");
    expect(out.recommendations[0]).toMatch(/→ v0\.33\.0/);
  });

  it("7f: a target with a whole-line deprecation notice stays the target, and says it is deprecated", async () => {
    ADVISORIES.glob = [adv("GHSA-5j98-mcp5-4vw2", "glob", [{ introduced: "10.2.0" }, { fixed: "10.5.0" }], { severity: "HIGH" })];
    const notice = "Old versions of glob are not supported";
    NPM.glob = { latest: "12.0.0", versions: { "10.4.5": { deprecated: notice }, "10.5.0": { deprecated: notice }, "12.0.0": {} } };
    project({ glob: "10.4.5" }, {});
    const { step } = await plan();
    const row = step("glob");
    expect(row.targetVersion).toBe("10.5.0");
    expect(row.reasons.join(" ")).toMatch(/10\.5\.0 is deprecated on npm \("Old versions of glob are not supported"\), a notice on its whole line rather than a withdrawn release/);
  });

  it("7g: a pin in a requirements file included with -r is declared", async () => {
    fs.mkdirSync(path.join(dir, "sub"), { recursive: true });
    fs.writeFileSync(path.join(dir, "requirements.txt"), "requests==2.19.0\n-r sub/inner.txt\n");
    fs.writeFileSync(path.join(dir, "sub", "inner.txt"), "jinja2==2.10\n");
    const { scanCurrentProject } = await import("../project-scanner.js");
    const scanned = scanCurrentProject(dir);
    expect(scanned.dependencies).toEqual(expect.arrayContaining(["requests", "jinja2"]));
    const { directFix } = await import("../live/fix-paths.js");
    expect(directFix(dir, "PyPI", "jinja2", "2.10", "2.11.3")).toEqual({ instruction: "change `jinja2==2.10` to `jinja2==2.11.3` in sub/inner.txt" });
  });

  it("severity parity: a dev-only medium ranks low in the plan, as the scan presents it", async () => {
    ADVISORIES.devmed = [adv("GHSA-devm-0000-0001", "devmed", fixedIn("1.1.0"), { severity: "MODERATE" })];
    NPM.devmed = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    project({}, { devmed: "1.0.0" });
    const { step } = await plan();
    expect(step("devmed").risk).toBe("low");
  });
});

// ---------------------------------------------------------------------------
// A declaration that already admits the target: the in-range refresh (4DA fix/c2-direct-refresh)
// ---------------------------------------------------------------------------

describe("directFix: a declaration that admits the target is refreshed in range, the manifest untouched", () => {
  async function fixIn(files: Record<string, string>, eco: string, name: string, installed: string, target: string, sub = "") {
    for (const [f, body] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      fs.writeFileSync(path.join(dir, f), body);
    }
    const { directFix } = await import("../live/fix-paths.js");
    return directFix(path.join(dir, sub), eco, name, installed, target);
  }
  const pkg = JSON.stringify({ name: "t", dependencies: { ms: "^2.1.1" } });

  it("npm, pnpm, yarn 1, yarn berry and Cargo name the verified refresh", async () => {
    expect(await fixIn({ "package.json": pkg, "package-lock.json": "{}" }, "npm", "ms", "2.1.1", "2.1.3")).toEqual({ command: "npm update ms", refresh: true });
    fs.rmSync(path.join(dir, "package-lock.json"));
    expect(await fixIn({ "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" }, "npm", "ms", "2.1.1", "2.1.3")).toEqual({ command: "pnpm update ms --no-save", refresh: true });
    fs.rmSync(path.join(dir, "pnpm-lock.yaml"));
    expect(await fixIn({ "yarn.lock": "# yarn lockfile v1\n" }, "npm", "ms", "2.1.1", "2.1.3")).toEqual({ command: "yarn upgrade ms", refresh: true });
    fs.writeFileSync(path.join(dir, "yarn.lock"), "__metadata:\n  version: 8\n");
    expect(await fixIn({}, "npm", "ms", "2.1.1", "2.1.3")).toEqual({ command: "yarn up -R ms", refresh: true });
    expect(await fixIn({ "Cargo.toml": '[dependencies]\nitoa = "1.0.5"\n' }, "crates.io", "itoa", "1.0.5", "1.0.11")).toEqual({ command: "cargo update -p itoa@1.0.5 --precise 1.0.11", refresh: true });
  });

  it("a range that excludes the target keeps the bump; >= and || are refreshed", async () => {
    expect(await fixIn({ "package.json": pkg, "package-lock.json": "{}" }, "npm", "ms", "2.1.1", "3.0.0")).toEqual({ command: 'npm install "ms@^3.0.0"' });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { ms: ">=2.0.0" } }));
    expect(await fixIn({}, "npm", "ms", "2.1.1", "2.1.3")).toEqual({ command: "npm update ms", refresh: true });
  });

  it("an npm workspace member is refreshed in its own directory; a workspace-inherited crate is never refreshed", async () => {
    const files = { "package.json": JSON.stringify({ name: "root", workspaces: ["packages/*"] }), "package-lock.json": "{}", "packages/a/package.json": pkg };
    expect(await fixIn(files, "npm", "ms", "2.1.1", "2.1.3", "packages/a")).toEqual({ command: "npm update ms", refresh: true });
    const crate = await fixIn({ "Cargo.toml": "[dependencies]\ntokio.workspace = true\n" }, "crates.io", "tokio", "1.38.0", "1.38.2");
    expect(crate && "instruction" in crate).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The 4DA lead's three decisions (2026-10-18)
// ---------------------------------------------------------------------------

describe("decision 1: one malware predicate (MAL- id or alias, or CWE-506)", () => {
  it("the real crossenv record is malware by CWE-506, and summary wording alone is not", async () => {
    const { isMalware, cweIdsOf } = await import("../live/malware.js");
    expect(cweIdsOf(CROSSENV)).toEqual(["CWE-506"]);
    expect(isMalware(CROSSENV.id, CROSSENV.aliases, cweIdsOf(CROSSENV))).toBe(true);
    expect(isMalware("GHSA-xxxx-0000-0001", ["MAL-2026-1"])).toBe(true);
    expect(isMalware("MAL-2026-2307")).toBe(true);
    expect(isMalware("GHSA-xxxx-0000-0002", ["CVE-2026-1"], [])).toBe(false);
    const { advisoryRanges } = await import("../live/osv-ranges.js");
    expect(advisoryRanges(CROSSENV, "crossenv", "npm")?.malware).toBe(true);
    const wording = adv("GHSA-word-0000-0001", "w", fixedIn("1.1.0"), { summary: "a malicious regex can hang the parser" });
    expect(advisoryRanges(wording, "w", "npm")?.malware).toBeUndefined();
  });

  it("GitHub's title template counts: the real GHSA-28f8-hqmc-7ph8 (no MAL- id, no CWE) is malware", async () => {
    // api.osv.dev/v1/vulns/GHSA-28f8-hqmc-7ph8, read 2026-10-18: "Malicious Package in ember-power-timepicker",
    // reviewed CRITICAL, aliases absent, cwe_ids [].
    const ember = JSON.parse(fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, "$1")), "fixtures", "osv", "GHSA-28f8-hqmc-7ph8.json"), "utf8")) as OsvVulnerability;
    const { isMalware, cweIdsOf } = await import("../live/malware.js");
    expect(cweIdsOf(ember)).toEqual([]);
    expect(isMalware(ember.id, ember.aliases ?? [], cweIdsOf(ember), ember.summary)).toBe(true);
    const { advisoryRanges } = await import("../live/osv-ranges.js");
    expect(advisoryRanges(ember, "ember-power-timepicker", "npm")?.malware).toBe(true);
    expect(isMalware("GHSA-x", [], [], "malicious code in lodash")).toBe(true);
  });

  it("a summary that only mentions malicious mid-sentence is not malware", async () => {
    const { isMalware } = await import("../live/malware.js");
    expect(isMalware("GHSA-y", [], [], "Prototype pollution lets a malicious payload overwrite Object")).toBe(false);
    expect(isMalware("GHSA-y", [], [], "A Malicious Package in the registry could be installed")).toBe(false);
    expect(isMalware("GHSA-y", [], [], "crossenv is malware")).toBe(false);
  });

  it("an installed malicious copy is critical in the scan, and its row names no release", async () => {
    ADVISORIES.evilpkg = [adv("GHSA-evil-0000-0001", "evilpkg", [{ introduced: "0" }], { severity: "LOW", aliases: ["MAL-2026-0100"] })];
    NPM.evilpkg = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    project({ evilpkg: "1.0.0" }, {});
    const s = await scan({ response_format: "detailed" });
    expect(s.vulnerabilities[0]).toMatchObject({ advisory_severity: "critical" });
    const { step } = await plan();
    expect(step("evilpkg")).toMatchObject({ targetVersion: null, action: "remove_dependency", risk: "critical" });
    expect(step("evilpkg").reasons.join(" ")).toContain("evilpkg is flagged malicious (GHSA-evil-0000-0001): remove or replace evilpkg");
  });
});

describe("decision 2: no release that brings in an advisory the installed version does not have", () => {
  it("a fix target: every fixing release brings in an unfixed advisory: no target, and why", async () => {
    ADVISORIES.intro = [
      adv("GHSA-intr-0000-0001", "intro", fixedIn("2.0.0"), { severity: "HIGH" }),
      adv("GHSA-intr-0000-0002", "intro", [{ introduced: "2.0.0" }], { severity: "MODERATE" }),
    ];
    NPM.intro = { latest: "2.1.0", versions: { "1.0.0": {}, "2.0.0": {}, "2.1.0": {} } };
    project({ intro: "1.0.0" }, {});
    const { step } = await plan();
    expect(step("intro").targetVersion).toBeNull();
    expect(step("intro").upgradeCommands).toBeUndefined();
    expect(step("intro").reasons.join(" ")).toContain("every fixing release brings in GHSA-intr-0000-0002");
  });

  it("an unfixed advisory the installed version already has is still skipped, and named", async () => {
    ADVISORIES.keep = [
      adv("GHSA-keep-0000-0001", "keep", fixedIn("1.1.0"), { severity: "HIGH" }),
      adv("GHSA-keep-0000-0002", "keep", [{ introduced: "0" }], { severity: "MODERATE" }),
    ];
    NPM.keep = { latest: "1.2.0", versions: { "1.0.0": {}, "1.1.0": {}, "1.2.0": {} } };
    project({ keep: "1.0.0" }, {});
    const { step } = await plan();
    expect(step("keep").targetVersion).toBe("1.1.0");
    expect(step("keep").reasons.join(" ")).toMatch(/1\.1\.0 remains affected by GHSA-keep-0000-0002 \(no fix published\)/);
  });

  it("a parent release that brings in an advisory of the parent's own is never named", async () => {
    ADVISORIES.leaf = [adv("GHSA-leaf-0000-0001", "leaf", fixedIn("1.1.0"), { severity: "HIGH" })];
    // par 1.1.0 and later carry an advisory par 1.0.0 does not have, with no fix.
    ADVISORIES.par = [adv("GHSA-par-0000-0010", "par", [{ introduced: "1.1.0" }], { severity: "MODERATE" })];
    NPM.leaf = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    NPM.par = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } }, "1.1.0": { dependencies: { leaf: "^1.1.0" } } } };
    project({ par: "1.0.0" }, {}, { par: { version: "1.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } });
    const { step } = await plan();
    expect(JSON.stringify(step("leaf").parentUpgrades ?? [])).not.toContain('"to":"1.1.0"');
  });
});

describe("decision 3: a row's only fix across a major raises the row, flagged, with the reason", () => {
  it("the parent's own row is raised to the major release, breaking, and says why", async () => {
    ADVISORIES.child = [adv("GHSA-chld-0000-0001", "child", fixedIn("2.0.0"), { severity: "HIGH" })];
    ADVISORIES.par = [adv("GHSA-par0-0000-0001", "par", fixedIn("1.0.1"), { severity: "HIGH" })];
    NPM.child = { latest: "2.0.0", versions: { "1.0.0": {}, "2.0.0": {} } };
    NPM.par = { latest: "2.0.0", versions: { "1.0.0": { dependencies: { child: "^1.0.0" } }, "1.0.1": { dependencies: { child: "^1.0.0" } }, "2.0.0": { dependencies: { child: "^2.0.0" } } } };
    project({ par: "1.0.0" }, {}, { par: { version: "1.0.0", dependencies: { child: "^1.0.0" } }, child: { version: "1.0.0" } });
    const { step } = await plan();
    expect(step("par")).toMatchObject({ targetVersion: "2.0.0", breaking: true });
    expect(step("par").reasons).toContain("the only release of par that fixes child is 2.0.0, a major upgrade");
  });
});

describe("the malware predicate matches fourda_depengine::is_malware exactly (4DA #992, b18f364f5)", () => {
  const fixture = (id: string) =>
    JSON.parse(fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, "$1")), "fixtures", "osv", `${id}.json`), "utf8")) as OsvVulnerability;

  it("the pinned malware cases", async () => {
    const { isMalware, cweIdsOf } = await import("../live/malware.js");
    for (const id of ["GHSA-c2m4-w5hm-vqjw", "GHSA-28f8-hqmc-7ph8"]) {
      const r = fixture(id);
      expect(isMalware(r.id, r.aliases ?? [], cweIdsOf(r), r.summary ?? ""), id).toBe(true);
    }
    // Trimmed, case-insensitive ids and CWEs; the summary trimStart-ed before the anchored match.
    expect(isMalware(" mal-2026-1 ")).toBe(true);
    expect(isMalware("GHSA-x", [" Mal-2026-2"])).toBe(true);
    expect(isMalware("GHSA-x", [], [" cwe-506 "])).toBe(true);
    expect(isMalware("GHSA-x", [], [], "   Malicious Package in bar")).toBe(true);
    expect(isMalware("GHSA-x", [], [], "MALICIOUS CODE IN baz")).toBe(true);
  });

  it("the pinned not-malware cases", async () => {
    const { isMalware } = await import("../live/malware.js");
    for (const summary of [
      "Malicious-looking prose",
      "Malicious packages can exploit foo",
      "Malicious input in bar causes a crash",
      "foo: Malicious Package in bar",
      "Malicious Packagein baz",
      "Prototype pollution allows malicious code in qux",
    ]) {
      expect(isMalware("GHSA-x", [], [], summary), summary).toBe(false);
    }
    expect(isMalware("GHSA-x", ["MALWARE-NOTE"])).toBe(false);
    expect(isMalware("GHSA-x", [], ["CWE-5060"])).toBe(false);
  });
});

// pr-010 (4DA #994, parity decision 2): a parent move never brings in an advisory the installed
// parent lacks. The only admitting par release carries GHSA-synt-0000-0002, which par 1.0.0 does
// not have: the row names no release (outcome "introduces"). When the installed par has it too
// (no fix published), it is skipped as unfixed and par 1.1.0 is named.
describe("pr-010: a parent move never introduces an advisory", () => {
  const line = (parentAdvisoryRanges: Array<Record<string, string>>, expectRow: Record<string, unknown>, parentTarget: string | null) => ({
    id: "pr-010-local",
    eco: "npm",
    tool: "npm",
    parent: {
      name: "par", installed: "1.0.0", declared: "1.0.0", lever: "direct", latest: "1.1.0", deprecated: false,
      releases: ["1.0.0", "1.1.0"], advisories: [{ id: "GHSA-synt-0000-0002", ranges: parentAdvisoryRanges }], own_target: parentTarget,
    },
    rows: [{
      pkg: "leaf", installed: "1.0.0", target: "1.1.0", releases: ["1.0.0", "1.1.0"],
      advisories: [{ id: "GHSA-synt-0000-0001", ranges: [{ introduced: "0", fixed: "1.1.0" }] }],
      requires: { "1.0.0": "1.0.0", "1.1.0": "^1.1.0" },
    }],
    expect: { parent_target: parentTarget, rows: [expectRow] },
  });
  const none = { requirement: null, peer: false, resolves_to: null, command: null, refresh: null };

  it("names no release when every admitting release brings in a new advisory", async () => {
    const v = line([{ introduced: "1.1.0" }], { pkg: "leaf", outcome: "introduces", smallest: null, to: null, breaking: false, ...none }, null);
    expect(await checkParentRelease(v)).toBeNull();
  });

  it("still names the release when the installed parent already has that unfixed advisory", async () => {
    const v = line([{ introduced: "0" }], { pkg: "leaf", outcome: "introduces", smallest: null, to: null, breaking: false, ...none }, null);
    // The contrast: this expectation must NOT hold, the advisory is unfixed and already installed.
    expect(await checkParentRelease(v)).toMatch(/"outcome":"release"/);
  });
});

// The same rule for a lever (the parent arrives through a declared dependency): lev 1.1.0 is the
// only lev release that brings in a par that admits a clean leaf, and it carries an advisory the
// installed lev 1.0.0 does not have, so no release is named.
describe("pr-010 for a lever: a lever move never introduces an advisory", () => {
  const graph = (levRanges: Array<Record<string, string>>, release: unknown) => ({
    id: "lever-introduces", eco: "npm", mode: "graph",
    nodes: [["lev", "1.0.0", true], ["par", "1.0.0", false], ["leaf", "1.0.0", false]],
    edges: [["lev", "1.0.0", "par", "1.0.0"], ["par", "1.0.0", "leaf", "1.0.0"]],
    advisories: [
      { id: "GHSA-synt-0000-0001", package: "leaf", ranges: [{ introduced: "0", fixed: "1.1.0" }] },
      { id: "GHSA-synt-0000-0003", package: "lev", ranges: levRanges },
    ],
    registry: {
      lev: { "dist-tags": { latest: "1.1.0" }, versions: { "1.0.0": { dependencies: { par: "1.0.0" } }, "1.1.0": { dependencies: { par: "^1.1.0" } } } },
      par: { "dist-tags": { latest: "1.1.0" }, versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } }, "1.1.0": { dependencies: { leaf: "^1.1.0" } } } },
      leaf: { "dist-tags": { latest: "1.1.0" }, versions: { "1.0.0": {}, "1.1.0": {} } },
    },
    expect: { rows: [], copies: [{ pkg: "leaf", installed: "1.0.0", target: "1.1.0", links: [{ parent: "par", release, levers: [], lever_unknown: false }] }] },
  });

  it("names no lever release when it brings in a new advisory", async () => {
    expect(await checkParentRelease(graph([{ introduced: "1.1.0" }], "introduces"))).toBeNull();
  });

  it("names the lever release when the installed lever already has that unfixed advisory", async () => {
    expect(await checkParentRelease(graph([{ introduced: "0" }], "introduces"))).toMatch(/"release":\{"to":"1\.1\.0"/);
  });
});

// The #994 review: "every fixing release brings in <ids>" names the UNION, sorted, of the
// advisories the installed version lacks over EVERY candidate blocked that way, not only the
// smallest one's. Two blocked candidates: 1.1.0 carries GHSA-synt-0000-0005 (fixed in 1.2.0),
// 1.2.0 carries GHSA-synt-0000-0004 (no fix). The installed 1.0.0 has neither.
describe("introduces names the union over every blocked candidate (#994 review)", () => {
  const span = (introduced: string, fixed: string | null = null) => ({ introduced, fixed, lastAffected: null });
  const both = "every fixing release brings in GHSA-synt-0000-0004, GHSA-synt-0000-0005, which the installed version does not have";

  it("fix-target walk: the copy's own target", () => {
    const clean = smallestCleanVersion({
      ecosystem: "npm",
      fixes: ["1.1.0"],
      advisories: [
        { id: "GHSA-synt-0000-0001", spans: [span("0", "1.1.0")], versions: [] },
        { id: "GHSA-synt-0000-0005", spans: [span("1.1.0", "1.2.0")], versions: [] },
        { id: "GHSA-synt-0000-0004", spans: [span("1.2.0")], versions: [] },
      ],
      published: ["1.0.0", "1.1.0", "1.2.0"],
      installed: "1.0.0",
    });
    expect(clean?.target).toBeNull();
    expect(clean?.introduces).toEqual(["GHSA-synt-0000-0004", "GHSA-synt-0000-0005"]);
    expect(introducesText(clean!.introduces!)).toContain(both);
  });

  const parentAdvisories = [
    { id: "GHSA-synt-0000-0005", ranges: [{ introduced: "1.1.0", fixed: "1.2.0" }] },
    { id: "GHSA-synt-0000-0004", ranges: [{ introduced: "1.2.0" }] },
  ];

  it("parent: both blocked admitting releases' advisories are named", async () => {
    const v = {
      id: "introduces-union", eco: "npm", tool: "npm",
      parent: { name: "par", installed: "1.0.0", declared: "1.0.0", lever: "direct", latest: "1.2.0", deprecated: false, releases: ["1.0.0", "1.1.0", "1.2.0"], advisories: parentAdvisories, own_target: null },
      rows: [{
        pkg: "leaf", installed: "1.0.0", target: "1.1.0", releases: ["1.0.0", "1.1.0"],
        advisories: [{ id: "GHSA-synt-0000-0001", ranges: [{ introduced: "0", fixed: "1.1.0" }] }],
        requires: { "1.0.0": "1.0.0", "1.1.0": "^1.1.0", "1.2.0": "^1.1.0" },
      }],
      expect: { parent_target: null, rows: [{ pkg: "leaf", outcome: "introduces", smallest: null, to: null, breaking: false, requirement: null, peer: false, resolves_to: null, command: null, refresh: null }] },
    };
    expect(await checkParentRelease(v)).toBeNull();
    const result = await planParentReleaseLine(v);
    const leaf = (result.recommendations as Array<Record<string, unknown>>).find((r) => r.package === "leaf");
    expect(JSON.stringify(leaf)).toContain(both);
  });

  it("lever: both blocked lever releases' advisories are named", async () => {
    const v = {
      id: "introduces-union-lever", eco: "npm", mode: "graph",
      nodes: [["lev", "1.0.0", true], ["par", "1.0.0", false], ["leaf", "1.0.0", false]],
      edges: [["lev", "1.0.0", "par", "1.0.0"], ["par", "1.0.0", "leaf", "1.0.0"]],
      advisories: [
        { id: "GHSA-synt-0000-0001", package: "leaf", ranges: [{ introduced: "0", fixed: "1.1.0" }] },
        ...parentAdvisories.map((a) => ({ ...a, package: "lev" })),
      ],
      registry: {
        lev: { "dist-tags": { latest: "1.2.0" }, versions: { "1.0.0": { dependencies: { par: "1.0.0" } }, "1.1.0": { dependencies: { par: "^1.1.0" } }, "1.2.0": { dependencies: { par: "^1.1.0" } } } },
        par: { "dist-tags": { latest: "1.1.0" }, versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } }, "1.1.0": { dependencies: { leaf: "^1.1.0" } } } },
        leaf: { "dist-tags": { latest: "1.1.0" }, versions: { "1.0.0": {}, "1.1.0": {} } },
      },
      expect: { rows: [], copies: [{ pkg: "leaf", installed: "1.0.0", target: "1.1.0", links: [{ parent: "par", release: "introduces", levers: [], lever_unknown: false }] }] },
    };
    expect(await checkParentRelease(v)).toBeNull();
    const result = await planParentReleaseLine(v);
    const leaf = (result.recommendations as Array<Record<string, unknown>>).find((r) => r.package === "leaf");
    expect(JSON.stringify(leaf)).toContain(both);
  });
});
