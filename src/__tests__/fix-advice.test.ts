// SPDX-License-Identifier: Apache-2.0
/**
 * Fix advice an agent can act on (audit 2026-10-12):
 * - B-8: a deprecated release is never the fix target (lodash 4.18.0, "Bad
 *   release", was recommended by vulnerability_scan);
 * - A6: an advisory that gives only `last_affected` gets the first clean
 *   release above it as a candidate, not "no fix";
 * - A4: a transitive blocked by a parent that is deprecated or already at its
 *   latest release gets override/replace advice, not "waiting on upstream";
 * - A5: npm `-security` placeholders are not installed malware;
 * - A8: direct devDependencies are scanned by default, labelled dev;
 * - A9: alias records of one vulnerability count once in dependency_check.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import type { OsvVulnerability, VulnerabilityEntry } from "../live/types.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { refs } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

const range = (events: Array<Record<string, string>>) => [{ type: "SEMVER", events }];
const adv = (id: string, name: string, events: Array<Record<string, string>>): OsvVulnerability => ({
  id,
  summary: `${name} advisory`,
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name, ecosystem: "npm" }, ranges: range(events) }],
});

const ADVISORIES: Record<string, OsvVulnerability[]> = {
  lodash: [adv("GHSA-lodash-a", "lodash", [{ introduced: "0" }, { fixed: "4.18.0" }])],
  "only-last": [adv("GHSA-last-1", "only-last", [{ introduced: "0" }, { last_affected: "1.0.0" }])],
  minimist: [adv("GHSA-minimist", "minimist", [{ introduced: "0" }, { fixed: "1.2.6" }])],
  fs: [{ id: "MAL-2023-0001", summary: "Malicious code in fs", affected: [{ package: { name: "fs", ecosystem: "npm" }, ranges: range([{ introduced: "0" }]) }] }],
  jest: [adv("GHSA-jest", "jest", [{ introduced: "0" }, { fixed: "30.0.0" }])],
  // GHSA-c2m4-w5hm-vqjw, "crossenv is malware": introduced 0, last_affected 1.0.1.
  crossenv: [adv("GHSA-c2m4-w5hm-vqjw", "crossenv", [{ introduced: "0" }, { last_affected: "1.0.1" }])],
  // A publisher's own `-security` prerelease is code, not npm's placeholder.
  "own-sec": [adv("GHSA-own-sec", "own-sec", [{ introduced: "0" }, { fixed: "1.0.1" }])],
};

/** npm abbreviated documents: versions (with a deprecation message where set) and the latest tag. */
let NPM: Record<string, { versions: Record<string, { deprecated?: string; dependencies?: Record<string, string> }>; latest: string }> = {};

function affects(v: OsvVulnerability, version: string): boolean {
  const ev = v.affected![0].ranges[0].events;
  const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
  const fixed = ev.find((e) => e.fixed)?.fixed;
  const last = ev.find((e) => e.last_affected)?.last_affected;
  if (fixed) return cmp(version, fixed) < 0;
  if (last) return cmp(version, last) <= 0;
  return true;
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
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: ADVISORIES[q.package.name] ?? [] });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      const doc = NPM[decodeURIComponent(npm[1])];
      if (!doc) return json({}, 404);
      if (npm[2]) return json({ dependencies: doc.versions[decodeURIComponent(npm[2])]?.dependencies ?? {} });
      return json({ name: npm[1], "dist-tags": { latest: doc.latest }, versions: doc.versions });
    }
    return json({}, 404);
  });
}

let dir: string;
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-fixadvice-"));
  NPM = {};
  stubNetwork();
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

function project(deps: Record<string, string>, devDeps: Record<string, string> = {}, extra: Record<string, { version: string; dev?: boolean; dependencies?: Record<string, string> }> = {}) {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: deps, devDependencies: devDeps }));
  const packages: Record<string, unknown> = { "": { name: "x", dependencies: deps, devDependencies: devDeps } };
  for (const [n, v] of Object.entries(deps)) packages[`node_modules/${n}`] = { version: v };
  for (const [n, v] of Object.entries(devDeps)) packages[`node_modules/${n}`] = { version: v, dev: true };
  for (const [n, e] of Object.entries(extra)) packages[`node_modules/${n}`] = e;
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
}

const scan = async (params: Record<string, unknown> = {}) =>
  (await executeVulnerabilityScan(null, { project_path: dir, ...params }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;

describe("fix targets", () => {
  it("B-8: never a deprecated release (lodash 4.18.0 'Bad release' -> 4.18.1)", async () => {
    NPM.lodash = { latest: "4.18.1", versions: { "4.17.15": {}, "4.17.21": {}, "4.18.0": { deprecated: "Bad release. Please use lodash@4.17.21 instead." }, "4.18.1": {} } };
    project({ lodash: "4.17.15" });
    const result = await scan();
    expect(result.vulnerable_packages[0]).toMatchObject({ package: "lodash", fixed_version: "4.18.1", fix_checked: "all_advisories" });
    // FX-H5: the withdrawn release is named in the registry's words.
    expect(result.recommendations[0]).toMatch(/Upgrade lodash 4\.17\.15 → 4\.18\.1 .*4\.18\.0 is deprecated on npm \("Bad release\. Please use lodash@4\.17\.21 instead\."\); 4\.18\.1 is the smallest clean release/);
    expect(result.vulnerable_packages[0]).toMatchObject({ withheld: ["4.18.0"] });
  });

  it("A6: an advisory with only last_affected gets the first clean release above it", async () => {
    NPM["only-last"] = { latest: "1.0.1", versions: { "0.9.0": {}, "1.0.0": {}, "1.0.1": {} } };
    project({ "only-last": "0.9.0" });
    const result = await scan();
    expect(result.vulnerable_packages[0]).toMatchObject({ package: "only-last", fixed_version: "1.0.1", fix_checked: "all_advisories" });
    expect(result.recommendations[0]).toMatch(/Upgrade only-last 0\.9\.0 → 1\.0\.1 .*no advisory names a fixed version/);
  });

  it("A5: an npm -security placeholder is not reported as malware", async () => {
    project({}, {}, { fs: { version: "0.0.1-security" } });
    const result = await scan();
    expect(result.total_vulnerable_packages).toBe(0);
  });

  it("L4: the placeholder holds under ANY advisory id, not only MAL- (crossenv 0.0.2-security, GHSA-c2m4)", async () => {
    project({}, {}, { crossenv: { version: "0.0.2-security" } });
    expect((await scan()).total_vulnerable_packages).toBe(0);
    project({}, {}, { crossenv: { version: "1.0.1" } });
    expect((await scan()).total_vulnerable_packages).toBe(1);
  });

  it("L4: only npm's 0.0.<n>-security shape is a placeholder; a publisher's 1.0.0-security stays affected", async () => {
    project({}, {}, { "own-sec": { version: "1.0.0-security" } });
    expect((await scan()).total_vulnerable_packages).toBe(1);
  });

  it("A8: direct devDependencies are scanned by default and labelled dev; include_dev: false leaves them out", async () => {
    NPM.jest = { latest: "30.0.0", versions: { "29.0.0": {}, "30.0.0": {} } };
    project({}, { jest: "29.0.0" });
    const byDefault = await scan();
    expect(byDefault.vulnerable_packages[0]).toMatchObject({ package: "jest", is_dev: true });
    const runtimeOnly = await scan({ include_dev: false });
    expect(runtimeOnly.total_vulnerable_packages).toBe(0);
  });
});

describe("A4: a parent that will not move", () => {
  function pinnedParent(parentDoc: (typeof NPM)[string]) {
    NPM.minimist = { latest: "1.2.8", versions: { "1.2.5": {}, "1.2.6": {}, "1.2.8": {} } };
    NPM["left-pad"] = parentDoc;
    project({ "left-pad": "1.0.0" }, {}, { minimist: { version: "1.2.5" }, "left-pad": { version: "1.0.0", dependencies: { minimist: "1.2.5" } } });
  }

  async function minimistStep() {
    const li = new LiveIntelligence(new Database(":memory:"));
    const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
    const { entries, discovery } = scanProjectTree(dir);
    li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    const plan = (await executeUpgradePlanner(noDb, { project_path: dir, include_dev: true }, li)) as Record<string, any>;
    return { plan, step: plan.recommendations.find((s: { package: string }) => s.package === "minimist") };
  }

  it("already at its latest release: override the transitive, with the npm syntax", async () => {
    pinnedParent({ latest: "1.0.0", versions: { "1.0.0": { dependencies: { minimist: "1.2.5" } } } });
    const { plan, step } = await minimistStep();
    expect(step.action).toBe("override_or_replace");
    expect(step.reasons.join(" ")).toMatch(/left-pad 1\.0\.0 is already its latest release/);
    expect(step.reasons.join(" ")).toMatch(/"overrides": \{ "minimist": "1\.2\.6" \}/);
    expect(plan.summary).toMatch(/override the version or replace the parent/);
  });

  it("deprecated: says so", async () => {
    // Retired as a whole (latest deprecated): the app's Standing::Deprecated (parent_release pr-006).
    pinnedParent({ latest: "1.3.0", versions: { "1.0.0": { dependencies: { minimist: "1.2.5" } }, "1.3.0": { deprecated: "use String.prototype.padStart()" } } });
    const { step } = await minimistStep();
    expect(step.action).toBe("override_or_replace");
    expect(step.reasons.join(" ")).toMatch(/left-pad is deprecated/);
  });

  it("deprecated, and no release admits a clean version: override, and says it is deprecated", async () => {
    pinnedParent({ latest: "1.3.0", versions: { "1.0.0": { dependencies: { minimist: "1.2.5" } }, "1.3.0": { deprecated: "use String.prototype.padStart()", dependencies: { minimist: "1.2.5" } } } });
    const { step } = await minimistStep();
    expect(step.action).toBe("override_or_replace");
    expect(step.reasons.join(" ")).toMatch(/left-pad is deprecated/);
  });

  // Readiness audit H1 (2026-10-16): a newer parent release is a move, not "waiting on upstream".
  it("a parent with a newer release that drops the dependency: upgrade the parent", async () => {
    pinnedParent({ latest: "1.1.0", versions: { "1.0.0": { dependencies: { minimist: "1.2.5" } }, "1.1.0": {} } });
    const { step } = await minimistStep();
    expect(step.action).toBe("upgrade_parent");
    expect(step.parentUpgrades).toMatchObject([{ parent: "left-pad", from: "1.0.0", to: "1.1.0", requirement: null }]);
    expect(step.reasons.join(" ")).toMatch(/left-pad 1\.1\.0 is the smallest left-pad release that no longer depends on minimist: upgrade left-pad to 1\.1\.0/);
  });
});

describe("A9: dependency_check counts a vulnerability once across its aliases", () => {
  const e = (id: string, aliases: string[], severity: VulnerabilityEntry["severity"]) => ({ vulnId: id, aliases, severity, summary: id }) as VulnerabilityEntry;
  it("GHSA + RUSTSEC pairs are one advisory each, keeping the most severe grade", () => {
    const merged = refs([
      e("RUSTSEC-2023-0001", ["GHSA-7rrj-xr53-82p7"], "unknown"),
      e("GHSA-7rrj-xr53-82p7", ["RUSTSEC-2023-0001"], "medium"),
      e("GHSA-4q83-7cq4-p6wg", ["RUSTSEC-2023-0005"], "low"),
      e("RUSTSEC-2023-0005", ["GHSA-4q83-7cq4-p6wg"], "unknown"),
    ]);
    expect(merged.map((r) => `${r.id}:${r.severity}`)).toEqual(["GHSA-7rrj-xr53-82p7:medium", "GHSA-4q83-7cq4-p6wg:low"]);
  });
});
