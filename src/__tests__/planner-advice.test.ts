// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_planner advice from the 6.2.5 readiness audit (2026-10-16):
 * - H1: "waiting on upstream" while a parent release that admits a clean
 *   version already exists (NodeGoat: express 4.16.4 pins path-to-regexp
 *   0.1.7, express 4.22.0 requires ~0.1.12; navcal: three @ai-sdk parents pin
 *   provider-utils 3.0.15). The plan now names the parent release, through
 *   the direct dependency when the parent is transitive, and a direct bump
 *   never stops at a release that still pulls a vulnerable transitive in.
 * - H4: vulnerable dev-only packages were left out by default (navcal 30 of
 *   34, NodeGoat 92 of 133); vulnerability_scan includes them since A8.
 * - H5: with OSV's /v1/query down and the registry up, lodash went to the
 *   deprecated 4.18.0 ("Bad release").
 * - M1: one advisory published as GHSA + PYSEC records was counted twice
 *   (django "96 known vulnerabilities" for 51).
 * - M2: an advisory with only `last_affected` below the target was reported
 *   as having "no published fix" (pyjwt PYSEC-2025-183, last_affected 2.10.1,
 *   target 2.15.0).
 * - L7: npm parent requirements come from dependencies and
 *   optionalDependencies only, as in the 4DA app.
 *
 * Registry and OSV shapes are the real ones (registry.npmjs.org abbreviated
 * documents, api.osv.dev records); the versions are cut down.
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
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

type Ev = Record<string, string>;
const adv = (id: string, name: string, events: Ev[], aliases: string[] = [], severity = "HIGH"): OsvVulnerability => ({
  id,
  aliases,
  summary: `${name} advisory ${id}`,
  database_specific: { severity },
  affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events }] }],
});
const fixedIn = (v: string): Ev[] => [{ introduced: "0" }, { fixed: v }];

let ADVISORIES: Record<string, OsvVulnerability[]> = {};
type VersionDoc = { deprecated?: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> };
let NPM: Record<string, { versions: Record<string, VersionDoc>; latest: string }> = {};
/** When true, OSV's per-package /v1/query fails (503) while querybatch and the registry answer (audit H5). */
let QUERY_DOWN = false;

const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
function affects(v: OsvVulnerability, version: string): boolean {
  const ev = v.affected![0].ranges[0].events;
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
      if (QUERY_DOWN) return new Response("unavailable", { status: 503 });
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: ADVISORIES[q.package.name] ?? [] });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({}, 404);
      if (npm[2]) return json(doc.versions[decodeURIComponent(npm[2])] ?? {});
      return json({ name, "dist-tags": { latest: doc.latest }, versions: doc.versions });
    }
    return json({}, 404);
  });
}

let dir: string;
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-planner-advice-"));
  ADVISORIES = {};
  NPM = {};
  QUERY_DOWN = false;
  stubNetwork();
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

type LockEntry = { version: string; dev?: boolean; dependencies?: Record<string, string> };
/** A package-lock v3 project: `direct` / `devDirect` are declared; `tree` adds each installed entry (direct ones too). */
function project(direct: Record<string, string>, devDirect: Record<string, string>, tree: Record<string, LockEntry>) {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: direct, devDependencies: devDirect }));
  const packages: Record<string, unknown> = { "": { name: "x", dependencies: direct, devDependencies: devDirect } };
  for (const [n, v] of Object.entries(direct)) packages[`node_modules/${n}`] = { version: v };
  for (const [n, v] of Object.entries(devDirect)) packages[`node_modules/${n}`] = { version: v, dev: true };
  for (const [n, e] of Object.entries(tree)) packages[`node_modules/${n}`] = e;
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
}

async function plan(params: Record<string, unknown> = {}, prepare?: (li: LiveIntelligence) => void | Promise<void>) {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  await prepare?.(li);
  const result = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50, ...params }, li)) as Record<string, any>;
  const step = (name: string, version?: string) =>
    result.recommendations.find((s: { package: string; currentVersion: string }) => s.package === name && (!version || s.currentVersion === version));
  return { result, step };
}

const scan = async (params: Record<string, unknown> = {}) =>
  (await executeVulnerabilityScan(null, { project_path: dir, ...params }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;

/** express 4.16.4 pins path-to-regexp 0.1.7; the releases and requirements are express's real ones (registry.npmjs.org). */
function expressProject() {
  ADVISORIES["path-to-regexp"] = [
    adv("GHSA-9wv6-86v2-598j", "path-to-regexp", fixedIn("0.1.10")),
    adv("GHSA-rhx6-c78j-4q9w", "path-to-regexp", fixedIn("0.1.12")),
    adv("GHSA-37ch-88jc-xwx2", "path-to-regexp", fixedIn("0.1.13")),
  ];
  ADVISORIES.express = [adv("GHSA-qw6h-vgh9-j6wx", "express", fixedIn("4.20.0"), [], "MODERATE")];
  NPM["path-to-regexp"] = { latest: "8.3.0", versions: { "0.1.7": {}, "0.1.10": {}, "0.1.12": {}, "0.1.13": {}, "8.3.0": {} } };
  NPM.express = {
    latest: "5.1.0",
    versions: {
      "4.16.4": { dependencies: { "path-to-regexp": "0.1.7" } },
      "4.20.0": { dependencies: { "path-to-regexp": "0.1.10" } },
      "4.21.2": { dependencies: { "path-to-regexp": "0.1.12" } },
      "4.22.0": { dependencies: { "path-to-regexp": "~0.1.12" } },
      "4.22.3": { dependencies: { "path-to-regexp": "~0.1.13" } },
      "5.1.0": { dependencies: { "path-to-regexp": "^8.0.0" } },
    },
  };
  project({ express: "4.16.4" }, {}, {
    express: { version: "4.16.4", dependencies: { "path-to-regexp": "0.1.7" } },
    "path-to-regexp": { version: "0.1.7" },
  });
}

describe("H1: a parent release that admits a clean version is named, not 'waiting on upstream'", () => {
  it("a direct parent: express 4.22.0 is the smallest release whose requirement admits path-to-regexp 0.1.13", async () => {
    expressProject();
    const { result, step } = await plan();
    const ptr = step("path-to-regexp");
    expect(ptr).toMatchObject({ action: "upgrade_parent", targetVersion: "0.1.13", fixPathChecked: "all_advisories" });
    expect(ptr.parentUpgrades).toEqual([
      {
        parent: "express", from: "4.16.4", to: "4.22.0", breaking: false, requirement: "~0.1.12", resolvesTo: "0.1.13",
        levers: [{ name: "express", version: "4.16.4", to: "4.22.0", breaking: false, commands: [{ dir: ".", command: "npm install express@4.22.0 --save-exact" }] }],
      },
    ]);
    const text = ptr.reasons.join(" ");
    expect(text).not.toMatch(/waiting on upstream/);
    expect(text).toMatch(/express 4\.22\.0 is the smallest express release whose requirement "~0\.1\.12" admits path-to-regexp 0\.1\.13/);
    expect(result.summary).toMatch(/1 transitive, fixed by upgrading the parent that pins it/);
    expect(result.summary).not.toMatch(/waiting on upstream/);
  });

  it("the direct bump is raised to the release that also clears the transitive it pins (express 4.20.0 still pins path-to-regexp 0.1.10)", async () => {
    expressProject();
    const { step } = await plan();
    const express = step("express");
    expect(express).toMatchObject({ action: "upgrade_direct", targetVersion: "4.22.0", upgradeType: "minor" });
    expect(express.upgradeCommands).toEqual([{ dir: ".", command: "npm install express@4.22.0 --save-exact" }]);
    expect(express.reasons.join(" ")).toMatch(/4\.22\.0, not 4\.20\.0: express 4\.20\.0 still requires a vulnerable path-to-regexp/);
  });

  it("a transitive parent: names the direct dependency it arrives through, and that dependency's release", async () => {
    ADVISORIES.bson = [adv("GHSA-4jwp-vfvf-657p", "bson", fixedIn("1.1.4"))];
    NPM.bson = { latest: "1.1.6", versions: { "1.0.9": {}, "1.1.0": {}, "1.1.4": {}, "1.1.6": {} } };
    NPM["mongodb-core"] = {
      latest: "3.2.7",
      versions: {
        "2.1.20": { dependencies: { bson: "~1.0.4" } },
        "3.0.0": { dependencies: { bson: "~1.0.4" } },
        "3.1.0": { dependencies: { bson: "^1.1.0" } },
        "3.2.7": { dependencies: { bson: "^1.1.1" } },
      },
    };
    NPM.mongodb = {
      latest: "3.1.0",
      versions: {
        "2.2.36": { dependencies: { "mongodb-core": "2.1.20" } },
        "3.0.0": { dependencies: { "mongodb-core": "3.0.0" } },
        "3.1.0": { dependencies: { "mongodb-core": "3.1.0" } },
      },
    };
    project({ mongodb: "2.2.36" }, {}, {
      mongodb: { version: "2.2.36", dependencies: { "mongodb-core": "2.1.20" } },
      "mongodb-core": { version: "2.1.20", dependencies: { bson: "~1.0.4" } },
      bson: { version: "1.0.9" },
    });
    const { step } = await plan();
    const bson = step("bson");
    expect(bson.action).toBe("upgrade_parent");
    expect(bson.parentUpgrades).toEqual([
      {
        parent: "mongodb-core", from: "2.1.20", to: "3.1.0", breaking: true, requirement: "^1.1.0", resolvesTo: "1.1.6",
        levers: [{ name: "mongodb", version: "2.2.36", to: "3.1.0", breaking: true, commands: [{ dir: ".", command: "npm install mongodb@3.1.0 --save-exact" }] }],
      },
    ]);
    expect(bson.reasons.join(" ")).toMatch(/mongodb-core arrives through mongodb 2\.2\.36, a direct dependency: mongodb 3\.1\.0 is the smallest mongodb release that brings in mongodb-core 3\.1\.0/);
  });

  it("several parents pin it (navcal's @ai-sdk/provider-utils): each parent's release is named", async () => {
    ADVISORIES["@ai-sdk/provider-utils"] = [adv("GHSA-866g-f22w-33x8", "@ai-sdk/provider-utils", fixedIn("3.0.28"))];
    NPM["@ai-sdk/provider-utils"] = { latest: "3.0.41", versions: { "3.0.15": {}, "3.0.28": {}, "3.0.41": {} } };
    NPM.ai = { latest: "5.0.277", versions: { "5.0.86": { dependencies: { "@ai-sdk/provider-utils": "3.0.15" } }, "5.0.277": { dependencies: { "@ai-sdk/provider-utils": "3.0.41" } } } };
    NPM["@ai-sdk/openai"] = { latest: "2.0.135", versions: { "2.0.59": { dependencies: { "@ai-sdk/provider-utils": "3.0.15" } }, "2.0.135": { dependencies: { "@ai-sdk/provider-utils": "3.0.41" } } } };
    project({ ai: "5.0.86", "@ai-sdk/openai": "2.0.59" }, {}, {
      ai: { version: "5.0.86", dependencies: { "@ai-sdk/provider-utils": "3.0.15" } },
      "@ai-sdk/openai": { version: "2.0.59", dependencies: { "@ai-sdk/provider-utils": "3.0.15" } },
      "@ai-sdk/provider-utils": { version: "3.0.15" },
    });
    const { step } = await plan();
    const utils = step("@ai-sdk/provider-utils");
    expect(utils.action).toBe("upgrade_parent");
    expect(utils.parentUpgrades.map((u: { parent: string; to: string }) => `${u.parent}@${u.to}`).sort()).toEqual(["@ai-sdk/openai@2.0.135", "ai@5.0.277"]);
  });

  it("the parent's requirements cannot be read: names its newest release and says to check it", async () => {
    expressProject();
    // The release facts answer; the requirement history does not (rate limited, or the registry stopped answering).
    const { step } = await plan({}, (li) => {
      li.getFixPathSources()!.requirementHistory = async () => null;
    });
    const ptr = step("path-to-regexp");
    expect(ptr.action).toBe("upgrade_parent");
    expect(ptr.parentUpgrades).toEqual([{ parent: "express", from: "4.16.4", to: null, breaking: false, latest: "5.1.0", levers: [{ name: "express", version: "4.16.4", to: null, breaking: false }] }]);
    expect(ptr.reasons.join(" ")).toMatch(/upgrade express \(express 5\.1\.0 is its newest release; check that it admits path-to-regexp >= 0\.1\.13\)/);
  });

  it("no release up to the newest admits a clean version: override or replace, not 'waiting on upstream'", async () => {
    ADVISORIES.minimist = [adv("GHSA-xvch-5gv4-984h", "minimist", fixedIn("1.2.6"))];
    NPM.minimist = { latest: "1.2.8", versions: { "1.2.5": {}, "1.2.6": {}, "1.2.8": {} } };
    NPM["left-pad"] = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { minimist: "1.2.5" } }, "1.1.0": { dependencies: { minimist: "1.2.5" } } } };
    project({ "left-pad": "1.0.0" }, {}, { "left-pad": { version: "1.0.0", dependencies: { minimist: "1.2.5" } }, minimist: { version: "1.2.5" } });
    const { step } = await plan();
    const minimist = step("minimist");
    expect(minimist.action).toBe("override_or_replace");
    expect(minimist.reasons.join(" ")).toMatch(/no left-pad release up to 1\.1\.0 admits a clean minimist/);
  });
});

describe("H4: dev-only vulnerable packages are in the plan by default, labelled", () => {
  function devProject() {
    ADVISORIES.vitest = [adv("GHSA-9crc-q9x8-hgqq", "vitest", fixedIn("3.2.5"), [], "CRITICAL")];
    ADVISORIES.esbuild = [adv("GHSA-67mh-4wv8-2f99", "esbuild", fixedIn("0.25.0"), [], "MODERATE")];
    NPM.vitest = { latest: "3.2.5", versions: { "3.2.4": { dependencies: { esbuild: "^0.21.0" } }, "3.2.5": { dependencies: { esbuild: "^0.25.0" } } } };
    NPM.esbuild = { latest: "0.25.0", versions: { "0.21.5": {}, "0.25.0": {} } };
    project({}, { vitest: "3.2.4" }, { esbuild: { version: "0.21.5", dev: true } });
  }

  it("matches vulnerability_scan's default: direct and transitive dev-only rows, isDev: true", async () => {
    devProject();
    const { result, step } = await plan();
    // Ranked by the grade vulnerability_scan presents: a dev-only critical is high (review finding 6).
    expect(step("vitest")).toMatchObject({ isDev: true, scope: "direct", targetVersion: "3.2.5", risk: "high" });
    expect(step("esbuild")).toMatchObject({ isDev: true, scope: "transitive" });
    expect(result.summary).toMatch(/2 dev-only \(isDev\)/);
    const scanned = await scan();
    expect(scanned.vulnerable_packages.map((v: { package: string }) => v.package).sort()).toEqual(["esbuild", "vitest"]);
  });

  it("a devDependency with no advisory is checked for freshness only with include_dev: true, and the default says so", async () => {
    NPM.prettier = { latest: "3.6.0", versions: { "3.5.0": {}, "3.6.0": {} } };
    project({}, { prettier: "3.5.0" }, {});
    const byDefault = await plan();
    expect(byDefault.step("prettier")).toBeUndefined();
    expect(byDefault.result.summary).toMatch(/1 devDependency with no known vulnerability was not checked for newer releases or deprecation \(include_dev: true checks them\)/);
    const all = await plan({ include_dev: true });
    expect(all.step("prettier")).toMatchObject({ isDev: true, targetVersion: "3.6.0", action: "upgrade_direct" });
  });

  it("include_dev: false leaves them out and the summary says what was left out", async () => {
    devProject();
    const { result } = await plan({ include_dev: false });
    expect(result.recommendations).toEqual([]);
    // A plan-only run at runtime scope never scanned vitest: it is counted as unchecked, not as vulnerable (review finding 10).
    expect(result.summary).toMatch(/include_dev: false left out 1 devDependency not checked for vulnerabilities and 1 dev-only vulnerable transitive copy/);
  });
});

describe("H5: a deprecated release is never the target, even when the advisory lookups fail", () => {
  it("OSV /v1/query down, registry up: lodash goes to 4.18.1, not the 'Bad release' 4.18.0, labelled unchecked", async () => {
    QUERY_DOWN = true;
    ADVISORIES.lodash = [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21")), adv("GHSA-f23m-r3pf-42rh", "lodash", fixedIn("4.18.0"))];
    NPM.lodash = { latest: "4.18.1", versions: { "4.17.20": {}, "4.17.21": {}, "4.18.0": { deprecated: "Bad release. Please use lodash@4.17.21 instead." }, "4.18.1": {} } };
    project({ lodash: "4.17.20" }, {}, {});
    const scanned = await scan();
    expect(scanned.vulnerable_packages[0]).toMatchObject({ package: "lodash", fixed_version: "4.18.1", fix_checked: "installed_advisories_only" });
    expect(scanned.recommendations[0]).toMatch(/^Upgrade lodash 4\.17\.20 → 4\.18\.1 .*4\.18\.0, the highest per-advisory fix, which is deprecated or yanked on the registry.*not checked against the package's other advisories/);
    expect(JSON.stringify(scanned)).not.toMatch(/→ 4\.18\.0/);
    const { step } = await plan();
    expect(step("lodash")).toMatchObject({ targetVersion: "4.18.1", fixPathChecked: "installed_advisories_only", upgradeCommands: [{ dir: ".", command: "npm install lodash@4.18.1 --save-exact" }] });
  });
});

describe("M1: an advisory published under two ids counts once", () => {
  it("GHSA + PYSEC-style alias records of one issue are one vulnerability in the plan", async () => {
    ADVISORIES.tar = [
      adv("GHSA-r628-mhmh-qjhw", "tar", fixedIn("4.4.18"), ["CVE-2021-37701"]),
      adv("NPM-2021-37701", "tar", fixedIn("4.4.18"), ["GHSA-r628-mhmh-qjhw", "CVE-2021-37701"]),
      adv("GHSA-9r2w-394v-53qc", "tar", fixedIn("4.4.16")),
    ];
    NPM.tar = { latest: "4.4.19", versions: { "4.4.8": {}, "4.4.16": {}, "4.4.18": {}, "4.4.19": {} } };
    project({ tar: "4.4.8" }, {}, {});
    const { step } = await plan();
    expect(step("tar").reasons[0]).toMatch(/^2 known vulnerabilities \(/);
  });
});

describe("M2: an advisory with only last_affected below the target is resolved by it", () => {
  it("pyjwt-shaped: 2.15.0 clears PYSEC-2025-183 (last_affected 2.10.1); no 'no published fix'", async () => {
    ADVISORIES.jwtish = [
      adv("GHSA-ffc3-869f-jxw9", "jwtish", fixedIn("2.15.0")),
      adv("PYSEC-2025-183", "jwtish", [{ introduced: "0" }, { last_affected: "2.10.1" }]),
    ];
    NPM.jwtish = { latest: "2.15.0", versions: { "2.4.0": {}, "2.10.1": {}, "2.11.0": {}, "2.15.0": {} } };
    project({ jwtish: "2.4.0" }, {}, {});
    const { step } = await plan();
    const text = step("jwtish").reasons.join(" ");
    expect(step("jwtish")).toMatchObject({ targetVersion: "2.15.0", fixPathChecked: "all_advisories" });
    expect(text).not.toMatch(/no published fix/);
    expect(text).toMatch(/PYSEC-2025-183 names no fixed version \(only a last affected one\); 2\.15\.0 is past it/);
    const scanned = await scan();
    expect(scanned.recommendations[0]).toMatch(/^Upgrade jwtish 2\.4\.0 → 2\.15\.0 in \. — resolves 2 CVEs \(PYSEC-2025-183 names no fixed version; 2\.15\.0 is past its last affected release\)/);
  });

  it("an advisory that still affects the target keeps 'no published fix'", async () => {
    ADVISORIES.jwtopen = [
      adv("GHSA-fix2-0000-0000", "jwtopen", fixedIn("2.15.0")),
      adv("GHSA-open-0000-0000", "jwtopen", [{ introduced: "0" }]),
    ];
    NPM.jwtopen = { latest: "2.15.0", versions: { "2.4.0": {}, "2.15.0": {} } };
    project({ jwtopen: "2.4.0" }, {}, {});
    const { step } = await plan();
    expect(step("jwtopen").reasons.join(" ")).toMatch(/1 of them has no published fix \(GHSA-open-0000-0000 also affects 2\.15\.0\)/);
    const scanned = await scan();
    expect(scanned.recommendations[0]).toMatch(/resolves 1 of 2 CVEs \(1 with no published fix\)/);
  });
});

describe("L7: an npm parent's requirement comes from dependencies and optionalDependencies, not peers", () => {
  it("a peer-only declaration is not read as the parent pinning the copy", async () => {
    const li = new LiveIntelligence(new Database(":memory:"));
    NPM.plugin = { latest: "1.0.0", versions: { "1.0.0": { peerDependencies: { react: "^17.0.0" }, dependencies: { lodash: "^4.17.0" } } } };
    const sources = li.getFixPathSources()!;
    expect(await sources.parentRequirements("npm", "plugin", "1.0.0", "react")).toEqual([]);
    expect(await sources.parentRequirements("npm", "plugin", "1.0.0", "lodash")).toEqual(["^4.17.0"]);
  });
});

/**
 * Independent review of the H1 parent-upgrade advice (2026-10-17, head 682f729): each case is
 * one of the reviewer's scenarios (scratchpad review-x/scen.test.ts), failing on 682f729.
 */
describe("readiness review 2026-10-17: parent-upgrade advice", () => {
  const leafOnly = (fix: string, versions: string[]) => {
    ADVISORIES.leaf = [adv("GHSA-leaf-0000-0001", "leaf", fixedIn(fix))];
    NPM.leaf = { latest: versions[versions.length - 1], versions: Object.fromEntries(versions.map((v) => [v, {}])) };
  };
  const commandsIn = (step: unknown) => JSON.stringify(step).match(/npm install [^"`]+/g) ?? [];

  it("1: a parent the lockfile walk cannot tie to a declaration names no lever and no command (never `npm install <transitive>`)", async () => {
    leafOnly("1.1.0", ["1.0.0", "1.1.0"]);
    NPM.mid = { latest: "2.0.1", versions: { "2.0.0": { dependencies: { leaf: "1.0.0" } }, "2.0.1": { dependencies: { leaf: "^1.1.0" } } } };
    const tree: Record<string, LockEntry> = { mid: { version: "2.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } };
    const topDeps: Record<string, string> = {};
    for (let i = 0; i < 45; i++) {
      tree[`t${i}`] = { version: "1.0.0", dependencies: { mid: "2.0.0" } };
      topDeps[`t${i}`] = "1.0.0";
    }
    tree.top = { version: "1.0.0", dependencies: topDeps };
    project({ top: "1.0.0" }, {}, tree);
    const { step } = await plan();
    const leaf = step("leaf");
    expect(leaf.action).toBe("upgrade_parent");
    expect(leaf.parentUpgrades).toMatchObject([{ parent: "mid", to: "2.0.1", levers: [] }]);
    expect(leaf.parentUpgrades[0].leverUnknown).toMatch(/walk up the lockfile stopped after 40 entries/);
    expect(commandsIn(leaf)).toEqual([]);
    expect(leaf.reasons.join(" ")).toMatch(/could not be worked out .*so no command is named: bump the one that does to a release that brings in mid >= 2\.0\.1/);
  });

  it("2a: a transitive parent release is clear of its own advisories, and its lever agrees with the parent's own row (mid 2.1.0 is CRITICAL; 2.5.0 via top 1.2.0)", async () => {
    leafOnly("1.1.0", ["1.0.0", "1.1.0"]);
    ADVISORIES.mid = [adv("GHSA-mid0-0000-0001", "mid", fixedIn("2.5.0"), [], "CRITICAL")];
    NPM.mid = { latest: "2.5.0", versions: { "2.0.0": { dependencies: { leaf: "1.0.0" } }, "2.1.0": { dependencies: { leaf: "^1.1.0" } }, "2.5.0": { dependencies: { leaf: "^1.1.0" } } } };
    NPM.top = { latest: "1.2.0", versions: { "1.0.0": { dependencies: { mid: "2.0.0" } }, "1.1.0": { dependencies: { mid: "2.1.0" } }, "1.2.0": { dependencies: { mid: "2.5.0" } } } };
    project({ top: "1.0.0" }, {}, { top: { version: "1.0.0", dependencies: { mid: "2.0.0" } }, mid: { version: "2.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } });
    const { step } = await plan();
    expect(step("leaf").parentUpgrades).toMatchObject([{ parent: "mid", to: "2.5.0", levers: [{ name: "top", to: "1.2.0", commands: [{ command: "npm install top@1.2.0 --save-exact" }] }] }]);
    expect(step("mid").parentUpgrades).toMatchObject([{ parent: "top", to: "1.2.0", levers: [{ name: "top", to: "1.2.0", commands: [{ command: "npm install top@1.2.0 --save-exact" }] }] }]);
    expect(step("leaf").reasons.join(" ")).toMatch(/mid 2\.5\.0 is the smallest mid release whose requirement "\^1\.1\.0" admits leaf 1\.1\.0.*, and no advisory of mid affects it/);
  });

  it("2b: a direct parent's release agrees with its own row (express's own advisory is fixed in 4.22.3: both rows say 4.22.3)", async () => {
    expressProject();
    ADVISORIES.express.push(adv("GHSA-expr-0000-0002", "express", fixedIn("4.22.3"), [], "HIGH"));
    const { step } = await plan();
    const ptr = step("path-to-regexp");
    expect(step("express")).toMatchObject({ targetVersion: "4.22.3", upgradeCommands: [{ command: "npm install express@4.22.3 --save-exact" }] });
    expect(ptr.parentUpgrades).toMatchObject([{ parent: "express", to: "4.22.3", levers: [{ to: "4.22.3", commands: [{ command: "npm install express@4.22.3 --save-exact" }] }] }]);
    expect(new Set([...commandsIn(ptr), ...commandsIn(step("express"))])).toEqual(new Set(["npm install express@4.22.3 --save-exact"]));
    expect(ptr.reasons.join(" ")).not.toMatch(/upgrade express to 4\.22\.0/);
  });

  it("2c: a lever below its own row's raised target follows it, in data and in text (qs needs express 4.22.3; path-to-regexp's 4.22.0 lifts)", async () => {
    expressProject();
    ADVISORIES.qs = [adv("GHSA-6rw7-vpxm-498p", "qs", fixedIn("6.16.0"))];
    NPM.qs = { latest: "6.16.1", versions: { "6.5.2": {}, "6.11.0": {}, "6.15.1": {}, "6.16.0": {}, "6.16.1": {} } };
    const deps = (ptr: string, qs: string) => ({ dependencies: { "path-to-regexp": ptr, qs } });
    NPM.express.versions = {
      "4.16.4": deps("0.1.7", "6.5.2"), "4.20.0": deps("0.1.10", "6.11.0"), "4.22.0": deps("~0.1.12", "~6.15.1"), "4.22.3": deps("~0.1.13", "~6.16.0"), "5.1.0": deps("^8.0.0", "^6.16.0"),
    };
    project({ express: "4.16.4" }, {}, {
      express: { version: "4.16.4", dependencies: { "path-to-regexp": "0.1.7", qs: "6.5.2" } },
      "path-to-regexp": { version: "0.1.7" },
      qs: { version: "6.5.2" },
    });
    const { step } = await plan();
    expect(step("express")).toMatchObject({ targetVersion: "4.22.3", upgradeCommands: [{ command: "npm install express@4.22.3 --save-exact" }] });
    const ptr = step("path-to-regexp");
    expect(ptr.parentUpgrades).toMatchObject([{ parent: "express", to: "4.22.3", requirement: "~0.1.13", levers: [{ to: "4.22.3", commands: [{ command: "npm install express@4.22.3 --save-exact" }] }] }]);
    expect(ptr.reasons.join(" ")).toMatch(/express 4\.22\.3, not 4\.22\.0: express's own row targets 4\.22\.3/);
    expect(ptr.reasons.join(" ")).not.toMatch(/upgrade express to 4\.22\.0/);
    expect(new Set([...commandsIn(ptr), ...commandsIn(step("qs")), ...commandsIn(step("express"))])).toEqual(new Set(["npm install express@4.22.3 --save-exact"]));
  });
  it("3: a new requirement that still admits the installed copy names the refresh too (npm 10.9.2 keeps the copy on install)", async () => {
    leafOnly("1.0.5", ["1.0.0", "1.0.5"]);
    NPM.par = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } }, "1.1.0": { dependencies: { leaf: "^1.0.0" } } } };
    project({ par: "1.0.0" }, {}, { par: { version: "1.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } });
    const { step } = await plan();
    const leaf = step("leaf");
    expect(leaf.parentUpgrades).toMatchObject([{ parent: "par", to: "1.1.0", refreshCommands: [{ dir: ".", command: "npm update leaf" }] }]);
    expect(leaf.reasons.join(" ")).toMatch(/leaf 1\.0\.0 still satisfies "\^1\.0\.0", and an install keeps a copy that satisfies it, so then run `npm update leaf`/);
    expect(leaf.reasons.join(" ")).not.toMatch(/a refresh then resolves/);
  });

  it("4: commands keep the declared operator (express declared ~4.16.4), on the direct row and on the lever", async () => {
    expressProject();
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: { express: "~4.16.4" } }));
    const { step } = await plan();
    expect(step("express").upgradeCommands).toEqual([{ dir: ".", command: 'npm install "express@~4.22.0"' }]);
    expect(step("path-to-regexp").parentUpgrades[0].levers[0].commands).toEqual([{ dir: ".", command: 'npm install "express@~4.22.0"' }]);
  });

  it("4: a spec whose operator cannot be carried names no command (>=)", async () => {
    expressProject();
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: { express: ">=4.16.0" } }));
    const { step } = await plan();
    expect(step("express").upgradeCommands).toBeUndefined();
    expect(step("path-to-regexp").parentUpgrades[0].levers[0].commands).toBeUndefined();
  });

  it("5: a parent reached through two declared dependencies names both; one that cannot move makes it an override", async () => {
    leafOnly("1.1.0", ["1.0.0", "1.1.0"]);
    NPM.mid = { latest: "2.1.0", versions: { "2.0.0": { dependencies: { leaf: "1.0.0" } }, "2.1.0": { dependencies: { leaf: "^1.1.0" } } } };
    NPM.a = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { mid: "2.0.0" } }, "1.1.0": { dependencies: { mid: "2.1.0" } } } };
    NPM.b = { latest: "1.0.0", versions: { "1.0.0": { dependencies: { mid: "2.0.0" } } } };
    const tree = { a: { version: "1.0.0", dependencies: { mid: "2.0.0" } }, b: { version: "1.0.0", dependencies: { mid: "2.0.0" } }, mid: { version: "2.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } };
    project({ a: "1.0.0", b: "1.0.0" }, {}, tree);
    const stuck = (await plan()).step("leaf");
    expect(stuck.action).toBe("override_or_replace");
    expect(stuck.reasons.join(" ")).toMatch(/mid arrives through b 1\.0\.0, and b 1\.0\.0 is already its latest release/);

    NPM.b = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { mid: "2.0.0" } }, "1.1.0": { dependencies: { mid: "2.1.0" } } } };
    const both = (await plan()).step("leaf");
    expect(both.action).toBe("upgrade_parent");
    expect(both.parentUpgrades[0].levers.map((l: { name: string; to: string }) => `${l.name}@${l.to}`)).toEqual(["a@1.1.0", "b@1.1.0"]);
    expect(both.reasons.join(" ")).toMatch(/mid arrives through a 1\.0\.0 and b 1\.0\.0, direct dependencies, each of which must move/);
  });

  it("6: ranks by the scan's scope-adjusted grade: dev-only criticals never push a runtime high out of max_recommendations", async () => {
    for (const [n, sev] of [["d1", "CRITICAL"], ["d2", "CRITICAL"], ["r1", "HIGH"]] as const) {
      ADVISORIES[n] = [adv(`GHSA-${n}00-0000-0001`, n, fixedIn("1.1.0"), [], sev)];
      NPM[n] = { latest: "1.1.0", versions: { "1.0.0": {}, "1.1.0": {} } };
    }
    project({ r1: "1.0.0" }, { d1: "1.0.0", d2: "1.0.0" }, {});
    const { result } = await plan({ max_recommendations: 2 });
    expect(result.recommendations.map((r: { package: string; risk: string }) => `${r.package}:${r.risk}`)).toEqual(["r1:high", "d1:high"]);
  });

  it("7: a lever a workspace member declares, which the tree walk cannot tie to a manifest, is declined (no root-directory command)", async () => {
    leafOnly("1.1.0", ["1.0.0", "1.1.0"]);
    NPM.par = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } }, "1.1.0": { dependencies: { leaf: "^1.1.0" } } } };
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }));
    fs.mkdirSync(path.join(dir, "packages", "app"), { recursive: true });
    fs.writeFileSync(path.join(dir, "packages", "app", "package.json"), JSON.stringify({ name: "app", version: "1.0.0", dependencies: { par: "^1.0.0" } }));
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: "root",
        lockfileVersion: 3,
        packages: {
          "": { name: "root", workspaces: ["packages/*"] },
          "packages/app": { name: "app", version: "1.0.0", dependencies: { par: "^1.0.0" } },
          "node_modules/app": { resolved: "packages/app", link: true },
          "node_modules/par": { version: "1.0.0", dependencies: { leaf: "1.0.0" } },
          "node_modules/leaf": { version: "1.0.0" },
        },
      }),
    );
    // The member's manifest is not one this server's tree walk reads as declaring par (par resolves
    // as non-direct), so the lever is declined: no command in the lockfile's directory, which
    // would run `npm install par@...` at the root and add par there (review findings 1 and 7).
    const { step } = await plan();
    const upgrade = step("leaf").parentUpgrades[0];
    expect(upgrade).toMatchObject({ parent: "par", to: "1.1.0", levers: [] });
    expect(upgrade.leverUnknown).toMatch(/no manifest this plan read declares par 1\.0\.0/);
    expect(commandsIn(step("leaf"))).toEqual([]);
  });

  it("8: a parent move across a major is flagged (mongodb 2.2.36 -> 3.1.0)", async () => {
    ADVISORIES.bson = [adv("GHSA-4jwp-vfvf-657p", "bson", fixedIn("1.1.4"))];
    NPM.bson = { latest: "1.1.6", versions: { "1.0.9": {}, "1.1.0": {}, "1.1.4": {}, "1.1.6": {} } };
    NPM.mongodb = { latest: "3.1.0", versions: { "2.2.36": { dependencies: { bson: "~1.0.4" } }, "3.1.0": { dependencies: { bson: "^1.1.0" } } } };
    project({ mongodb: "2.2.36" }, {}, { mongodb: { version: "2.2.36", dependencies: { bson: "~1.0.4" } }, bson: { version: "1.0.9" } });
    const { step } = await plan();
    expect(step("bson").parentUpgrades).toMatchObject([{ parent: "mongodb", to: "3.1.0", breaking: true, levers: [{ name: "mongodb", to: "3.1.0", breaking: true }] }]);
  });

  it("9: a step whose lookups outlive the budget is never written to afterwards; reconcile is bounded too", async () => {
    expressProject();
    const li = new LiveIntelligence(new Database(":memory:"));
    const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
    const { entries, discovery } = scanProjectTree(dir);
    li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    const sources = li.getFixPathSources()!;
    const slow = sources.packageAdvisories.bind(sources);
    sources.packageAdvisories = async (...a: Parameters<typeof slow>) => {
      await new Promise((r) => setTimeout(r, 300));
      return slow(...a);
    };
    const { verifyFixPaths, reconcileDirectTargets } = await import("../tools/upgrade-planner-fixpaths.js");
    const step = {
      package: "path-to-regexp", ecosystem: "npm", currentVersion: "0.1.7", targetVersion: "0.1.13", upgradeType: "patch" as const,
      reasons: ["2 known vulnerabilities", "Transitive dependency — not declared in your manifest"], breaking: false, scope: "transitive" as const, action: "waiting_on_upstream",
    };
    const before = JSON.stringify({ ...step, fixPathChecked: "installed_advisories_only" });
    expect(await verifyFixPaths([{ step, fixes: ["0.1.13"], sourceDirs: [dir] }], li, 50)).toBe(1);
    await new Promise((r) => setTimeout(r, 1200));
    expect(JSON.stringify(step)).toBe(before);

    const row = { package: "express", ecosystem: "npm", currentVersion: "4.16.4", targetVersion: "4.20.0", upgradeType: "minor" as const, reasons: [] as string[], breaking: false, scope: "direct" as const, action: "upgrade_direct" };
    const pinned = { ...step, action: "upgrade_parent", parentUpgrades: [{ parent: "express", from: "4.16.4", to: "4.22.0", breaking: false, levers: [{ name: "express", version: "4.16.4", to: "4.22.0", breaking: false }] }] };
    await reconcileDirectTargets([row, pinned], [{ step: row, fixes: ["4.20.0"], sourceDirs: [dir] }], li, 20);
    expect(row.targetVersion).toBe("4.20.0");
    expect(row.reasons.join(" ")).toMatch(/could not be checked against express's own advisories in time/);
    await new Promise((r) => setTimeout(r, 600));
    expect(row.targetVersion).toBe("4.20.0");
  });

  it("10: a parent that moves the package into peerDependencies still installs it: not 'no longer depends on'", async () => {
    leafOnly("1.1.0", ["1.0.0", "1.1.0"]);
    NPM.par = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { leaf: "1.0.0" } }, "1.1.0": { peerDependencies: { leaf: "^1.1.0" } } } };
    project({ par: "1.0.0" }, {}, { par: { version: "1.0.0", dependencies: { leaf: "1.0.0" } }, leaf: { version: "1.0.0" } });
    const { step } = await plan();
    const leaf = step("leaf");
    expect(leaf.parentUpgrades).toMatchObject([{ parent: "par", to: "1.1.0", requirement: "^1.1.0", peer: true }]);
    expect(leaf.reasons.join(" ")).toMatch(/whose peer requirement "\^1\.1\.0" admits leaf 1\.1\.0 \(npm 7\+ installs a missing peer\)/);
    expect(leaf.reasons.join(" ")).not.toMatch(/no longer depends on/);
  });

  it("10: include_dev: false counts only the vulnerable devDependencies it left out, and the override summary names every reason", async () => {
    ADVISORIES.vitest = [adv("GHSA-9crc-q9x8-hgqq", "vitest", fixedIn("3.2.5"), [], "CRITICAL")];
    NPM.vitest = { latest: "3.2.5", versions: { "3.2.4": {}, "3.2.5": {} } };
    NPM.prettier = { latest: "3.6.0", versions: { "3.5.0": {}, "3.6.0": {} } };
    project({}, { vitest: "3.2.4", prettier: "3.5.0" }, {});
    const { result } = await plan({ include_dev: false }, async (li) => {
      await li.scanVulnerabilities(dir, { includeDev: true });
    });
    expect(result.summary).toMatch(/include_dev: false left out 1 vulnerable devDependency \(the default, true, plans them\)/);

    ADVISORIES.minimist = [adv("GHSA-xvch-5gv4-984h", "minimist", fixedIn("1.2.6"))];
    NPM.minimist = { latest: "1.2.8", versions: { "1.2.5": {}, "1.2.6": {}, "1.2.8": {} } };
    NPM["left-pad"] = { latest: "1.1.0", versions: { "1.0.0": { dependencies: { minimist: "1.2.5" } }, "1.1.0": { dependencies: { minimist: "1.2.5" } } } };
    project({ "left-pad": "1.0.0" }, {}, { "left-pad": { version: "1.0.0", dependencies: { minimist: "1.2.5" } }, minimist: { version: "1.2.5" } });
    const blocked = await plan();
    expect(blocked.result.summary).toMatch(/blocked by a parent that will not move \(deprecated, already its latest release, or no release admits a clean version\)/);
  });
});
