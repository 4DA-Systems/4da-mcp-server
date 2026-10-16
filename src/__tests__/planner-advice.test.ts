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

async function plan(params: Record<string, unknown> = {}, prepare?: (li: LiveIntelligence) => void) {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  prepare?.(li);
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
      { parent: "express", from: "4.16.4", to: "4.22.0", requirement: "~0.1.12", resolvesTo: "0.1.13", lever: { name: "express", version: "4.16.4", to: "4.22.0" }, command: "npm install express@4.22.0" },
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
    expect(express.upgradeCommands).toEqual([{ dir: ".", command: "npm install express@4.22.0" }]);
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
        parent: "mongodb-core", from: "2.1.20", to: "3.1.0", requirement: "^1.1.0", resolvesTo: "1.1.6",
        lever: { name: "mongodb", version: "2.2.36", to: "3.1.0" }, command: "npm install mongodb@3.1.0",
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
    expect(ptr.parentUpgrades).toEqual([{ parent: "express", from: "4.16.4", to: null, latest: "5.1.0", lever: { name: "express", version: "4.16.4", to: null } }]);
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
    expect(step("vitest")).toMatchObject({ isDev: true, scope: "direct", targetVersion: "3.2.5", risk: "critical" });
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
    expect(result.summary).toMatch(/include_dev: false left out 1 devDependency and 1 dev-only vulnerable transitive copy/);
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
    expect(step("lodash")).toMatchObject({ targetVersion: "4.18.1", fixPathChecked: "installed_advisories_only", upgradeCommands: [{ dir: ".", command: "npm install lodash@4.18.1" }] });
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
