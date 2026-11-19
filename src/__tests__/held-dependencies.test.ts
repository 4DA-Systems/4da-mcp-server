// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 6.2.5 D-4: a release's own advisories are not the whole answer.
 *
 * On NodeGoat (express 4.16.4) vulnerability_scan and dependency_check named express 4.20.0 the
 * clean fix. 4.20.0 exact-pins qs 6.11.0, cookie 0.6.0, body-parser 1.20.3 and path-to-regexp
 * 0.1.10, all affected, so installing it leaves the project vulnerable; agents wrote it in 2 of 2
 * headless runs, one via `dependency_check {to: "4.x"}`. 4.22.0 to 4.22.2 are no better: their qs
 * ranges ("~6.14.0", "~6.15.1") admit no qs the qs advisories leave clean. upgrade_planner already
 * said 4.22.3, from the project's lock tree.
 *
 * The shapes are the real ones (registry.npmjs.org documents, api.osv.dev records); the release
 * lists are cut down to the ones that decide it.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { exactPinVersion, heldSpecsOf, npmAliasTarget } from "../live/held-dependencies.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { analyzeUpgradeImpact, executeUpgradeImpact } from "../tools/upgrade-impact.js";
import { createUpgradeNet } from "../live/upgrade-sources.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

const adv = (id: string, name: string, fixed: string, severity: string): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity },
  affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed }] }] }],
});

const ADVISORIES: Record<string, OsvVulnerability[]> = {
  express: [adv("GHSA-qw6h-vgh9-j6wx", "express", "4.20.0", "LOW"), adv("GHSA-rv95-896h-c2vc", "express", "4.19.2", "MODERATE")],
  // Real ranges (OSV 2026-10-26): qs is clean only from 6.16.0; path-to-regexp 0.1.x from 0.1.13.
  qs: [adv("GHSA-4mjr-xmp4-gh2g", "qs", "6.16.0", "MODERATE")],
  "path-to-regexp": [adv("GHSA-37ch-88jc-xwx2", "path-to-regexp", "0.1.13", "HIGH")],
};

type VersionDoc = { dependencies?: Record<string, string> };
let NPM: Record<string, { latest: string; versions: Record<string, VersionDoc> }>;

function registry() {
  NPM = {
    express: {
      latest: "5.0.0",
      versions: {
        "4.16.4": { dependencies: { qs: "6.5.2", "path-to-regexp": "0.1.7", cookie: "0.3.1", debug: "2.6.9" } },
        "4.19.2": { dependencies: { qs: "6.11.0", "path-to-regexp": "0.1.7", cookie: "0.6.0", debug: "2.6.9" } },
        "4.20.0": { dependencies: { qs: "6.11.0", "path-to-regexp": "0.1.10", cookie: "0.6.0", debug: "2.6.9" } },
        "4.21.2": { dependencies: { qs: "6.13.0", "path-to-regexp": "0.1.12", cookie: "0.7.1", debug: "2.6.9" } },
        "4.22.0": { dependencies: { qs: "~6.14.0", "path-to-regexp": "~0.1.12", cookie: "~0.7.1", debug: "2.6.9" } },
        "4.22.3": { dependencies: { qs: "~6.16.0", "path-to-regexp": "~0.1.13", cookie: "~0.7.1", debug: "2.6.9" } },
        // Another major: never a candidate for a 4.x fix.
        "5.0.0": { dependencies: { qs: "^6.14.0", "path-to-regexp": "^8.0.0", cookie: "^0.7.1", debug: "^4.3.6" } },
      },
    },
    qs: { latest: "6.16.0", versions: Object.fromEntries(["6.5.2", "6.11.0", "6.13.0", "6.14.0", "6.14.2", "6.15.3", "6.16.0"].map((v) => [v, {}])) },
    "path-to-regexp": { latest: "8.0.0", versions: Object.fromEntries(["0.1.7", "0.1.10", "0.1.12", "0.1.13", "8.0.0"].map((v) => [v, {}])) },
    cookie: { latest: "0.7.1", versions: Object.fromEntries(["0.3.1", "0.6.0", "0.7.1"].map((v) => [v, {}])) },
    debug: { latest: "4.3.6", versions: Object.fromEntries(["2.6.9", "4.3.6"].map((v) => [v, {}])) },
  };
}

/** When true, an OSV querybatch that asks about anything but express fails: the held-dependency lookup is down. */
let HELD_LOOKUP_DOWN = false;
/** What the registry answers when asked for one release by name that it does not list. */
let MISSING_RELEASE_STATUS = 404;

const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
const affects = (v: OsvVulnerability, version: string) => cmp(version, v.affected![0].ranges[0].events.find((e) => e.fixed)!.fixed!) < 0;

function stubNetwork() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      if (HELD_LOOKUP_DOWN && queries.some((q) => q.package.name !== "express")) return new Response("unavailable", { status: 503 });
      return json({ results: queries.map((q) => ({ vulns: (ADVISORIES[q.package.name] ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(ADVISORIES).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      // With a version (upgrade_impact asks about one release): only the advisories that affect it.
      const q = JSON.parse(String(init?.body)) as { package: { name: string }; version?: string };
      const all = ADVISORIES[q.package.name] ?? [];
      return json({ vulns: q.version ? all.filter((v) => affects(v, q.version!)) : all });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({}, 404);
      // One document serves both readers: the abbreviated one (fix paths) and the full packument (dependency_check).
      const time = Object.fromEntries([["created", "2015-01-01T00:00:00.000Z"], ...Object.keys(doc.versions).map((v) => [v, "2025-01-01T00:00:00.000Z"])]);
      return json({ name, "dist-tags": { latest: doc.latest }, versions: doc.versions, time });
    }
    // One release asked for by name (fix-paths versionExists): 404 = the registry does not have it; 503 = it could not be asked.
    if (/^https:\/\/registry\.npmjs\.org\/[^/]+\/[^/]+$/.test(url)) return json({}, MISSING_RELEASE_STATUS);
    return json({}, 404);
  });
}

let dir: string;
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-held-"));
  HELD_LOOKUP_DOWN = false;
  MISSING_RELEASE_STATUS = 404;
  registry();
  stubNetwork();
  // NodeGoat's declaration, cut down to the one package that decides it.
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: { express: "4.16.4" } }));
  fs.writeFileSync(
    path.join(dir, "package-lock.json"),
    JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", dependencies: { express: "4.16.4" } }, "node_modules/express": { version: "4.16.4" } } }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

/** A live layer for the project on its own in-memory cache (a project_path scan would share the server's cache file across tests). */
async function liveFor(): Promise<LiveIntelligence> {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  vi.spyOn(li, "getProjectRoot").mockReturnValue(dir);
  return li;
}
const scan = async (params: Record<string, unknown> = {}) => (await executeVulnerabilityScan(null, params, await liveFor())) as Record<string, any>;
const check = async (items: unknown[]) =>
  (await executeDependencyCheck(noDb, { items } as never, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
const advisoriesOf = (r: { signals: Array<{ id: string; value: any; effect: string; evidence: string }> }) => r.signals.find((s) => s.id === "advisories") as { value: any; effect: string; evidence: string };

describe("held dependencies: what an npm spec installs whatever the lockfile holds", () => {
  it("an exact pin is a bare version or =version; every registry range is held, wide ones too (round 10, W13)", () => {
    expect(exactPinVersion("6.11.0")).toBe("6.11.0");
    expect(exactPinVersion("=6.11.0")).toBe("6.11.0");
    expect(exactPinVersion("v1.2.3-beta.1")).toBe("1.2.3-beta.1");
    for (const spec of ["^6.11.0", "~6.11.0", "6.x", ">=6", "*", "latest", "npm:qs@6.11.0", "git+https://x/y.git"]) expect(exactPinVersion(spec), spec).toBeNull();
    // A wide range is held too: whether a refresh reaches a clean release is judged, not assumed.
    expect(heldSpecsOf({ qs: "6.11.0", send: "~0.19.0", debug: "^2.6.9", any: "*" }, { fsevents: "1.2.9" })).toEqual({ qs: "6.11.0", send: "~0.19.0", debug: "^2.6.9", any: "*", fsevents: "1.2.9" });
    // Not registry ranges: dist-tags, protocols, paths install nothing this can judge.
    expect(heldSpecsOf({ a: "latest", b: "file:../x", c: "git+https://x/y.git", d: "github:u/r" })).toEqual({});
  });
});

describe("vulnerability_scan: a fix target is judged by what it installs (audit 6.2.5 D-4)", () => {
  it("express 4.16.4 goes to 4.22.3, not 4.20.0 (which exact-pins an affected qs), and says why", async () => {
    const concise = await scan();
    expect(concise.vulnerable_packages[0]).toMatchObject({ package: "express", fixed_version: "4.22.3", fix_checked: "all_advisories" });
    const rec = concise.recommendations[0] as string;
    expect(rec).toMatch(/^Upgrade express 4\.16\.4 → 4\.22\.3 /);
    expect(rec).toMatch(/4\.20\.0 exact-pins qs 6\.11\.0 \(GHSA-4mjr-xmp4-gh2g\) and path-to-regexp 0\.1\.10 \(GHSA-37ch-88jc-xwx2\)/);
    expect(rec).toMatch(/2 later releases \(4\.21\.2 to 4\.22\.0\) still bring in an affected qs, path-to-regexp; so 4\.22\.3, the smallest later release on its line/);
    const detailed = await scan({ response_format: "detailed" });
    expect(detailed.fix_targets["express@4.16.4"]).toMatchObject({ target: "4.22.3", checked: "all_advisories" });
  });

  it("when no release on the line clears what it holds, the target is not called a clean fix", async () => {
    NPM.express.versions["4.22.3"] = { dependencies: { qs: "6.13.0", "path-to-regexp": "0.1.13", cookie: "0.7.1" } };
    const concise = await scan();
    expect(concise.vulnerable_packages[0]).toMatchObject({ fixed_version: null, fix_note: expect.stringMatching(/^NOT CHECKED: 4.20.0 /), fix_checked: "installed_advisories_only" });
    expect(concise.recommendations[0]).toMatch(/4\.20\.0 exact-pins qs 6\.11\.0 .*no later release on its line up to 4\.22\.3 that its own advisories leave clean clears them, so 4\.20\.0 is NOT a clean fix/);
  });

  it("a release whose held dependencies cannot be judged is named NOT CHECKED, never counted as not clearing them (4DA #1039)", async () => {
    NPM.express.versions["4.22.3"] = { dependencies: { qs: "6.13.0", "path-to-regexp": "0.1.13", cookie: "0.7.1" } };
    // 4.21.2 narrowly ranges a package the registry does not serve: what it installs cannot be read.
    NPM.express.versions["4.21.2"] = { dependencies: { "gone-dep": "~1.0.0" } };
    const concise = await scan();
    expect(concise.vulnerable_packages[0]).toMatchObject({ fixed_version: null, fix_note: expect.stringMatching(/^NOT CHECKED: 4.20.0 /), fix_checked: "installed_advisories_only" });
    expect(concise.recommendations[0]).toMatch(
      /no later release on its line up to 4\.22\.3 that its own advisories leave clean clears them, of the releases that could be checked \(4\.21\.2 NOT CHECKED\), so 4\.20\.0 is NOT a clean fix/,
    );
  });

  it("fails closed: when the held dependencies cannot be looked up, the claim is not upgraded", async () => {
    HELD_LOOKUP_DOWN = true;
    const concise = await scan();
    // The advisories' own target, never a release picked without the check, and never "all_advisories".
    expect(concise.vulnerable_packages[0]).toMatchObject({ fixed_version: null, fix_note: expect.stringMatching(/^NOT CHECKED: 4.20.0 /), fix_checked: "installed_advisories_only" });
    expect(concise.recommendations[0]).toMatch(/whether the dependencies 4\.20\.0 holds are affected was NOT CHECKED/);
  });
});

describe("dependency_check: an exact `to` that holds an affected dependency is not proceed (audit 6.2.5 D-4)", () => {
  it("{to: 4.20.0} is avoid (path-to-regexp's advisory is high), names the pins, and the line's safe release", async () => {
    const out = await check([{ ecosystem: "npm", package: "express", to: "4.20.0" }]);
    const r = out.results[0];
    expect(r.verdict).toBe("avoid");
    const a = advisoriesOf(r);
    expect(a.effect).toBe("avoid");
    expect(a.value.affecting_to).toEqual([]);
    expect(a.value.held_dependencies_affected.map((d: { package: string; installs: string }) => `${d.package}@${d.installs}`).sort()).toEqual(["path-to-regexp@0.1.10", "qs@6.11.0"]);
    expect(a.evidence).toMatch(/No advisory of express itself affects 4\.20\.0, but 4\.20\.0 exact-pins qs 6\.11\.0/);
    expect(r.range_check).toMatchObject({ basis: "same_line", smallest_safe_in_range: "4.22.3", safe_versions: ["4.22.3"] });
    expect(r.reason).toMatch(/Safe on 4\.20\.0's line \(4\.x\): smallest 4\.22\.3, newest 4\.22\.3/);
  });

  it("a moderate held advisory alone grades review, as a moderate advisory of `to` itself does", async () => {
    NPM.express.versions["4.20.0"] = { dependencies: { qs: "6.11.0", "path-to-regexp": "~0.1.13", cookie: "0.6.0" } };
    const r = (await check([{ ecosystem: "npm", package: "express", to: "4.20.0" }])).results[0];
    expect(r.verdict).toBe("review");
    expect(advisoriesOf(r).value.held_dependencies_affected.map((d: { package: string }) => d.package)).toEqual(["qs"]);
  });

  it("{to: 4.x}: the smallest safe release skips the ones that hold an affected dependency, narrow ranges included", async () => {
    const r = (await check([{ ecosystem: "npm", package: "express", from: "4.16.4", to: "4.x" }])).results[0];
    expect(r.to).toBe("4.22.3");
    expect(r.verdict).toBe("proceed");
    expect(r.range_check).toMatchObject({ basis: "requested", smallest_safe_in_range: "4.22.3", smallest_safe_upgrade: "4.22.3", safe_versions: ["4.22.3"], held_excluded: 3 });
    expect(r.reason).toMatch(/3 releases clear of express's own advisories left out/);
  });

  it("fails closed: when the held dependencies cannot be looked up, `to` is unknown, never proceed", async () => {
    HELD_LOOKUP_DOWN = true;
    const r = (await check([{ ecosystem: "npm", package: "express", to: "4.20.0" }])).results[0];
    expect(r.verdict).toBe("unknown");
    expect(advisoriesOf(r)).toMatchObject({ effect: "unknown" });
    expect(advisoriesOf(r).evidence).toMatch(/was not checked/);
  });
});

describe("upgrade_planner: a transitive row's target is judged the same way (pr-007, 4DA #1039)", () => {
  it("serve-static 1.13.2 under express goes to 1.16.1, not 1.16.0 (which exact-pins an affected send)", async () => {
    // The real ids and bounds (OSV 2026-10-27), the releases cut down to the ones that decide it.
    ADVISORIES["serve-static"] = [adv("GHSA-cm22-4g7w-348p", "serve-static", "1.16.0", "LOW")];
    ADVISORIES.send = [adv("GHSA-m6fv-jmcg-4jfg", "send", "0.19.0", "LOW")];
    NPM["serve-static"] = {
      latest: "1.16.2",
      versions: {
        "1.13.2": { dependencies: { send: "0.16.2" } },
        "1.16.0": { dependencies: { send: "0.18.0" } },
        "1.16.1": { dependencies: { send: "0.19.0" } },
        "1.16.2": { dependencies: { send: "0.19.0" } },
      },
    };
    NPM.send = { latest: "0.19.0", versions: { "0.16.2": {}, "0.18.0": {}, "0.19.0": {} } };
    const packages = {
      "": { name: "x", dependencies: { express: "4.16.4" } },
      "node_modules/express": { version: "4.16.4", dependencies: { "serve-static": "1.13.2" } },
      "node_modules/serve-static": { version: "1.13.2", dependencies: { send: "0.16.2" } },
      "node_modules/send": { version: "0.16.2" },
    };
    fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
    try {
      const result = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, await liveFor())) as Record<string, any>;
      const row = result.recommendations.find((s: { package: string; currentVersion: string }) => s.package === "serve-static" && s.currentVersion === "1.13.2");
      expect(row?.targetVersion).toBe("1.16.1");
      expect(row.reasons.join(" ")).toMatch(/1\.16\.0 exact-pins send 0\.18\.0 \(GHSA-m6fv-jmcg-4jfg\)/);
      // 6.2.6 delta audit F5: a held-blocked transitive row is never summed as fixed, nor blamed on the network.
      NPM["serve-static"].versions["1.16.1"] = { dependencies: { send: "0.18.0" } };
      NPM["serve-static"].versions["1.16.2"] = { dependencies: { send: "0.18.0" } };
      const blocked = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, await liveFor())) as Record<string, any>;
      const stuck = blocked.recommendations.find((s: { package: string; currentVersion: string }) => s.package === "serve-static" && s.currentVersion === "1.13.2");
      expect(stuck).toMatchObject({ targetVersion: null, reasons: expect.arrayContaining([expect.stringMatching(/^NOT CHECKED: 1.16.0 /)]), fixPathChecked: "installed_advisories_only" });
      expect(blocked.summary).toMatch(/1 fix target NOT a clean fix: the release exact-pins, narrowly ranges or holds a range whose newest release is affected/);
      expect(blocked.summary).not.toMatch(/did not answer in time/);
    } finally {
      delete ADVISORIES["serve-static"];
      delete ADVISORIES.send;
    }
  });
});

describe("upgrade_planner: 6.2.6 second review (I1, I2)", () => {
  it("I1: a direct target that is NOT a clean fix is not counted as upgradable", async () => {
    NPM.express.versions["4.22.3"] = { dependencies: { qs: "6.13.0", "path-to-regexp": "0.1.13", cookie: "0.7.1" } };
    const result = (await executeUpgradePlanner(noDb, { project_path: dir, package: "express" }, await liveFor())) as Record<string, any>;
    expect(result.recommendations.find((s: { package: string }) => s.package === "express")).toMatchObject({ targetVersion: null, reasons: expect.arrayContaining([expect.stringMatching(/^NOT CHECKED: 4.20.0 /)]), fixPathChecked: "installed_advisories_only" });
    expect(result.summary).toMatch(/1 fix target NOT a clean fix/);
    expect(result.summary).not.toMatch(/upgradable directly/);
  });

  it("I2: a target the registry does not list yet is said, and what it pins is NOT CHECKED, never clean", async () => {
    // express's own advisory names 5.0.1, newer than every release the registry lists (latest 5.0.0),
    // and the registry, asked for 5.0.1 by name, does not answer: whether it is published is unknown.
    ADVISORIES.express = [adv("GHSA-qw6h-vgh9-j6wx", "express", "5.0.1", "LOW")];
    MISSING_RELEASE_STATUS = 503;
    try {
      const result = (await executeUpgradePlanner(noDb, { project_path: dir, package: "express" }, await liveFor())) as Record<string, any>;
      const row = result.recommendations.find((s: { package: string }) => s.package === "express");
      expect(row).toMatchObject({ targetVersion: null, reasons: expect.arrayContaining([expect.stringMatching(/^NOT CHECKED: 5.0.1 /)]), fixPathChecked: "installed_advisories_only" });
      const reasons = row.reasons.join(" ");
      expect(reasons).toMatch(/5\.0\.1 is an advisory's fixed version newer than every release the registry listed when it was read: confirm it is published/);
      expect(reasons).toMatch(/NOT CHECKED \(the npm registry does not list 5\.0\.1 yet/);
    } finally {
      ADVISORIES.express = [adv("GHSA-qw6h-vgh9-j6wx", "express", "4.20.0", "LOW"), adv("GHSA-rv95-896h-c2vc", "express", "4.19.2", "MODERATE")];
    }
  });

  it("a fixed version the registry, asked for it by name, does not serve is never the target (audit 2026-11-11, M6)", async () => {
    // The same advisory, and this time the registry answers 404 for express@5.0.1: it does not exist.
    ADVISORIES.express = [adv("GHSA-qw6h-vgh9-j6wx", "express", "5.0.1", "LOW")];
    try {
      const result = (await executeUpgradePlanner(noDb, { project_path: dir, package: "express" }, await liveFor())) as Record<string, any>;
      const row = result.recommendations.find((s: { package: string }) => s.package === "express");
      expect(row).toMatchObject({ targetVersion: null, action: "no_fix_available", fixPathChecked: "all_advisories" });
      expect(row.withheld).toEqual(["5.0.1"]);
      const reasons = row.reasons.join(" ");
      expect(reasons).toMatch(/No installable fix: 5\.0\.1 is not a version the npm registry serves for express \(asked for by name\), and no later release is known to clear it/);
      expect(reasons).not.toMatch(/confirm it is published/);
      expect(JSON.stringify(row)).not.toMatch(/npm install/);
      // The scan's own fix target says the same.
      const scan = (await executeVulnerabilityScan(noDb, { project_path: dir, response_format: "detailed" }, await liveFor())) as Record<string, any>;
      expect(scan.fix_targets["express@4.16.4"]).toMatchObject({ target: null, withheld: ["5.0.1"] });
      expect(scan.vulnerabilities[0]).toMatchObject({ fixed_version: null, withheld: ["5.0.1"] });
    } finally {
      ADVISORIES.express = [adv("GHSA-qw6h-vgh9-j6wx", "express", "4.20.0", "LOW"), adv("GHSA-rv95-896h-c2vc", "express", "4.19.2", "MODERATE")];
    }
  });
});

describe("upgrade_planner: a direct row's target is judged the same way", () => {
  it("planned on its own (package: express), express goes to 4.22.3 as the scan says", async () => {
    const result = (await executeUpgradePlanner(noDb, { project_path: dir, package: "express" }, await liveFor())) as Record<string, any>;
    const express = result.recommendations.find((s: { package: string }) => s.package === "express");
    expect(express).toMatchObject({ targetVersion: "4.22.3", fixPathChecked: "all_advisories" });
    expect(express.reasons.join(" ")).toMatch(/4\.20\.0 exact-pins qs 6\.11\.0/);
  });
});

/**
 * Black-box audit of 5d709ff (r7 BLOCKER): `{express, "4.x"}` healthy said safe smallest/newest
 * 4.22.3; with OSV failing only for express's own dependencies it said `unknown` and
 * safe {smallest 4.20.0, newest 4.22.3}, and the summary told the agent to write a safe version
 * the item names. A failed check never makes the safe set wider than the healthy one.
 */
describe("r7 blocker: a held check that could not run never widens the safe set", () => {
  const safeOf = (r: Record<string, any>) => ({
    smallest: r.range_check?.smallest_safe_in_range ?? null,
    newest: r.range_check?.newest_safe_in_range ?? null,
    list: r.range_check?.safe_versions ?? [],
  });
  const wider = (healthy: string[], faulted: string[]) => faulted.filter((v) => !healthy.includes(v));

  it("{to: 4.x} with OSV down for express's dependencies: no release named safe, NOT CHECKED, never wider than healthy", async () => {
    const healthy = (await check([{ ecosystem: "npm", package: "express", to: "4.x" }])).results[0];
    expect(safeOf(healthy)).toMatchObject({ smallest: "4.22.3", newest: "4.22.3" });
    HELD_LOOKUP_DOWN = true;
    const out = await check([{ ecosystem: "npm", package: "express", to: "4.x" }]);
    const r = out.results[0];
    expect(r.verdict).toBe("unknown");
    const s = safeOf(r);
    expect(wider(safeOf(healthy).list, s.list)).toEqual([]);
    expect(s.smallest).toBeNull();
    expect(s.newest).toBeNull();
    // Nor a release outside the range in its place: the healthy answer names none.
    expect(r.range_check?.newest_safe_outside_range ?? null).toBeNull();
    expect(r.reason).toMatch(/NOT CHECKED/);
    expect(r.reason).not.toMatch(/Safe in 4\.x: smallest/);
    expect(out.summary).not.toMatch(/write a safe version the item names/i);
  });

  it("{from 4.16.4, to: 4.x}: the smallest safe upgrade is not named either", async () => {
    HELD_LOOKUP_DOWN = true;
    const r = (await check([{ ecosystem: "npm", package: "express", from: "4.16.4", to: "4.x" }])).results[0];
    expect(r.verdict).toBe("unknown");
    expect(r.range_check?.smallest_safe_upgrade ?? null).toBeNull();
    expect(r.range_check?.smallest_safe_in_range ?? null).toBeNull();
  });

  it("an exact affected `to` (4.20.0): the same-line safe releases are not named from an unchecked held lookup", async () => {
    HELD_LOOKUP_DOWN = true;
    ADVISORIES.express.push(adv("GHSA-test-only-0420", "express", "4.21.0", "MODERATE"));
    try {
      const r = (await check([{ ecosystem: "npm", package: "express", to: "4.20.0" }])).results[0];
      expect(["review", "avoid"]).toContain(r.verdict);
      expect(r.range_check?.smallest_safe_in_range ?? null).toBeNull();
      expect(r.reason).not.toMatch(/Safe on 4\.20\.0's line/);
    } finally {
      ADVISORIES.express.pop();
    }
  });

  it("the npm registry unreadable for what releases hold: no release named safe", async () => {
    // The packument serves dependency_check's index; releaseFacts reads the same URL. Make every
    // release hold something and the held lookup fail: the same answer as the OSV fault.
    HELD_LOOKUP_DOWN = true;
    const r = (await check([{ ecosystem: "npm", package: "express", to: "^4.21.0" }])).results[0];
    expect(r.range_check?.smallest_safe_in_range ?? null).toBeNull();
  });
});

describe("upgrade_impact: the target is judged by what it installs (pre-publish round 10, W6)", () => {
  // express 4.21.2 exact-pins qs 6.13.0 and path-to-regexp 0.1.12; upgrade_impact said
  // `advisories_remaining: []` and "2 advisories fixed", as if installing it were clean.
  const impact = async (to: string) =>
    (await executeUpgradeImpact(noDb, { ecosystem: "npm", package: "express", from_version: "4.16.4", to_version: to }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;

  it("4.21.2 names the held advisories, is not summarised as clean, and names 4.22.3 as the first clean release", async () => {
    const r = await impact("4.21.2");
    expect(r.advisories_remaining).toEqual([]);
    expect(r.held_dependencies_affected.map((d: { package: string; installs: string }) => `${d.package}@${d.installs}`).sort()).toEqual(["path-to-regexp@0.1.12", "qs@6.13.0"]);
    expect(r.held_dependencies_affected.find((d: { package: string }) => d.package === "qs").advisories).toEqual(["GHSA-4mjr-xmp4-gh2g"]);
    expect(r.first_clean_release).toBe("4.22.3");
    expect(r.summary).toMatch(/advisories fixed; but 4\.21\.2 exact-pins qs 6\.13\.0 \(GHSA-4mjr-xmp4-gh2g\) and path-to-regexp 0\.1\.12 \(GHSA-37ch-88jc-xwx2\): installing 4\.21\.2 installs them, so 4\.21\.2 is not a clean target; 4\.22\.3 is the first later release on its line/);
    expect(r.held_note).toBe(r.summary.split("; but ")[1].replace(/\.$/, ""));
  });

  it("a target whose held dependencies are clean (4.22.3) carries no held fields", async () => {
    const r = await impact("4.22.3");
    expect(r).not.toHaveProperty("held_dependencies_affected");
    expect(r).not.toHaveProperty("held_dependencies_unchecked");
    expect(r.summary).not.toMatch(/; but |NOT CHECKED/);
  });

  it("no later release on the line clears them: nothing is named clean", async () => {
    NPM.express.versions["4.22.3"] = { dependencies: { qs: "6.13.0", "path-to-regexp": "0.1.13", cookie: "0.7.1" } };
    const r = await impact("4.21.2");
    expect(r.first_clean_release).toBeNull();
    expect(r.summary).toMatch(/so 4\.21\.2 is not a clean target; no later release on its line up to 4\.22\.3 that its own advisories leave clean clears them: confirm a release with dependency_check/);
  });

  it("fails closed: the held lookup down is NOT CHECKED, never clean", async () => {
    HELD_LOOKUP_DOWN = true;
    const r = await impact("4.21.2");
    expect(r.held_dependencies_unchecked).toEqual(expect.any(String));
    expect(r).not.toHaveProperty("held_dependencies_affected");
    expect(r).not.toHaveProperty("first_clean_release");
    expect(r.summary).toMatch(/; NOT CHECKED: whether the dependencies 4\.21\.2 holds \(its exact pins and ranges\) have known advisories could not be checked \(.+\); installing 4\.21\.2 installs them, so this is not a clean result\.$/);
  });

  it("fails closed: with no advisory lookup at all (no live layer), a target that holds something is NOT CHECKED", async () => {
    const r = (await analyzeUpgradeImpact(
      { ecosystem: "npm", package: "express", from_version: "4.16.4", to_version: "4.21.2" },
      { net: createUpgradeNet(null), projectRoot: null, installed: [], offline: false, held: null },
    )) as Record<string, any>;
    expect(r.held_dependencies_unchecked).toBe("this server has no advisory lookup for them");
    expect(r.summary).toMatch(/NOT CHECKED/);
    // A release that holds nothing needs no lookup, and says nothing of the kind.
    NPM.express.versions["4.21.2"] = { dependencies: {} };
    const clean = (await analyzeUpgradeImpact(
      { ecosystem: "npm", package: "express", from_version: "4.16.4", to_version: "4.21.2" },
      { net: createUpgradeNet(null), projectRoot: null, installed: [], offline: false, held: null },
    )) as Record<string, any>;
    expect(clean).not.toHaveProperty("held_dependencies_unchecked");
  });
});
