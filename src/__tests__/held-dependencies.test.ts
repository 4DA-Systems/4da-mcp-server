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
import { exactPinVersion, heldSpecsOf, isNarrowRange } from "../live/held-dependencies.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
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
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: ADVISORIES[q.package.name] ?? [] });
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
const advisoriesOf = (r: { signals: Array<{ id: string }> }) => r.signals.find((s) => s.id === "advisories") as { value: any; effect: string; evidence: string };

describe("held dependencies: what an npm spec installs whatever the lockfile holds", () => {
  it("an exact pin is a bare version or =version; a narrow range is capped below the next major", () => {
    expect(exactPinVersion("6.11.0")).toBe("6.11.0");
    expect(exactPinVersion("=6.11.0")).toBe("6.11.0");
    expect(exactPinVersion("v1.2.3-beta.1")).toBe("1.2.3-beta.1");
    for (const spec of ["^6.11.0", "~6.11.0", "6.x", ">=6", "*", "latest", "npm:qs@6.11.0", "git+https://x/y.git"]) expect(exactPinVersion(spec), spec).toBeNull();
    for (const spec of ["~6.14.0", "^0.1.12", "0.1.x", "1.2", ">=1.2.0 <1.3.0", "1.2.0 - 1.4.0"]) expect(isNarrowRange(spec), spec).toBe(true);
    for (const spec of ["^6.14.0", ">=1", "*", "latest", "6.11.0", "1.x || 2.x", "file:../x"]) expect(isNarrowRange(spec), spec).toBe(false);
    expect(heldSpecsOf({ qs: "6.11.0", send: "~0.19.0", debug: "^2.6.9" }, { fsevents: "1.2.9" })).toEqual({ qs: "6.11.0", send: "~0.19.0", fsevents: "1.2.9" });
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
    expect(concise.vulnerable_packages[0]).toMatchObject({ fixed_version: "4.20.0", fix_checked: "installed_advisories_only" });
    expect(concise.recommendations[0]).toMatch(/4\.20\.0 exact-pins qs 6\.11\.0 .*no release on its line up to 4\.22\.3 that its own advisories leave clean clears them, so 4\.20\.0 is NOT a clean fix/);
  });

  it("a release whose held dependencies cannot be judged is named NOT CHECKED, never counted as not clearing them (4DA #1039)", async () => {
    NPM.express.versions["4.22.3"] = { dependencies: { qs: "6.13.0", "path-to-regexp": "0.1.13", cookie: "0.7.1" } };
    // 4.21.2 narrowly ranges a package the registry does not serve: what it installs cannot be read.
    NPM.express.versions["4.21.2"] = { dependencies: { "gone-dep": "~1.0.0" } };
    const concise = await scan();
    expect(concise.vulnerable_packages[0]).toMatchObject({ fixed_version: "4.20.0", fix_checked: "installed_advisories_only" });
    expect(concise.recommendations[0]).toMatch(
      /no release on its line up to 4\.22\.3 that its own advisories leave clean clears them, of the releases that could be checked \(4\.21\.2 NOT CHECKED\), so 4\.20\.0 is NOT a clean fix/,
    );
  });

  it("fails closed: when the held dependencies cannot be looked up, the claim is not upgraded", async () => {
    HELD_LOOKUP_DOWN = true;
    const concise = await scan();
    // The advisories' own target, never a release picked without the check, and never "all_advisories".
    expect(concise.vulnerable_packages[0]).toMatchObject({ fixed_version: "4.20.0", fix_checked: "installed_advisories_only" });
    expect(concise.recommendations[0]).toMatch(/whether the dependencies 4\.20\.0 exact-pins or narrowly ranges are affected was NOT CHECKED/);
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
      expect(stuck).toMatchObject({ targetVersion: "1.16.0", fixPathChecked: "installed_advisories_only" });
      expect(blocked.summary).toMatch(/1 fix target NOT a clean fix: the release pins \(or narrowly ranges\) an affected dependency/);
      expect(blocked.summary).not.toMatch(/did not answer in time/);
    } finally {
      delete ADVISORIES["serve-static"];
      delete ADVISORIES.send;
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
