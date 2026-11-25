// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, blind check of the integrated build: what_should_i_know still wrote repository
 * directory names raw into its sentences (`advisories[].action` = "Upgrade lodash 4.17.20 -> 4.18.1
 * in packages/a$(PWN1), packages/b`PWN2`, ..."), as could dependency_health and upgrade_impact.
 * Every sentence of the four tools now names such a directory escaped; the only strings that may
 * hold a raw name are data fields named here (upgrade_impact's `your_code.files[].path`).
 *
 * The fixture is the reviewer's ws-hostile workspace, rebuilt in a temp folder; the network is the
 * harness's stubbed fetch (nothing leaves the process; a dead proxy would route around the stub).
 */

import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeUpgradeImpact } from "../tools/upgrade-impact.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const HOSTILE = ["a$(PWN1)", "b`PWN2`", "c;PWN3", "--registry=PWN4", "e'PWN5'", "f %PWN6%"];
/** Data fields that may hold a path verbatim: upgrade_impact's file list. */
const DATA_KEYS = new Set(["path"]);

let h: Harness;
const PROXY_VARS = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of PROXY_VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  h = createHarness();
  h.ADVISORIES.lodash = [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21"))];
  h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } } };
  const members = HOSTILE.map((d) => `packages/${d}`);
  const packages: Record<string, unknown> = { "": { name: "root", version: "1.0.0", workspaces: ["packages/*"] } };
  for (const [i, m] of members.entries()) {
    const manifest = { name: `m${i}`, version: "1.0.0", dependencies: { lodash: "4.17.20" } };
    h.write(`${m}/package.json`, JSON.stringify(manifest));
    packages[m] = manifest;
    packages[`node_modules/m${i}`] = { resolved: m, link: true };
  }
  packages["node_modules/lodash"] = { version: "4.17.20" };
  h.write("package.json", JSON.stringify({ name: "root", version: "1.0.0", private: true, workspaces: ["packages/*"] }));
  h.write("package-lock.json", JSON.stringify({ name: "root", version: "1.0.0", lockfileVersion: 3, requires: true, packages }));
});
afterEach(() => {
  h.dispose();
  for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
});

function live(): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(h.dir);
  li.initFromProjectTree(h.dir, treeResolutionGroups(entries), discovery);
  return li;
}

/** Every string outside DATA_KEYS that holds a hostile directory name raw. */
function rawHits(value: unknown): string[] {
  const hits: string[] = [];
  const walk = (v: unknown, key: string | null, at: string) => {
    if (typeof v === "string") {
      if (key !== null && DATA_KEYS.has(key)) return;
      for (const d of HOSTILE) if (v.includes(d)) hits.push(`${at}: ${v.slice(0, 200)}`);
    } else if (Array.isArray(v)) v.forEach((x, i) => walk(x, key, `${at}[${i}]`));
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, k, `${at}.${k}`);
  };
  walk(value, null, "$");
  return hits;
}

describe("no sentence of the four tools carries a raw unsafe directory name", () => {
  it("what_should_i_know (its advisories name the directories)", async () => {
    const intel = live();
    await executeVulnerabilityScan(null, { project_path: h.dir }, intel);
    const out = await executeWhatShouldIKnow(null, { task: "upgrade lodash in every project" }, intel);
    const text = JSON.stringify(out);
    expect(text).toMatch(/PWN1/);
    expect(rawHits(out)).toEqual([]);
  });

  it("dependency_health", async () => {
    const intel = live();
    const out = await executeDependencyHealth(null, {}, intel);
    expect(rawHits(out)).toEqual([]);
  });

  it("upgrade_impact (file paths are data and may stay)", async () => {
    const intel = live();
    const out = await executeUpgradeImpact(null, { package: "lodash", to_version: "4.17.21" }, intel);
    expect(rawHits(out)).toEqual([]);
  });

  it("upgrade_planner and vulnerability_scan", async () => {
    const plan = await executeUpgradePlanner(null, { project_path: h.dir, max_recommendations: 50 }, live());
    expect(rawHits(plan)).toEqual([]);
    const scan = await executeVulnerabilityScan(null, { project_path: h.dir, response_format: "detailed" }, live());
    expect(rawHits(scan)).toEqual([]);
  });
});
