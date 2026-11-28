// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25 G-3: `upgrade_planner {project_path: "*"}` silently became a plan for the
 * server's own project when the app's stored plan could not be read (no app attached, no plan
 * stored, a newer plan format). The desktop app's Brief hand-off relies on "*" meaning every
 * project. The answer now leads with NOT CHECKED for the all-projects scope, says why, and says
 * what follows covers only this project; it is never CVE-aware for "*".
 *
 * G-6: for "*" the app's plan step said "resolves to the fixed release (0.18.2 -> 0.18.2)": an
 * unverified target is not called "fixed", and a line whose target is its installed version is
 * not printed as a move.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { nextStep, type AppPlanStepView } from "../tools/app-plan.js";
import { executeUpgradePlanner, type UpgradePlanResult } from "../tools/upgrade-planner.js";
import { buildAppDb, VENDORED_APP_SCHEMA } from "./helpers/a1123-appmode.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let dbRoot: string;
const opened: FourDADatabase[] = [];
const PROXY_VARS = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
const saved: Record<string, string | undefined> = {};

beforeAll(() => {
  dbRoot = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1125-all-"));
});
afterAll(() => {
  for (const db of opened) db.close();
  fs.rmSync(dbRoot, { recursive: true, force: true });
});
beforeEach(() => {
  for (const k of PROXY_VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  h = createHarness();
  h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.21": {} } } };
  h.npmProject({ lodash: "4.17.21" }, {}, { lodash: { version: "4.17.21" } });
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

function appDb(name: string, plan: unknown | null): FourDADatabase {
  const file = path.join(dbRoot, `${name}.db`);
  buildAppDb(file, VENDORED_APP_SCHEMA, (raw) => {
    if (plan !== null) raw.prepare("INSERT INTO kv_store (key, value) VALUES (?, ?)").run("upgrade_plan_snapshot", JSON.stringify(plan));
  });
  const db = new FourDADatabase(file);
  opened.push(db);
  return db;
}

describe('upgrade_planner "*" when the app\'s stored plan cannot be read', () => {
  it("the scope of one project is unchanged (control)", async () => {
    const plan = (await executeUpgradePlanner(null, { project_path: h.dir }, live())) as UpgradePlanResult;
    expect(plan.summary).not.toMatch(/every project/);
    expect(plan.vulnerabilityDataAvailable).toBe(true);
  });

  it("no app attached: NOT CHECKED for every project, why, and that only this project follows", async () => {
    const plan = (await executeUpgradePlanner(null, { project_path: "*" }, live())) as UpgradePlanResult;
    expect(plan.provenance.mode).toBe("lockfile_engine");
    expect(plan.summary).toMatch(/^NOT CHECKED: project_path "\*" asks for every project, and only the 4DA app's stored plan covers more than one: /);
    expect(plan.summary).toMatch(/the 4DA desktop app's database is not attached/);
    expect(plan.summary).toContain(`What follows covers only ${h.dir}`);
    expect(plan.vulnerabilityDataAvailable).toBe(false);
    expect(plan.allProjects).toMatchObject({ covered: false });
  });

  it("the app attached with no plan stored: says so", async () => {
    const plan = (await executeUpgradePlanner(appDb("no-plan", null), { project_path: "*" }, live())) as UpgradePlanResult;
    expect(plan.summary).toMatch(/^NOT CHECKED: project_path "\*" asks for every project/);
    expect(plan.summary).toMatch(/has not computed an upgrade plan yet/);
    expect(plan.vulnerabilityDataAvailable).toBe(false);
  });

  it("a plan format newer than this server reads: names the format and which side to update", async () => {
    const plan = (await executeUpgradePlanner(appDb("format-9", { schema_version: 9, steps: [], items: [] }), { project_path: "*" }, live())) as UpgradePlanResult;
    expect(plan.summary).toMatch(/^NOT CHECKED: project_path "\*" asks for every project/);
    expect(plan.summary).toMatch(/format 9/);
    expect(plan.summary).toMatch(/update @4da\/mcp-server/);
    expect(plan.vulnerabilityDataAvailable).toBe(false);
  });
});

describe("no project_path: the answer is what it was before the G-3 lead, whatever the scope resolver says", () => {
  let prior: string | undefined;
  beforeEach(() => {
    prior = process.env.FOURDA_PROJECT_DIR;
  });
  afterEach(() => {
    if (prior === undefined) delete process.env.FOURDA_PROJECT_DIR;
    else process.env.FOURDA_PROJECT_DIR = prior;
  });

  it("a folder holding npm sub-projects and no root manifest: planned, no all-projects lead", async () => {
    const lock = (n: string) => JSON.stringify({ name: n, version: "1.0.0", lockfileVersion: 3, packages: { "": { name: n, version: "1.0.0", dependencies: { lodash: "4.17.21" } }, "node_modules/lodash": { version: "4.17.21" } } });
    for (const d of ["one", "two"]) {
      h.write(`${d}/package.json`, JSON.stringify({ name: d, version: "1.0.0", dependencies: { lodash: "4.17.21" } }));
      h.write(`${d}/package-lock.json`, lock(d));
    }
    fs.rmSync(path.join(h.dir, "package.json"));
    fs.rmSync(path.join(h.dir, "package-lock.json"));
    process.env.FOURDA_PROJECT_DIR = h.dir;
    const plan = (await executeUpgradePlanner(null, {}, live())) as UpgradePlanResult;
    expect(plan.summary).not.toMatch(/every project|NOT CHECKED/);
    expect(plan.allProjects).toBeUndefined();
    expect(plan.vulnerabilityDataAvailable).toBe(true);
  });

  it("a root whose manifests are Ruby's: no all-projects lead", async () => {
    fs.rmSync(path.join(h.dir, "package.json"));
    fs.rmSync(path.join(h.dir, "package-lock.json"));
    h.write("Gemfile", ['source "https://rubygems.org"', 'gem "rack", "2.2.3"', ""].join("\n"));
    h.write("Gemfile.lock", ["GEM", "  remote: https://rubygems.org/", "  specs:", "    rack (2.2.3)", "", "PLATFORMS", "  ruby", "", "DEPENDENCIES", "  rack (= 2.2.3)", ""].join("\n"));
    process.env.FOURDA_PROJECT_DIR = h.dir;
    const plan = (await executeUpgradePlanner(null, {}, live())) as UpgradePlanResult;
    expect(plan.summary).not.toMatch(/every project|covers only/);
    expect(plan.allProjects).toBeUndefined();
  });
});

describe("the app's plan never calls an unverified target fixed, nor prints a no-op move", () => {
  const step = (lines: Array<{ installed: string; target: string | null }>, mechanism: AppPlanStepView["mechanism"] = "lockfile_refresh"): AppPlanStepView => ({
    item_id: "upgrade-plan:npm:esbuild",
    ecosystem: "npm",
    package: "esbuild",
    lines: lines.map((l) => ({ ...l, upgrade_type: l.target && l.target !== l.installed ? "patch" : null, clears_all_known: true, sites: [{ project: "d:/web", direct: false, dev: false }] })),
    mechanism,
    advisory_ids: ["GHSA-x"],
    verification: "v",
    title: null,
    urgency: "medium",
    next_step: "",
  });

  it("a refresh names the app's release, not 'the fixed release'", () => {
    const text = nextStep(step([{ installed: "0.18.1", target: "0.18.2" }]), 5);
    expect(text).not.toMatch(/fixed release/);
    expect(text).toMatch(/^Refresh the lockfile so esbuild resolves to the release the app's plan names \(0\.18\.1 -> 0\.18\.2 \(patch\)\)/);
  });

  it("a line whose target is its installed version is not printed as a move", () => {
    const text = nextStep(step([{ installed: "0.18.2", target: "0.18.2" }, { installed: "0.17.0", target: "0.18.2" }]), 5);
    expect(text).not.toMatch(/0\.18\.2 -> 0\.18\.2/);
    expect(text).toMatch(/0\.17\.0 -> 0\.18\.2/);
  });

  it("a step whose every line is already at its target says there is nothing to move", () => {
    for (const mechanism of ["lockfile_refresh", "manifest_bump", "parent_update", "mixed", "lockfile_or_parent_update"] as const) {
      const text = nextStep(step([{ installed: "0.18.2", target: "0.18.2" }], mechanism), 5);
      expect(text).not.toMatch(/0\.18\.2 -> 0\.18\.2/);
      expect(text).not.toMatch(/fixed release/);
      expect(text).toMatch(/already at the release the app's plan names \(esbuild 0\.18\.2\)/);
    }
  });
});
