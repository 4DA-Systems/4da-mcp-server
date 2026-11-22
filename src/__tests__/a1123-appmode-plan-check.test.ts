// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_planner with the desktop app's database attached (DESIGN section 3):
 *
 * - one project's answer is always this server's own plan from the lockfiles on disk
 *   (`provenance.mode: "lockfile_engine"`), never the app's stored plan relayed;
 * - `app_plan_check` compares the app's stored plan for that project with it, by ecosystem +
 *   package + installed version, and says when it cannot (`no_plan`, `not_comparable`);
 * - `include_dev: false` is honoured and no other project's versions reach a scoped answer;
 * - for every project ("*") the answer is the app's stored plan, labelled unverified, and stale
 *   whenever its expiry, its advisory data's age or a changed lockfile says so.
 *
 * The app database is built from the vendored app schema; OSV.dev and the npm registry are stubbed.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeUpgradePlanner, type UpgradePlanResult } from "../tools/upgrade-planner.js";
import type { AppPlanResult } from "../tools/app-plan.js";
import { normalizeProjectPath } from "../tools/project-scope.js";
import { advisory, installFetchStub, type Stub } from "./helpers/briefing-stub.js";
import { buildAppDb, npmProject, VENDORED_APP_SCHEMA } from "./helpers/a1123-appmode.js";

const HOUR = 3_600_000;
const iso = (ms: number) => new Date(ms).toISOString();
/** SQLite's `datetime('now')` form, as the app writes `osv_sync_status`. */
const sqlTime = (ms: number) => iso(ms).replace("T", " ").slice(0, 19);

let root: string;
let project: string;
let other: string;
let elsewhere: string;
let priorProjectDir: string | undefined;
const opened: FourDADatabase[] = [];
let stub: Stub;

type Site = { project: string; direct: boolean; dev: boolean };
const site = (dir: string, dev = false): Site => ({ project: normalizeProjectPath(dir), direct: true, dev });

function step(pkg: string, lines: Array<[string, string | null, Site[]]>, mechanism = "manifest_bump") {
  return {
    item_id: `upgrade-plan:npm:${pkg}`,
    ecosystem: "npm",
    package: pkg,
    lines: lines.map(([installed, target, sites]) => ({ installed, target, upgrade_type: target ? "patch" : null, clears_all_known: target !== null, sites })),
    mechanism,
    advisory_ids: ["GHSA-test"],
    verification: "re-run 4da plan --json",
  };
}

function snapshot(steps: ReturnType<typeof step>[], over: Record<string, unknown> = {}) {
  const now = Date.now();
  return {
    schema_version: 5,
    generated_at: iso(now - HOUR),
    expires_at: iso(now + 5 * HOUR),
    generator_version: "1.0.4",
    entitlement_scope_at_generation: "free",
    multi_version_coverage: true,
    dependency_inventory_hash: "fixture",
    validation_drop_count: 0,
    source_freshness: sqlTime(now - 2 * HOUR),
    engine_run_id: null,
    item_count: steps.length,
    items: steps.map((s) => ({ id: s.item_id, title: `Upgrade ${s.package}`, urgency: "high" })),
    steps,
    ...over,
  };
}

/** An app database (the vendored app schema) holding `plan` and an advisory sync `syncedHoursAgo` hours old. */
function appDb(name: string, plan: unknown | null, syncedHoursAgo = 2): FourDADatabase {
  const file = path.join(root, `${name}.db`);
  buildAppDb(file, VENDORED_APP_SCHEMA, (raw) => {
    if (plan !== null) raw.prepare("INSERT INTO kv_store (key, value) VALUES (?, ?)").run("upgrade_plan_snapshot", JSON.stringify(plan));
    raw.prepare("INSERT INTO osv_sync_status (ecosystem, last_synced_at, advisory_count, error) VALUES (?, ?, 10, NULL)").run("npm", sqlTime(Date.now() - syncedHoursAgo * HOUR));
    raw.prepare("INSERT INTO project_dependencies (project_path, manifest_type, package_name, version, language) VALUES (?, 'package.json', 'minimist', '1.2.5', 'javascript')").run(normalizeProjectPath(project));
  });
  const db = new FourDADatabase(file);
  opened.push(db);
  return db;
}

function live(dir: string): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

/** Lockfiles written well before any plan the tests store (a plan is never older than the disk by accident). */
function backdate(dir: string): void {
  const then = new Date(Date.now() - 48 * HOUR);
  for (const f of ["package.json", "package-lock.json"]) fs.utimesSync(path.join(dir, f), then, then);
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-plancheck-"));
  project = path.join(root, "web");
  other = path.join(root, "other-project");
  elsewhere = path.join(root, "not-a-project");
  npmProject(project, { minimist: "1.2.5", lodash: "4.17.20" }, { braces: "3.0.2" });
  // A directory the repository ignores: the app indexes it, this server does not scan it.
  fs.writeFileSync(path.join(project, ".gitignore"), "ignored/\n");
  npmProject(path.join(project, "ignored"), { qs: "6.5.2" });
  backdate(path.join(project, "ignored"));
  npmProject(other, { qs: "6.5.2" });
  fs.mkdirSync(elsewhere, { recursive: true });
  backdate(project);
  backdate(other);
  priorProjectDir = process.env.FOURDA_PROJECT_DIR;
});

afterAll(() => {
  if (priorProjectDir === undefined) delete process.env.FOURDA_PROJECT_DIR;
  else process.env.FOURDA_PROJECT_DIR = priorProjectDir;
  for (const db of opened) db.close();
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

beforeEach(() => {
  process.env.FOURDA_PROJECT_DIR = project;
  stub = {
    npm: {
      minimist: { latest: "1.2.8", versions: ["1.2.5", "1.2.6", "1.2.7", "1.2.8"] },
      lodash: { latest: "4.17.21", versions: ["4.17.20", "4.17.21"] },
      braces: { latest: "3.0.3", versions: ["3.0.2", "3.0.3"] },
      qs: { latest: "6.5.3", versions: ["6.5.2", "6.5.3"] },
    },
    osv: [
      advisory("GHSA-xvch-5gv4-984h", "minimist", "CRITICAL", { fixed: "1.2.6" }),
      advisory("GHSA-35jh-r3h4-6jhm", "lodash", "HIGH", { fixed: "4.17.21" }),
      advisory("GHSA-grv7-fg5c-xmjg", "braces", "HIGH", { fixed: "3.0.3" }),
      advisory("GHSA-hrpp-h998-j3pp", "qs", "HIGH", { fixed: "6.5.3" }),
    ],
    asked: [],
  };
  installFetchStub(stub);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function planFor(db: FourDADatabase, params: Record<string, unknown> = {}): Promise<UpgradePlanResult> {
  return (await executeUpgradePlanner(db, params, live(project))) as UpgradePlanResult;
}

const rowOf = (r: UpgradePlanResult, pkg: string) => r.recommendations.find((x) => x.package === pkg);

describe("one project: this server's plan, never the app's stored one", () => {
  it("a stored plan with 0 steps while the lockfile pins vulnerable minimist: the answer carries the minimist row, and the check says the plans differ", async () => {
    const result = await planFor(appDb("zero-steps", snapshot([])));
    expect(result.provenance.mode).toBe("lockfile_engine");
    expect(result.provenance.note).toContain("lockfiles on disk");
    expect(rowOf(result, "minimist")).toMatchObject({ currentVersion: "1.2.5", targetVersion: "1.2.6" });
    const check = result.app_plan_check!;
    expect(check.status).toBe("differs");
    expect(check.differences).toContainEqual({ ecosystem: "npm", package: "minimist", installed: "1.2.5", app_target: null, server_target: "1.2.6" });
    expect(check.note).toMatch(/^This answer is computed from the lockfiles on disk; the 4DA app's stored plan \(generated .+\) differs from it on \d+ packages?/);
    expect(check.plan_generated_at).toBeTypeOf("string");
    expect(check.advisory_data_age_hours).toBeGreaterThanOrEqual(1.9);
    expect(check.advisory_data_age_hours).toBeLessThan(3);
  });

  it("agrees when the stored plan names the same targets for the same installed copies", async () => {
    const plan = snapshot([
      step("minimist", [["1.2.5", "1.2.6", [site(project)]]]),
      step("lodash", [["4.17.20", "4.17.21", [site(project)]]]),
      step("braces", [["3.0.2", "3.0.3", [site(project, true)]]]),
    ]);
    const result = await planFor(appDb("agrees", plan));
    expect(result.app_plan_check?.status).toBe("agrees");
    expect(result.app_plan_check?.differences).toBeUndefined();
    expect(result.app_plan_check?.note).toContain("agrees with it on every package");
  });

  it("differs when a target disagrees, or when the stored plan moves a copy the lockfile no longer holds", async () => {
    const plan = snapshot([
      step("minimist", [["1.2.5", "1.2.8", [site(project)]]]),
      step("lodash", [["4.17.20", "4.17.21", [site(project)]]]),
      step("braces", [["3.0.2", "3.0.3", [site(project, true)]]]),
      // An upgrade already done: the lockfile no longer holds 4.17.15.
      step("left-pad", [["1.0.0", "1.3.0", [site(project)]]]),
    ]);
    const result = await planFor(appDb("differs", plan));
    const check = result.app_plan_check!;
    expect(check.status).toBe("differs");
    expect(check.differences).toEqual(
      expect.arrayContaining([
        { ecosystem: "npm", package: "minimist", installed: "1.2.5", app_target: "1.2.8", server_target: "1.2.6" },
        { ecosystem: "npm", package: "left-pad", installed: "1.0.0", app_target: "1.3.0", server_target: null },
      ]),
    );
    expect(check.differences).toHaveLength(2);
    expect(check.note).toContain("differs from it on 2 packages");
    // The answer is still this server's.
    expect(rowOf(result, "minimist")?.targetVersion).toBe("1.2.6");
  });

  it("a stored step in a directory .gitignore excludes is not planned, and not counted as a difference", async () => {
    const plan = snapshot([
      step("minimist", [["1.2.5", "1.2.6", [site(project)]]]),
      step("lodash", [["4.17.20", "4.17.21", [site(project)]]]),
      step("braces", [["3.0.2", "3.0.3", [site(project, true)]]]),
      step("qs", [["6.5.2", "6.5.3", [site(path.join(project, "ignored"))]]]),
    ]);
    const result = await planFor(appDb("ignored-dir", plan));
    expect(rowOf(result, "qs")).toBeUndefined();
    expect(result.app_plan_check?.status).toBe("agrees");
    expect(result.app_plan_check?.note).toContain("1 of the app's rows are in directories this answer does not scan");
    expect(result.summary).toContain("ignored/package-lock.json");
  });

  it("lists at most 10 differences, and the note gives the full count", async () => {
    const many = Array.from({ length: 13 }, (_, i) => step(`gone-${i}`, [["1.0.0", "2.0.0", [site(project)]]]));
    const check = (await planFor(appDb("many", snapshot(many)))).app_plan_check!;
    expect(check.status).toBe("differs");
    expect(check.differences).toHaveLength(10);
    // 13 gone, plus the three this server plans that the stored plan does not name.
    expect(check.note).toContain("differs from it on 16 packages");
  });

  it("no_plan when the app stored none, saying why", async () => {
    const check = (await planFor(appDb("no-plan", null))).app_plan_check!;
    expect(check.status).toBe("no_plan");
    expect(check.note).toContain("has not computed an upgrade plan");
    expect(check.advisory_data_age_hours).toBeTypeOf("number");
  });

  it("not_comparable when the app's advisory data is 40 days old", async () => {
    const plan = snapshot([step("minimist", [["1.2.5", "1.2.6", [site(project)]]])]);
    const check = (await planFor(appDb("old-advisories", plan, 40 * 24))).app_plan_check!;
    expect(check.status).toBe("not_comparable");
    expect(check.advisory_data_age_hours).toBeGreaterThanOrEqual(959);
    expect(check.note).toMatch(/advisory data was last verified 9\d\d(\.\d)? hours ago/);
    expect(check.note).toContain("more than 24 hours");
    expect(check.differences).toBeUndefined();
  });

  it("not_comparable when the plan's own advisory floor (source_freshness) is old, even with a fresh sync row", async () => {
    const plan = snapshot([step("minimist", [["1.2.5", "1.2.6", [site(project)]]])], { source_freshness: sqlTime(Date.now() - 5 * 24 * HOUR) });
    const check = (await planFor(appDb("old-floor", plan))).app_plan_check!;
    expect(check.status).toBe("not_comparable");
    expect(check.advisory_data_age_hours).toBeGreaterThanOrEqual(119);
  });

  it("not_comparable when the plan was generated before the newest lockfile changed", async () => {
    const plan = snapshot([step("minimist", [["1.2.5", "1.2.6", [site(project)]]])], { generated_at: iso(Date.now() - 72 * HOUR), expires_at: iso(Date.now() + HOUR) });
    const check = (await planFor(appDb("lockfile-newer", plan))).app_plan_check!;
    expect(check.status).toBe("not_comparable");
    expect(check.note).toMatch(/generated \(.+\) before package-lock\.json was last modified/);
  });

  it("plan formats 4 and 5 are compared; an unknown format 6 is not_comparable, naming both versions and the side to update", async () => {
    const steps = [step("minimist", [["1.2.5", "1.2.6", [site(project)]]]), step("lodash", [["4.17.20", "4.17.21", [site(project)]]]), step("braces", [["3.0.2", "3.0.3", [site(project, true)]]])];
    expect((await planFor(appDb("format-4", snapshot(steps, { schema_version: 4 })))).app_plan_check?.status).toBe("agrees");
    expect((await planFor(appDb("format-5", snapshot(steps, { schema_version: 5 })))).app_plan_check?.status).toBe("agrees");
    const six = (await planFor(appDb("format-6", snapshot(steps, { schema_version: 6 })))).app_plan_check!;
    expect(six.status).toBe("not_comparable");
    expect(six.note).toContain("format 6");
    expect(six.note).toContain("reads plan formats 4 and 5");
    expect(six.note).toContain("update @4da/mcp-server");
  });
});

describe("a scoped answer is about this project only", () => {
  it("include_dev: false leaves the dev-only copy out, and the stored plan's dev-only line is not counted against it", async () => {
    const plan = snapshot([
      step("minimist", [["1.2.5", "1.2.6", [site(project)]]]),
      step("lodash", [["4.17.20", "4.17.21", [site(project)]]]),
      step("braces", [["3.0.2", "3.0.3", [site(project, true)]]]),
    ]);
    const db = appDb("no-dev", plan);
    const withDev = await planFor(db);
    expect(rowOf(withDev, "braces")).toBeDefined();
    const runtime = await planFor(db, { include_dev: false });
    expect(rowOf(runtime, "braces")).toBeUndefined();
    expect(runtime.recommendations.every((r) => !r.isDev)).toBe(true);
    expect(runtime.app_plan_check?.status).toBe("agrees");
  });

  it("no other project's steps, versions or paths reach the answer", async () => {
    const plan = snapshot([
      step("minimist", [["1.2.5", "1.2.6", [site(project)]]]),
      step("lodash", [["4.17.20", "4.17.21", [site(project)]]]),
      step("braces", [["3.0.2", "3.0.3", [site(project, true)]]]),
      step("qs", [["6.5.2", "6.5.3", [site(other)]]]),
      step("minimist", [["0.0.8", "1.2.6", [site(other)]]]),
    ]);
    const result = await planFor(appDb("scoped", plan));
    const text = JSON.stringify(result);
    expect(result.recommendations.map((r) => r.package).sort()).toEqual(["braces", "lodash", "minimist"]);
    expect(text).not.toContain("qs");
    expect(text).not.toContain("0.0.8");
    expect(text).not.toContain("6.5.2");
    expect(text.toLowerCase()).not.toContain(normalizeProjectPath(other));
    expect(result.app_plan_check?.status).toBe("agrees");
  });
});

describe('every project ("*"): the app\'s stored plan, labelled, and never stale: false when it is stale', () => {
  const steps = () => [step("minimist", [["1.2.5", "1.2.6", [site(project)]]]), step("qs", [["6.5.2", "6.5.3", [site(other)]]])];

  async function allProjects(db: FourDADatabase): Promise<AppPlanResult> {
    return (await executeUpgradePlanner(db, { project_path: "*" }, live(project))) as AppPlanResult;
  }

  it("a fresh plan: stale false, status unverified, and the note says it was not checked against the disk", async () => {
    const result = await allProjects(appDb("all-fresh", snapshot(steps())));
    expect(result.provenance.mode).toBe("app_plan");
    expect(result.stale).toBe(false);
    expect(result.staleness).toBeNull();
    expect(result.app_plan_check.status).toBe("unverified");
    expect(result.app_plan_check.note).toContain("not checked against the lockfiles on disk");
    expect(result.app_plan_check.note).toContain("call upgrade_planner with that project's path");
    expect(result.provenance.note).toContain("not check it against the lockfiles on disk");
    expect(result.steps.map((s) => s.package)).toEqual(["minimist", "qs"]);
  });

  it("an expired plan is stale", async () => {
    const result = await allProjects(appDb("all-expired", snapshot(steps(), { generated_at: iso(Date.now() - 30 * HOUR), expires_at: iso(Date.now() - 24 * HOUR) })));
    expect(result.stale).toBe(true);
    expect(result.staleness).toContain("past its freshness horizon");
    expect(result.app_plan_check.status).toBe("unverified");
  });

  it("40-day-old advisory data: stale, and not_comparable", async () => {
    const result = await allProjects(appDb("all-old-advisories", snapshot(steps()), 40 * 24));
    expect(result.stale).toBe(true);
    expect(result.staleness).toContain("more than 24 hours");
    expect(result.app_plan_check.status).toBe("not_comparable");
    expect(result.app_plan_check.advisory_data_age_hours).toBeGreaterThanOrEqual(959);
  });

  it("a lockfile newer than the plan: stale, naming the project", async () => {
    const changed = path.join(root, "changed-later");
    npmProject(changed, { minimist: "1.2.5" });
    const plan = snapshot([...steps(), step("minimist", [["1.2.5", "1.2.6", [site(changed)]]])]);
    const result = await allProjects(appDb("all-lockfile-newer", plan));
    expect(result.stale).toBe(true);
    expect(result.staleness).toContain("a lockfile changed after the plan was generated");
    expect(result.staleness?.toLowerCase()).toContain(normalizeProjectPath(changed));
    expect(result.staleness?.toLowerCase()).not.toContain(normalizeProjectPath(project));
    expect(result.app_plan_check.status).toBe("unverified");
  });

  it("a server started outside a project is the all-projects scope too", async () => {
    process.env.FOURDA_PROJECT_DIR = elsewhere;
    const result = (await executeUpgradePlanner(appDb("all-default", snapshot(steps())), {}, live(elsewhere))) as AppPlanResult;
    expect(result.provenance.mode).toBe("app_plan");
    expect(result.app_plan_check.status).toBe("unverified");
  });

  it("this server's own words never tell the agent to run a `4da` command", async () => {
    const result = await allProjects(appDb("all-words", snapshot(steps(), { expires_at: iso(Date.now() - HOUR) }), 40 * 24));
    const own = [result.summary, result.staleness ?? "", result.provenance.note, result.app_plan_check.note].join("\n");
    expect(own).not.toMatch(/\b4da plan\b|`4da /);
    // The step's verification text is the app's own, passed through.
    expect(result.steps[0].verification).toBe("re-run 4da plan --json");
  });

  it("an unreadable stored plan: this server's plan, with the check saying why", async () => {
    const result = (await executeUpgradePlanner(appDb("all-format-6", snapshot(steps(), { schema_version: 6 })), { project_path: "*" }, live(project))) as UpgradePlanResult;
    expect(result.provenance.mode).toBe("lockfile_engine");
    expect(result.app_plan_check?.status).toBe("not_comparable");
  });
});
