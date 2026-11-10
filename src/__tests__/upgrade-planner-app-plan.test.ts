// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_planner reads the 4DA app's plan (AD-049): one brain.
 *
 * Fixture databases hold the `upgrade_plan_snapshot` envelope the Rust app
 * writes (`evidence::plan_snapshot::persist_upgrade_plan`, schema 4; schema 5 at the end). The tool
 * returns that plan's work order when it is current, returns it flagged stale
 * past `expires_at`, and falls back to the standalone heuristic — saying why —
 * when the snapshot is missing, from another schema, or the store is absent.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { executeUpgradePlanner, type UpgradePlanResult } from "../tools/upgrade-planner.js";
import { readAppPlan, APP_PLAN_SCHEMA_VERSIONS, type AppPlanResult } from "../tools/app-plan.js";

let root: string;
const opened: FourDADatabase[] = [];

const UNDICI_ID = "upgrade-plan:npm:undici";
const BRACE_ID = "upgrade-plan:npm:brace-expansion";
const RSA_ID = "upgrade-plan:crates.io:rsa";

function envelope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const hour = 3_600_000;
  return {
    // A schema-4 snapshot, as the app wrote it until 2026-11-10 (schema 5 below).
    schema_version: 4,
    generated_at: new Date(Date.now() - hour).toISOString(),
    expires_at: new Date(Date.now() + 23 * hour).toISOString(),
    generator_version: "1.0.3",
    entitlement_scope_at_generation: "signal",
    multi_version_coverage: true,
    dependency_inventory_hash: "abc",
    validation_drop_count: 0,
    source_freshness: "2026-10-01 00:00:00",
    engine_run_id: null,
    item_count: 3,
    items: [
      { id: UNDICI_ID, title: "Upgrade undici to >= 6.28.1 (major) — clears 3 advisories across 1 project", urgency: "high" },
      { id: BRACE_ID, title: "Upgrade brace-expansion to >= 1.1.21 — clears 1 advisory across 2 projects", urgency: "medium" },
      { id: RSA_ID, title: "No fix published for rsa — 1 advisory across 1 project", urgency: "medium" },
    ],
    steps: [
      {
        item_id: UNDICI_ID,
        ecosystem: "npm",
        package: "undici",
        lines: [
          {
            installed: "5.28.4",
            target: "6.28.1",
            upgrade_type: "major",
            clears_all_known: true,
            sites: [{ project: "c:/users/dev/navcal", direct: false, dev: false }],
          },
        ],
        mechanism: "lockfile_or_parent_update",
        advisory_ids: ["GHSA-3wwx-pv8p-q78v", "GHSA-8xcm-r25x-g524", "GHSA-cxrh-j4jr-qwg3"],
        verification: "re-run 4da plan --json",
      },
      {
        item_id: BRACE_ID,
        ecosystem: "npm",
        package: "brace-expansion",
        lines: [
          {
            installed: "1.1.12",
            target: "1.1.21",
            upgrade_type: "patch",
            clears_all_known: true,
            sites: [
              { project: "c:/users/dev/navcal", direct: false, dev: true },
              { project: "d:/web", direct: true, dev: false },
            ],
          },
        ],
        mechanism: "mixed",
        advisory_ids: ["GHSA-q2hr-2g5m-vwhr"],
        verification: "re-run 4da plan --json",
      },
      {
        item_id: RSA_ID,
        ecosystem: "crates.io",
        package: "rsa",
        lines: [
          {
            installed: "0.9.8",
            target: null,
            upgrade_type: null,
            clears_all_known: false,
            sites: [{ project: "d:/relay", direct: true, dev: false }],
          },
        ],
        mechanism: "no_fix",
        advisory_ids: ["RUSTSEC-2023-0071"],
        verification: "re-run 4da plan --json",
      },
    ],
    ...overrides,
  };
}

/** A database file as the app leaves it: a `kv_store` with (optionally) a plan. */
function dbWith(name: string, snapshot: string | null, withStore = true): FourDADatabase {
  const file = path.join(root, `${name}.db`);
  const raw = new Database(file);
  if (withStore) {
    raw.exec("CREATE TABLE kv_store (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
    if (snapshot !== null) {
      raw.prepare("INSERT INTO kv_store (key, value) VALUES (?, ?)").run("upgrade_plan_snapshot", snapshot);
    }
  } else {
    raw.exec("CREATE TABLE unrelated (id INTEGER)");
  }
  raw.close();
  const db = new FourDADatabase(file);
  opened.push(db);
  return db;
}

let priorProjectDir: string | undefined;

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-app-plan-"));
  // These suites read the whole plan: the server's directory is not a project,
  // so the default scope is every project (see the project_path suite below).
  priorProjectDir = process.env.FOURDA_PROJECT_DIR;
  process.env.FOURDA_PROJECT_DIR = root;
});

afterAll(() => {
  if (priorProjectDir === undefined) delete process.env.FOURDA_PROJECT_DIR;
  else process.env.FOURDA_PROJECT_DIR = priorProjectDir;
  for (const db of opened) db.close();
  fs.rmSync(root, { recursive: true, force: true });
});

describe("upgrade_planner returns the app's plan when there is one", () => {
  it("a fresh snapshot comes back as the app's work order, targets untouched", async () => {
    const db = dbWith("fresh", JSON.stringify(envelope()));
    const result = (await executeUpgradePlanner(db, {}, null)) as AppPlanResult;

    expect(result.provenance.mode).toBe("app_plan");
    expect(result.stale).toBe(false);
    expect(result.staleness).toBeNull();
    expect(result.totalSteps).toBe(3);
    expect(result.steps.map((s) => s.item_id)).toEqual([UNDICI_ID, BRACE_ID, RSA_ID]);

    const undici = result.steps[0];
    expect(undici.lines[0]).toMatchObject({ installed: "5.28.4", target: "6.28.1", upgrade_type: "major" });
    expect(undici.mechanism).toBe("lockfile_or_parent_update");
    // The item's own title and urgency travel with the step.
    expect(undici.title).toContain(">= 6.28.1");
    expect(undici.urgency).toBe("high");

    expect(result.summary).toContain("1 lockfile or parent update(s)");
    expect(result.summary).toContain("1 mixed");
    expect(result.summary).toContain("1 with no fix published");
    expect(result.summary).toContain("1 cross a major version");
    expect(result.snapshot).toMatchObject({ schemaVersion: 4, itemCount: 3, multiVersionCoverage: true });
  });

  it("an expired snapshot is still the app's plan, flagged stale", async () => {
    const db = dbWith(
      "expired",
      JSON.stringify(
        envelope({
          generated_at: "2026-09-01T00:00:00Z",
          expires_at: "2026-09-02T00:00:00Z",
        }),
      ),
    );
    const result = (await executeUpgradePlanner(db, {}, null)) as AppPlanResult;
    expect(result.provenance.mode).toBe("app_plan");
    expect(result.stale).toBe(true);
    expect(result.staleness).toContain("STALE");
    expect(result.summary).toContain("STALE");
    expect(result.steps).toHaveLength(3);
  });

  it("an empty plan is the app's answer (evaluated, nothing to do), not a reason to guess", async () => {
    const db = dbWith("empty", JSON.stringify(envelope({ items: [], steps: [], item_count: 0 })));
    const result = (await executeUpgradePlanner(db, {}, null)) as AppPlanResult;
    expect(result.provenance.mode).toBe("app_plan");
    expect(result.steps).toEqual([]);
    expect(result.summary).toMatch(/^0 steps from the 4DA app's plan/);
  });

  it("risk_threshold filters by the app's urgency and max_recommendations limits the steps", async () => {
    const db = dbWith("filtered", JSON.stringify(envelope()));
    const high = (await executeUpgradePlanner(db, { risk_threshold: "high" }, null)) as AppPlanResult;
    expect(high.steps.map((s) => s.item_id)).toEqual([UNDICI_ID]);
    const two = (await executeUpgradePlanner(db, { max_recommendations: 2 }, null)) as AppPlanResult;
    expect(two.steps).toHaveLength(2);
    expect(two.totalSteps).toBe(3);
    expect(two.summary).toContain("3 in the full plan");
  });

  it("returns 20 steps by default, like the standalone plan, and says how to get the rest", async () => {
    const env = envelope() as { steps: unknown[] };
    const many = { ...env, steps: Array.from({ length: 25 }, (_, i) => ({ ...(env.steps[0] as object), item_id: `upgrade-plan:npm:pkg${i}`, package: `pkg${i}` })) };
    const db = dbWith("many-steps", JSON.stringify(many));
    const result = (await executeUpgradePlanner(db, {}, null)) as AppPlanResult;
    expect(result.steps).toHaveLength(20);
    expect(result.totalSteps).toBe(25);
    expect(result.summary).toContain("25 in the full plan (raise max_recommendations for the rest)");
  });

  it("package narrows the app's plan to that package, as it does the standalone plan", async () => {
    const db = dbWith("one-package", JSON.stringify(envelope()));
    const one = (await executeUpgradePlanner(db, { package: "UNDICI" }, null)) as AppPlanResult;
    expect(one.steps.map((s) => s.item_id)).toEqual([UNDICI_ID]);
    expect(one.totalSteps).toBe(3);
    const none = (await executeUpgradePlanner(db, { package: "not-in-plan" }, null)) as AppPlanResult;
    expect(none.steps).toEqual([]);
  });
});

describe("upgrade_planner falls back to the standalone heuristic, and says why", () => {
  async function fallback(db: FourDADatabase | null) {
    const result = await executeUpgradePlanner(db as FourDADatabase, {}, null);
    expect(result.provenance.mode).toBe("standalone_heuristic");
    return result as { appPlanUnavailable?: string };
  }

  it("no snapshot computed yet", async () => {
    const result = await fallback(dbWith("missing", null));
    expect(result.appPlanUnavailable).toContain("has not computed an upgrade plan");
  });

  it("an older schema (v3, no work order) is never read as a v4 plan", async () => {
    const v3 = envelope({ schema_version: 3 });
    delete v3.steps;
    const result = await fallback(dbWith("v3", JSON.stringify(v3)));
    expect(result.appPlanUnavailable).toContain("schema 3");
  });

  it("a newer schema is not trusted either", async () => {
    expect(APP_PLAN_SCHEMA_VERSIONS).toEqual([4, 5]);
    const result = await fallback(dbWith("v6", JSON.stringify(envelope({ schema_version: 6 }))));
    expect(result.appPlanUnavailable).toContain("schema 6");
    expect(result.appPlanUnavailable).toContain("reads schemas 4 and 5");
  });

  it("a database without the plan store (standalone MCP database)", async () => {
    const result = await fallback(dbWith("nostore", null, false));
    expect(result.appPlanUnavailable).toContain("no plan store");
  });

  it("garbage JSON and no database at all", async () => {
    expect((await fallback(dbWith("garbage", "not json"))).appPlanUnavailable).toContain("unreadable");
    expect((await fallback(null)).appPlanUnavailable).toContain("no 4DA database");
  });
});

describe("readAppPlan", () => {
  it("an unparseable expires_at cannot prove freshness: stale", () => {
    const read = readAppPlan(dbWith("badexpiry", JSON.stringify(envelope({ expires_at: "soon" }))));
    expect(read.kind).toBe("plan");
    if (read.kind === "plan") expect(read.stale).toBe(true);
  });

  it("a step whose item is missing keeps its fields, with no title", () => {
    const env = envelope();
    (env.items as unknown[]).splice(0, 1);
    const read = readAppPlan(dbWith("orphan", JSON.stringify(env)));
    expect(read.kind).toBe("plan");
    if (read.kind === "plan") {
      expect(read.snapshot.steps[0].title).toBeNull();
      expect(read.snapshot.steps[0].lines[0].target).toBe("6.28.1");
    }
  });
});

/**
 * 2026-10-07 eval: called from D:\4DA, the planner's top steps were for
 * navcal, verax and 4da-ledger: the app's plan covers every project it
 * tracks. It is narrowed to one project now.
 */
describe("upgrade_planner project_path", () => {
  function scopedEnvelope(web: string, navcal: string) {
    const env = envelope();
    const steps = env.steps as Array<{ lines: Array<{ sites: Array<{ project: string }> }> }>;
    steps[0].lines[0].sites[0].project = navcal.split(path.sep).join("/").toLowerCase();
    steps[1].lines[0].sites[0].project = navcal.split(path.sep).join("/").toLowerCase();
    steps[1].lines[0].sites[1].project = web.split(path.sep).join("/").toLowerCase();
    steps[2].lines[0].sites[0].project = `${web.split(path.sep).join("/").toLowerCase()}/relay`;
    return env;
  }

  it("defaults to the server's project and keeps only the lines and sites in it", async () => {
    const web = path.join(root, "web");
    const navcal = path.join(root, "navcal");
    fs.mkdirSync(path.join(web, "relay"), { recursive: true });
    fs.mkdirSync(navcal, { recursive: true });
    fs.writeFileSync(path.join(web, "package.json"), "{}");
    const db = dbWith("scoped", JSON.stringify(scopedEnvelope(web, navcal)));
    process.env.FOURDA_PROJECT_DIR = web;
    try {
      const result = (await executeUpgradePlanner(db, {}, null)) as AppPlanResult;
      expect(result.provenance.mode).toBe("app_plan");
      expect(result.projectScope).toBe(path.resolve(web));
      // undici only touches navcal; brace-expansion keeps its web site only; rsa sits under web/relay.
      expect(result.steps.map((s) => s.package)).toEqual(["brace-expansion", "rsa"]);
      expect(result.steps[0].lines[0].sites).toEqual([{ project: web.split(path.sep).join("/").toLowerCase(), direct: true, dev: false }]);
      expect(result.otherProjectSteps).toBe(1);
      expect(result.summary).toMatch(/1 step only touch(es)? other projects/);

      const navcalOnly = (await executeUpgradePlanner(db, { project_path: navcal }, null)) as AppPlanResult;
      expect(navcalOnly.steps.map((s) => s.package)).toEqual(["undici", "brace-expansion"]);

      const all = (await executeUpgradePlanner(db, { project_path: "*" }, null)) as AppPlanResult;
      expect(all.projectScope).toBeNull();
      expect(all.steps).toHaveLength(3);
    } finally {
      process.env.FOURDA_PROJECT_DIR = root;
    }
  });

  // Audit 6.2.5 D-1: a desktop-mode server started in a project the app never
  // indexed narrowed the app's plan to it and answered "0 steps" for NodeGoat
  // (83 vulnerable packages). The plan does not cover that project at all.
  it("plans a project the app does not track from its own files, and says so", async () => {
    const other = path.join(root, "untracked");
    fs.mkdirSync(other, { recursive: true });
    fs.writeFileSync(path.join(other, "package.json"), "{}");
    const db = dbWith("untracked", JSON.stringify(envelope()));
    const result = (await executeUpgradePlanner(db, { project_path: other }, null)) as UpgradePlanResult;
    expect(result.provenance.mode).toBe("standalone_heuristic");
    expect(result.appPlanUnavailable).toMatch(/does not track/);
  });

  it("an app-tracked project with nothing to do still gets the app's (empty) plan", async () => {
    const quiet = path.join(root, "quiet");
    fs.mkdirSync(quiet, { recursive: true });
    fs.writeFileSync(path.join(quiet, "package.json"), "{}");
    const db = dbWith("tracked-quiet", JSON.stringify(envelope()));
    // The app writes this table; the server opens its database read-only.
    const writer = new Database(path.join(root, "tracked-quiet.db"));
    writer.exec("CREATE TABLE project_dependencies (package_name TEXT, language TEXT, project_path TEXT, is_dev INTEGER, is_direct INTEGER)");
    writer.prepare("INSERT INTO project_dependencies VALUES (?, ?, ?, 0, 1)").run("left-pad", "npm", quiet);
    writer.close();
    const result = (await executeUpgradePlanner(db, { project_path: quiet }, null)) as AppPlanResult;
    expect(result.provenance.mode).toBe("app_plan");
    expect(result.totalSteps).toBe(0);
  });

  it("rejects a project_path that is not a directory", async () => {
    const db = dbWith("scoped-bad", JSON.stringify(envelope()));
    await expect(executeUpgradePlanner(db, { project_path: path.join(root, "nope") }, null)).rejects.toThrow(/not a directory/);
  });
});

/**
 * Schema 5 (the app's Y5, 2026-11-10): decided routes have their own mechanisms, and a copy no
 * published release can fix carries a `blocked_upstream` hold. The blocked step is the app's own
 * example: zip 8.6.0 under docx-rs 0.4.22, its newest release, which still requires zip ^8.6.0.
 */
describe("upgrade_planner reads a schema-5 plan", () => {
  const ZIP_ID = "upgrade-plan:crates.io:zip";
  const QS_ID = "upgrade-plan:npm:qs";
  const SEND_ID = "upgrade-plan:npm:send";
  const MIX_ID = "upgrade-plan:npm:cookie";
  const site = (project: string, direct = false) => ({ project, direct, dev: false });
  const line = (installed: string, target: string, upgrade_type: string, sites: unknown[]) => ({ installed, target, upgrade_type, clears_all_known: true, sites });
  const zipHold = {
    project: "d:/4da/src-tauri",
    installed: "8.6.0",
    cleared_version: "9.0.5",
    parent: "docx-rs",
    parent_version: "0.4.22",
    requirement: "^8.6.0",
    held_by: "docx-rs",
    held_by_newest: "0.4.22",
    options: [
      "fork docx-rs so it accepts zip >= 9.0.5 and point `[patch.crates-io]` at the fork",
      "backport the fix onto the zip line docx-rs allows and point `[patch.crates-io]` at that fork",
      "accept the risk with a written review date",
    ],
  };
  const cookieHold = {
    project: "d:/api",
    installed: "0.6.0",
    cleared_version: "0.7.0",
    parent: "old-server",
    parent_version: "1.0.0",
    requirement: "0.6.0",
    held_by: "old-server",
    held_by_newest: "1.0.0",
    options: ["force cookie >= 0.7.0 with an override", "accept the risk with a written review date"],
  };
  const v5 = () =>
    envelope({
      schema_version: 5,
      item_count: 4,
      items: [
        { id: ZIP_ID, title: "zip 8.6.0 is blocked upstream by docx-rs", urgency: "high" },
        { id: QS_ID, title: "Refresh qs to >= 6.14.1", urgency: "medium" },
        { id: SEND_ID, title: "Upgrade send to >= 0.19.0 via express", urgency: "medium" },
        { id: MIX_ID, title: "Upgrade cookie to >= 0.7.0", urgency: "medium" },
      ],
      steps: [
        { item_id: ZIP_ID, ecosystem: "crates.io", package: "zip", lines: [line("8.6.0", "9.0.5", "major", [site("d:/4da/src-tauri")])], mechanism: "blocked_upstream", blocked_upstream: [zipHold], advisory_ids: ["GHSA-zip"], verification: "v" },
        { item_id: QS_ID, ecosystem: "npm", package: "qs", lines: [line("6.14.0", "6.14.1", "patch", [site("d:/web")])], mechanism: "lockfile_refresh", advisory_ids: ["GHSA-qs"], verification: "v" },
        { item_id: SEND_ID, ecosystem: "npm", package: "send", lines: [line("0.18.0", "0.19.0", "minor", [site("d:/web")])], mechanism: "parent_update", advisory_ids: ["GHSA-send"], verification: "v" },
        {
          item_id: MIX_ID,
          ecosystem: "npm",
          package: "cookie",
          lines: [line("0.6.0", "0.7.0", "minor", [site("d:/web"), site("d:/api")])],
          mechanism: "lockfile_or_parent_update",
          blocked_upstream: [cookieHold],
          advisory_ids: ["GHSA-cookie"],
          verification: "v",
        },
      ],
    });

  it("is read as the app's plan, with the schema it was written in", async () => {
    const result = (await executeUpgradePlanner(dbWith("v5plan", JSON.stringify(v5())), {}, null)) as AppPlanResult;
    expect(result.provenance.mode).toBe("app_plan");
    expect(result.snapshot.schemaVersion).toBe(5);
    expect(result.steps.map((s) => s.mechanism)).toEqual(["blocked_upstream", "lockfile_refresh", "parent_update", "lockfile_or_parent_update"]);
    expect(result.summary).toContain("1 lockfile refresh(es)");
    expect(result.summary).toContain("1 parent update(s)");
    expect(result.summary).toContain("1 transitive with the route undecided or mixed");
    expect(result.summary).toContain("1 blocked upstream (no published release admits the fix yet: nothing to upgrade, options listed per step)");
  });

  it("a blocked step names no upgrade: it says what holds the copy and lists the options", async () => {
    const result = (await executeUpgradePlanner(dbWith("v5blocked", JSON.stringify(v5())), {}, null)) as AppPlanResult;
    const zip = result.steps[0];
    expect(zip.blocked_upstream).toEqual([zipHold]);
    expect(zip.next_step).toMatch(/^Do not upgrade zip: no published release of what pulls it in admits the fixed version yet\./);
    expect(zip.next_step).toContain("zip 8.6.0 in d:/4da/src-tauri is held by docx-rs 0.4.22 (its newest release), which requires zip ^8.6.0; 9.0.5 would clear it");
    expect(zip.next_step).toContain("Options: fork docx-rs so it accepts zip >= 9.0.5");
    expect(zip.next_step).toContain("or accept the risk with a written review date.");
    expect(zip.next_step).not.toMatch(/\bBump\b|\bRefresh\b|Update the parent/);
  });

  it("each decided route reads as what to do; a mixed-route step names its blocked copies", async () => {
    const result = (await executeUpgradePlanner(dbWith("v5routes", JSON.stringify(v5())), {}, null)) as AppPlanResult;
    const [, qs, send, cookie] = result.steps;
    expect(qs.next_step).toMatch(/^Refresh the lockfile so qs resolves to the fixed release \(6\.14\.0 -> 6\.14\.1 \(patch\)\); every parent's requirement already admits it/);
    expect(send.next_step).toMatch(/^Update the parent that pulls send in to a release whose requirement admits the fix/);
    expect(cookie.next_step).toMatch(/^Transitive only, and the route is undecided or differs between copies/);
    expect(cookie.next_step).toContain("Blocked upstream: cookie 0.6.0 in d:/api is held by old-server 1.0.0 (its newest release), which requires cookie 0.6.0");
  });

  it("project scope keeps only the holds in that project", async () => {
    const web = path.join(root, "v5web");
    fs.mkdirSync(web, { recursive: true });
    const env = v5();
    const steps = env.steps as Array<{ lines: Array<{ sites: Array<{ project: string }> }> }>;
    steps[3].lines[0].sites[0].project = web.split(path.sep).join("/").toLowerCase();
    const result = (await executeUpgradePlanner(dbWith("v5scope", JSON.stringify(env)), { project_path: web }, null)) as AppPlanResult;
    expect(result.steps.map((s) => s.package)).toEqual(["cookie"]);
    // The blocked copy is in d:/api, not this project.
    expect(result.steps[0].blocked_upstream).toBeUndefined();
  });

  it("a schema-4 snapshot keeps the schema-4 meaning of lockfile_or_parent_update", async () => {
    const result = (await executeUpgradePlanner(dbWith("v4words", JSON.stringify(envelope())), {}, null)) as AppPlanResult;
    expect(result.snapshot.schemaVersion).toBe(4);
    expect(result.steps[0].next_step).toMatch(/^Transitive only: refresh the lockfile, or update the parent that pulls undici in \(5\.28\.4 -> 6\.28\.1 \(major\)\)/);
    expect(result.summary).toContain("1 lockfile or parent update(s) (transitive only)");
  });

  it("a mechanism this server does not know is not acted on", async () => {
    const env = v5();
    (env.steps as Array<{ mechanism: string }>)[1].mechanism = "vendor_patch";
    const result = (await executeUpgradePlanner(dbWith("v5unknown", JSON.stringify(env)), {}, null)) as AppPlanResult;
    expect(result.steps[1].next_step).toMatch(/^This server does not know the mechanism "vendor_patch": read the plan item before acting on it\./);
  });
});
