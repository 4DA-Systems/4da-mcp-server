// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25 F-B1: after a truncated directory walk (the 20,000-directory bound, or the walk's
 * time budget, walk-budget.ts) what_should_i_know answered safe_to_delegate and "No dependency of
 * this project is named in the task" for a package in the part never read, without a word about
 * the truncation, and upgrade_planner said vulnerabilityDataAvailable: true. A truncated walk is
 * incomplete coverage everywhere: the briefing never says safe_to_delegate and leads with what was
 * not read, the planner says false with a NOT CHECKED summary, and dependency_health says it first
 * and never "all healthy".
 *
 * The truncation is set on the discovery the walk returns (a real one needs 20,000 directories or a
 * slow disk); the network is the harness's stubbed fetch: nothing leaves the process.
 */

import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
const PROXY_VARS = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of PROXY_VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  h = createHarness();
  h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.21": {} } }, minimist: { latest: "1.2.8", versions: { "1.2.6": {}, "1.2.8": {} } } };
  h.npmProject({ lodash: "4.17.21" }, {}, { lodash: { version: "4.17.21" } });
});
afterEach(() => {
  h.dispose();
  for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
});

function live(truncation: "none" | "dirs" | "time"): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(h.dir);
  const cut = truncation === "none" ? discovery : { ...discovery, walkTruncated: true, ...(truncation === "time" ? { walkStopped: "time_budget" as const } : {}) };
  li.initFromProjectTree(h.dir, treeResolutionGroups(entries), cut);
  return li;
}

describe("what_should_i_know after a truncated walk", () => {
  it("the control (whole tree read) is safe_to_delegate for a package the project does not have", async () => {
    const out = await executeWhatShouldIKnow(null, { task: "review how the CLI parser uses minimist" }, live("none"));
    expect(out.delegation_assessment.level).toBe("safe_to_delegate");
  });

  it.each(["dirs", "time"] as const)("never safe_to_delegate, and the summary leads with what was not read (%s)", async (how) => {
    const out = await executeWhatShouldIKnow(null, { task: "review how the CLI parser uses minimist" }, live(how));
    expect(out.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(out.summary).toMatch(/^NOT CHECKED: the directory walk stopped/);
    expect(out.summary).not.toMatch(/No dependency of this project is named in the task/);
    expect(out.summary).toMatch(/No dependency named in the task was found in the part of the project that was read/);
    expect(out.delegation_assessment.reason).toMatch(/directory walk stopped/);
  });

  it("a task naming a package that was read still says the walk first", async () => {
    const out = await executeWhatShouldIKnow(null, { task: "review how the CLI parser uses lodash" }, live("dirs"));
    expect(out.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(out.summary).toMatch(/^NOT CHECKED: the directory walk stopped/);
  });
});

describe("upgrade_planner after a truncated walk", () => {
  it("the control is CVE-aware", async () => {
    const plan = (await executeUpgradePlanner(null, { project_path: h.dir }, live("none"))) as Record<string, any>;
    expect(plan.vulnerabilityDataAvailable).toBe(true);
  });

  it.each(["dirs", "time"] as const)("vulnerabilityDataAvailable is false and the summary starts NOT CHECKED (%s)", async (how) => {
    const plan = (await executeUpgradePlanner(null, { project_path: h.dir }, live(how))) as Record<string, any>;
    expect(plan.vulnerabilityDataAvailable).toBe(false);
    expect(plan.summary).toMatch(/^NOT CHECKED: the directory walk stopped/);
  });
});

describe("dependency_health after a truncated walk", () => {
  it("the control may say all healthy", async () => {
    const health = await executeDependencyHealth(null, {}, live("none"));
    expect(health.summary).toMatch(/all healthy/);
  });

  it.each(["dirs", "time"] as const)("leads with NOT CHECKED, marks the score partial, never all healthy (%s)", async (how) => {
    const health = await executeDependencyHealth(null, {}, live(how));
    expect(health.summary).toMatch(/^NOT CHECKED: the directory walk stopped/);
    expect(health.summary).not.toMatch(/all healthy/);
    expect(health.scoreCoverage?.complete).toBe(false);
  });
});
