// SPDX-License-Identifier: Apache-2.0
/**
 * An upgrade_planner call answers from one dependency set. Review of the 6.5.1 candidate
 * (2026-11-24, p-race.mjs): a plan in flight while another call re-resolved the set (a lockfile
 * changed, dependency_check refreshed it) answered with rows from the old set and lockfile problems
 * from the new one (deps read before the awaits, problems after them). Now the problems, discovery
 * and lockfile state are read with the rows, and a set that changed during the call makes the plan
 * say NOT CHECKED ("plan again"), never a clean answer.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM = { ms: { latest: "2.1.3", versions: { "2.1.3": {} } } };
  h.npmProject({ ms: "2.1.3" }, {}, { ms: { version: "2.1.3" } });
});
afterEach(() => h.dispose());

describe("a dependency set that changes while a plan is computed", () => {
  it("the plan says NOT CHECKED and plan again", async () => {
    const live = await h.live();
    // The first outbound request of the plan: the set changes under it, as another call's refresh would.
    const inner = globalThis.fetch;
    let moved = false;
    globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
      if (!moved) {
        moved = true;
        const file = path.join(h.dir, "yarn.lock");
        fs.writeFileSync(file, '# yarn lockfile v1\n\n\nms@2.1.3:\n  version "2.1.2"\n  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.2.tgz#x"\n');
        live.refreshIfLockfilesChanged();
      }
      return inner(input, init);
    }) as typeof fetch;
    const plan = (await executeUpgradePlanner(null as never, { project_path: h.dir }, live)) as Record<string, any>;
    globalThis.fetch = inner;
    expect(moved).toBe(true);
    expect(plan.vulnerabilityDataAvailable).toBe(false);
    expect(String(plan.summary)).toMatch(/^NOT CHECKED: the dependency set changed while this plan was computed/);
  });
});
