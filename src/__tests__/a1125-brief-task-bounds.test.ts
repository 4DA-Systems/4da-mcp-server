// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know on a task with one enormous word (pre-publish audit 2026-11-25, F-M3).
 * 199,000 characters of "1.1" repeated took 89 s and blocked the event loop: a regex in
 * private-guard.ts nameForms (`host:port` forms) was quadratic in the length of a task token, and
 * briefing-names.ts TOML_TABLE_ENTRY was slow on crafted input. Every task token is now bounded
 * before a pattern reads it, and the two patterns are linear.
 *
 * Judged on the CPU time of the call (process.cpuUsage, this worker only), not the wall clock of a
 * loaded machine; the best of three runs.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { nameForms } from "../live/private-guard.js";
import { normalizeVersionSyntax } from "../tools/briefing-names.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
});
afterEach(() => h.dispose());

const LIMIT_CPU_MS = 2_000;

async function cpuOf(work: () => Promise<unknown>): Promise<number> {
  let best = Number.POSITIVE_INFINITY;
  for (let i = 0; i < 3; i++) {
    const start = process.cpuUsage();
    await work();
    const used = process.cpuUsage(start);
    best = Math.min(best, (used.user + used.system) / 1000);
    if (best <= LIMIT_CPU_MS) break;
  }
  return best;
}

describe("a task token of unbounded length", () => {
  it.each([
    ["199,000 characters of 1.1", "1.1".repeat(66_333)],
    ["add + 199,000 characters of 1.1", `add ${"1.1".repeat(66_333)}`],
    ["a.b: repeated with a colon at the end", `${"a.b".repeat(60_000)}:`],
    ["dots then a colon", `install x${".".repeat(150_000)}:1`],
    ["a TOML-looking entry with 100 KB of blanks", `add x = {${" ".repeat(100_000)}`],
    ["brackets", `add x${"[".repeat(150_000)}`],
  ])("%s answers within 2 s of CPU", async (_label, task) => {
    const live = await h.live();
    const cpu = await cpuOf(() => executeWhatShouldIKnow(null, { task, project_path: h.dir }, live));
    expect(cpu).toBeLessThan(LIMIT_CPU_MS);
  });

  it("nameForms and normalizeVersionSyntax are linear on a long word", async () => {
    const cpu = await cpuOf(async () => {
      nameForms("1.1".repeat(66_333));
      nameForms(`${"a.b".repeat(60_000)}:`);
      normalizeVersionSyntax(`x = {${" ".repeat(100_000)}`);
      normalizeVersionSyntax(`${"a={".repeat(30_000)}`);
    });
    expect(cpu).toBeLessThan(LIMIT_CPU_MS);
  });

  it("a long word sends nothing", async () => {
    const live = await h.live();
    await executeWhatShouldIKnow(null, { task: `add ${"zq".repeat(400)}x`, project_path: h.dir }, live);
    expect(h.requests.filter((u) => u.includes("zqzq"))).toEqual([]);
  });
});
