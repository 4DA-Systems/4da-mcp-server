// SPDX-License-Identifier: Apache-2.0
/**
 * The executed-plan gate counts the plan's claims the rescan contradicts: vulnerable copies a step
 * ran for that were still there (`prediction.planned_but_remained`) and vulnerable copies the run
 * brought in (`prediction.new_vulnerable_copies`). The harness recorded both and the gate read
 * neither (the 6.5.0 candidate's run over 14 projects: 22 and 24).
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { gateFindings, totals, type ProjectResult } from "../../bench/plan-exec/lib.mjs";

const project = (id: string, remained: string[], fresh: number): ProjectResult => ({
  id,
  order_source: "run_order",
  counts: { steps: 5, steps_run: 5, steps_failed: 0, steps_refused: 0, steps_without_effect: 0, steps_lowering: 0, steps_lowering_earlier: 0 },
  advisories: { before: 100, after: 10 },
  prediction: { vulnerable_copies_before: 10, predicted_remaining: 1, remaining: 1 + remained.length, vulnerable_copies_after: 1 + remained.length + fresh, planned_but_remained: remained, new_vulnerable_copies: fresh },
});

describe("the gate on contradicted claims", () => {
  it("sums both counts over the corpus and fails past either limit", () => {
    const thresholds = { max_planned_but_remained: 2, max_new_vulnerable_copies: 3 };
    const ps = [project("a", ["npm|x|1.0.0"], 1), project("b", ["npm|y|1.0.0"], 2)];
    const t = totals(ps);
    expect(t).toMatchObject({ planned_but_remained: 2, new_vulnerable_copies: 3 });
    expect(gateFindings(t, thresholds, ps)).toEqual([]);
    const over = [...ps, project("c", ["npm|z|1.0.0"], 1)];
    expect(gateFindings(totals(over), thresholds, over)).toEqual([
      "3 vulnerable copies a step ran for were still there after the run (allowed: 2)",
      "4 vulnerable copies the run brought in that were not there before (allowed: 3)",
    ]);
  });

  it("reads a result recorded before the counts existed as none", () => {
    const old = project("a", [], 0);
    delete old.prediction.planned_but_remained;
    delete old.prediction.new_vulnerable_copies;
    expect(totals([old])).toMatchObject({ planned_but_remained: 0, new_vulnerable_copies: 0 });
  });

  it("thresholds.json holds both limits, at what the 6.5.0 code measured over the 15 projects", () => {
    const thresholds = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "bench", "plan-exec", "thresholds.json"), "utf8"));
    expect(thresholds).toMatchObject({ max_planned_but_remained: 24, max_new_vulnerable_copies: 26, max_lowering_steps: 1, max_failed_steps: 0 });
    expect(thresholds.about).toMatch(/never raise them to pass/);
  });
});
