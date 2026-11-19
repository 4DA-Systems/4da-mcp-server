// SPDX-License-Identifier: Apache-2.0
/**
 * The requirement judge's deadline follows the call's remaining budget. A fixed 10 s from the
 * first judge() left jinja2 3.1.2 "NOT CHECKED ... did not finish in time" in a cold 25-item PyPI
 * batch that finished in 11 s of a 20 s budget; alone the same item named 3.1.6.
 *
 * Fake timers stand in for a slow registry: the outcome is asserted, never a duration.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runWithCallBudget } from "../call-budget.js";
import type { RequirementSources } from "../live/release-requirements.js";
import { RequirementJudge } from "../tools/dependency-check-held.js";

/** A registry whose requirement list arrives after `delayMs`. */
function slowSources(delayMs: number): RequirementSources {
  return {
    reads: () => true,
    requirements: () => new Promise((resolve) => setTimeout(() => resolve({ status: "ok", data: { requirements: [], unreadable: 0 } }), delayMs)),
    releaseFacts: async () => null,
    packageAdvisories: async () => [],
    publishedVersions: async () => [],
  };
}
const query = async () => ({ vulnerabilities: [], totalScanned: 0, offline: false }) as never;

let budget: string | undefined;
beforeEach(() => {
  budget = process.env.FOURDA_CALL_BUDGET_MS;
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
});
afterEach(() => {
  vi.useRealTimers();
  if (budget === undefined) delete process.env.FOURDA_CALL_BUDGET_MS;
  else process.env.FOURDA_CALL_BUDGET_MS = budget;
});

async function judgeWith(delayMs: number, inCall: boolean) {
  const judge = new RequirementJudge(slowSources(delayMs), query);
  const run = async () => {
    const done = judge.judge([{ ecosystem: "PyPI", pkg: "jinja-like", versions: ["3.1.6"] }]);
    await vi.advanceTimersByTimeAsync(delayMs + 1);
    await done;
    return judge.at("PyPI", "jinja-like", "3.1.6");
  };
  return inCall ? runWithCallBudget(Date.now(), run) : run();
}

describe("RequirementJudge: the deadline follows the call's budget", () => {
  it("an answer at 11 s of a 20 s call is judged, not NOT CHECKED", async () => {
    process.env.FOURDA_CALL_BUDGET_MS = "20000";
    expect(await judgeWith(11_000, true)).toEqual({ status: "checked", affected: [], examined: 0 });
  });

  it("an answer past the call's budget (less the reserve for writing the answer) is unchecked", async () => {
    process.env.FOURDA_CALL_BUDGET_MS = "20000";
    expect(await judgeWith(19_000, true)).toMatchObject({ status: "unchecked" });
  });

  it("outside a tool call the judge keeps its own bound", async () => {
    expect(await judgeWith(11_000, false)).toMatchObject({ status: "unchecked" });
  });
});
