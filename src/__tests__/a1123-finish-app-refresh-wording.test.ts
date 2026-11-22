// SPDX-License-Identifier: Apache-2.0
/**
 * The desktop app writes `lockfile_refresh` for a direct dependency whose declared range already
 * admits the fix, as well as for a transitive copy whose parents admit it. The server's words for
 * the mechanism fit both: never "(transitive)" or "every parent's requirement" for a direct site.
 */
import { describe, expect, it } from "vitest";

import { formatAppPlan, nextStep, type AppPlanStepView } from "../tools/app-plan.js";

const site = (project: string, direct: boolean) => ({ project, direct, dev: false });
const step = (sites: Array<ReturnType<typeof site>>): AppPlanStepView => ({
  item_id: "i1",
  ecosystem: "npm",
  package: "qs",
  lines: [{ installed: "6.14.0", target: "6.14.1", upgrade_type: "patch", clears_all_known: true, sites }],
  mechanism: "lockfile_refresh",
  advisory_ids: ["GHSA-qs"],
  verification: "v",
  title: null,
  urgency: "medium",
  next_step: "",
});

describe("lockfile_refresh in the app's plan", () => {
  it("a direct dependency: its declared range already admits the fix; no parent is named", () => {
    const text = nextStep(step([site("d:/web", true)]), 5);
    expect(text).toMatch(/^Refresh the lockfile so qs resolves to the fixed release/);
    expect(text).toMatch(/the range the project declares for qs already admits it/);
    expect(text).not.toMatch(/parent/);
  });

  it("a transitive copy: every parent's requirement already admits it, as before", () => {
    expect(nextStep(step([site("d:/web", false)]), 5)).toMatch(/every parent's requirement already admits it, so no manifest changes/);
  });

  it("direct in one project, transitive in another: both are said", () => {
    const text = nextStep(step([site("d:/web", true), site("d:/api", false)]), 5);
    expect(text).toMatch(/the declared range where qs is direct and every parent's requirement where it is transitive already admit it/);
  });

  it("the plan summary does not call a refresh transitive", () => {
    const s = step([site("d:/web", true)]);
    const result = formatAppPlan(
      {
        kind: "plan",
        stale: false,
        snapshot: { schemaVersion: 5, generatedAt: "2026-11-22T00:00:00Z", expiresAt: "2026-11-29T00:00:00Z", generatorVersion: null, sourceFreshness: null, multiVersionCoverage: null, validationDropCount: null, itemCount: 1, steps: [{ ...s, next_step: nextStep(s, 5) }] },
      },
      {},
      { staleReasons: [], check: { status: "unverified", note: "n" } } as never,
    );
    expect(result.summary).toMatch(/1 lockfile refresh\(es\) \(no manifest change: every declared range already admits the fix\)/);
    expect(result.summary).not.toMatch(/refresh\(es\) \(transitive/);
  });
});
