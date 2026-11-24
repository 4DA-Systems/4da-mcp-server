// SPDX-License-Identifier: Apache-2.0
/**
 * A manifest below the root with no lockfile (the scan's `manifests_without_lockfile`) makes the scan
 * incomplete, and the plan says so too.
 *
 * Review of the 6.5.1 candidate (2026-11-24, p-agree2.mjs, case sub-manifest-no-lockfile): with a
 * clean root package-lock.json and `apps/b/package.json` declaring `lodash ^4.17.0` and no lockfile,
 * vulnerability_scan said `coverage.complete: false` while upgrade_planner said
 * `vulnerabilityDataAvailable: true` with no NOT CHECKED: apps/b's dependencies were never checked.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM = { ms: { latest: "2.1.3", versions: { "2.1.3": {} } } };
  h.npmProject({ ms: "2.1.3" }, {}, { ms: { version: "2.1.3" } });
});
afterEach(() => h.dispose());

describe("a subdirectory package.json with no lockfile", () => {
  it("the scan and the plan both say not complete", async () => {
    h.write("apps/b/package.json", JSON.stringify({ name: "b", version: "1.0.0", dependencies: { lodash: "^4.17.0" } }));
    const scan = await h.scan();
    const { result: plan } = await h.plan();
    expect(scan.coverage.complete).toBe(false);
    expect(plan.vulnerabilityDataAvailable).toBe(false);
    expect(String(plan.summary)).toMatch(/^NOT CHECKED/);
  });

  it("control: without it both say complete", async () => {
    const scan = await h.scan();
    const { result: plan } = await h.plan();
    expect(scan.coverage.complete).toBe(true);
    expect(plan.vulnerabilityDataAvailable).toBe(true);
  });
});
