// SPDX-License-Identifier: Apache-2.0
/**
 * A per-call cap on how many upgrade targets have their own requirements examined defers work; it
 * never withholds a target for good. saleor 3.1.0 had 29 of 39 PyPI fix targets withheld ("this
 * call examines what at most 10 upgrade targets require"), and four calls in a row gave the same
 * count: every call examined the same first ten again.
 *
 * Now a release past the cap says so (NOT CHECKED words, with why), is examined after the call
 * returns, and the next call answers it; releases examined to a verdict recently do not count
 * against the next call's cap.
 */

import { afterEach, describe, expect, it } from "vitest";
import { runWithCallBudget } from "../call-budget.js";
import type { FixTargetResult } from "../live/fix-paths.js";
import type { RequirementSources } from "../live/release-requirements.js";
import { MAX_REQUIRED_TARGETS, notExaminedCapText, requiredTargetsWarmed, setRequiredTargetWarming, withRequiredTargets } from "../live/required-targets.js";

const clean = (target: string): FixTargetResult => ({ target, basis: "advisory_fixes", floor: target, floorAffectedBy: [], stillAffectedBy: [], unfixable: [], withheld: [] }) as unknown as FixTargetResult;
const sources = (asked: string[]): RequirementSources => ({
  reads: () => true,
  requirements: async (_eco, name, version) => {
    asked.push(`${name}@${version}`);
    return { status: "ok", data: { requirements: [], unreadable: 0 } };
  },
  releaseFacts: async () => null,
  packageAdvisories: async () => [],
  publishedVersions: async () => [],
});
const query = async () => ({ vulnerabilities: [], totalScanned: 0, offline: false }) as never;

afterEach(() => setRequiredTargetWarming(true));

describe("PyPI upgrade targets past the per-call cap", () => {
  const items = Array.from({ length: MAX_REQUIRED_TARGETS * 3 + 2 }, (_, i) => ({ key: `k${i}`, ecosystem: "PyPI", name: `a1123-afour-pkg${i}`, clean: clean("2.0.0") }));
  const call = (asked: string[]) => runWithCallBudget(Date.now(), () => withRequiredTargets(sources(asked), query, items, Date.now() + 5_000));

  it("are said to be deferred, examined after the call, and answered by the next call", async () => {
    const asked: string[] = [];
    const first = await call(asked);
    const capped = [...first.values()].filter((c) => c.requiresUnchecked === notExaminedCapText());
    expect(capped).toHaveLength(items.length - MAX_REQUIRED_TARGETS);
    expect(notExaminedCapText()).toMatch(/is examined after this call returns, so calling again answers it/);

    await requiredTargetsWarmed();
    expect(new Set(asked).size).toBe(items.length);

    const second = await call(asked);
    // Nothing is withheld for the cap on the second call: every target was examined to a verdict.
    expect([...second.values()].filter((c) => c.requiresUnchecked !== undefined)).toEqual([]);
  });
});
