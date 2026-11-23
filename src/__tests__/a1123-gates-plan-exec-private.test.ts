// SPDX-License-Identifier: Apache-2.0
/**
 * bench/plan-exec: when a scan's advisory counts are evidence. The gate fails a project whose
 * scan stayed NOT CHECKED, and the first run on GitHub (2026-11-23, 281 steps, none failed)
 * failed on mcp-python-sdk alone: an example lockfile of that repository takes three packages
 * from an internal index, the server never looks a private dependency up, and it says so with
 * "NOT CHECKED (private)" on every attempt. That gap is the server's rule, not missing data.
 */

import { describe, expect, it } from "vitest";

import { scanComplete } from "../../bench/plan-exec/lib.mjs";

const PRIVATE_NOTE =
  "NOT CHECKED (private): 3 dependencies are private (colorama, h11, iniconfig) and were never sent to OSV.dev or a registry, so nothing is known about their advisories: this is not a clean result for them. See coverage.private_dependency_list for why each is private.";
/** The scan of mcp-python-sdk as the run recorded it, cut to what the rule reads. */
const privateOnly = {
  summary: `${PRIVATE_NOTE} In the dependencies that were checked, 2 advisories on 2 package versions are rated critical by the advisory itself (anyio@4.6.2.post1, certifi@2024.8.30).`,
  coverage: { lockfiles_not_scanned: 0, complete: false, note: PRIVATE_NOTE, unchecked_dependencies: 0, checked_dependencies: 34, private_dependencies: 3 },
};

describe("scanComplete", () => {
  it("a scan with nothing left out is complete", () => {
    expect(scanComplete({ summary: "12 advisories on 9 package versions.", coverage: { unchecked_dependencies: 0, checked_dependencies: 300 } })).toBe(true);
    expect(scanComplete({ summary: "No known vulnerabilities in 40 dependencies." })).toBe(true);
  });

  it("private dependencies as the only gap: complete, its counts are evidence for the rest", () => {
    expect(scanComplete(privateOnly)).toBe(true);
  });

  it("lookups that did not answer leave it incomplete, with or without private dependencies", () => {
    expect(scanComplete({ summary: "NOT CHECKED: OSV.dev did not answer for 12 of 300 dependencies.", coverage: { unchecked_dependencies: 12 } })).toBe(false);
    expect(scanComplete({ ...privateOnly, coverage: { ...privateOnly.coverage, unchecked_dependencies: 2 } })).toBe(false);
    // The count can be 0 while the summary still says a lookup is missing (advisory details).
    expect(scanComplete({ summary: "NOT CHECKED (advisory details): 3 records were not read.", coverage: { unchecked_dependencies: 0 } })).toBe(false);
  });

  it("a second gap beside the private one leaves it incomplete", () => {
    const both = `${PRIVATE_NOTE} NOT CHECKED (advisory details): 2 records were not read in this call.`;
    expect(scanComplete({ summary: both, coverage: { ...privateOnly.coverage, note: both } })).toBe(false);
    expect(scanComplete({ ...privateOnly, coverage: { ...privateOnly.coverage, note: `${PRIVATE_NOTE} NOT CHECKED (merge conflict): 1 file holds git merge-conflict markers.` } })).toBe(false);
    expect(scanComplete({ ...privateOnly, coverage: { ...privateOnly.coverage, lockfiles_not_scanned: 1 } })).toBe(false);
  });

  it("stale data is never complete", () => {
    expect(scanComplete({ summary: "STALE: the OSV.dev answers for 4 dependencies have expired.", coverage: { unchecked_dependencies: 0 } })).toBe(false);
    expect(scanComplete({ ...privateOnly, summary: `${PRIVATE_NOTE} STALE: 4 answers have expired.` })).toBe(false);
  });

  it("the private wording without a private count is not taken on trust", () => {
    expect(scanComplete({ summary: PRIVATE_NOTE, coverage: { unchecked_dependencies: 0, private_dependencies: 0 } })).toBe(false);
    expect(scanComplete({ summary: PRIVATE_NOTE })).toBe(false);
  });
});
