// SPDX-License-Identifier: Apache-2.0
/**
 * bench/plan-exec: a scan whose only gap is a file the server cannot read counts as evidence for
 * what was read. h3 keeps a binary `docs/bun.lockb`; once the scan led with it (an unread lockfile
 * is never passed over), the gate failed h3 on every run, as it had failed on private
 * dependencies. No retry reads that file.
 */

import { describe, expect, it } from "vitest";

import { scanComplete } from "../../bench/plan-exec/lib.mjs";

const NOTE =
  "UNREADABLE: 1 lockfile could not be read, so its dependencies were not checked: docs/bun.lockb (bun.lockb is Bun's binary lockfile, which this server cannot read).";
const scan = {
  summary: `NOT CHECKED: ${NOTE} In the dependencies that were checked, 13 advisories on 10 package versions are rated critical by the advisory itself.`,
  coverage: { complete: false, note: NOTE, lockfiles_not_scanned: 0, unreadable_lockfiles: [{ path: "docs/bun.lockb", error: "binary" }] },
};

describe("scanComplete with an unreadable lockfile", () => {
  it("the unreadable file as the only gap: complete", () => {
    expect(scanComplete(scan)).toBe(true);
  });

  it("lookups that did not answer, a merge conflict beside it, or stale data: not complete", () => {
    expect(scanComplete({ ...scan, coverage: { ...scan.coverage, unchecked_dependencies: 3 } })).toBe(false);
    expect(scanComplete({ ...scan, coverage: { ...scan.coverage, note: `${NOTE} NOT CHECKED (merge conflict): 1 file holds git merge-conflict markers.` } })).toBe(false);
    expect(scanComplete({ ...scan, summary: `${scan.summary} STALE: 4 answers have expired.` })).toBe(false);
  });

  it("the wording without the file named in coverage is not taken on trust", () => {
    expect(scanComplete({ summary: scan.summary, coverage: { complete: false, note: NOTE } })).toBe(false);
  });
});
