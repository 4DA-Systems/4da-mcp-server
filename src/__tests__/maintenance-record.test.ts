// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { isActionableVulnerability, isMaintenanceRecord } from "../live/maintenance.js";
import type { OsvVulnerability } from "../live/types.js";

/** RUSTSEC-2018-0017 as OSV serves it: the flag only on the affected entry, no notice wording. */
const tempdir: OsvVulnerability = {
  id: "RUSTSEC-2018-0017",
  summary: "`tempdir` crate has been deprecated; use `tempfile` instead",
  affected: [
    {
      package: { name: "tempdir", ecosystem: "crates.io" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0.0.0-0" }] }],
      database_specific: { informational: "unmaintained" },
    },
  ],
} as OsvVulnerability;

describe("isMaintenanceRecord: the notice predicate both engines share (sv-024/sv-025)", () => {
  it("reads informational on the affected entry for this package", () => {
    expect(isMaintenanceRecord(tempdir, "tempdir", "crates.io")).toBe(true);
  });

  it("does not borrow another package's per-affected flag", () => {
    expect(isMaintenanceRecord(tempdir, "tempfile", "crates.io")).toBe(false);
    expect(isMaintenanceRecord(tempdir, "tempdir", "npm")).toBe(false);
  });

  it("keeps unsound a vulnerability", () => {
    const smallvec = {
      ...tempdir,
      id: "RUSTSEC-2018-0018",
      summary: "smallvec creates uninitialized value of any type",
      affected: [{ ...tempdir.affected![0], package: { name: "smallvec", ecosystem: "crates.io" }, database_specific: { informational: "unsound" } }],
    } as OsvVulnerability;
    expect(isMaintenanceRecord(smallvec, "smallvec", "crates.io")).toBe(false);
  });

  it("reads the record-level flag and the summary wording", () => {
    const recordLevel = { id: "X-1", summary: "advisory", database_specific: { informational: "notice" }, affected: [] } as unknown as OsvVulnerability;
    expect(isMaintenanceRecord(recordLevel, "any", "npm")).toBe(true);
    const worded = { id: "X-2", summary: "foo is no longer maintained", affected: [] } as unknown as OsvVulnerability;
    expect(isMaintenanceRecord(worded, "foo", "npm")).toBe(true);
  });

  it("an entry the scan marked maintenance is not actionable, whatever its summary", () => {
    expect(isActionableVulnerability({ summary: tempdir.summary!, platformActive: true, maintenance: true })).toBe(false);
    expect(isActionableVulnerability({ summary: tempdir.summary!, platformActive: true })).toBe(true);
  });
});
