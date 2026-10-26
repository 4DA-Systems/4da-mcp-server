// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { isActionableVulnerability, isMaintenanceNotice, isMaintenanceRecord } from "../live/maintenance.js";
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

// Audit 6.2.5 F-7 / the 2026-10-26 amendment: a stated `informational` class decides alone; the
// summary wording counts only when no class is stated. serde_yml's RustSec advisory is
// `unsound` but its summary says "unmaintained", and it was hidden as a notice that never blocks.
describe("a stated informational class beats the summary wording", () => {
  const rec = (summary: string, own?: string, record?: string) => ({
    summary,
    ...(record ? { database_specific: { informational: record } } : {}),
    affected: [{ package: { name: "serde_yml", ecosystem: "crates.io" }, ranges: [], ...(own ? { database_specific: { informational: own } } : {}) }],
  });

  it("unsound is a vulnerability even when the summary says unmaintained", () => {
    expect(isMaintenanceRecord(rec("serde_yml is unsound and unmaintained", "unsound") as never, "serde_yml", "crates.io")).toBe(false);
  });
  it("the affected entry's class wins over the record's", () => {
    expect(isMaintenanceRecord(rec("x", "unsound", "unmaintained") as never, "serde_yml", "crates.io")).toBe(false);
    expect(isMaintenanceRecord(rec("x", "unmaintained", "unsound") as never, "serde_yml", "crates.io")).toBe(true);
  });
  it("with no class stated, the wording still decides", () => {
    expect(isMaintenanceRecord(rec("serde_yml is unmaintained") as never, "serde_yml", "crates.io")).toBe(true);
    expect(isMaintenanceRecord(rec("memory corruption in serde_yml") as never, "serde_yml", "crates.io")).toBe(false);
  });
  it("a scan entry's explicit answer beats its wording", () => {
    expect(isMaintenanceNotice({ summary: "unmaintained and unsound", maintenance: false })).toBe(false);
    expect(isMaintenanceNotice({ summary: "unmaintained" })).toBe(true);
  });
});

describe("an alias group is a notice only when every record is one", () => {
  it("serde_yml: the GHSA's wording does not hide RUSTSEC-2025-0068's stated unsound", async () => {
    const { collapseAliases } = await import("../tools/vulnerability-scan-format.js");
    const entry = (vulnId: string, aliases: string[], maintenance: boolean, cvssScore: number | null) => ({
      package: "serde_yml", currentVersion: "0.0.12", ecosystem: "crates.io" as const, isDev: false, isDirect: true, devScopeKnown: true,
      vulnId, aliases, severity: "medium" as const, cvssScore, summary: "serde_yml crate is unsound and unmaintained", fixedVersion: null,
      published: "", references: [], target: null, platformActive: true, sourceDirs: ["."], maintenance,
    });
    const kept = collapseAliases([entry("GHSA-hhw4-xg65-fp2x", ["RUSTSEC-2025-0068"], true, 5), entry("RUSTSEC-2025-0068", ["GHSA-hhw4-xg65-fp2x"], false, null)] as never);
    expect(kept).toHaveLength(1);
    expect(isMaintenanceNotice(kept[0])).toBe(false);
  });
});
