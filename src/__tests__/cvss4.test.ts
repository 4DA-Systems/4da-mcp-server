// SPDX-License-Identifier: Apache-2.0
/**
 * CVSS v4.0 scoring (cvss4.ts) and its use as a grade.
 *
 * RUSTSEC-2026-0459 (libsqlite3-sys) carries only `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/...`
 * and no label; it was graded "unknown". The expected scores are the FIRST reference calculator's
 * (github.com/FIRSTdotorg/cvss-v4-calculator, run on each vector): the port was also compared
 * with it on 100,000 random base, threat and environmental vectors with no difference. The first
 * six are the scores NVD and GitHub publish for those vectors.
 */

import { describe, expect, it } from "vitest";
import { cvss4Score } from "../live/cvss4.js";
import { deriveSeverity, extractCvssScore } from "../live/osv-scanner.js";

const REFERENCE: Array<[string, number]> = [
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 8.7],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 6.9],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.2],
  // RUSTSEC-2026-0459.
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 6.8],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 2],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 1],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:H/SI:H/SA:L", 6.4],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:H/SA:N", 7],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:H", 1.8],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:L/VI:H/VA:N/SC:H/SI:H/SA:L", 7],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:L/SC:H/SI:N/SA:H", 7.2],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N", 5.8],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:L/VI:H/VA:L/SC:H/SI:N/SA:N", 5.7],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:H/SA:L", 4.5],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:N/SC:H/SI:L/SA:H", 8.4],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:N/VI:N/VA:N/SC:L/SI:H/SA:H", 2.3],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", 4.1],
  // Threat and environmental metrics.
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 8.1],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:L/IR:L/AR:L", 7.9],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MSI:S", 8.9],
];

describe("CVSS v4.0 score: the FIRST reference calculator's", () => {
  it.each(REFERENCE)("%s = %d", (vector, score) => {
    expect(cvss4Score(vector)).toBe(score);
  });

  it("returns null for anything but a complete, valid v4.0 vector (never a made-up score)", () => {
    expect(cvss4Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeNull();
    expect(cvss4Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")).toBeNull(); // subsequent-system metrics missing
    expect(cvss4Score("CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeNull(); // bad value
    expect(cvss4Score("CVSS:4.0/AV:N/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeNull(); // repeated metric
    expect(cvss4Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N")).toBeNull(); // S is MSI's, not SI's
    for (const bad of ["", "CVSS:4.0", "CVSS:4.0/", "/////", ":::", "🙂", "CVSS:4.0/AV"]) expect(cvss4Score(bad)).toBeNull();
  });
});

describe("a record graded by its CVSS v4.0 vector", () => {
  const rustsec = { id: "RUSTSEC-2026-0459", severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" }] };

  it("RUSTSEC-2026-0459, v4.0 only and no label: medium (6.8), not unknown", () => {
    expect(deriveSeverity(rustsec)).toEqual({ severity: "medium", cvssScore: 6.8 });
  });

  it("the curated label still wins over the vector, and a v3.x vector over a v4.0 one", () => {
    expect(deriveSeverity({ ...rustsec, database_specific: { severity: "HIGH" } }).severity).toBe("high");
    const both = [
      { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
      { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" },
    ];
    expect(extractCvssScore(both)).toBe(5.3);
  });

  it("each band: critical >= 9, high >= 7, medium >= 4, low > 0", () => {
    const grade = (score: string) => deriveSeverity({ severity: [{ type: "CVSS_V4", score }] }).severity;
    expect(grade("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBe("critical");
    expect(grade("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N")).toBe("high");
    expect(grade("CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:H/SA:L")).toBe("medium");
    expect(grade("CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")).toBe("low");
    // 0.0 is no score band at all: unknown, as for v3.
    expect(grade("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")).toBe("unknown");
  });
});
