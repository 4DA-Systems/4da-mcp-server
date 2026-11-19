// SPDX-License-Identifier: Apache-2.0
/**
 * An unlabelled advisory is graded by the highest valid CVSS score among the vectors it carries.
 * A vector that scores 0.0, or cannot be read, never hides one that can: PYSEC-2026-1943 carries a
 * v3.1 vector with no impact (0.0) beside a v4.0 vector that scores 8.7, and was graded unknown.
 */

import { describe, expect, it } from "vitest";
import { deriveSeverity, extractCvssScore } from "../live/osv-scanner.js";

const V3_NONE = { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" }; // 0.0
const V3_HIGH = { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }; // 7.5
const V3_CRITICAL = { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }; // 9.8
const V4_HIGH = { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N" }; // 8.7
const V4_CRITICAL = { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }; // 9.3
const V4_NONE = { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N" }; // 0.0
const UNREADABLE = { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:banana" };

describe("the highest valid CVSS score grades an unlabelled advisory", () => {
  it("a v3 vector that scores 0.0 does not hide a v4 vector that scores 8.7 (PYSEC-2026-1943)", () => {
    expect(deriveSeverity({ severity: [V3_NONE, V4_HIGH] })).toEqual({ severity: "high", cvssScore: 8.7 });
    // Whichever comes first in the record.
    expect(deriveSeverity({ severity: [V4_HIGH, V3_NONE] })).toEqual({ severity: "high", cvssScore: 8.7 });
  });

  it("an unreadable vector does not hide a readable one", () => {
    expect(deriveSeverity({ severity: [UNREADABLE, V4_HIGH] })).toEqual({ severity: "high", cvssScore: 8.7 });
    expect(deriveSeverity({ severity: [UNREADABLE, V3_CRITICAL] })).toEqual({ severity: "critical", cvssScore: 9.8 });
  });

  it("a numeric 0 does not hide a vector", () => {
    expect(deriveSeverity({ severity: [{ type: "CVSS_V3", score: "0.0" }, V3_CRITICAL] })).toEqual({ severity: "critical", cvssScore: 9.8 });
  });

  it("with a v3 and a v4 vector that both score, the higher one grades", () => {
    expect(extractCvssScore([V3_HIGH, V4_CRITICAL])).toBe(9.3);
    expect(deriveSeverity({ severity: [V3_HIGH, V4_CRITICAL] }).severity).toBe("critical");
    expect(extractCvssScore([V3_CRITICAL, V4_HIGH])).toBe(9.8);
    expect(deriveSeverity({ severity: [V4_HIGH, V3_CRITICAL] }).severity).toBe("critical");
  });

  it("only vectors that score 0.0: the score is 0 and the grade unknown, never low", () => {
    expect(deriveSeverity({ severity: [V3_NONE] })).toEqual({ severity: "unknown", cvssScore: 0 });
    expect(deriveSeverity({ severity: [V3_NONE, V4_NONE] })).toEqual({ severity: "unknown", cvssScore: 0 });
  });

  it("nothing readable: no score, grade unknown", () => {
    expect(deriveSeverity({ severity: [UNREADABLE] })).toEqual({ severity: "unknown", cvssScore: null });
    expect(deriveSeverity({ severity: [] })).toEqual({ severity: "unknown", cvssScore: null });
    expect(deriveSeverity({})).toEqual({ severity: "unknown", cvssScore: null });
  });

  it("the curated label still decides the grade; the score reported is the highest", () => {
    expect(deriveSeverity({ severity: [V3_NONE, V4_HIGH], database_specific: { severity: "LOW" } })).toEqual({ severity: "low", cvssScore: 8.7 });
  });

  it("a severity entry with no score string is passed over, not a crash", () => {
    const broken = [{ type: "CVSS_V3" } as unknown as { type: string; score: string }, V4_HIGH];
    expect(deriveSeverity({ severity: broken })).toEqual({ severity: "high", cvssScore: 8.7 });
  });
});
