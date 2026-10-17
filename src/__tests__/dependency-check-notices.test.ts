// SPDX-License-Identifier: Apache-2.0
/**
 * Audit L3 (readiness of 6.2.5): an unmaintained-package notice names no
 * exploitable vulnerability, so it never moves dependency_check's verdict. A
 * target carrying a NEW notice used to read `review`; it is reported in its
 * own `maintenance_notices` field instead, the same split vulnerability_scan
 * makes.
 */
import { describe, expect, it } from "vitest";
import { advisoriesSignal, type AdvisoryRef, type CheckItem } from "../tools/dependency-check-signals.js";

const item: CheckItem = { ecosystem: "crates.io", package: "atty", from: "0.2.13", to: "0.2.14" };
const notice: AdvisoryRef = { id: "RUSTSEC-2024-0375", severity: "unknown", summary: "`atty` is unmaintained", maintenance: true };
const medium: AdvisoryRef = { id: "RUSTSEC-2021-0145", severity: "medium", summary: "Potential unaligned read", maintenance: false };

describe("maintenance notices (L3)", () => {
  it("a new notice on the target does not block proceed and is listed on its own", () => {
    const s = advisoriesSignal(item, { available: true, from: [], to: [notice] });
    expect(s.effect).toBe("proceed");
    expect(s.value).toMatchObject({ affecting_to: [], maintenance_notices: ["RUSTSEC-2024-0375"] });
    expect(s.evidence).toContain("RUSTSEC-2024-0375");
    expect(s.evidence).toContain("no exploitable vulnerability");
  });

  it("a notice already on `from` says so", () => {
    const s = advisoriesSignal(item, { available: true, from: [notice], to: [notice] });
    expect(s.effect).toBe("proceed");
    expect(s.evidence).toContain("already on 0.2.13");
  });

  it("a real advisory still decides, with the notice reported beside it", () => {
    const s = advisoriesSignal(item, { available: true, from: [], to: [notice, medium] });
    expect(s.effect).toBe("review");
    expect(s.value).toMatchObject({ affecting_to: ["RUSTSEC-2021-0145"], maintenance_notices: ["RUSTSEC-2024-0375"] });
  });

  it("no notice: no maintenance_notices field", () => {
    const s = advisoriesSignal(item, { available: true, from: [], to: [] });
    expect(s.effect).toBe("proceed");
    expect(s.value).not.toHaveProperty("maintenance_notices");
  });
});
