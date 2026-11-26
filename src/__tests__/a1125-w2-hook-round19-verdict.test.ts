// SPDX-License-Identifier: Apache-2.0
/**
 * Round 19 (N5, the seventeenth check's S1): a release inside the age hold answers wait even when
 * another signal asks for review (wait stops an install, review does not), and the review finding
 * is listed beside the wait. The other orders stay: a failed lookup outranks the age hold (a1119),
 * a concrete review finding outranks a failed lookup, avoid outranks everything, and a waived hold
 * (Decision 12) is no wait.
 */

import { describe, expect, it } from "vitest";

import { worseVerdict } from "../tools/dependency-check-resolution.js";
import { decide, type Signal } from "../tools/dependency-check-signals.js";

const sig = (id: Signal["id"], effect: Signal["effect"], evidence: string): Signal => ({ id, value: null, evidence, effect });
const AGE = sig("release_age", "wait", "0.29.0 was published 0.2 days ago; releases younger than 3 days are held.");
const PY = sig("python_support", "review", "0.29.0 requires Python >=3.10; the project allows >=3.9.");

describe("N5: wait above review", () => {
  it("httpx 0.29.0 (0.2 days old, a python_support review): wait, with the review listed", () => {
    const d = decide([AGE, PY, sig("advisories", "proceed", "No known vulnerability affects 0.29.0.")]);
    expect(d.verdict).toBe("wait");
    expect(d.reason).toContain("release_age:");
    expect(d.reason).toContain("python_support:");
  });
  it("the other orders are kept", () => {
    expect(decide([AGE, PY, sig("advisories", "avoid", "GHSA-x high")]).verdict).toBe("avoid");
    expect(decide([AGE, sig("advisories", "unknown", "OSV.dev could not be reached")]).verdict).toBe("unknown");
    expect(decide([PY, sig("advisories", "unknown", "OSV.dev could not be reached")]).verdict).toBe("review");
    // Decision 12: a waived hold is no wait (release_age proceeds, hold_waived), so the review stands.
    expect(decide([sig("release_age", "proceed", "held release, hold waived: no settled safe release (hold_waived)"), PY]).verdict).toBe("review");
  });
  it("worseVerdict agrees", () => {
    expect(worseVerdict("wait", "review")).toBe("wait");
    expect(worseVerdict("review", "wait")).toBe("wait");
    expect(worseVerdict("wait", "unknown")).toBe("unknown");
    expect(worseVerdict("review", "unknown")).toBe("review");
    expect(worseVerdict("avoid", "wait")).toBe("avoid");
  });
});
