// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-merge replay of round 3 (2026-11-14): "bump omega-internal-risk to 3.2.0" in a project that
 * installs it from a private pip index led with "omega-internal-risk 3.1.0, omega-internal-risk":
 * the installed PyPI copy, then the same name again because the rules also call it private in npm.
 */
import { describe, expect, it } from "vitest";
import { privateAdvisoryText, privateTaskPackages } from "../tools/briefing-private.js";

describe("privateTaskPackages", () => {
  it("names a private package once, whatever ecosystems call it private", () => {
    const dep = { ecosystem: "PyPI", name: "omega-internal-risk", version: "3.1.0" };
    const live = {
      getPrivateAuditDeps: () => [dep as never],
      getAuditDeps: () => [],
      getPrivateDependencies: () => [{ ...dep, why: "requirements.txt --index-url" }],
      privateReason: (_eco: string, name: string) => (name.toLowerCase() === "omega-internal-risk" ? "private" : null),
    };
    const found = privateTaskPackages("bump omega-internal-risk to 3.2.0", [], live);
    expect(found.map((p) => [p.ecosystem, p.package, p.installed])).toEqual([["PyPI", "omega-internal-risk", ["3.1.0"]]]);
    expect(privateAdvisoryText(found)).toMatch(/touches omega-internal-risk 3\.1\.0, a private package:/);
  });
});
