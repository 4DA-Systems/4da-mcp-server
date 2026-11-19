// SPDX-License-Identifier: Apache-2.0
/**
 * Cargo: a wildcard is `*`, `x` or `X` standing as a whole numeric component.
 * An `x` inside a prerelease (`1.0.0-alpha.x`) is an identifier, so the bare
 * requirement keeps Cargo's caret reading.
 */
import { describe, expect, it } from "vitest";
import { cargoReqAdmits } from "../live/range-satisfies.js";

describe("cargo: `x` in a prerelease is not a wildcard", () => {
  it("1.0.0-alpha.x is ^1.0.0-alpha.x", () => {
    expect(cargoReqAdmits("1.0.0-alpha.x", "1.2.0")).toBe(true);
    expect(cargoReqAdmits("1.0.0-alpha.x", "1.0.0")).toBe(true);
    expect(cargoReqAdmits("1.0.0-alpha.x", "2.0.0")).toBe(false);
    expect(cargoReqAdmits("1.0.0-alpha.x", "1.0.0-alpha.w")).toBe(false);
  });

  it("wildcards in the numeric part are still read as the line they write out", () => {
    expect(cargoReqAdmits("1.0.*", "1.0.9")).toBe(true);
    expect(cargoReqAdmits("1.0.*", "1.1.0")).toBe(false);
    expect(cargoReqAdmits("1.x", "1.9.0")).toBe(true);
    expect(cargoReqAdmits("1.x", "2.0.0")).toBe(false);
    expect(cargoReqAdmits("1.2.X", "1.3.0")).toBe(false);
  });
});
