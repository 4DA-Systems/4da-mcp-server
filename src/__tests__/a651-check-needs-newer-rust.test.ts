// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check states the caveat upgrade_planner flags (needsNewerRust): a crate release that
 * needs a newer Rust than the project's rust-version. Claims review of the 6.5.1 candidate
 * (2026-11-24): time 0.3.47 in a project declaring rust-version 1.64 was `proceed` with no mention.
 * The verdict is unchanged (no advisory); the item carries `needs_newer_rust` and the reason says so.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.CRATES = { time: [{ vers: "0.3.36", rust_version: "1.63" }, { vers: "0.3.47", rust_version: "1.88" }] };
  h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\nrust-version = "1.64"\n\n[dependencies]\ntime = "0.3.36"\n');
  h.write("Cargo.lock", 'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "time",\n]\n\n[[package]]\nname = "time"\nversion = "0.3.36"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n');
});
afterEach(() => h.dispose());

describe("a crate release that needs a newer Rust than rust-version", () => {
  it("is answered with the caveat", async () => {
    const r = (await executeDependencyCheck(null, { items: [{ ecosystem: "crates.io", package: "time", to: "0.3.47", from: "0.3.36" }] }, await h.live())) as { results: Array<Record<string, any>> };
    const item = r.results[0];
    expect(item.needs_newer_rust).toEqual({ needs: "1.88", declared: "1.64", manifest: expect.stringContaining("Cargo.toml") });
    expect(item.reason).toMatch(/needs Rust 1\.88 .* rust-version 1\.64/);
  });

  it("control: a release that declares an older Rust carries none", async () => {
    const r = (await executeDependencyCheck(null, { items: [{ ecosystem: "crates.io", package: "time", to: "0.3.36" }] }, await h.live())) as { results: Array<Record<string, any>> };
    expect(r.results[0].needs_newer_rust).toBeUndefined();
  });
});
