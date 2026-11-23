// SPDX-License-Identifier: Apache-2.0
/**
 * A Cargo project that declares `rust-version` (its MSRV) promises to build with that Rust. A plan
 * step that installs a crate release needing a newer Rust breaks that promise: bat v0.23.0 declares
 * rust-version 1.64, and its plan moved time 0.3.14 to 0.3.47 (`cargo update -p time@0.3.14
 * --precise 0.3.47`), whose own rust-version is 1.88 (blind check 1 of 6.5.0, SF2). `--precise`
 * and `cargo add x@version` install the release whatever rust-version says; the build then fails
 * on the declared Rust. Every such step now says so: the row's `needsNewerRust` names the crate,
 * the Rust it needs and the manifest that declares the older one, a reason says what to do, and
 * the summary and run_order_note count them.
 */

import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { declaredRustVersion, rustNewer } from "../tools/upgrade-planner-rust-version.js";

describe("the declared rust-version and the comparison", () => {
  it("compares Rust versions part by part, a missing patch as 0", () => {
    expect(rustNewer("1.88.0", "1.64")).toBe(true);
    expect(rustNewer("1.64.0", "1.64")).toBe(false);
    expect(rustNewer("1.67.1", "1.67")).toBe(true);
    expect(rustNewer("1.9", "1.64")).toBe(false);
    expect(rustNewer("stable", "1.64")).toBeNull();
  });

  it("a member that inherits reads the workspace root above it; a virtual root's [workspace.package] counts; comments and other tables do not", () => {
    const hh = createHarness();
    try {
      hh.write("Cargo.toml", '[workspace]\nmembers = ["crates/a"]\n\n[workspace.package]\nrust-version = "1.70" # the MSRV\n\n[workspace.dependencies]\nrust-version = "9.9"\n');
      hh.write("crates/a/Cargo.toml", '[package]\nname = "a"\nversion = "0.1.0"\nrust-version = { workspace = true }\n\n[dependencies]\ntime = "0.3"\n');
      hh.write("crates/b/Cargo.toml", '[package]\nname = "b"\nversion = "0.1.0"\n# rust-version = "1.50"\n');
      expect(declaredRustVersion(path.join(hh.dir, "crates", "a"))).toEqual({ version: "1.70", manifest: path.join(hh.dir, "Cargo.toml") });
      expect(declaredRustVersion(hh.dir)).toEqual({ version: "1.70", manifest: path.join(hh.dir, "Cargo.toml") });
      expect(declaredRustVersion(path.join(hh.dir, "crates", "b"))).toBeNull();
    } finally {
      hh.dispose();
    }
  });
});

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.ADVISORIES = { time: [adv("RUSTSEC-2026-0009", "time", [{ introduced: "0.3.6" }, { fixed: "0.3.47" }], "crates.io")] };
  h.CRATES = {
    time: [
      { vers: "0.3.14", rust_version: "1.59.0" },
      { vers: "0.3.47", rust_version: "1.88.0" },
    ],
  };
});
afterEach(() => h.dispose());

const REG = 'source = "registry+https://github.com/rust-lang/crates.io-index"\n';
const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");

function directProject(packageTable: string, extra = ""): void {
  h.write("Cargo.toml", `[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n${packageTable}\n[dependencies]\ntime = "0.3.14"\n${extra}`);
  h.write("Cargo.lock", `version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "time",\n]\n\n[[package]]\nname = "time"\nversion = "0.3.14"\n${REG}`);
}

describe("a Cargo step that installs a release needing a newer Rust than rust-version declares", () => {
  it("a direct upgrade: the row names the crate, the Rust it needs and the manifest; summary and run_order_note say it", async () => {
    directProject('rust-version = "1.64"\n');
    const { result, step } = await h.plan();
    const row = step("time");
    expect(row).toMatchObject({ action: "upgrade_direct", targetVersion: "0.3.47" });
    expect(row.needsNewerRust).toEqual([{ crate: "time", version: "0.3.47", needs: "1.88.0", declared: "1.64", manifest: "Cargo.toml" }]);
    expect(reasonsOf(row)).toContain("Rust version: time 0.3.47 needs Rust 1.88.0 (its rust-version on crates.io), and Cargo.toml declares rust-version 1.64");
    expect(result.summary).toMatch(/1 row plans a crate release that needs a newer Rust than the project's rust-version/);
    expect(result.run_order_note).toMatch(/needs a newer Rust than its rust-version/);
  });

  it("a lockfile refresh of a transitive copy (`cargo update --precise`) is flagged the same way", async () => {
    h.CRATES.plist = [{ vers: "1.3.1", deps: [{ name: "time", req: "^0.3.3" }] }];
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\nrust-version = "1.64"\n\n[dependencies]\nplist = "1.3.1"\n');
    h.write(
      "Cargo.lock",
      `version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "plist",\n]\n\n[[package]]\nname = "plist"\nversion = "1.3.1"\n${REG}dependencies = [\n "time",\n]\n\n[[package]]\nname = "time"\nversion = "0.3.14"\n${REG}`,
    );
    const { result, step } = await h.plan();
    const row = step("time");
    expect(row).toMatchObject({ action: "lockfile_refresh", targetVersion: "0.3.47" });
    expect(row.needsNewerRust).toEqual([{ crate: "time", version: "0.3.47", needs: "1.88.0", declared: "1.64", manifest: "Cargo.toml" }]);
    expect(reasonsOf(row)).toContain("after this step the project no longer builds with Rust 1.64");
    expect(result.summary).toMatch(/needs a newer Rust than the project's rust-version/);
  });

  it("reads rust-version inherited from [workspace.package]", async () => {
    directProject("rust-version.workspace = true\n", '\n[workspace]\nmembers = []\n\n[workspace.package]\nrust-version = "1.70.0"\n');
    const { step } = await h.plan();
    expect(step("time").needsNewerRust).toEqual([{ crate: "time", version: "0.3.47", needs: "1.88.0", declared: "1.70.0", manifest: "Cargo.toml" }]);
  });

  it("says nothing when the declared Rust is new enough, none is declared, or the release declares none", async () => {
    directProject('rust-version = "1.88"\n');
    let plan = await h.plan();
    expect(plan.step("time").needsNewerRust).toBeUndefined();
    expect(plan.result.summary).not.toMatch(/newer Rust/);

    directProject("");
    plan = await h.plan();
    expect(plan.step("time").needsNewerRust).toBeUndefined();

    directProject('rust-version = "1.64"\n');
    h.CRATES.time = [{ vers: "0.3.14" }, { vers: "0.3.47" }];
    plan = await h.plan();
    expect(plan.step("time").needsNewerRust).toBeUndefined();
    expect(reasonsOf(plan.step("time"))).not.toMatch(/Rust version:/);
  });
});
