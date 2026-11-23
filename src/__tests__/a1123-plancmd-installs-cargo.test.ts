// SPDX-License-Identifier: Apache-2.0
/**
 * Cargo: `cargo add smallvec@1.6.1` writes the requirement "1.6.1", which Cargo reads as ^1.6.1, and
 * the lockfile takes the newest release it admits (cargo 1.97.0, 2026-11-23: `cargo add itoa@1.0.1`
 * from itoa 0.4.1 locked 1.0.19; `cargo add "itoa@~1.0.1"` locked 1.0.19; `cargo add "itoa@=1.0.1"`
 * locked 1.0.1). So the release a resolve takes is checked as the target was (its advisories, what
 * it requires), and when it fails or cannot be established the command requires the target exactly.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsmallvec = "0.6.9"\n');
  h.write(
    "Cargo.lock",
    'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "smallvec",\n]\n\n[[package]]\nname = "smallvec"\nversion = "0.6.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
  );
  h.CRATES = { smallvec: ["0.6.9", "0.6.14", "1.6.0", "1.6.1", "1.13.2"].map((vers) => ({ vers })) };
  h.ADVISORIES = { smallvec: [adv("RUSTSEC-2021-0003", "smallvec", fixedIn("1.6.1"), "crates.io")] };
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");

describe("a Cargo upgrade written as a caret requirement", () => {
  it("keeps the command when the release a resolve takes passes the target's checks, and says which", async () => {
    const { step } = await h.plan();
    const row = step("smallvec");
    expect(row).toMatchObject({ action: "upgrade_direct", targetVersion: "1.6.1" });
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: "cargo add smallvec@1.6.1", installs: "1.13.2" }]);
    expect(reasonsOf(row)).toContain(
      '`cargo add smallvec@1.6.1` installs smallvec 1.13.2, not 1.6.1: it is the newest release "^1.6.1" admits, which a resolve takes; 1.13.2 was checked as 1.6.1 was: no advisory of smallvec affects it, and what it requires carries no advisory',
    );
  });

  it("requires the target exactly when an advisory affects the release a resolve takes", async () => {
    h.ADVISORIES.smallvec.push(adv("RUSTSEC-2024-0388", "smallvec", [{ introduced: "1.13.0" }], "crates.io"));
    const { result, step } = await h.plan();
    const row = step("smallvec");
    expect(row.targetVersion).toBe("1.6.1");
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: 'cargo add "smallvec@=1.6.1"' }]);
    expect(reasonsOf(row)).toContain(
      '`cargo add "smallvec@=1.6.1"`, not `cargo add smallvec@1.6.1`: Cargo installs smallvec 1.13.2 for "^1.6.1" (it is the newest release "^1.6.1" admits, which a resolve takes), and RUSTSEC-2024-0388 affects 1.13.2, not 1.6.1; the exact form installs 1.6.1, the release this plan checked',
    );
    expect((result.run_order as Array<{ run: string }>).map((s) => s.run)).toContain('cargo add "smallvec@=1.6.1"');
  });
});
