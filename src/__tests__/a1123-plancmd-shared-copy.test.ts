// SPDX-License-Identifier: Apache-2.0
/**
 * A direct upgrade moves the project's own copy, not the copies other packages require on the old
 * line. uptime-kuma 1.23.0 declares tar "~6.1.11"; its one tar 6.1.15 is also what cacache,
 * node-gyp and two more require ("^6..."). After `npm install "tar@~7.5.21"` (npm 10.9.2) the root
 * had tar 7.5.23 and each of them a nested tar 6.2.1, which 12 advisories affect, while the row
 * said `fixes: ["npm:tar"]`. The row now says which packages keep which copy, whether a release
 * inside their requirements clears it, and the hand step; it is not counted as fixed and is not in
 * run_order.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.ADVISORIES = { tar: [adv("GHSA-r6q2-hw4h-h46w", "tar", fixedIn("7.5.21"))] };
  h.NPM = {
    tar: { latest: "7.5.21", versions: { "6.1.15": {}, "6.2.1": {}, "7.5.21": {} } },
    cacache: { latest: "15.3.0", versions: { "15.3.0": { dependencies: { tar: "^6.0.2" } } } },
    "node-gyp": { latest: "8.4.1", versions: { "8.4.1": { dependencies: { tar: "^6.1.2" } } } },
    shared: { latest: "1.0.0", versions: { "1.0.0": { dependencies: { tar: ">=6" } } } },
  };
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");

describe("a direct upgrade whose copy other packages also use on the old line", () => {
  it("says which packages keep which copy, and does not count or script the row as a fix", async () => {
    h.npmProject({ tar: "~6.1.11", cacache: "^15.3.0", "node-gyp": "^8.4.1" }, {}, {
      tar: { version: "6.1.15" },
      cacache: { version: "15.3.0", dependencies: { tar: "^6.0.2" } },
      "node-gyp": { version: "8.4.1", dependencies: { tar: "^6.1.2" } },
    });
    const { result, step } = await h.plan();
    const row = step("tar");
    expect(row).toMatchObject({ action: "upgrade_direct", targetVersion: "7.5.21" });
    expect(reasonsOf(row)).toContain(
      'Other packages that use this copy of tar keep one on its old line after this upgrade: 2 packages require tar outside 7.5.21: cacache 15.3.0 ("^6.0.2"), node-gyp 8.4.1 ("^6.1.2"); npm installs tar 6.2.1 for them (the newest release their requirement admits), and 1 advisory still affects it (GHSA-r6q2-hw4h-h46w). Upgrading tar moves only this project\'s own copy; no release inside their requirements is clear of every advisory: an override that crosses a major (npm: add "overrides": { "tar": "7.5.21" } to package.json (npm 8.3+), then npm install; check they run on it) or upgrades of those packages to releases that require tar 7.5.21 or later move them. Until then those copies remain, so this row is not counted as fixed and is a hand edit, not in run_order',
    );
    expect(row.upgradeInstructions).toEqual([
      { dir: ".", instruction: "after upgrading tar, the copies of tar that 2 other packages keep remain (6.2.1): move them by hand, with an override that crosses a major or by upgrading those packages, then run vulnerability_scan" },
    ]);
    // The upgrade itself is still named on the row.
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: 'npm install "tar@~7.5.21"' }]);
    // No step claims to fix tar; the note names the row as a hand edit; the summary does not count it.
    const steps = result.run_order as Array<{ run: string; fixes: string[] }>;
    expect(steps.some((s) => s.fixes.includes("npm:tar"))).toBe(false);
    expect(result.run_order_note).toMatch(/1 row is a hand edit and is not in this script: tar 6\.1\.15/);
    expect(result.summary).toContain("1 direct upgrade that moves only this project's own copy: other packages keep an affected copy on the old line, moved by hand");
    expect(result.summary).not.toMatch(/\d+ upgradable directly/);
  });

  it("calls an override inside the major one past the range they declare, not one that crosses a major", async () => {
    h.ADVISORIES = { qs: [adv("GHSA-4mjr-xmp4-gh2g", "qs", fixedIn("6.16.0"))] };
    h.NPM.qs = { latest: "6.16.0", versions: { "6.10.4": {}, "6.10.7": {}, "6.16.0": {} } };
    h.NPM.req = { latest: "2.88.12", versions: { "2.88.12": { dependencies: { qs: "~6.10.3" } } } };
    h.npmProject({ qs: "~6.10.3", req: "^2.88.12" }, {}, { qs: { version: "6.10.4" }, req: { version: "2.88.12", dependencies: { qs: "~6.10.3" } } });
    const { step } = await h.plan();
    const row = step("qs");
    expect(reasonsOf(row)).toContain('npm installs qs 6.10.7 for them (the newest release their requirement admits), and 1 advisory still affects it (GHSA-4mjr-xmp4-gh2g)');
    expect(reasonsOf(row)).toContain("an override past the range they declare (npm: add \"overrides\": { \"qs\": \"6.16.0\" } to package.json");
    expect(row.upgradeInstructions).toEqual([
      { dir: ".", instruction: "after upgrading qs, the copy of qs that req keeps remains (6.10.7): move it by hand, with an override past the range they declare or by upgrading that package, then run vulnerability_scan" },
    ]);
  });

  it("does not take a peer requirement for a copy of its own", async () => {
    h.NPM.plugin = { latest: "1.0.0", versions: { "1.0.0": { peerDependencies: { tar: "^6.0.0" } } } };
    const root = { name: "x", version: "1.0.0", dependencies: { tar: "~6.1.11", plugin: "^1.0.0" } };
    h.write("package.json", JSON.stringify(root));
    h.write(
      "package-lock.json",
      JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": root, "node_modules/tar": { version: "6.1.15" }, "node_modules/plugin": { version: "1.0.0", peerDependencies: { tar: "^6.0.0" } } } }),
    );
    const { step } = await h.plan();
    expect(reasonsOf(step("tar"))).not.toMatch(/Other packages that use this copy/);
  });

  it("says nothing when every other package's requirement admits the target", async () => {
    h.npmProject({ tar: "~6.1.11", shared: "^1.0.0" }, {}, {
      tar: { version: "6.1.15" },
      shared: { version: "1.0.0", dependencies: { tar: ">=6" } },
    });
    const { result, step } = await h.plan();
    const row = step("tar");
    expect(reasonsOf(row)).not.toMatch(/Other packages that use this copy/);
    expect(row.upgradeInstructions).toBeUndefined();
    expect((result.run_order as Array<{ fixes: string[] }>).some((s) => s.fixes.includes("npm:tar"))).toBe(true);
    expect(result.summary).toMatch(/1 upgradable directly/);
  });
});
