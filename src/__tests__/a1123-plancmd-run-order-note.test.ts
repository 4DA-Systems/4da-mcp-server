// SPDX-License-Identifier: Apache-2.0
/**
 * run_order_note: "safe to run from the first to the last" is a claim about the order (no step
 * lowers what is installed or what an earlier step set), and it read as one about the result. The
 * note says it as an order claim and adds that an upgraded package's own dependencies below the
 * first level are not checked, so a scan follows the run.
 */

import { describe, expect, it } from "vitest";
import { buildRunOrder, type SequencedRow } from "../tools/upgrade-plan-sequence.js";

const row = (pkg: string, action: string, runs: string[], extra: Partial<SequencedRow> = {}): SequencedRow => ({
  package: pkg,
  ecosystem: "npm",
  currentVersion: "1.0.0",
  targetVersion: "1.0.1",
  action,
  reasons: [],
  commands: runs.map((run) => ({ dir: ".", run })),
  ...extra,
});

describe("run_order_note", () => {
  it("states the order claim as one about order, and that the run is followed by a scan", () => {
    const out = buildRunOrder({ rows: [row("a", "upgrade_direct", ["npm install a@1.0.1 --save-exact"], { upgradeCommands: [{ dir: ".", command: "npm install a@1.0.1 --save-exact" }] })], totalRows: 1, heldUnclean: () => false });
    expect(out.run_order_note).toMatch(
      /^run_order is 1 step for 1 of the 1 row shown, in an order that is safe to run from the first step to the last \(no step lowers a version that is installed or that an earlier step sets\), each in the directory it names: /,
    );
    expect(out.run_order_note).toContain(
      ". An upgraded package's own dependencies are checked one level down, and on npm their exact pins two levels down; a range at that level, anything deeper and a copy bundled inside a package are not, so run vulnerability_scan again after running it.",
    );
    expect(out.run_order_note).not.toContain("\n");
  });

  it("an empty script names no scan to follow it", () => {
    const out = buildRunOrder({ rows: [row("a", "waiting_on_upstream", [])], totalRows: 1, heldUnclean: () => false });
    expect(out.run_order_note).toMatch(/^run_order is empty/);
    expect(out.run_order_note).not.toContain("run vulnerability_scan again");
  });
});
