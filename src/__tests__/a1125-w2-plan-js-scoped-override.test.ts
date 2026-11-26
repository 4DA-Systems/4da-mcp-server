// SPDX-License-Identifier: Apache-2.0
/**
 * An npm override scoped to a parent (`npm pkg set "overrides.request.qs=6.16.1"`) stops
 * `npm update` from moving any package inside that parent's subtree, whether the override has been
 * applied by an install yet or not. starship v1.0.0 docs/ (npm 10.9.2, 2026-11-26, scripts off):
 * with the override written first, `npm update jsprim` (request > http-signature > jsprim) said
 * "up to date" and left jsprim 1.4.1 / json-schema 0.2.3; a top-level override (`overrides.form-data`)
 * did not stop it; run before the override, it moved jsprim to 1.4.2 and json-schema to 0.4.0, and
 * the override and the install after it still landed (qs 6.16.1 under request). The audit's harness
 * scored that step "without effect".
 */

import { describe, expect, it } from "vitest";
import { buildRunOrder, type SequencedRow } from "../tools/upgrade-plan-sequence.js";

const cmd = (run: string, dir = ".") => ({ dir, run });
function row(pkg: string, action: string, runs: string[], fields: Partial<SequencedRow> = {}): SequencedRow {
  const commands = runs.map((r) => cmd(r));
  return { package: pkg, ecosystem: "npm", currentVersion: "1.0.0", targetVersion: "2.0.0", action, reasons: [], commands, refreshCommands: commands.map((c) => ({ dir: c.dir, command: c.run })), ...fields };
}
const lock = () => "/p/docs/package-lock.json";

describe("an npm override scoped to a parent and the refreshes on its lockfile", () => {
  const rows = () => [
    row("qs", "lockfile_refresh", ['npm pkg set "overrides.request.qs=6.16.1"', "npm install"], { currentVersion: "6.5.2" }),
    row("form-data", "lockfile_refresh", ['npm pkg set "overrides.form-data=2.5.6"', "npm install"], { currentVersion: "2.3.3" }),
    row("json-schema", "lockfile_refresh", ["npm update jsprim"], { currentVersion: "0.2.3" }),
  ];

  it("the refreshes run before the scoped override (starship docs: npm update jsprim)", () => {
    const order = buildRunOrder({ rows: rows(), totalRows: 3, heldUnclean: () => false, jsLockfileOf: lock }).run_order.map((s) => s.run);
    expect(order.indexOf("npm update jsprim")).toBeLessThan(order.indexOf('npm pkg set "overrides.request.qs=6.16.1"'));
    // The top-level override is not moved behind the refresh; the install stays last.
    expect(order.indexOf('npm pkg set "overrides.form-data=2.5.6"')).toBeLessThan(order.indexOf("npm update jsprim"));
    expect(order[order.length - 1]).toBe("npm install");
  });

  it("another lockfile's refresh is not ordered against it", () => {
    const other = [...rows().slice(0, 1), row("json-schema", "lockfile_refresh", ["npm update jsprim"], { commands: [cmd("npm update jsprim", "site")], refreshCommands: [{ dir: "site", command: "npm update jsprim" }] })];
    const out = buildRunOrder({ rows: other, totalRows: 2, heldUnclean: () => false, jsLockfileOf: (dir) => (dir === "site" ? "/p/site/package-lock.json" : lock()) }).run_order;
    // The root's override (phase of a version-setting step) comes first, as it did before.
    expect(out.map((s) => s.run)[0]).toBe('npm pkg set "overrides.request.qs=6.16.1"');
  });
});
