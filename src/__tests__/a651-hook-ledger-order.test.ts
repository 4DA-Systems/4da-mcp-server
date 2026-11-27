// SPDX-License-Identifier: Apache-2.0
/**
 * An avoid or wait for the exact version holds until a later proceed or review for it, whatever
 * lies between; and "later" is the entry's time, not its place in the file.
 *
 * Independent re-check of 0d30b40 (S2): with avoid, then an `unknown` (time budget) for the same
 * version, then a private answer, the private answer let the version through, although the
 * changelog says a private answer never goes ahead over an avoid or wait for the exact version.
 * And entries were ordered by their place in the files, so an avoid one minute old written before
 * a proceed an hour old lost to it (several servers append to one ledger).
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE, LEDGER_PREVIOUS_FILE } from "../check-ledger.js";

let home: string;
let project: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "a651-ledger-order-"));
  project = mkdtempSync(join(tmpdir(), "a651-ledger-order-proj-"));
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(project, { recursive: true, force: true });
});

const NOW = Date.parse("2026-11-24T12:00:00Z");
const MIN = 60_000;
const e = (minutesAgo: number, fields: Record<string, unknown>) => ({ t: new Date(NOW - minutesAgo * MIN).toISOString(), ecosystem: "npm", package: "lodash", version: "4.17.20", ...fields });
const lines = (entries: unknown[]) => entries.map((x) => JSON.stringify({ sv: "6.6.0", ...(x as object) })).join("\n") + "\n";
const decide = () => (respond({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd: project, tool_input: { command: "npm i lodash@4.17.20" } }, { FOURDA_MCP_HOME: home }, NOW) === "" ? "allow" : "deny");

describe("an avoid or wait holds over a later private answer, whatever lies between", () => {
  it.each([
    ["avoid, unknown (time budget), private", { verdict: "avoid" }, { verdict: "unknown", not_checked: "time_budget" }],
    ["avoid, unknown (plain), private", { verdict: "avoid" }, { verdict: "unknown" }],
    ["wait, unknown, private", { verdict: "wait" }, { verdict: "unknown" }],
  ])("%s: held", (_label, first, between) => {
    writeFileSync(join(home, LEDGER_FILE), lines([e(30, first), e(20, between), e(10, { verdict: "unknown", not_checked: "private", private_rule: "listed", project })]));
    expect(decide()).toBe("deny");
  });

  it("a later proceed for the version still lets it through", () => {
    writeFileSync(join(home, LEDGER_FILE), lines([e(30, { verdict: "avoid" }), e(20, { verdict: "unknown" }), e(10, { verdict: "proceed" })]));
    expect(decide()).toBe("allow");
  });
});

describe("later means the entry's time, not its place in the files", () => {
  it("an avoid one minute old written before a proceed an hour old: held", () => {
    writeFileSync(join(home, LEDGER_FILE), lines([e(1, { verdict: "avoid" }), e(60, { verdict: "proceed" })]));
    expect(decide()).toBe("deny");
  });

  it("a proceed one minute old in the previous file and an avoid an hour old in the current one: allowed", () => {
    writeFileSync(join(home, LEDGER_PREVIOUS_FILE), lines([e(1, { verdict: "proceed" })]));
    writeFileSync(join(home, LEDGER_FILE), lines([e(60, { verdict: "avoid" })]));
    expect(decide()).toBe("allow");
  });

  it("two entries with the same time keep their file order (the later line counts)", () => {
    writeFileSync(join(home, LEDGER_FILE), lines([e(5, { verdict: "avoid" }), e(5, { verdict: "proceed" })]));
    expect(decide()).toBe("allow");
  });
});
