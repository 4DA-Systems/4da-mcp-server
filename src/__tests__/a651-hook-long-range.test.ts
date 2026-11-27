// SPDX-License-Identifier: Apache-2.0
/**
 * A range or constraint longer than 80 characters is read and judged like any other (round 4 of
 * the hook review, item 4; the checker's c6-longrange).
 *
 * Round 3 held any version or constraint over 80 characters as "could not be read", so a real peer
 * range such as `^3.0.0 || ^4.0.0 || ... || ^10.0.0-0` (81 characters, which the server accepts and
 * records) stayed held for ever, even after a proceed for that same constraint. The 80-character
 * bound belongs to a single version; a range or constraint has a bound of its own (1,000
 * characters), past which it is held.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";

const R = "^3.0.0 || ^4.0.0 || ^5.0.0 || ^6.0.0 || ^7.0.0 || ^8.0.0-0 || ^9.0.0 || ^10.0.0-0";
const R2 = ">=16.14.0 <17.0.0 || >=17.0.2 <18.0.0 || >=18.2.0 <19.0.0 || >=19.0.0 <20.0.0";

let dir: string;
let home: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "a651-long-range-"));
  home = join(dir, "home");
  mkdirSync(home);
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function ledger(entries: Array<Record<string, unknown>>) {
  writeFileSync(join(home, LEDGER_FILE), entries.map((e) => JSON.stringify({ sv: "6.6.0", t: new Date(Date.now() - 60_000).toISOString(), ecosystem: "npm", ...e })).join("\n") + "\n");
}
function decide(input: Record<string, unknown>): { decision: "allow" | "deny"; text: string } {
  const out = respond({ hook_event_name: "PreToolUse", cwd: dir, ...input }, { FOURDA_MCP_HOME: home }, Date.now());
  return out === "" ? { decision: "allow", text: "" } : { decision: "deny", text: (JSON.parse(out) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason };
}

describe("a range over 80 characters with a proceed for that constraint goes ahead", () => {
  it("npm i 'eslint@<81-character range>'", () => {
    expect(R.length).toBeGreaterThan(80);
    ledger([{ package: "eslint", version: "10.0.0", requested: R, verdict: "proceed" }]);
    expect(decide({ tool_name: "Bash", tool_input: { command: `npm i 'eslint@${R}'` } }).decision).toBe("allow");
  });

  it("an Edit of a peer range to it, and an added react peer range", () => {
    ledger([
      { package: "eslint", version: "10.0.0", requested: R, verdict: "proceed" },
      { package: "react", version: "19.2.0", requested: R2, verdict: "proceed" },
    ]);
    const file = join(dir, "package.json");
    writeFileSync(file, JSON.stringify({ name: "p", version: "1.0.0", peerDependencies: { eslint: "^3.0.0 || ^9.0.0" } }, null, 2));
    expect(decide({ tool_name: "Edit", tool_input: { file_path: file, old_string: '"^3.0.0 || ^9.0.0"', new_string: JSON.stringify(R) } }).decision).toBe("allow");
    expect(decide({ tool_name: "Edit", tool_input: { file_path: file, old_string: '"peerDependencies": {', new_string: `"peerDependencies": {\n    "react": ${JSON.stringify(R2)},` } }).decision).toBe("allow");
  });

  it("without a verdict it is held with the call for that constraint, not as unreadable", () => {
    ledger([{ package: "other", version: "1.0.0", verdict: "proceed" }]);
    const r = decide({ tool_name: "Bash", tool_input: { command: `npm i 'eslint@${R}'` } });
    expect(r.decision).toBe("deny");
    expect(r.text).not.toMatch(/could not be read/);
    expect(r.text).toContain(JSON.stringify({ ecosystem: "npm", package: "eslint", to: R }).slice(1, -1));
  });
});

describe("still held as not read", () => {
  it("a single version over 80 characters", () => {
    ledger([{ package: "other", version: "1.0.0", verdict: "proceed" }]);
    expect(decide({ tool_name: "Bash", tool_input: { command: `npm i lodash@4.17.20+${"a".repeat(80)}` } }).text).toMatch(/could not be read \(a version over 80 characters\)/);
    expect(decide({ tool_name: "Bash", tool_input: { command: `pip install requests==${"2.0.0" + ".0".repeat(38)}` } }).text).toMatch(/a version over 80 characters/);
  });

  it("a range over 1,000 characters", () => {
    ledger([{ package: "other", version: "1.0.0", verdict: "proceed" }]);
    const huge = Array.from({ length: 120 }, (_, i) => `^${i}.0.0`).join(" || ");
    expect(huge.length).toBeGreaterThan(1000);
    expect(decide({ tool_name: "Bash", tool_input: { command: `npm i 'eslint@${huge}'` } }).text).toMatch(/could not be read \(a constraint over 1000 characters\)/);
  });
});
