// SPDX-License-Identifier: Apache-2.0
/**
 * Round 8 (R8-4): the raw text of a call is normalised once before the ledger's name test: case
 * folded, every run of `/` and `\` one `/`, `/./` dropped, `name/../` resolved as text, `\\?\`
 * stripped, and the `//localhost/c$/`, `/c/`, `/mnt/c/` and `/cygdrive/c/` forms read as `c:/`.
 * The data folder's path in any of those spellings is held like the path itself.
 */

import { realpathSync } from "node:fs";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "GHSA-35jh-r3h4-6jhm" };

let s: Sandbox;
let H: string;
beforeEach(() => {
  s = sandbox();
  s.ledger([AVOID]);
  H = realpathSync(s.home).replace(/\\/g, "/");
});
afterEach(() => s.dispose());

const B = "\\";
const cmd = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const write = (file_path: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path, content: "x" } });

/** The data folder's path in another spelling. */
const spellings: [string, (h: string) => string][] = [
  ["upper case with a doubled slash", (h) => `${h.toUpperCase()}//`],
  ["doubled backslashes", (h) => h.replace(/\//g, B + B) + B + B],
  ["the Git Bash /c/ form", (h) => (/^[A-Za-z]:/.test(h) ? `/${h[0].toLowerCase()}${h.slice(2)}/` : `${h}/`)],
  ["the /mnt/c/ form", (h) => (/^[A-Za-z]:/.test(h) ? `/mnt/${h[0].toLowerCase()}${h.slice(2)}/` : `${h}/`)],
  ["the /cygdrive/c/ form", (h) => (/^[A-Za-z]:/.test(h) ? `/cygdrive/${h[0].toLowerCase()}${h.slice(2)}/` : `${h}/`)],
  ["a \\\\?\\ prefix", (h) => (/^[A-Za-z]:/.test(h) ? `${B}${B}?${B}${h.replace(/\//g, B)}${B}` : `${h}/`)],
  ["a //localhost/c$/ share", (h) => (/^[A-Za-z]:/.test(h) ? `//localhost/${h[0].toLowerCase()}$${h.slice(2)}/` : `${h}/`)],
  ["a /./ step", (h) => `${h}/./`],
  ["a name/../ step", (h) => `${h.slice(0, h.lastIndexOf("/"))}/zz/../${h.slice(h.lastIndexOf("/") + 1)}/`],
  ["a trailing name/../ step", (h) => `${h}/sub/..//`],
];

describe("the data folder in another spelling is held", () => {
  it.each(spellings)("a command writing through %s", (_label, spell) => {
    const r = cmd(`echo x > '${spell(H)}x.txt'`);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("it names the 4da check ledger");
  });

  it.each(spellings)("a Write through %s", (_label, spell) => {
    expect(write(`${spell(H)}x.json`).decision).toBe("deny");
  });
});

describe("ordinary paths still go ahead", () => {
  it.each([
    ["a relative write", "echo hi > docs/notes.txt"],
    ["a parent step", "cd ../a && ls"],
    ["a plain read of the ledger", ""],
    ["a path elsewhere with ../", "cat src/../README.md"],
  ])("%s", (_label, command) => {
    const r = cmd(command || `cat '${H}/check-ledger.jsonl'`);
    expect(r.decision, r.text).toBe("allow");
  });
});
