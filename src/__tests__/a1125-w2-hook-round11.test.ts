// SPDX-License-Identifier: Apache-2.0
/**
 * Round 11, from the ninth independent check (the header read sentence by sentence): each item
 * with the reviewer's cases.
 */

import { realpathSync } from "node:fs";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

/** Held; the dependency_check call its denial names, answered proceed, releases it. */
function releasedByTheCall(command: string, tool = "Bash"): void {
  const r = run(command, tool);
  expect(r.decision, r.text).toBe("deny");
  expect(r.items, r.text).not.toBeNull();
  answerDenial(s, r, "proceed");
  expect(run(command, tool).decision).toBe("allow");
}

const LS = "‘";
const RS = "’";
const LD = "“";
const RD = "”";
const LOW = "‚";
const LOWD = "„";

describe("1: PowerShell's typographic quotes are quotes", () => {
  it.each([
    `n${LS}${RS}pm i lodash@4.17.20`,
    `npm ${LS}i${RS} lodash@4.17.20`,
    `npm ${LD}install${RD} lodash@4.17.20`,
    `p${LS}${RS}ip install requests==2.5.0`,
    `pnpm ${LS}add${RS} lodash@4.17.20`,
    `uv ${LS}add${RS} requests==2.5.0`,
    `cargo ${LD}add${RD} serde@1.0.0`,
    `go ${LS}get${RS} rsc.io/quote@v1.5.0`,
    `npm ${LOW}i${RS} lodash@4.17.20`,
    `npm ${LOWD}i${RD} lodash@4.17.20`,
  ])("%s: read, held, released by the call", (command) => {
    releasedByTheCall(command, "PowerShell");
  });
});
