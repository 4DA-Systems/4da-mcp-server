// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14, from the twelfth independent check: a cut. Fewer things go ahead, decided by positive
 * evidence. Each rule (R1-R12) with the reviewer's cases.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("R1 / R2: changes the round-14 cut makes to earlier rows", () => {
  it.each([
    "pnpm add --trust-policy no-downgrade lodash@4.17.21",
    "go get -u github.com/pkg/errors@upgrade",
    "pip install --no-index --find-links ./wheels requests",
  ])("%s: held as not read (off the allow list, or more than one source)", (command) => {
    expect(run(command).text).toContain("could not be read");
  });
});
