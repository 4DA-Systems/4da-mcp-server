// SPDX-License-Identifier: Apache-2.0
/**
 * Round 8 (R8-6): one-letter options run together and ending in one that takes a value
 * (`pip install -Ur requirements.txt`, `-qr requirements.txt`) take the next word as that value,
 * and no denial ever names a file name as a package to check.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([{ ecosystem: "PyPI", package: "requests", version: "2.31.0", verdict: "proceed" }]);
});
afterEach(() => s.dispose());

const cmd = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("a cluster ending in a value option takes the next word", () => {
  it.each([
    "pip install -Ur requirements.txt",
    "pip install -qr requirements.txt",
    "pip3 install -qUr requirements-dev.txt",
    "python -m pip install -Ur requirements.in",
    "pip install -Uqr requirements.txt requests==2.31.0",
    "uv pip install -Ur requirements.txt",
  ])("%s", (command) => {
    const r = cmd(command);
    expect(r.decision, r.text).toBe("allow");
    expect(r.text).not.toMatch(/requirements/);
  });

  it("a glued file (-qrreq.txt) reads the same", () => {
    expect(cmd("pip install -qrrequirements.txt").decision).toBe("allow");
  });
});

describe("no denial names a file as a package to check", () => {
  it.each([
    "pip install requirements.txt",
    "pip install -U requirements.txt",
    "pip install constraints.in",
    "npm install deps.json",
  ])("%s", (command) => {
    const r = cmd(command);
    expect(r.items ?? []).toEqual([]);
    expect(r.text).not.toMatch(/dependency_check \{"items":\[[^\]]*(?:requirements|constraints|deps)\./);
  });
});
