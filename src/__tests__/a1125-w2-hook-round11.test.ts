// SPDX-License-Identifier: Apache-2.0
/**
 * Round 11, from the ninth independent check (the header read sentence by sentence): each item
 * with the reviewer's cases.
 */

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

describe("2: sed and awk are text only under a positive grammar", () => {
  it.each([
    "echo a | sed '1e npm i lodash@4.17.20'",
    "echo a | sed --expression='e npm i lodash@4.17.20'",
    "echo a | sed '/a/e pip install requests==2.5.0'",
    "echo a | sed '$e npm i lodash@4.17.20'",
    "echo a | sed '1,3e npm i lodash@4.17.20'",
    "echo a | sed -ee 'npm i lodash@4.17.20'",
    "sed -e 's/x/y/' -e '1e npm i lodash@4.17.20' f",
    "sed 's/x/npm i lodash@4.17.20/w out.sh' f",
    "awk 'BEGIN { system(\"npm i lodash@4.17.20\") }'",
    "awk '{ print \"npm i lodash@4.17.20\" | \"sh\" }' f",
    "awk -f prog.awk 'npm i lodash@4.17.20'",
  ])("%s: held", (command) => {
    expect(run(command).decision, command).toBe("deny");
  });

  it.each([
    "sed 's/npm install/npm ci/' README.md",
    "sed -n '/pip install/p' docs/setup.md",
    "sed -E 's|pip install (.*)|uv add \\1|g' notes.md",
    "sed '1d;s/npm install/pnpm install/' a.md",
    "awk '/pip install/ {print}' docs/setup.md",
    "awk '{print $1}' 'npm install.log'",
    "awk -F: 'NR==1' 'npm install.txt'",
  ])("%s: goes ahead", (command) => {
    expect(run(command).decision, command).toBe("allow");
  });
});

describe("3: a constraints or overrides file beside a named package, on every reader", () => {
  it.each([
    "uv tool install ruff -c c.txt",
    "uv tool install ruff --overrides o.txt",
    "uv tool install ruff --with black --constraints c.txt",
    "uv pip install requests -c c.txt",
    "uv add requests --constraints c.txt",
    "pip install requests --constraint c.txt",
    "python -m pip install requests -c c.txt",
  ])("%s: held, name the version; the named version, checked, goes ahead", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("name the version on the command line");
    releasedByTheCall(command.startsWith("uv tool") ? "uv tool install ruff==0.8.0" : "pip install requests==2.32.3");
  });
});
