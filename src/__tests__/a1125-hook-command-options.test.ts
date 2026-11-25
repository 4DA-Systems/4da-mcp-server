// SPDX-License-Identifier: Apache-2.0
/**
 * Global options before the subcommand that the hook read wrong, so the install after them was not
 * seen (audit 2026-11-25, D minors): npm's Boolean options take a following `true` / `false`
 * (`npm --audit false install x@1`, nopt reads `false` as the option's value), uv's global options
 * (`uv -q pip install`), pip's general options that take a value (`pip --cert ca.pem install`)
 * and pnpm's `--prefix <dir>`.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });
const NPM_AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "advisories" };
const PY_AVOID = { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "advisories" };

describe("each spelling is held with an avoid on record, and released by the denial's own call", () => {
  it.each([
    ["npm --audit false install lodash@4.17.20", NPM_AVOID, "lodash@4.17.21", "lodash"],
    ["npm --no-audit true i lodash@4.17.20", NPM_AVOID, "lodash@4.17.21", "lodash"],
    ["npm --save-dev false install lodash@4.17.20", NPM_AVOID, "lodash@4.17.21", "lodash"],
    ["npm --ignore-scripts true --audit false install lodash@4.17.20", NPM_AVOID, "lodash@4.17.21", "lodash"],
    ["pnpm --prefix sub add lodash@4.17.20", NPM_AVOID, "lodash@4.17.21", "lodash"],
    ["uv -q pip install requests==2.19.0", PY_AVOID, "requests==2.32.3", "requests"],
    ["uv --cache-dir /tmp/c --directory sub pip install requests==2.19.0", PY_AVOID, "requests==2.32.3", "requests"],
    ["uv --color never pip compile --upgrade-package requests==2.19.0 requirements.in", PY_AVOID, "requests==2.32.3", "requests"],
    ["pip --cert ca.pem install requests==2.19.0", PY_AVOID, "requests==2.32.3", "requests"],
    ["pip --client-cert c.pem --exists-action w install requests==2.19.0", PY_AVOID, "requests==2.32.3", "requests"],
    ["python -m pip --cert ca.pem install requests==2.19.0", PY_AVOID, "requests==2.32.3", "requests"],
    ["pip3 --use-feature truststore install requests==2.19.0", PY_AVOID, "requests==2.32.3", "requests"],
  ])("%s", (command, avoid, safe, name) => {
    s.ledger([avoid]);
    const held = run(command);
    expect(held.decision, held.text).toBe("deny");
    expect(held.text).toContain("answered avoid");
    // The same spelling with a version that has no verdict names the call; answering it releases it.
    const [oldSpec] = command.match(/(lodash@4\.17\.20|requests==2\.19\.0)/) ?? [];
    const safeCommand = command.replace(oldSpec ?? "", safe);
    const first = run(safeCommand);
    expect(first.items?.map((i) => i.package), first.text).toEqual([name]);
    answerDenial(s, first);
    expect(run(safeCommand).decision).toBe("allow");
  });

  it("PowerShell reads them the same way", () => {
    s.ledger([NPM_AVOID, PY_AVOID]);
    expect(run("npm --audit false install lodash@4.17.20", "PowerShell").decision).toBe("deny");
    expect(run("uv -q pip install requests==2.19.0", "PowerShell").decision).toBe("deny");
  });
});

describe("what installs nothing is not held", () => {
  it.each([
    "npm --audit false ls lodash",
    "npm --audit false run build",
    "npm --json true view lodash@4.17.20 version",
    "uv -q pip list",
    "uv --directory sub pip show requests",
    "pip --cert ca.pem download requests==2.19.0 -d wheels",
    "pip --cert ca.pem list",
    "pnpm --prefix sub run build",
  ])("%s", (command) => {
    s.ledger([NPM_AVOID, PY_AVOID]);
    expect(run(command).decision).toBe("allow");
  });

  it("a `true` or `false` after an install's own Boolean option is not a package", () => {
    s.ledger([]);
    const held = run("npm install --save false lodash@4.17.21");
    expect(held.items).toEqual([{ ecosystem: "npm", package: "lodash", to: "4.17.21" }]);
  });
});
