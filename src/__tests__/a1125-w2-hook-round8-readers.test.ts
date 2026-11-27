// SPDX-License-Identifier: Apache-2.0
/**
 * Round 8, from the sixth independent check's tables: manifest spellings now read (a requirements
 * line continued with a backslash, [tool.rye] dev-dependencies, pixi's pypi-dependencies, a
 * [tool.uv.sources] entry naming a public [[tool.uv.index]]), and the ledger's plain reads made
 * strict (less and more take no option but a search; no control or line-separator character).
 */

import { realpathSync } from "node:fs";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const AVOID = { ecosystem: "PyPI", package: "requests", version: "2.0.0", verdict: "avoid", reason: "test avoid" };

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([AVOID]);
});
afterEach(() => s.dispose());

describe("manifest spellings now read", () => {
  it.each([
    ["requirements.txt", "requests\\\n==2.0.0\n"],
    ["requirements.txt", "requests=\\\n=2.0.0\n"],
    ["pyproject.toml", '[tool.rye]\ndev-dependencies = ["requests==2.0.0"]\n'],
    ["pyproject.toml", '[tool.pixi.pypi-dependencies]\nrequests = "==2.0.0"\n'],
    ["pyproject.toml", '[tool.pixi.feature.test.pypi-dependencies]\nrequests = { version = "==2.0.0" }\n'],
    [
      "pyproject.toml",
      '[project]\nname = "p"\nversion = "0.1"\ndependencies = ["requests==2.0.0"]\n[tool.uv.sources]\nrequests = { index = "pypi" }\n[[tool.uv.index]]\nname = "pypi"\nurl = "https://pypi.org/simple"\n',
    ],
  ])("%s: %j is judged (an avoid on record)", (name, content) => {
    const r = s.write(s.file(name, ""), content);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("avoid");
  });

  it("a [tool.uv.sources] entry naming a private index still goes ahead", () => {
    const content = '[project]\nname = "p"\nversion = "0.1"\ndependencies = ["requests==2.0.0"]\n[tool.uv.sources]\nrequests = { index = "corp" }\n[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\nexplicit = true\n';
    // Round 25 (S3): an index that is not explicit can serve public names: only an explicit one goes ahead unread.
    expect(s.write(s.file("pyproject.toml", ""), content).decision).toBe("allow");
  });

  it("a pixi dependency from git goes ahead (no version)", () => {
    expect(s.write(s.file("pyproject.toml", ""), '[tool.pixi.pypi-dependencies]\nrequests = { git = "https://example.invalid/r.git" }\n').decision).toBe("allow");
  });
});

describe("the ledger's plain reads are strict", () => {
  let L: string;
  beforeEach(() => {
    L = `${realpathSync(s.home).replace(/\\/g, "/")}/check-ledger.jsonl`;
  });
  const cmd = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

  it.each(["less -O '<L>' -", "less -o '<L>' -", "less --log-file='<L>' -", "less '+!rm <L>' /dev/null", "more -k '<L>'"])("held: %s", (c) => {
    expect(cmd(c.replaceAll("<L>", L)).decision).toBe("deny");
  });

  it("held: a control or line-separator character in the line", () => {
    for (const sep of [" ", "\u0085", "\u000b", "\u000c"]) expect(cmd(`cat '${L}'${sep}rm x`).decision).toBe("deny");
  });

  it.each(["less '<L>'", "more '+/proceed' '<L>'", "cat '<L>'", "tail -n 5 '<L>'"])("goes ahead: %s", (c) => {
    expect(cmd(c.replaceAll("<L>", L)).decision).toBe("allow");
  });
});
