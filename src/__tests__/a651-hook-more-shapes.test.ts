// SPDX-License-Identifier: Apache-2.0
/**
 * More shapes that write a version, read (independent re-check of 0d30b40, S7): `npm pkg set` with
 * an alias, `latest`, a Yarn glob or a pnpm `parent>child` key; Cargo package ids
 * (`time:0.3.17`, `-ptime`, a registry URL with `#name@version`); pip-tools run as a module or
 * through uvx; `go work edit -replace`; a quoted module path in go.mod; a PEP 440 epoch
 * (`1!2.0`); and a PowerShell command with a splatted variable beside the install (an undefined
 * variable passes nothing, so the rest installs).
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { installsIn, respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";

const read = (command: string, dialect: "bash" | "powershell" = "bash") => installsIn(command, dialect).map((r) => `${r.ecosystem} ${r.name} ${r.spec}`);

describe("commands", () => {
  it.each([
    ["npm pkg set dependencies.x=npm:lodash@4.17.20", ["npm lodash 4.17.20"]],
    ["npm pkg set 'dependencies.lodash=npm:lodash@4.17.20'", ["npm lodash 4.17.20"]],
    ["npm pkg set dependencies.lodash=latest", ["npm lodash latest"]],
    ["npm pkg set 'resolutions.**/qs=6.5.2'", ["npm qs 6.5.2"]],
    ["npm pkg set 'pnpm.overrides.express>qs=6.5.2'", ["npm qs 6.5.2"]],
    ["npm pkg set 'overrides.express.qs=6.5.2'", ["npm qs 6.5.2"]],
    ["cargo update -p time:0.3.17 --precise 0.3.20", ["crates.io time 0.3.20"]],
    ["cargo update -ptime --precise 0.3.20", ["crates.io time 0.3.20"]],
    ["cargo update -p https://github.com/rust-lang/crates.io-index#time@0.3.17 --precise 0.3.20", ["crates.io time 0.3.20"]],
    ["cargo update -p registry+https://github.com/rust-lang/crates.io-index#time@0.3.17 --precise 0.3.20", ["crates.io time 0.3.20"]],
    ['python -m piptools compile requirements.in --upgrade-package "idna==3.15"', ["PyPI idna ==3.15"]],
    ['uvx pip-compile requirements.in --upgrade-package "idna==3.15"', ["PyPI idna ==3.15"]],
    ["go work edit -replace=golang.org/x/net=golang.org/x/net@v0.17.0", ["Go golang.org/x/net v0.17.0"]],
    ["pip install 'requests==1!2.0'", ["PyPI requests ==1!2.0"]],
  ])("%s", (command, expected) => {
    expect(read(command)).toEqual(expected);
  });

  it("PowerShell: a splatted variable beside the install leaves the rest read", () => {
    expect(read("npm i lodash@4.17.20 @x", "powershell")).toEqual(["npm lodash 4.17.20"]);
    expect(read("npm i @x lodash@4.17.20", "powershell")).toEqual(["npm lodash 4.17.20"]);
  });
});

describe("a PEP 440 epoch reaches the ledger check whole", () => {
  it("a proceed for 2.0 does not cover ==1!2.0; one for 1!2.0 does", () => {
    const dir = mkdtempSync(join(tmpdir(), "a651-epoch-"));
    try {
      const entry = (version: string) => JSON.stringify({ sv: "6.6.0", t: new Date(Date.now() - 60_000).toISOString(), ecosystem: "PyPI", package: "requests", version, verdict: "proceed" }) + "\n";
      const decide = () => respond({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd: dir, tool_input: { command: "pip install 'requests==1!2.0'" } }, { FOURDA_MCP_HOME: dir }, Date.now());
      writeFileSync(join(dir, LEDGER_FILE), entry("2.0"));
      expect((JSON.parse(decide()) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason).toContain('"requests" "==1!2.0" (PyPI)');
      writeFileSync(join(dir, LEDGER_FILE), entry("1!2.0"));
      expect(decide()).toBe("");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("go.mod with a quoted module path", () => {
  let dir: string;
  let home: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "a651-more-shapes-"));
    home = join(dir, "home");
    mkdirSync(home);
    writeFileSync(join(home, LEDGER_FILE), "");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it.each([
    ['replace golang.org/x/net => "github.com/fork/net" v0.17.0', '"github.com/fork/net" "v0.17.0" (Go)'],
    ['require "golang.org/x/text" v0.14.0', '"golang.org/x/text" "v0.14.0" (Go)'],
  ])("%s is held", (line, named) => {
    const file = join(dir, "go.mod");
    writeFileSync(file, "module example.com/app\n\ngo 1.22\n");
    const out = respond({ hook_event_name: "PreToolUse", tool_name: "Write", cwd: dir, tool_input: { file_path: file, content: `module example.com/app\n\ngo 1.22\n\n${line}\n` } }, { FOURDA_MCP_HOME: home }, Date.now());
    expect(out).toContain(named.replace(/"/g, '\\"'));
  });
});
