// SPDX-License-Identifier: Apache-2.0
/**
 * The guard hook limits that 6.5.2's changelog adds under "Known limits" (after the fix round of
 * 2026-11-25/26), held as they are. Each row pins a sentence of the changelog, beside the control
 * that shows the hook reads the plain form. A row that starts failing means the hook changed: fix
 * the changelog sentence with it.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";

let dir: string;
let home: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "a652-limits2-"));
  home = join(dir, "home");
  mkdirSync(home);
  writeFileSync(join(home, LEDGER_FILE), "");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

type Decision = "allow" | "not read" | "no verdict";
function decide(input: Record<string, unknown>): Decision {
  const out = respond({ hook_event_name: "PreToolUse", cwd: dir, ...input }, { FOURDA_MCP_HOME: home }, Date.now());
  if (out === "") return "allow";
  const text = (JSON.parse(out) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason;
  return text.includes("could not be read") ? "not read" : "no verdict";
}
const bash = (command: string) => decide({ tool_name: "Bash", tool_input: { command } });
const pwsh = (command: string) => decide({ tool_name: "PowerShell", tool_input: { command } });
function edit(file: string, before: string, after: string): Decision {
  const path = join(dir, file);
  writeFileSync(path, before);
  return decide({ tool_name: "Write", tool_input: { file_path: path, content: after } });
}

const WS = 'packages:\n  - "pkgs/*"\n';
const CARGO = '[package]\nname = "a"\nversion = "0.1.0"\n';

describe("block-style YAML the hook does not read in pnpm-workspace.yaml goes ahead", () => {
  it("the plain override is read (control)", () => {
    expect(edit("pnpm-workspace.yaml", WS, `${WS}overrides:\n  lodash: 4.17.20\n`)).toBe("no verdict");
  });
  it.each([
    ["a value with an anchor", "overrides:\n  lodash: &v 4.17.20\n"],
    ["a value with a tag", "overrides:\n  lodash: !!str 4.17.20\n"],
    ["a value on the next line", "overrides:\n  lodash:\n    4.17.20\n"],
    ["a block scalar", "overrides:\n  lodash: >-\n    4.17.20\n"],
    ["an explicit key", "overrides:\n  ? lodash\n  : 4.17.20\n"],
  ])("%s", (_label, section) => {
    expect(edit("pnpm-workspace.yaml", WS, WS + section)).toBe("allow");
  });
  it("a merge key", () => {
    const base = `${WS}x: &b\n  lodash: 4.17.20\n`;
    expect(edit("pnpm-workspace.yaml", base, `${base}overrides:\n  <<: *b\n`)).toBe("allow");
  });
});

describe("a pnpm-workspace.yaml with a brace outside a comment line", () => {
  const BRACE = `${WS}catalog: { react: ^18.2.0 }\n`;
  it("holds a quote-style change and a comment change as not read", () => {
    expect(edit("pnpm-workspace.yaml", BRACE, BRACE.replace('"pkgs/*"', "'pkgs/*'"))).toBe("not read");
    expect(edit("pnpm-workspace.yaml", `${BRACE}# a\n`, `${BRACE}# b\n`)).toBe("not read");
  });
  it("lets a re-save and a blank-line change through", () => {
    expect(edit("pnpm-workspace.yaml", BRACE, BRACE)).toBe("allow");
    expect(edit("pnpm-workspace.yaml", BRACE, `${BRACE}\n`)).toBe("allow");
  });
});

describe("forms the hook still does not read", () => {
  it("go install goes ahead; go get is read (control)", () => {
    expect(bash("go install golang.org/x/tools/gopls@v0.16.0")).toBe("allow");
    expect(bash("go get golang.org/x/tools@v0.16.0")).toBe("no verdict");
  });
  it("Cargo root dotted keys, a root inline table and the underscore table names are read (wave 2; no longer a limit)", () => {
    expect(edit("Cargo.toml", CARGO, `${CARGO}[dependencies]\nserde = "1.0.100"\n`)).toBe("no verdict");
    // These sit at the top of the file: below [package] a dotted key is [package]'s own.
    expect(edit("Cargo.toml", CARGO, `dependencies.serde = "1.0.100"\n${CARGO}`)).toBe("no verdict");
    expect(edit("Cargo.toml", CARGO, `dependencies = { serde = "1.0.100" }\n${CARGO}`)).toBe("no verdict");
    expect(edit("Cargo.toml", CARGO, `${CARGO}[dev_dependencies]\nserde = "1.0.100"\n`)).toBe("no verdict");
    expect(edit("Cargo.toml", CARGO, `${CARGO}[build_dependencies]\nserde = "1.0.100"\n`)).toBe("no verdict");
  });
  it("a Poetry inline dependencies table is read (wave 2; no longer a limit)", () => {
    const poetry = '[tool.poetry]\nname = "a"\n';
    expect(edit("pyproject.toml", poetry, `${poetry}[tool.poetry.dependencies]\nrequests = "2.25.0"\n`)).toBe("no verdict");
    expect(edit("pyproject.toml", poetry, `${poetry}dependencies = { requests = "2.25.0" }\n`)).toBe("no verdict");
  });
  it("a PowerShell comma list and --% go ahead", () => {
    expect(pwsh("npm i lodash@4.17.20")).toBe("no verdict");
    expect(pwsh("npm i lodash@4.17.20,ms@2.0.0")).toBe("allow");
    expect(pwsh("npm --% i lodash@4.17.20")).toBe("allow");
  });
});
