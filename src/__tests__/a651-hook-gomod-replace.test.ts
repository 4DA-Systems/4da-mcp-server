// SPDX-License-Identifier: Apache-2.0
/**
 * A go.mod `replace` that points at a module version is what gets built: the guard holds it as it
 * holds an npm override (blind review 2026-11-24, item 6). `replace golang.org/x/net =>
 * golang.org/x/net v0.17.0` and `replace golang.org/x/net v0.20.0 => github.com/someone/net
 * v0.0.1` went ahead with no verdict; a replace to a directory still names no release.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";
// The hook's PATH lookups see a stub for each manager and runner word, whatever the machine (Windows).
import "./helpers/a1125-manager-stubs.js";

let dir: string;
let home: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "a651-hook-gomod-"));
  home = join(dir, "home");
  mkdirSync(home);
  writeFileSync(join(home, LEDGER_FILE), "");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const BASE = "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/net v0.20.0\n";

function denial(added: string): string | null {
  const file = join(dir, "go.mod");
  writeFileSync(file, BASE);
  const out = respond(
    { hook_event_name: "PreToolUse", tool_name: "Edit", cwd: dir, tool_input: { file_path: file, old_string: "require golang.org/x/net v0.20.0\n", new_string: `require golang.org/x/net v0.20.0\n${added}` } },
    { FOURDA_MCP_HOME: home },
    Date.now(),
  );
  return out === "" ? null : (JSON.parse(out) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason;
}

describe("go.mod replace", () => {
  it("to the same module at another version: held, naming that version", () => {
    expect(denial("replace golang.org/x/net => golang.org/x/net v0.17.0\n")).toContain('"golang.org/x/net" "v0.17.0" (Go)');
  });

  it("to another module: held, naming the replacement", () => {
    expect(denial("replace golang.org/x/net v0.20.0 => github.com/someone/net v0.0.1\n")).toContain('"github.com/someone/net" "v0.0.1" (Go)');
  });

  it("in a replace block", () => {
    expect(denial("replace (\n\tgolang.org/x/net => golang.org/x/net v0.17.0\n)\n")).toContain('"golang.org/x/net" "v0.17.0" (Go)');
  });

  it("to a directory: goes ahead (no release named)", () => {
    expect(denial("replace golang.org/x/net => ../net\n")).toBeNull();
  });
});
