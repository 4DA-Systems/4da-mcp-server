// SPDX-License-Identifier: Apache-2.0
/**
 * A PEP 440 spelling change of the same version is no new version (independent re-check of
 * 0d30b40, notes): `5.0.0rc1` -> `5.0.0-rc1`, `+cpu` -> `+CPU`, `2.31.0` -> `2.31.0.0` in a
 * requirements file or pyproject.toml were held as introduced versions. Python versions in an edit
 * are now compared in PEP 440 normal form; a real change is still held.
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
  dir = mkdtempSync(join(tmpdir(), "a651-pep440-spelling-"));
  home = join(dir, "home");
  mkdirSync(home);
  writeFileSync(join(home, LEDGER_FILE), "");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function edit(file: string, before: string, from: string, to: string): string {
  const path = join(dir, file);
  writeFileSync(path, before);
  return respond({ hook_event_name: "PreToolUse", tool_name: "Edit", cwd: dir, tool_input: { file_path: path, old_string: from, new_string: to } }, { FOURDA_MCP_HOME: home }, Date.now());
}

describe("requirements.txt", () => {
  it.each([
    ["x==5.0.0rc1", "x==5.0.0-rc1"],
    ["torch==2.0.0+cpu", "torch==2.0.0+CPU"],
    ["requests==2.31.0", "requests==2.31.0.0"],
    ["requests>=2.31,<3", "requests>=2.31.0,<3.0"],
  ])("%s -> %s goes ahead", (from, to) => {
    expect(edit("requirements.txt", `${from}\n`, from, to)).toBe("");
  });

  it("a real change is still held", () => {
    expect(edit("requirements.txt", "requests==2.31.0\n", "requests==2.31.0", "requests==2.25.0")).not.toBe("");
  });
});

describe("pyproject.toml", () => {
  it("the same spelling change goes ahead", () => {
    expect(edit("pyproject.toml", '[project]\nname = "a"\ndependencies = ["x==5.0.0rc1"]\n', '"x==5.0.0rc1"', '"x==5.0.0-rc1"')).toBe("");
  });
});
