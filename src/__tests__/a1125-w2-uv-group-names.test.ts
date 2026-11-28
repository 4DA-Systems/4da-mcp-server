// SPDX-License-Identifier: Apache-2.0
/**
 * A uv dependency group's name comes from the project's own pyproject.toml (uv.lock repeats it): it
 * is third-party text. pypi-direct.ts quoted `r.where` ("the "<group>" dependency group") raw into
 * the plan's instruction, and a quoted group key was not read at all. A group name outside the group
 * grammar (letters and digits, with `.`, `_`, `-` inside) now gets words, never a command, and is
 * never quoted unescaped (the same treatment as wave 1's unsafe directory names).
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { pyprojectDirectFix } from "../live/pypi-direct.js";
import { escapedNameLabel, isPlainName } from "../live/shell-safe.js";

let dir: string;
beforeEach(() => {
  dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "4da-w2-groups-")));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function project(groupKey: string, specifier: string) {
  fs.writeFileSync(path.join(dir, "pyproject.toml"), '[project]\nname = "app"\nversion = "0.1.0"\n');
  fs.writeFileSync(
    path.join(dir, "uv.lock"),
    [
      'version = 1\nrequires-python = ">=3.10"\n',
      `[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[package.metadata]\nrequires-dist = []\n\n[package.metadata.requires-dev]\n${groupKey} = [{ name = "pytest", specifier = "${specifier}" }]\n`,
      '[[package]]\nname = "pytest"\nversion = "7.4.4"\nsource = { registry = "https://pypi.org/simple" }\n',
    ].join("\n"),
  );
}

describe("dependency group names", () => {
  it("a plain group keeps its command and its name in the words", () => {
    project("dev", ">=7.4.3,<8.0.0");
    expect(pyprojectDirectFix(dir, "pytest", "7.4.4", "7.4.5")).toEqual({ command: "uv lock --upgrade-package pytest==7.4.5", refresh: true });
    const words = pyprojectDirectFix(dir, "pytest", "7.4.4", "9.0.3");
    expect(words).toEqual({ instruction: 'pyproject.toml requires pytest ">=7.4.3,<8.0.0" (the "dev" dependency group), which excludes 9.0.3: widen that requirement to admit 9.0.3, then run `uv lock --upgrade-package pytest==9.0.3`' });
  });

  it.each(['"dev$(PWN1)"', '"lint;PWN2"', '"x`PWN3`"', '"a b"'])("a group named %s: words, no command, the name escaped", (key) => {
    project(key, ">=7.4.3,<8.0.0");
    // The refresh the plain group would get is not given: words instead.
    const fix = pyprojectDirectFix(dir, "pytest", "7.4.4", "7.4.5");
    expect(fix).not.toHaveProperty("command");
    const text = (fix as { instruction: string }).instruction;
    const raw = key.slice(1, -1);
    expect(text).not.toContain(raw);
    expect(text).toContain(escapedNameLabel(raw, "dependency group"));
    expect(text).toMatch(/names no command for a package listed under a group it cannot quote/);
  });

  it("the grammar: letters and digits with . _ - inside", () => {
    for (const ok of ["dev", "lint-tools", "docs.v2", "a_b", "x1"]) expect(isPlainName(ok)).toBe(true);
    for (const bad of ["-dev", "dev-", ".x", "a b", "a$(b)", "", "x".repeat(101)]) expect(isPlainName(bad)).toBe(false);
    expect(escapedNameLabel("dev$(PWN1)", "dependency group")).toBe("[dependency group whose name is not plain, escaped: dev\\u0024\\u0028PWN1\\u0029]");
  });
});
