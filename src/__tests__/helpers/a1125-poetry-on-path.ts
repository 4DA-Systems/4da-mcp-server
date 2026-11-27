// SPDX-License-Identifier: Apache-2.0
/**
 * Round 24b: on Windows the hook looks a bare manager name up on PATH before it reads an install
 * with a character cmd.exe rewrites, and a name it does not find is not read. Tests that read
 * `poetry add "x@>=1"` as an install need poetry on PATH: this puts an empty poetry.exe in a temp
 * folder at the front of PATH for the test file that imports it (a side effect, Windows only).
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

if (process.platform === "win32") {
  const dir = mkdtempSync(join(tmpdir(), "a1125-poetry-path-"));
  writeFileSync(join(dir, "poetry.exe"), "");
  const path = `${dir};${process.env.PATH ?? process.env.Path ?? ""}`;
  process.env.PATH = path;
}
