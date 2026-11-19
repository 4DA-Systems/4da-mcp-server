// SPDX-License-Identifier: Apache-2.0
/**
 * A `[project]` dependency that `[tool.uv] override-dependencies` (or
 * `constraint-dependencies`) covers can legitimately have no `[[package]]`
 * table: the uv.lock below is what uv wrote for this pyproject.toml (the
 * override's marker never holds for requires-python >= 3.12, so six is not
 * locked). That is not damage.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { resolvePython } from "../live/lockfile-parsers-pygo.js";

const PYPROJECT = (tool: string) => `[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["idna>=3", "six>=1"]
${tool}`;
const UV_LOCK = `version = 1
revision = 1
requires-python = ">=3.12"

[manifest]
overrides = [{ name = "six", marker = "python_full_version < '3.0'" }]

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "idna" },
]

[package.metadata]
requires-dist = [
    { name = "idna", specifier = ">=3" },
    { name = "six", specifier = ">=1" },
]

[[package]]
name = "idna"
version = "3.20"
source = { registry = "https://pypi.org/simple" }
`;

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1119-uv-overrides-"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const problemsFor = (pyproject: string) => {
  fs.writeFileSync(path.join(dir, "pyproject.toml"), pyproject);
  fs.writeFileSync(path.join(dir, "uv.lock"), UV_LOCK);
  return resolvePython(dir).problems ?? [];
};

describe("uv.lock: a dependency an override or constraint covers", () => {
  it("is not reported missing when override-dependencies names it", () => {
    expect(problemsFor(PYPROJECT(`\n[tool.uv]\noverride-dependencies = ["six; python_version < '3.0'"]\n`))).toEqual([]);
  });

  it("is not reported missing when constraint-dependencies names it", () => {
    expect(problemsFor(PYPROJECT(`\n[tool.uv]\nconstraint-dependencies = [\n  "Six<0",\n]\n`))).toEqual([]);
  });

  it("is still reported when nothing covers it", () => {
    const found = problemsFor(PYPROJECT(""));
    expect(found).toHaveLength(1);
    expect(found[0].error).toMatch(/pyproject\.toml declares a dependency it holds no \[\[package\]\] table for \(six\)/);
  });
});
