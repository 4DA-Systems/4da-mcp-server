// SPDX-License-Identifier: Apache-2.0
/**
 * pyproject.toml: only dependency declarations count. A comment, `description` or any other string
 * field that happens to hold requirement-shaped text is not a dependency (it was denied), and a
 * comment naming a package never hides a real change to that package's pin (a later comment
 * replaced the pin in the hook's map, so an unchecked pin went ahead).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const PYPROJECT = `[project]
name = "demo"
version = "0.1.0"
description = "A demo"
requires-python = ">=3.10"
dependencies = [
    "requests==2.32.3",
    "click>=8.1",
]

[project.optional-dependencies]
dev = ["pytest==8.3.3"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.pytest.ini_options]
minversion = "8.0"
addopts = "-q"
`;

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

describe("text that is not a dependency declaration", () => {
  it.each([
    ["a comment inside the array", '    "click>=8.1",\n]', '    "click>=8.1",\n    # requests>=2.0 broke on 3.13, keep the pin above\n]'],
    ["a comment after an element", '    "click>=8.1",', '    "click>=8.1",  # django>=4.2 needs this'],
    ["a comment line between tables", "[build-system]", "# pinned: flask==3.0.2 later\n[build-system]"],
    ["description", 'description = "A demo"', 'description = "A demo that needs django>=4.2 to run"'],
    ["a description that is a requirement", 'description = "A demo"', 'description = "django>=4.2"'],
    ["addopts", 'addopts = "-q"', 'addopts = "-q -p pytest_cov>=4.0"'],
    ["a multi-line string", 'description = "A demo"', 'description = """\nrequests==2.0.0 was the last good one\n"""'],
    ["urls", 'requires-python = ">=3.10"', 'requires-python = ">=3.10"\nurls = { Changelog = "https://example.com/flask==3.0.2" }'],
    ["classifiers and keywords", 'requires-python = ">=3.10"', 'requires-python = ">=3.10"\nkeywords = ["numpy>=2"]\nclassifiers = ["Framework :: Django :: 4.2"]'],
  ])("%s", (_label, oldString, newString) => {
    const file = s.file("pyproject.toml", PYPROJECT);
    const run = s.edit(file, oldString, newString);
    expect(run.decision, run.text).toBe("allow");
  });
});

describe("a comment never hides a real change", () => {
  const MASK = '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = [\n    "requests==2.32.3",\n    # requests>=2.0 is the floor we test against\n]\n';

  it("a pin changed above a comment that names the same package is held", () => {
    const file = s.file("pyproject.toml", MASK);
    expect(s.edit(file, '"requests==2.32.3"', '"requests==2.31.0"').items).toEqual([{ ecosystem: "PyPI", package: "requests", to: "2.31.0", from: "2.32.3" }]);
  });

  it("and the same when the comment is on the pin's own line", () => {
    const file = s.file("pyproject.toml", MASK.replace('"requests==2.32.3",', '"requests==2.32.3",  # requests>=2.0 tested'));
    expect(s.edit(file, '"requests==2.32.3"', '"requests==2.31.0"').items).toEqual([{ ecosystem: "PyPI", package: "requests", to: "2.31.0", from: "2.32.3" }]);
  });
});

describe("dependency declarations are still read", () => {
  it.each([
    ["[project] dependencies", '    "click>=8.1",\n', '    "click>=8.1",\n    "httpx==0.27.2",\n', "httpx", "0.27.2"],
    ["optional-dependencies", 'dev = ["pytest==8.3.3"]', 'dev = ["pytest==8.3.3", "httpx==0.27.2"]', "httpx", "0.27.2"],
    ["a requirement with a marker and extras", '    "click>=8.1",\n', '    "click>=8.1",\n    "httpx[http2]==0.27.2 ; python_version >= \'3.10\'",\n', "httpx", "0.27.2"],
    ["build-system requires", 'requires = ["hatchling"]', 'requires = ["hatchling==1.25.0"]', "hatchling", "1.25.0"],
    ["[dependency-groups]", "[build-system]", '[dependency-groups]\nlint = ["ruff==0.7.1", { include-group = "dev" }]\n\n[build-system]', "ruff", "0.7.1"],
    ["[tool.uv] dev-dependencies", "[build-system]", '[tool.uv]\ndev-dependencies = ["ruff==0.7.1"]\n\n[build-system]', "ruff", "0.7.1"],
    ["dotted optional-dependencies", 'requires-python = ">=3.10"', 'requires-python = ">=3.10"\noptional-dependencies.extra = ["httpx==0.27.2"]', "httpx", "0.27.2"],
    ["a literal string", '    "click>=8.1",\n', "    \"click>=8.1\",\n    'httpx==0.27.2',\n", "httpx", "0.27.2"],
  ])("%s", (_label, oldString, newString, pkg, to) => {
    const file = s.file("pyproject.toml", PYPROJECT);
    const run = s.edit(file, oldString, newString);
    expect(run.items).toEqual([{ ecosystem: "PyPI", package: pkg, to }]);
  });

  it("a Write of the whole file reads the arrays, not the comments", () => {
    const file = s.file("pyproject.toml", PYPROJECT);
    const run = s.write(file, PYPROJECT.replace('"requests==2.32.3",', '"requests==2.31.0",  # was requests==2.32.3').replace('description = "A demo"', 'description = "needs flask>=3"'));
    expect(run.items).toEqual([{ ecosystem: "PyPI", package: "requests", to: "2.31.0", from: "2.32.3" }]);
  });

  it("after the edit (FOURDA_GUARD=advise), a snippet inside the dependencies array is read and a comment is not", () => {
    const after = PYPROJECT.replace('    "click>=8.1",\n', '    "click>=8.1",\n    "httpx==0.27.2",  # flask==3.0.2 later\n');
    const file = s.file("pyproject.toml", after);
    const run = s.post(file, '    "click>=8.1",\n', '    "click>=8.1",\n    "httpx==0.27.2",  # flask==3.0.2 later\n');
    expect(run.items).toEqual([{ ecosystem: "PyPI", package: "httpx", to: "0.27.2" }]);
  });
});
