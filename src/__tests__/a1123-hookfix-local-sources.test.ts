// SPDX-License-Identifier: Apache-2.0
/**
 * A dependency taken from a path, git, URL or a named non-public source names no registry release,
 * and its name may be private: the guard lets it go ahead whatever version it also gives, and its
 * name never appears in a denial (a denial asks for a registry lookup of every name it repeats).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const CARGO = '[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\nanyhow = "1.0.89"\n';
const PYPROJECT = '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = [\n    "requests==2.32.3",\n]\n';
const POETRY = '[tool.poetry]\nname = "demo"\n\n[tool.poetry.dependencies]\npython = "^3.10"\nrequests = "2.32.3"\n';
const GOMOD = "module example.com/demo\n\ngo 1.22\n\nrequire (\n\tgithub.com/google/uuid v1.6.0\n)\n";
const PKG = '{\n  "name": "app",\n  "dependencies": {\n    "react": "18.3.1"\n  }\n}\n';

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

/** The edit goes ahead, or is denied only for `real` (a public name beside the local one), never naming `local`. */
function onlyReal(run: { decision: string; text: string; items: Array<Record<string, string>> | null }, local: string, real?: string) {
  if (real === undefined) expect(run.decision, run.text).toBe("allow");
  else expect(run.items?.map((i) => i.package)).toEqual([real]);
  expect(run.text).not.toContain(local);
}

describe("Cargo: path, git and another registry", () => {
  it.each([
    ['mylib = { path = "../mylib", version = "0.3.0" }'],
    ['mylib = { git = "https://github.com/acme/mylib", version = "0.3.0" }'],
    ['mylib = { version = "0.3.0", registry = "corp" }'],
    ['mylib = { version = "0.3.0", git = "https://example.com/x", branch = "main" }'],
  ])("inline: %s", (line) => {
    const file = s.file("Cargo.toml", CARGO);
    onlyReal(s.edit(file, 'anyhow = "1.0.89"\n', `anyhow = "1.0.89"\n${line}\nregex = "1.11.0"\n`), "mylib", "regex");
  });

  it("table form and dotted keys", () => {
    const file = s.file("Cargo.toml", CARGO);
    onlyReal(s.edit(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\n\n[dependencies.mylib]\nversion = "0.3.0"\npath = "../mylib"\n'), "mylib");
    onlyReal(s.edit(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\nmylib.version = "0.3.0"\nmylib.path = "../mylib"\n'), "mylib");
  });

  it("a bump of a path dependency's version goes ahead", () => {
    const file = s.file("Cargo.toml", CARGO + 'mylib = { path = "../mylib", version = "0.3.0" }\n');
    onlyReal(s.edit(file, 'version = "0.3.0"', 'version = "0.4.0"'), "mylib");
  });

  it("a crates.io dependency in the same table is still held", () => {
    const file = s.file("Cargo.toml", CARGO);
    expect(s.edit(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\nregex = { version = "1.11.0", features = ["std"] }\n').items).toEqual([{ ecosystem: "crates.io", package: "regex", to: "1.11.0" }]);
  });
});

describe("npm: file, link, workspace, git and URL specifiers", () => {
  it.each([["file:../my-lib"], ["link:../my-lib"], ["workspace:^1.0.0"], ["workspace:*"], ["git+https://github.com/acme/my-lib.git#1.0.0"], ["github:acme/my-lib#semver:^1.0.0"], ["https://example.com/my-lib-1.0.0.tgz"], ["npm:other@1.0.0"], ["catalog:"]])("%s", (spec) => {
    const file = s.file("package.json", PKG);
    onlyReal(s.edit(file, '"react": "18.3.1"', `"react": "18.3.1",\n    "my-lib": "${spec}"`), "my-lib");
  });
});

describe("pyproject: direct references, [tool.uv.sources] and Poetry sources", () => {
  it.each([["mylib @ file:///C:/src/mylib"], ["mylib @ git+https://github.com/acme/mylib@v0.3.0"], ["mylib @ https://example.com/mylib-0.3.0.tar.gz"]])("a direct reference: %s", (req) => {
    const file = s.file("pyproject.toml", PYPROJECT);
    onlyReal(s.edit(file, '    "requests==2.32.3",\n', `    "requests==2.32.3",\n    "${req}",\n`), "mylib");
  });

  it.each([['{ path = "../mylib" }'], ['{ path = "../mylib", editable = true }'], ['{ git = "https://github.com/acme/mylib", tag = "v0.3.0" }'], ['{ url = "https://example.com/mylib.whl" }'], ['{ index = "corp" }'], ["{ workspace = true }"]])(
    "[tool.uv.sources] mylib = %s: the requirement goes ahead",
    (source) => {
      const file = s.file("pyproject.toml", PYPROJECT + `\n[tool.uv.sources]\nmylib = ${source}\n`);
      onlyReal(s.edit(file, '    "requests==2.32.3",\n', '    "requests==2.32.3",\n    "mylib>=0.3.0",\n    "httpx==0.27.2",\n'), "mylib", "httpx");
    },
  );

  it("the source written in the same edit counts too, and so does the table form", () => {
    const file = s.file("pyproject.toml", PYPROJECT);
    onlyReal(s.write(file, PYPROJECT.replace('"requests==2.32.3",', '"requests==2.32.3",\n    "MyLib==0.3.0",') + '\n[tool.uv.sources.mylib]\npath = "../mylib"\n'), "MyLib");
  });

  it("a name with no source entry is held", () => {
    const file = s.file("pyproject.toml", PYPROJECT + '\n[tool.uv.sources]\nother = { path = "../other" }\n');
    expect(s.edit(file, '    "requests==2.32.3",\n', '    "requests==2.32.3",\n    "mylib==0.3.0",\n').items?.map((i) => i.package)).toEqual(["mylib"]);
  });

  it.each([
    ['{ path = "../mylib", develop = true }'],
    ['{ git = "https://github.com/acme/mylib.git", tag = "v0.3.0" }'],
    ['{ url = "https://example.com/mylib-0.3.0.tar.gz" }'],
    ['{ version = "0.3.0", source = "corp" }'],
    ['[{ version = "0.3.0", python = "<3.11", source = "corp" }, { version = "0.4.0", python = ">=3.11" }]'],
  ])("Poetry mylib = %s", (value) => {
    const file = s.file("pyproject.toml", POETRY);
    onlyReal(s.edit(file, 'requests = "2.32.3"\n', `requests = "2.32.3"\nmylib = ${value}\n`), "mylib");
  });

  it("Poetry with source = pypi, and the list-of-constraints form, are held", () => {
    const file = s.file("pyproject.toml", POETRY);
    expect(s.edit(file, 'requests = "2.32.3"\n', 'requests = "2.32.3"\nhttpx = { version = "0.27.2", source = "PyPI" }\n').items?.map((i) => i.package)).toEqual(["httpx"]);
    expect(
      s.edit(file, 'requests = "2.32.3"\n', 'requests = "2.32.3"\nhttpx = [{ version = "0.27.2", python = "<3.11" }, { version = "0.28.1", python = ">=3.11" }]\n').items,
    ).toEqual([
      { ecosystem: "PyPI", package: "httpx", to: "0.27.2" },
      { ecosystem: "PyPI", package: "httpx", to: "0.28.1" },
    ]);
  });

  it("after the edit (FOURDA_GUARD=advise), a source on disk is honoured for a snippet that does not show it", () => {
    const after = PYPROJECT.replace('"requests==2.32.3",', '"requests==2.32.3",\n    "mylib>=0.3.0",') + '\n[tool.uv.sources]\nmylib = { path = "../mylib" }\n';
    const file = s.file("pyproject.toml", after);
    expect(s.post(file, '    "requests==2.32.3",\n', '    "requests==2.32.3",\n    "mylib>=0.3.0",\n').decision).toBe("allow");
  });
});

describe("go.mod: replace to a local directory", () => {
  it.each([["replace github.com/acme/mylib => ../mylib\n"], ["replace (\n\tgithub.com/acme/mylib => ./third_party/mylib\n)\n"], ["replace github.com/acme/mylib v0.3.0 => C:/src/mylib\n"]])(
    "the replaced module's requirement goes ahead: %s",
    (replace) => {
      const file = s.file("go.mod", GOMOD);
      onlyReal(s.write(file, GOMOD.replace("\tgithub.com/google/uuid v1.6.0\n", "\tgithub.com/google/uuid v1.6.0\n\tgithub.com/acme/mylib v0.3.0\n") + `\n${replace}`), "acme/mylib");
    },
  );

  it("a replace of another version, or by another module, does not hide the requirement", () => {
    const file = s.file("go.mod", GOMOD + "\nreplace github.com/acme/mylib v0.2.0 => ../mylib\n");
    expect(s.edit(file, "\tgithub.com/google/uuid v1.6.0\n", "\tgithub.com/google/uuid v1.6.0\n\tgithub.com/acme/mylib v0.3.0\n").items?.map((i) => i.package)).toEqual(["github.com/acme/mylib"]);
    const fork = s.file("go.mod", GOMOD + "\nreplace github.com/acme/mylib => github.com/fork/mylib v0.3.1\n");
    expect(s.edit(fork, "\tgithub.com/google/uuid v1.6.0\n", "\tgithub.com/google/uuid v1.6.0\n\tgithub.com/acme/mylib v0.3.0\n").items?.map((i) => i.package)).toEqual(["github.com/acme/mylib"]);
  });

  it("a replace block with a version on its left side introduces nothing", () => {
    const file = s.file("go.mod", GOMOD);
    expect(s.edit(file, "go 1.22\n", "go 1.22\n\nreplace (\n\tgithub.com/google/uuid v1.6.0 => ../uuid\n)\n").decision).toBe("allow");
  });
});
