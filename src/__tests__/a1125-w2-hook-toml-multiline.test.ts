// SPDX-License-Identifier: Apache-2.0
/**
 * Round 8 (R8-5): a new or changed Cargo.toml / pyproject.toml line in a dependency table, or with
 * a dependency key, that opens a multi-line string (`"""` or `'''`) is held as not read
 * (`package = """\nserde"""`). A multi-line description elsewhere, or one left unchanged, is not.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const NOT_READ = "opens a multi-line string";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([{ ecosystem: "crates.io", package: "serde", version: "1.0.200", verdict: "proceed" }]);
});
afterEach(() => s.dispose());

const CARGO = '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\n';
const PY = '[project]\nname = "app"\nversion = "0.1.0"\n';

describe("held as not read", () => {
  it.each([
    ["Cargo: a renamed dependency's package key", "Cargo.toml", CARGO, `${CARGO}x = { package = """\nserde""", version = "1.0.200" }\n`],
    ["Cargo: a version in ''' in [dependencies]", "Cargo.toml", CARGO, `${CARGO}serde = '''\n1.0.200'''\n`],
    ["Cargo: a [dependencies.x] table", "Cargo.toml", CARGO, `${CARGO}\n[dependencies.x]\npackage = """serde"""\nversion = "1.0.200"\n`],
    ["Cargo: a target table", "Cargo.toml", CARGO, `${CARGO}\n[target.'cfg(unix)'.dependencies]\nserde = """1.0.200"""\n`],
    ["pyproject: dependencies = '''", "pyproject.toml", PY, `${PY}dependencies = '''\nrequests'''\n`],
    ["pyproject: a dependency group", "pyproject.toml", PY, `${PY}\n[dependency-groups]\ndev = ["""pytest"""]\n`],
    ["pyproject: Poetry dependencies", "pyproject.toml", PY, `${PY}\n[tool.poetry.dependencies]\nrequests = """2.31.0"""\n`],
    ["pyproject: uv sources", "pyproject.toml", PY, `${PY}\n[tool.uv.sources]\nfoo = { git = """https://example.invalid/foo""" }\n`],
  ])("%s", (_label, name, before, after) => {
    const path = s.file(name, before);
    const r = s.write(path, after);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain(NOT_READ);
  });
});

describe("not held", () => {
  it.each([
    ["a multi-line description in [package]", "Cargo.toml", CARGO, CARGO.replace('version = "0.1.0"', 'version = "0.1.0"\ndescription = """\nA tool.\n"""')],
    ["a multi-line description in [project]", "pyproject.toml", PY, `${PY}description = '''\nA tool.\n'''\n`],
    ["a one-line string in [dependencies]", "Cargo.toml", CARGO, `${CARGO}serde = "1.0.200"\n`],
  ])("%s", (_label, name, before, after) => {
    const path = s.file(name, before);
    expect(s.write(path, after).text).not.toContain(NOT_READ);
  });

  it("an unchanged multi-line dependency line, with another line changed", () => {
    const before = `${CARGO}x = { package = """serde""", version = "1.0.200" }\n`;
    const path = s.file("Cargo.toml", before);
    expect(s.write(path, before.replace('name = "app"', 'name = "app2"')).text).not.toContain(NOT_READ);
  });
});
