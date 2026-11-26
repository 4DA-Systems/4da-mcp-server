// SPDX-License-Identifier: Apache-2.0
/**
 * Round 15, from the thirteenth independent check: each cause with its cases and a sweep of its class.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });
const write = (name: string, content: string) => s.write(`${s.project}/${name}`, content);
const ct = (deps: string) => `[package]\nname = "x"\nversion = "0.1.0"\nedition = "2021"\n\n${deps}\n`;

describe("H2: a declaration that bounds nothing is the request latest; a tag word is held", () => {
  it.each([
    ["requirements.txt", "pytest\n", "PyPI", "pytest"],
    ["requirements.txt", "numpy[all]\n", "PyPI", "numpy"],
    ["requirements.txt", 'numpy; python_version >= "3.9"\n', "PyPI", "numpy"],
    ["pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["numpy"]\n', "PyPI", "numpy"],
    ["pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["numpy[all]"]\n', "PyPI", "numpy"],
    ["pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\n[project.optional-dependencies]\ndev = ["pytest"]\n', "PyPI", "pytest"],
    ["pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\n[dependency-groups]\ndev = ["pytest"]\n', "PyPI", "pytest"],
    ["pyproject.toml", '[tool.poetry]\nname = "x"\n[tool.poetry.dependencies]\nnumpy = "*"\n', "PyPI", "numpy"],
    ["package.json", '{"dependencies":{"express":""}}', "npm", "express"],
    ["package.json", '{"dependencies":{"express":"*"}}', "npm", "express"],
    ["package.json", '{"devDependencies":{"vite":"x"}}', "npm", "vite"],
    ["package.json", '{"peerDependencies":{"vite":"X"}}', "npm", "vite"],
    ["package.json", '{"optionalDependencies":{"vite":"*"}}', "npm", "vite"],
    ["package.json", '{"overrides":{"vite":"*"}}', "npm", "vite"],
    ["Cargo.toml", ct('[dependencies]\nrand = "*"'), "crates.io", "rand"],
    ["Cargo.toml", ct('[dependencies]\nrand = { features = ["small_rng"] }'), "crates.io", "rand"],
    ["Cargo.toml", ct('[dev-dependencies]\nrand = "*"'), "crates.io", "rand"],
    ["Cargo.toml", ct('[build-dependencies]\nrand = "*"'), "crates.io", "rand"],
    ["pnpm-workspace.yaml", "catalog:\n  vite: latest\n", "npm", "vite"],
    ["pnpm-workspace.yaml", "catalog:\n  vite: '*'\n", "npm", "vite"],
  ])("%s %j: held for a verdict on latest", (name, content, ecosystem, pkg) => {
    const r = write(name, content);
    expect(r.decision, r.text).toBe("deny");
    expect(r.items).toEqual([{ ecosystem, package: pkg, to: "latest" }]);
  });
  it.each([
    ["package.json", '{"dependencies":{"vite":"next"}}'],
    ["package.json", '{"devDependencies":{"vite":"beta"}}'],
    ["pnpm-workspace.yaml", "catalog:\n  vite: next\n"],
  ])("%s %j: a dist-tag other than latest, held: name the version", (name, content) => {
    const r = write(name, content);
    expect(r.decision).toBe("deny");
    expect(r.text).toMatch(/name the version|dist-tag/);
  });
  it("a non-registry form still goes ahead; a workspace-inherited Cargo dependency is no request", () => {
    expect(write("package.json", '{"dependencies":{"a":"file:../a","b":"workspace:*","c":"github:x/y","d":"./d.tgz"}}').decision).toBe("allow");
    expect(write("Cargo.toml", ct('[dependencies]\nrand = { workspace = true }\nlocal = { path = "../local" }')).decision).toBe("allow");
  });
  it("a specifier that is none of these is held as not read", () => {
    expect(write("package.json", '{"dependencies":{"vite":"~>!"}}').text).toContain("a specifier this hook does not read");
  });
});

describe("H3: pnpm packageExtensions are declarations; an unknown pnpm-workspace.yaml key is held", () => {
  it.each([
    ["pnpm-workspace.yaml", "packageExtensions:\n  ms:\n    dependencies:\n      lodash: 4.17.20\n"],
    ["pnpm-workspace.yaml", "packageExtensions:\n  'ms@2':\n    peerDependencies:\n      lodash: 4.17.20\n"],
    ["package.json", '{"pnpm":{"packageExtensions":{"ms":{"dependencies":{"lodash":"4.17.20"}}}}}'],
    ["package.json", '{"pnpm":{"packageExtensions":{"ms@*":{"optionalDependencies":{"lodash":"4.17.20"}}}}}'],
    ["package.json", '{"packageExtensions":{"ms":{"dependencies":{"lodash":"4.17.20"}}}}'],
  ])("%s %j: judged (avoid on record)", (name, content) => {
    const r = write(name, content);
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("answered avoid");
  });
  it.each([
    ["registry: https://npm.corp.example\n"],
    ["resolutionMode: lowest-direct\n"],
    ["someNewKey:\n  lodash: 4.17.20\n"],
  ])("a change under a key neither judged nor known to install nothing is held: %j", (content) => {
    expect(write("pnpm-workspace.yaml", content).text).toContain("could not be read");
  });
  it("a setting known to install nothing goes ahead", () => {
    expect(write("pnpm-workspace.yaml", "packages:\n  - 'apps/*'\nonlyBuiltDependencies:\n  - esbuild\nnodeLinker: hoisted\n").decision).toBe("allow");
  });
});

describe("H8b: a backslash in double quotes that bash leaves literal", () => {
  it.each(['echo "## Upgrading\\nRun pip install -U six" >> README.md', 'printf "%s\\n" "cargo add serde"'])("%s: text, goes ahead", (command) => {
    expect(run(command).decision).toBe("allow");
  });
  it.each(['echo "\\$(npm i lodash@4.17.20)"', 'echo "a\\"b" ; npm i lodash@4.17.20'])("%s: held (an escaped special is still not read, or the install is judged)", (command) => {
    expect(run(command).decision).toBe("deny");
  });
});
