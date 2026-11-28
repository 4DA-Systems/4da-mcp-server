// SPDX-License-Identifier: Apache-2.0
/**
 * Round 26b of the hook lane (sentence check 22): stop resolving where a named source points (D1),
 * dependency tables and resolver namespaces default-deny on the parsed tree (D2), one detector for
 * an expansion in a manager's words (D3), and the smaller faults (F7, F10-F17).
 */

import { join } from "node:path";
import { writeFileSync } from "node:fs";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "regex", version: "1.5.4", requested: "=1.5.4", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());

const bash = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const ps = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "PowerShell", tool_input: { command } });
const C = (dep: string) => `[package]\nname = "a"\nversion = "0.1.0"\n\n${dep}\n`;
const P = (rest: string) => `[project]\nname = "a"\nversion = "0.1.0"\ndependencies = ["requests==2.19.0"]\n${rest}`;

describe("D1: a source named by name is not resolved: the dependency is judged", () => {
  it.each([
    '[dependencies]\nregex = { version = "=1.5.4", registry = "corp" }',
    '[dependencies]\nregex = { version = "=1.5.4", registry-index = "sparse+https://cargo.corp.internal/index/" }',
    '[dependencies]\nregex = { version = "=1.5.4", registry-index = "sparse+https://index.crates.io/" }',
  ])("Cargo %s: judged on the avoid", (dep) => {
    s.file(".cargo/config.toml", '[registries.corp]\nindex = "sparse+https://cargo.corp.internal/index/"\n');
    expect(s.write(join(s.project, "Cargo.toml"), C(dep)).text).toContain("answered avoid");
  });
  it.each([
    '[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.corp.internal/simple"\nexplicit = true\n\n[tool.uv.sources]\nrequests = { index = "corp" }\n',
    '[tool.uv.sources]\nrequests = [{ index = "corp", marker = "sys_platform == \'linux\'" }, { path = "../r" }]\n',
  ])("uv %j: judged", (tables) => {
    const file = s.file("pyproject.toml", P("").replace('"requests==2.19.0"', "") + tables);
    expect(s.write(file, P(tables)).text).toContain("answered avoid");
  });
  it("Poetry source by name: judged; a path alternative exempts only itself", () => {
    const head = '[tool.poetry]\nname = "a"\n\n[tool.poetry.dependencies]\n';
    expect(s.write(s.file("pyproject.toml", head), `${head}requests = { version = "2.19.0", source = "corp" }\n`).text).toContain("answered avoid");
    expect(s.write(s.file("pyproject.toml", head), `${head}requests = [{ path = "../r", platform = "linux" }, { version = "2.19.0", platform = "win32" }]\n`).text).toContain("answered avoid");
    expect(s.write(s.file("pyproject.toml", head), `${head}requests = { path = "../r" }\n`).decision).toBe("allow");
  });
  it("a literal path or git source stays the project's own", () => {
    expect(s.write(join(s.project, "Cargo.toml"), C('[dependencies]\nregex = { path = "../regex", version = "=1.5.4" }')).decision).toBe("allow");
    const t = '[tool.uv.sources]\nrequests = { git = "https://github.com/psf/requests" }\n';
    expect(s.write(s.file("pyproject.toml", P("").replace('"requests==2.19.0"', "") + t), P(t)).decision).toBe("allow");
  });
});

describe("D2: dependency tables and resolver namespaces", () => {
  it.each(['[patch.crates-io]\nregex = "=1.5.4"', '[patch."https://github.com/x/y"]\nregex = "=1.5.4"', '[replace]\n"regex:1.0.0" = "=1.5.4"', '[workspace.dependencies]\nregex = "=1.5.4"'])("Cargo %s is judged", (t) => {
    expect(s.write(join(s.project, "Cargo.toml"), C(t)).text).toContain("answered avoid");
  });
  it("Poetry requires-plugins is judged", () => {
    expect(s.write(join(s.project, "pyproject.toml"), '[tool.poetry]\nname = "a"\n\n[tool.poetry.requires-plugins]\nrequests = "2.19.0"\n').text).toContain("answered avoid");
  });
  it.each([
    '[tool]\nuv = { index-url = "https://x.example/simple" }\n',
    '[tool]\npoetry = { source = [{ name = "x", url = "https://x.example/simple" }] }\n',
    '[tool.poetry.frob]\nx = 1\n',
    '[tool.pdm.frob]\nx = 1\n',
    '[tool.hatch.metadata]\nallow-direct-references = true\n',
    '[tool.flit.metadata]\nrequires = ["requests==2.19.0"]\n',
    '[tool.setuptools.frob]\nx = 1\n',
  ])("held: %j", (t) => {
    const before = '[project]\nname = "a"\nversion = "0.1.0"\n';
    expect(s.write(s.file("pyproject.toml", before), `${before}${t}`).decision).toBe("deny");
  });
  it("top-level dotted keys are read as the same leaves", () => {
    expect(s.write(s.file("pyproject.toml", ""), 'tool.uv.index-url = "https://x.example/simple"\n').decision).toBe("deny");
  });
  it.each(['[tool.poetry]\nname = "a"\nversion = "1"\ndescription = "x"\n', '[tool.setuptools]\npackages = ["a"]\n', '[tool.ruff]\nline-length = 1\n'])("not held: %j", (t) => {
    expect(s.write(s.file("pyproject.toml", ""), t).decision).toBe("allow");
  });
});

describe("D3: an expansion in a manager's words", () => {
  const LEADS = ["npm", "pnpm", "yarn", "yarnpkg", "bun", "pip", "pip3", "uv", "poetry", "cargo", "go", "npx", "pnpx", "bunx", "python -m pip", "py -m pip", "sudo npm", "env X=1 npm", "cmd /c npm", "time npm"];
  const EXP = ["$X", "${X}", '"${A[@]}"', '"$@"', "$(cat p)", "`cat p`"];
  const cases = LEADS.flatMap((lead) => EXP.flatMap((e) => [
    [`${lead} ${e}`, true],
    [`${lead} install ${e}`, !["cargo", "go"].includes(lead) || true],
  ] as const));
  it.each(cases)("%s: held", (command) => {
    expect(bash(command).decision, command).toBe("deny");
  });
  it.each(["npm run build -- $ARGS", "npm test $FILTER", "pnpm run lint $FILES", "cargo build $FLAGS", "go test $PKGS", "echo npm $HOME", "git commit -m \"$MSG\""])("%s: a literal non-install verb first, or no manager at the command's start: goes ahead", (command) => {
    expect(bash(command).decision, command).toBe("allow");
  });
  it.each(["npm i $env:PKG", "npm @a", "npm @(1)", "npm i %PKG%"])("PowerShell %s: held", (command) => {
    expect(ps(command).decision, command).toBe("deny");
  });
});

describe("F7: config verbs through every spelling P1 reads a manager through", () => {
  it.each(["python -m pip config set global.index-url https://x/", "py -m pip config set global.index-url https://x/", "python3 -m pip config set global.index-url https://x/", "uv run pip config set global.index-url https://x/"])("%s: held", (command) => {
    expect(bash(command).decision, command).toBe("deny");
  });
  it("an inert key through python -m pip goes ahead", () => {
    expect(bash("python -m pip config set global.timeout 60").decision).toBe("allow");
  });
});

describe("F10: non-string values in dependency-bearing positions", () => {
  it.each([
    { name: "a", dependencies: "lodash" },
    { name: "a", dependencies: ["lodash"] },
    { name: "a", dependencies: 1 },
    { name: "a", overrides: { lodash: 1 } },
    { name: "a", overrides: "x" },
    { name: "a", resolutions: ["x"] },
    { name: "a", pnpm: { overrides: 1 } },
  ])("package.json %j: held", (doc) => {
    expect(s.write(join(s.project, "package.json"), JSON.stringify(doc)).decision).toBe("deny");
  });
  it.each(['regex = { git = 1 }', 'regex = { path = true }', 'regex = { package = 1, version = "1" }', 'regex = { version = "1", branch = 2, git = "x" }', 'regex = { version = "1", optional = "yes" }', 'regex = { version = "1", workspace = "x" }'])("Cargo %s: held", (dep) => {
    expect(s.write(join(s.project, "Cargo.toml"), C(`[dependencies]\n${dep}`)).decision).toBe("deny");
  });
  it.each(['requests = { path = 1 }', 'requests = { git = true }', 'requests = [1, 2]'])("uv sources %s: held", (src) => {
    expect(s.write(join(s.project, "pyproject.toml"), P(`[tool.uv.sources]\n${src}\n`)).decision).toBe("deny");
  });
  it.each(['requests = { version = "2", source = 1 }', 'requests = { git = 1 }', 'requests = { version = "2", markers = 3 }', 'requests = [1]'])("Poetry %s: held", (dep) => {
    expect(s.write(join(s.project, "pyproject.toml"), `[tool.poetry]\nname = "a"\n\n[tool.poetry.dependencies]\n${dep}\n`).decision).toBe("deny");
  });
  it("a Write whose content is not a string, and a command that is not a string", () => {
    expect(s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: join(s.project, "package.json"), content: { dependencies: { lodash: "4.17.20" } } } }).decision).toBe("deny");
    expect(s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: ["npm", "i", "lodash@4.17.20"] } }).decision).toBe("deny");
  });
});

describe("F11, F12: config files", () => {
  it("a NotebookEdit of a config file is held", () => {
    expect(s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "NotebookEdit", tool_input: { notebook_path: join(s.project, ".npmrc"), new_source: "x" } }).decision).toBe("deny");
  });
  it.each([[".cargo/config.toml", "[build"], [".cargo/config.toml", "!!!"], ["uv.toml", "cache-dir = [\n"], [".npmrc", "[build"], ["pip.conf", "!!!"]])("%s with %j: held", (path, text) => {
    expect(s.write(s.file(path, ""), text).decision, text).toBe("deny");
  });
  it("the inert keys added: engine-strict, shamefully-hoist, enableScripts", () => {
    expect(s.write(s.file(".npmrc", ""), "engine-strict=true\nshamefully-hoist=true\n").decision).toBe("allow");
    expect(s.write(s.file(".yarnrc.yml", ""), "enableScripts: false\n").decision).toBe("allow");
    expect(s.write(s.file(".npmrc", ""), "auto-install-peers=true\n").decision).toBe("deny");
  });
});

describe("F13: a ledger line that parses but is no verdict object", () => {
  it.each(['["npm","lodash"]', '{"verdict":"proceed"}', "42", "null"])("%s after a proceed makes it unknown", (line) => {
    writeFileSync(join(s.home, "check-ledger.jsonl"), `${JSON.stringify({ t: new Date(Date.now() - 60_000).toISOString(), sv: "6.6.0", ecosystem: "npm", package: "ms", version: "2.1.3", verdict: "proceed" })}\n${line}\n`);
    expect(bash("npm i ms@2.1.3").decision).toBe("deny");
  });
});

describe("F16 and precision", () => {
  it("GOTOOLCHAIN is not inert (toolchain settings are held); poetry lock --check goes ahead", () => {
    expect(bash("go env -w GOTOOLCHAIN=go1.22.0").decision).toBe("deny");
    expect(bash("poetry lock --check").decision).toBe("allow");
  });
});
