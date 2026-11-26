// SPDX-License-Identifier: Apache-2.0
/**
 * Round 15, from the thirteenth independent check: each cause with its cases and a sweep of its class.
 */

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { NAMED_OPTIONS } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");

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

describe("H7: every option on the allow lists is taken by the reader (generated from NAMED_OPTIONS)", () => {
  const COMMAND: Record<string, string> = {
    npm: "npm install {} lodash@4.17.21", pnpm: "pnpm add {} lodash@4.17.21", yarn: "yarn add {} lodash@4.17.21", bun: "bun add {} lodash@4.17.21",
    poetry: "poetry add {} requests==2.32.3", pip: "pip install {} requests==2.32.3", uvpip: "uv pip install {} requests==2.32.3", uvadd: "uv add {} requests==2.32.3",
    uvtool: "uv tool install {} ruff==0.6.9", cargoadd: "cargo add {} serde@1.0.200", cargoinstall: "cargo install {} ripgrep@14.1.1",
    goget: "go get {} rsc.io/quote@v1.5.2", goinstall: "go install {} golang.org/x/tools/gopls@v0.16.2", gomodedit: "go mod edit {} -require=rsc.io/quote@v1.5.2",
  };
  const rows: [string, string, string][] = [];
  for (const [key, list] of Object.entries(NAMED_OPTIONS as Record<string, [string, string][]>)) {
    for (const [spec] of list) for (const w of spec.split(" ")) rows.push([key, w.replace(/[=?]$/, ""), w.endsWith("=") ? `${w.slice(0, -1)} x1` : w.endsWith("?") ? `${w.slice(0, -1)}=x1` : w]);
    // (an optional-value option is written with its value attached: Poetry's bare --optional before a package is held by its own rule)
  }
  it("covers the lead's additions", () => {
    for (const o of ["--no-package-lock", "--omit", "--strict-peer-deps", "--engine-strict", "--foreground-scripts", "--ignore-engines", "--no-cache-dir"]) expect(rows.some((r) => r[1] === o), o).toBe(true);
  });
  it.each(rows)("%s %s is never held as an option off the list", (key, name, option) => {
    const r = run(COMMAND[key].replace("{}", option));
    expect(r.text, `${key} ${option}`).not.toContain(`the option ${name} beside`);
    for (const end of [")", " ", "="]) expect(r.text, `${key} ${option}`).not.toContain(`could not be read (the option ${name}${end}`);
  });
  it("cargo install --vers / --version name the operand's version: judged at that version", () => {
    for (const c of ["cargo install ripgrep --vers 13.0.0", "cargo install ripgrep --version 13.0.0", "cargo install ripgrep --vers=13.0.0"]) {
      const r = run(c);
      expect(r.items, c).toEqual([{ ecosystem: "crates.io", package: "ripgrep", to: "13.0.0" }]);
    }
  });
});

describe("H6: the registries' own aliases and public mirrors are public", () => {
  it.each([
    "pip install https://pypi.io/packages/source/r/requests/requests-2.19.0.tar.gz",
    "pip install https://www.pypi.io/packages/source/r/requests/requests-2.19.0.tar.gz",
  ])("%s: read as requests 2.19.0, judged", (command) => {
    const r = run(command);
    expect(r.items).toEqual([{ ecosystem: "PyPI", package: "requests", to: "2.19.0" }]);
  });
  it.each([
    "pip install -i https://pypi.tuna.tsinghua.edu.cn/simple requests==2.19.0",
    "pip install -i https://mirrors.aliyun.com/pypi/simple requests==2.19.0",
    "npm install --registry https://registry.npmmirror.com lodash@4.17.20",
  ])("a public mirror is no project's own source (one index that is public: held): %s", (command) => {
    expect(run(command).text).toContain("could not be read");
  });
  it("a file URL on a public host in a form this hook does not read stays held", () => {
    expect(run("pip install https://pypi.io/simple/requests/").decision).toBe("deny");
  });
});

describe("H5: a payload the hook cannot read whole is the failure rule's", () => {
  const big = (input: Record<string, unknown>) => JSON.stringify({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", ...input }).replace('"PAD"', JSON.stringify("x".repeat(65 * 1024 * 1024)));
  const spawnRaw = (text: string) => {
    const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: s.home };
    delete env.FOURDA_GUARD;
    return spawnSync(process.execPath, [HOOK], { input: text, encoding: "utf8", env, timeout: 30_000, maxBuffer: 1 << 26 }).stdout;
  };
  it("a Bash call over 64 MB (an install after 65 MB of echo): held", () => {
    expect(spawnRaw(big({ tool_name: "Bash", tool_input: { command: "PAD" } }).replace('"command":"', '"command":"echo ').replace(/"\}\}$/, '; npm install lodash@4.17.20"}}'))).toContain('"deny"');
  }, 60_000);
  it("a payload over 64 MB whose tool is not in its first part: held; a README Write: nothing", () => {
    expect(spawnRaw(`{"session_id":"s","hook_event_name":"PreToolUse","pad":${JSON.stringify("x".repeat(65 * 1024 * 1024))},"tool_name":"Bash","tool_input":{"command":"ls"}}`)).toContain('"deny"');
    expect(spawnRaw(big({ tool_name: "Write", tool_input: { file_path: `${s.project}/README.md`, content: "PAD" } }))).toBe("");
  }, 60_000);
});
