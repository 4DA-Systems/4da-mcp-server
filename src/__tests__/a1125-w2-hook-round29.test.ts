// SPDX-License-Identifier: Apache-2.0
/**
 * Round 29 of the hook lane (sentence check 25): strict readers for config files (H0), no raw-text
 * pre-check before parsing (H1), configuration-source options as detector tokens (H2),
 * patchedDependencies held in pnpm-workspace.yaml (H3), requirements files counted per file read
 * (H4), the go.mod grammar and a stricter TOML walk (H8), advised commands (H9), and the precision
 * costs: a repaired file, TOML escapes, multi-line strings, `>=0`, variables in quoted text, an
 * expansion in a global option's value, grep on the ledger.
 */

import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { PNPM_INERT_KEYS } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "semver", version: "7.5.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "npm", package: "lodash", version: "4.18.1", verdict: "proceed" },
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "regex", version: "1.5.4", requested: "=1.5.4", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());

const bash = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });
const post = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command }, tool_response: {} });

describe("H0: a config file is read with a strict reader of its format", () => {
  // [file, a plain inert first line, the resolution key line]
  const formats: Array<[string, string, string]> = [
    [".npmrc", "fund=false", "registry=http://127.0.0.1:9/"],
    ["pip.conf", "[global]\ntimeout = 30", "index-url = http://127.0.0.1:9/simple"],
    [".yarnrc", 'save-prefix "~"', 'registry "http://127.0.0.1:9/"'],
    [".yarnrc.yml", "nodeLinker: node-modules", 'npmRegistryServer: "http://127.0.0.1:9/"'],
    ["uv.toml", 'cache-dir = "./c"', 'index-url = "http://127.0.0.1:9/simple"'],
    ["bunfig.toml", "[install]\nexact = true", 'registry = "http://127.0.0.1:9/"'],
  ];
  const tricks: Array<[string, (first: string, key: string) => string]> = [
    ["a tab before the key", (f, k) => `${f}\n\t${k}\n`],
    ["a space before the key", (f, k) => `${f}\n  ${k}\n`],
    ["a tab and a space", (f, k) => `${f}\n \t${k}\n`],
    ["a lone CR", (f, k) => `${f}\r${k}\n`],
    ["a form feed", (f, k) => `${f}\n\f${k}\n`],
    ["an NBSP", (f, k) => `${f}\n ${k}\n`],
    ["U+3000", (f, k) => `${f}\n　${k}\n`],
    ["a backslash continuation", (f, k) => `${f} \\\n${k}\n`],
    ["a BOM past the start", (f, k) => `${f}\n﻿${k}\n`],
  ];
  for (const [file, first, key] of formats) {
    for (const [label, make] of tricks) {
      it(`${file}: ${label}`, () => {
        const path = s.file(file, `${first}\n`);
        const r = s.write(path, make(first, key));
        expect(r.decision, r.text).toBe("deny");
      });
    }
    it(`${file}: the inert line alone goes ahead`, () => {
      const path = s.file(file, "");
      expect(s.write(path, `${first}\n`).decision).toBe("allow");
    });
  }
  it.each([
    ["a second document", "nodeLinker: node-modules\n---\nnpmRegistryServer: x\n"],
    ["an anchor", "nodeLinker: &a node-modules\n"],
    ["a tag", "nodeLinker: !!str node-modules\n"],
    ["a flow mapping", "npmScopes: { acme: { npmRegistryServer: x } }\n"],
    ["a # inside a key's scalar", 'nodeLinker: "node-modules" #\n\tnpmRegistryServer: x\n'],
  ])(".yarnrc.yml %s: held", (_label, text) => {
    expect(s.write(s.file(".yarnrc.yml", ""), text).decision).toBe("deny");
  });
  it("an ini value with # or ; inside, unquoted: held", () => {
    expect(s.write(s.file(".npmrc", "fund=false\n"), "fund=false\nloglevel=warn # registry=http://127.0.0.1:9/\n").decision).toBe("deny");
  });
  it("pip's multi-line keys take indented continuation lines; any other key does not", () => {
    const base = "[global]\ntimeout = 30\n";
    expect(s.write(s.file("pip.conf", base), `${base}extra-index-url = https://a.example/\n  https://b.example/\n`).text).toContain("extra-index-url");
    expect(s.write(s.file("pip.conf", base), `${base}timeout = 30\n  index-url = http://127.0.0.1:9/\n`).decision).toBe("deny");
  });
  it("a nested block under a key with no value is read", () => {
    expect(s.write(s.file(".yarnrc.yml", ""), "packageExtensions:\n  foo@*:\n    dependencies:\n      bar: 1.0.0\n").text).toContain('"packageextensions"');
  });
});

describe("H1: no raw-text test for a key before parsing", () => {
  const B = (n: string) => String.fromCharCode(92) + "u" + n.charCodeAt(0).toString(16).padStart(4, "0");
  const esc = (key: string, at: number) => key.slice(0, at) + B(key[at]) + key.slice(at + 1);
  // [label, a package.json that the readers act on, written with a key part escaped]
  const docs: Array<[string, (k: (key: string) => string) => string, string]> = [
    ["pnpm.patchedDependencies", (k) => `{"name":"p","${k("pnpm")}":{"${k("patchedDependencies")}":{"semver@7.6.3":"p.patch"}}}`, "deny"],
    ["pnpm.supportedArchitectures", (k) => `{"name":"p","${k("pnpm")}":{"${k("supportedArchitectures")}":{"os":["linux"]}}}`, "deny"],
    ["pnpm.ignoredOptionalDependencies", (k) => `{"name":"p","${k("pnpm")}":{"${k("ignoredOptionalDependencies")}":["x"]}}`, "deny"],
    ["patchedDependencies", (k) => `{"name":"p","${k("patchedDependencies")}":{"semver@7.6.3":"p.patch"}}`, "deny"],
    ["dependencies", (k) => `{"name":"p","${k("dependencies")}":{"semver":"7.5.0"}}`, "deny"],
    ["devDependencies", (k) => `{"name":"p","${k("devDependencies")}":{"semver":"7.5.0"}}`, "deny"],
    ["overrides", (k) => `{"name":"p","${k("overrides")}":{"semver":"7.5.0"}}`, "deny"],
    ["a dependency name", (k) => `{"name":"p","dependencies":{"${k("semver")}":"7.5.0"}}`, "deny"],
  ];
  for (const [label, make] of docs) {
    for (const at of [0, 1, 3]) {
      it(`package.json ${label}, the key escaped at ${at}`, () => {
        const r = s.write(s.file("package.json", '{"name":"p"}'), make((key) => esc(key, Math.min(at, key.length - 1))));
        expect(r.decision, r.text).toBe("deny");
      });
    }
  }
  it("a key given twice, once escaped, is a duplicate", () => {
    expect(s.write(s.file("package.json", '{"name":"p"}'), `{"name":"p","dependencies":{"semver":"7.5.0"},"${esc("dependencies", 2)}":{"lodash":"4.18.1"}}`).text).toContain("given twice");
  });
  it.each([
    ["a quoted table and key", '[project]\nname = "a"\n["tool"."uv"]\n\'index-url\' = "https://mirror.example.cn/simple"\n'],
    ["an escaped table", `[project]\nname = "a"\n["tool".${JSON.stringify("uv")}]\n"${esc("index-url", 0)}" = "https://mirror.example.cn/simple"\n`],
  ])("pyproject %s: the setting is read", (_label, text) => {
    expect(s.write(s.file("pyproject.toml", '[project]\nname = "a"\n'), text).text).toContain("tool.uv.index-url");
  });
  it("a TOML escaped dependency name is read as the name", () => {
    const c = '[package]\nname = "t"\nversion = "0.1.0"\n';
    expect(s.write(s.file("Cargo.toml", c), `${c}[dependencies]\n"rege${B("x")}" = "=1.5.4"\n`).text).toContain("answered avoid");
  });
  it("a quoted YAML key in pnpm-workspace.yaml is the key", () => {
    expect(s.write(s.file("pnpm-workspace.yaml", "packages:\n  - .\n"), 'packages:\n  - .\n"overrides":\n  semver: 7.5.0\n').text).toContain("answered avoid");
  });
});

describe("H2: every CONFIG_SOURCE_OPTIONS entry is a detector token of its manager", () => {
  it.each(["poetry --directory sub run pytest", "poetry -P sub run pytest", "poetry --project=sub build", "bun -c ./bunfig.toml run build", "bun -c=x test", "bun --config=x.toml run build"])("%s: not read", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
  it.each(["poetry run pytest", "bun run build"])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});

describe("H3: patchedDependencies is held in pnpm-workspace.yaml as in package.json", () => {
  it("PNPM_INERT_KEYS no longer lists it", () => {
    expect(PNPM_INERT_KEYS.has("patchedDependencies")).toBe(false);
    expect(PNPM_INERT_KEYS.has("nodeLinker")).toBe(true);
  });
  it("adding it is held", () => {
    const base = 'packages:\n  - "."\n';
    expect(s.write(s.file("pnpm-workspace.yaml", base), `${base}patchedDependencies:\n  semver@7.6.3: patches/semver@7.6.3.patch\n`).decision).toBe("deny");
  });
});

describe("H4: REQUIREMENTS_FILES counts every file a read reaches", () => {
  it("40 sibling includes are past the bound", () => {
    for (let i = 0; i < 40; i++) s.file(`s${i}.txt`, "six==1.17.0\n");
    s.file("top.txt", Array.from({ length: 40 }, (_, i) => `-r s${i}.txt`).join("\n") + "\n");
    expect(bash("pip install -r top.txt").text).toContain("files of -r and -c");
  });
});

describe("H8: the go.mod grammar and the TOML walk", () => {
  const G = "module example.com/t\n\ngo 1.21\n";
  it("a block opened with no blank, and an empty block, are go.mod", () => {
    expect(s.write(s.file("go.mod", G), `${G}\nrequire(\n\trsc.io/quote v1.5.2\n)\n`).text).not.toContain("not valid go.mod");
    expect(s.write(s.file("go.mod", G), `${G}\nrequire ()\n`).decision).toBe("allow");
  });
  const C = '[package]\nname = "t"\nversion = "0.1.0"\n';
  it.each(["x = 1 2\n", "x = [1 2]\n", "x = 1.2.3\n", "x = true false\n"])("Cargo.toml gains %j: not valid TOML", (line) => {
    expect(s.write(s.file("Cargo.toml", C), C + line).text).toContain("not valid TOML");
  });
  it.each(['description = "A \\"demo\\" crate"\n', "[package.metadata]\nd = 1979-05-27 07:32:00\nt = 1979-05-27T07:32:00.999Z\nf = -1.5e3\n", 'notes = """\nA tool.\n"""\n'])("Cargo.toml gains %j: valid", (line) => {
    expect(s.write(s.file("Cargo.toml", C), C + line).decision).toBe("allow");
  });
});

describe("H9: the advice line after the commands that let the manager choose versions", () => {
  it.each(["uv tool upgrade --all", "uv tool upgrade ruff", "pnpm fetch", "pnpm import", "yarn upgrade-interactive"])("%s", (command) => {
    expect(post(command).decision).toBe("advise");
  });
});

describe("precision: a repaired file, and an invalid one, are judged by the file the edit makes", () => {
  const bad = '{\n  "name": "t",\n  "description": "A small app",\n  "dependencies": { "lodash": "4.18.1" },\n}\n';
  it("an edit that repairs an invalid package.json is read normally", () => {
    expect(s.write(s.file("package.json", bad), bad.replace("},\n}", "}\n}")).decision).toBe("allow");
    expect(s.write(s.file("package.json", '{\n  // x\n  "name": "t",\n  "dependencies": { "lodash": "4.18.1" }\n}\n'), '{\n  "name": "t",\n  "dependencies": { "lodash": "4.18.1" }\n}\n').decision).toBe("allow");
  });
  it("an edit that leaves it invalid gets the syntax denial, never a version form", () => {
    const r = s.write(s.file("package.json", bad), bad.replace('"A small app"', '"A smaller app"'));
    expect(r.text).toContain("is not valid JSON");
    expect(r.text).not.toContain("version form");
  });
});

describe("precision: the costs", () => {
  it("`>=0`, `>=0.0.0` and `*` in a manifest are the reading latest", () => {
    s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.18.1", requested: "latest", verdict: "proceed" }]);
    for (const spec of [">=0", ">=0.0.0", "*"]) expect(s.write(s.file("package.json", '{"name":"p"}'), `{"name":"p","dependencies":{"lodash":"${spec}"}}`).decision, spec).toBe("allow");
  });
  it.each(['echo "deploy $X npm install"', 'git commit -m "npm i $X"', 'printf "%s" "pip install ${A}"'])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
  it.each(['npm install "$X"', 'V=ms@2.1.3; npm install -D "$V"', 'echo "npm i $(whoami)"'])("%s: held", (command) => {
    expect(bash(command).decision).toBe("deny");
  });
  it.each(['pnpm --filter "$PKG" build', 'npm --prefix "$P" run build'])("%s: a quoted value of a known global option goes ahead before a verb that installs nothing", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
  it.each(["pnpm --filter $PKG build", 'npm --prefix "$P" install lodash@4.18.1', "npm --cache $X"])("%s: held (an unquoted value is split into words; an install after it)", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
  it.each(["pnpm --dir @X build"])("PowerShell %s: a splat is held", (command) => {
    expect(bash(command, "PowerShell").text).toContain("could not be read");
  });
  it("grep on the ledger file is a plain read", () => {
    const ledger = join(s.home, "check-ledger.jsonl").split(String.fromCharCode(92)).join("/");
    expect(bash(`grep proceed ${ledger}`).decision).toBe("allow");
    expect(bash(`grep proceed ${ledger} > x.txt`).decision).toBe("deny");
  });
});
