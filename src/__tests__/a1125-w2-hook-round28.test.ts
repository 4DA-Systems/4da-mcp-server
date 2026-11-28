// SPDX-License-Identifier: Apache-2.0
/**
 * Round 28 of the hook lane (sentence check 24): the runner reading is best effort (L3), with the
 * cheap fixes that only hold more (F2, F4, F5, F11); the file an edit makes must parse strictly in
 * its kind (G2); a version beside a path or git source is judged (G3); configuration verbs from each
 * manager's own command table (G4); an expansion before a manager's verb (G5); more advised
 * commands (G6); a conditional path alternative with no registry reading goes ahead (G7).
 */

import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { JS_MANAGERS, installsIn } from "../../hooks/manifest-edit.mjs";
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

const bash = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const ps = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "PowerShell", tool_input: { command } });
const post = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command }, tool_response: {} });
const readings = (command: string) => installsIn(command, "bash").map((x: { name: string; spec: string }) => `${x.name} ${x.spec}`);

describe("the runner reading, best effort, holds more where it sees more", () => {
  it.each([
    ["npx x@npm:semver@7.5.0 --help", ["semver 7.5.0"]],
    ["npx -p x@npm:semver@7.5.0 semver --help", ["semver 7.5.0"]],
    ["bunx -p x@npm:semver@7.5.0 semver --help", ["semver 7.5.0"]],
    ["npx semver@https://registry.npmjs.org/semver/-/semver-7.5.0.tgz --help", ["semver 7.5.0"]],
    ["uvx -- black@24.3.0 --version", ["black ==24.3.0"]],
    ["uv tool run -- black@24.3.0 --version", ["black ==24.3.0"]],
    ["go run -- golang.org/x/text/cmd/gotext@v0.3.0 -h", ["golang.org/x/text/cmd/gotext v0.3.0"]],
    ["pipx run -- black==24.3.0", ["black ==24.3.0"]],
    ["npx go@3.0.1 --version", ["go 3.0.1"]],
    ["npx -p pip@0.0.1 x", ["pip 0.0.1"]],
    ["npx cargo@1.0.0", ["cargo 1.0.0"]],
    ["npx -y pnpm@9 add lodash@4.18.1", ["lodash 4.18.1"]],
  ])("F2 F4 F11: %s reads %j", (command, expected) => {
    expect(readings(command)).toEqual(expected);
  });
  it("JS_MANAGERS is the runner family's own list", () => {
    expect([...JS_MANAGERS]).toEqual(expect.arrayContaining(["npm", "pnpm", "yarn", "bun"]));
    expect(JS_MANAGERS.has("go")).toBe(false);
  });
  it.each(["npx x@npm:semver@7.5.0 --help", "npx semver@https://registry.npmjs.org/semver/-/semver-7.5.0.tgz --help", "npx semver@x --version", "npx semver@X", "npx semver@https://files.example.com/s.tgz", "uvx -- black@24.3.0", "npx go@3.0.1 --version"])("%s: held", (command) => {
    expect(bash(command).decision).toBe("deny");
  });
  it.each(["uvx --exclude-newer 2024-01-01 --from black black --version", "uvx --prerelease allow black", "uvx --resolution lowest-direct black", "uv run --exclude-newer 2024-01-01 --with requests python", "npx --before 2024-01-01 semver"])("F5: %s: a release-picking option is not read", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
});

describe("G2: the file an edit makes is valid in its kind", () => {
  const kinds: Array<[string, string, Array<[string, string]>]> = [
    [
      "package.json",
      '{\n  "name": "t",\n  "dependencies": {\n    "lodash": "4.18.1"\n  }\n}\n',
      [
        ["single-quoted keys", "{\n  'name': 't',\n  'dependencies': {\n    'semver': '7.5.0'\n  }\n}\n"],
        ["a trailing comma", '{\n  "name": "t",\n  "dependencies": {\n    "semver": "7.5.0",\n  }\n}\n'],
        ["a comment", '{\n  // deps\n  "name": "t",\n  "dependencies": { "semver": "7.5.0" }\n}\n'],
        ["an unclosed object", '{\n  "name": "t",\n  "dependencies": { "semver": "7.5.0" }\n'],
        ["a bare key", '{\n  name: "t",\n  "dependencies": { "semver": "7.5.0" }\n}\n'],
        ["an array at the top", '[{ "dependencies": { "semver": "7.5.0" } }]\n'],
      ],
    ],
    [
      "Cargo.toml",
      '[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\n',
      [
        ["an unclosed header", '[package\nname = "a"\n\n[dependencies]\nregex = "=1.5.4"\n'],
        ["a key with no value", '[package]\nname = "a"\n\n[dependencies]\nregex =\n'],
        ["a line with no =", '[package]\nname = "a"\n\n[dependencies]\nregex "=1.5.4"\n'],
        ["an unquoted value", '[package]\nname = "a"\n\n[dependencies]\nregex = latest\n'],
        ["an unclosed inline table", '[package]\nname = "a"\n\n[dependencies]\nregex = { version = "=1.5.4"\n'],
        ["two values on a line", '[package]\nname = "a"\n\n[dependencies]\nregex = "=1.5.4" "x"\n'],
      ],
    ],
    [
      "pyproject.toml",
      '[project]\nname = "a"\nversion = "0.1.0"\ndependencies = []\n',
      [
        ["an unclosed array", '[project]\nname = "a"\ndependencies = ["requests==2.19.0"\n'],
        ["a missing comma", '[project]\nname = "a"\ndependencies = ["requests==2.19.0" "six"]\n'],
        ["an unclosed header", '[project\nname = "a"\ndependencies = ["requests==2.19.0"]\n'],
      ],
    ],
    [
      "go.mod",
      "module example.com/a\n\ngo 1.22\n",
      [
        ["an unknown directive", "module example.com/a\n\ngo 1.22\n\nrequires golang.org/x/text v0.3.0\n"],
        ["an unclosed block", "module example.com/a\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.3.0\n"],
        ["an unbalanced quote", 'module example.com/a\n\ngo 1.22\n\nrequire "golang.org/x/text v0.3.0\n'],
      ],
    ],
  ];
  for (const [file, before, breaks] of kinds) {
    for (const [label, after] of breaks) {
      it(`${file}: ${label} (Write)`, () => {
        const r = s.write(s.file(file, before), after);
        expect(r.decision).toBe("deny");
        expect(r.text).toContain("could not be read");
      });
    }
  }
  it("an Edit with replace_all that breaks the JSON is held", () => {
    const file = s.file("package.json", '{\n  "name": "t",\n  "dependencies": { "lodash": "4.18.1" }\n}\n');
    const r = s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: { file_path: file, old_string: '"', new_string: "'", replace_all: true } });
    expect(r.text).toContain("is not valid JSON");
  });
  it("a valid file with a comment or a date goes ahead", () => {
    expect(s.write(s.file("Cargo.toml", '[package]\nname = "a"\nversion = "0.1.0"\n'), '[package]\nname = "a" # the name\nversion = "0.1.0"\nedition = "2021"\n\n[package.metadata]\nreleased = 1979-05-27T07:32:00Z\nratio = 1.5\nflags = [\n  "a",\n  "b",\n]\n').decision).toBe("allow");
    expect(s.write(s.file("go.mod", "module example.com/a\n\ngo 1.22\n\ntoolchain go1.24.4\n"), "module example.com/a\n\ngo 1.22\n\n// a note\ntoolchain go1.24.4\n").decision).toBe("allow");
    // Round 35 (C4): a toolchain line the edit adds makes the go command fetch that release: held.
    expect(s.write(s.file("go.mod", "module example.com/a\n\ngo 1.22\n"), "module example.com/a\n\ngo 1.22\n\n// a note\ntoolchain go1.24.4\n").decision).toBe("deny");
  });
});

describe("G3: a version beside a path or git source is judged", () => {
  const C = (dep: string) => `[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\n${dep}\n`;
  it.each(['regex = { version = "=1.5.4", path = "../regex" }', 'regex = { version = "=1.5.4", git = "https://github.com/rust-lang/regex" }', '[dependencies.regex]\nversion = "=1.5.4"\npath = "../regex"'])("Cargo %s: judged", (dep) => {
    expect(s.write(join(s.project, "Cargo.toml"), C(dep)).text).toContain("answered avoid");
  });
  it.each(['regex = { path = "../regex" }', 'regex = { git = "https://github.com/rust-lang/regex", branch = "main" }'])("Cargo %s: own", (dep) => {
    expect(s.write(join(s.project, "Cargo.toml"), C(dep)).decision).toBe("allow");
  });
  const head = '[tool.poetry]\nname = "t"\nversion = "0.1.0"\n[tool.poetry.dependencies]\n';
  it("Poetry: a path with a version is judged; a path alone, or with a condition, is own (G7)", () => {
    expect(s.write(join(s.project, "pyproject.toml"), `${head}requests = { path = "../r", version = "2.19.0" }\n`).text).toContain("answered avoid");
    expect(s.write(join(s.project, "pyproject.toml"), `${head}requests = { path = "../r" }\n`).decision).toBe("allow");
    expect(s.write(join(s.project, "pyproject.toml"), `${head}requests = { path = "../r", python = "<3.10" }\n`).decision).toBe("allow");
    expect(s.write(join(s.project, "pyproject.toml"), `${head}requests = { path = "../r", platform = "win32" }\n`).decision).toBe("allow");
  });
});

describe("G4: configuration verbs from each manager's own command table", () => {
  // Sources: `npm config --help` and `npm set --help` (npm 10.9.2: config, alias c; set; get),
  // `pnpm help` and `pnpm help config` (pnpm 10.34.6: c, config; set, get print the config usage),
  // `yarn help config` (Yarn 1.22.22: config set, get, delete, list), Yarn 2+: config set, unset,
  // `set version`, `set resolution`.
  const writes: Array<[string, string]> = [
    ["npm", "config set registry=https://evil-mirror.com/"],
    ["npm", "c set registry=https://evil-mirror.com/"],
    ["npm", "set registry=https://evil-mirror.com/"],
    ["npm", "config delete registry"],
    ["npm", "config rm registry"],
    ["npm", "config edit"],
    ["pnpm", "config set registry https://evil-mirror.com/"],
    ["pnpm", "c set registry https://evil-mirror.com/"],
    ["pnpm", "set registry https://evil-mirror.com/"],
    ["pnpm", "config delete registry"],
    ["pnpm", "c delete registry"],
    ["yarn", "config set registry https://evil-mirror.com/"],
    ["yarn", "config delete registry"],
    ["yarn", "config unset npmRegistryServer"],
    ["yarn", "set version ./other-yarn.cjs"],
    ["yarn", "set version https://files.example.com/yarn.cjs"],
    ["yarn", "set version stable"],
    ["yarn", "set resolution lodash@npm:4.17.20 npm:4.18.1"],
  ];
  it.each(writes)("%s %s: not read", (manager, rest) => {
    expect(bash(`${manager} ${rest}`).text).toContain("could not be read");
  });
  it("yarn set: the remedy says the user changes the Yarn release", () => {
    expect(bash("yarn set version stable").text).toContain("the user changes the Yarn release");
  });
  it.each(["npm config get registry", "npm get registry", "pnpm c get registry", "pnpm get registry", "pnpm config list", "yarn config get registry", "npm config set fund=false", "pnpm set fund false"])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});

describe("G5: an expansion before a manager's verb", () => {
  it.each(["npm --cache @X install", "npm --loglevel @X i", "pnpm --dir @X add", "npm @X install"])("PowerShell %s: not read", (command) => {
    expect(ps(command).text).toContain("could not be read");
  });
  it.each(["npm --cache $X install", "pnpm --dir $D add lodash@4.18.1"])("bash %s: not read", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
});

describe("G6: more manager-chosen updates are advised", () => {
  it.each(["cargo generate-lockfile", "go work sync", "uv pip compile requirements.in -o requirements.txt", "uv pip compile --upgrade requirements.in"])("%s", (command) => {
    expect(post(command).decision).toBe("advise");
  });
});
