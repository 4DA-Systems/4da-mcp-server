// SPDX-License-Identifier: Apache-2.0
/**
 * Round 11, from the ninth independent check (the header read sentence by sentence): each item
 * with the reviewer's cases.
 */

import { realpathSync } from "node:fs";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { followRemedy, answerDenial } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  // Round 25 (S2): a requirements or constraints file a command names is read at the call: these exist, empty.
  for (const f of ["requirements.txt", "requirements-dev.txt", "constraints.txt", "c.txt", "o.txt", "req.txt"]) s.file(f, "");
  s.ledger([]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

/** Held; the dependency_check call its denial names, answered proceed, releases it. */
function releasedByTheCall(command: string, tool = "Bash"): void {
  const r = run(command, tool);
  expect(r.decision, r.text).toBe("deny");
  expect(r.items, r.text).not.toBeNull();
  answerDenial(s, r, "proceed");
  expect(run(command, tool).decision).toBe("allow");
}

const LS = "‘";
const RS = "’";
const LD = "“";
const RD = "”";
const LOW = "‚";
const LOWD = "„";

describe("1: PowerShell's typographic quotes are quotes", () => {
  it.each([
    `n${LS}${RS}pm i lodash@4.17.20`,
    `npm ${LS}i${RS} lodash@4.17.20`,
    `npm ${LD}install${RD} lodash@4.17.20`,
    `p${LS}${RS}ip install requests==2.5.0`,
    `pnpm ${LS}add${RS} lodash@4.17.20`,
    `uv ${LS}add${RS} requests==2.5.0`,
    `cargo ${LD}add${RD} serde@1.0.0`,
    `go ${LS}get${RS} rsc.io/quote@v1.5.0`,
    `npm ${LOW}i${RS} lodash@4.17.20`,
    `npm ${LOWD}i${RD} lodash@4.17.20`,
  ])("%s: read, held, released by the call", (command) => {
    releasedByTheCall(command, "PowerShell");
  });
});

// Round 12: the grammar was beaten (a bracket expression, an option value read as the program): sed and awk
// are no data programs at all now. A manager word and verb in their words is held, with the grep / Write remedy.
describe("2: sed and awk (round 12: never text)", () => {
  it.each([
    "echo a | sed '1e npm i lodash@4.17.20'",
    "echo a | sed --expression='e npm i lodash@4.17.20'",
    "echo a | sed '/a/e pip install requests==2.5.0'",
    "echo a | sed '$e npm i lodash@4.17.20'",
    "echo a | sed '1,3e npm i lodash@4.17.20'",
    "echo a | sed -ee 'npm i lodash@4.17.20'",
    "sed -e 's/x/y/' -e '1e npm i lodash@4.17.20' f",
    "sed 's/x/npm i lodash@4.17.20/w out.sh' f",
    "awk 'BEGIN { system(\"npm i lodash@4.17.20\") }'",
    "awk '{ print \"npm i lodash@4.17.20\" | \"sh\" }' f",
    "awk -f prog.awk 'npm i lodash@4.17.20'",
  ])("%s: held", (command) => {
    expect(run(command).decision, command).toBe("deny");
  });

  it.each([
    "sed 's/npm install/npm ci/' README.md",
    "sed -n '/pip install/p' docs/setup.md",
    "sed -E 's|pip install (.*)|uv add \\1|g' notes.md",
    "sed '1d;s/npm install/pnpm install/' a.md",
    "awk '/pip install/ {print}' docs/setup.md",
  ])("%s: held, with the grep / Write remedy", (command) => {
    const r = run(command);
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("use grep, rg or Select-String");
  });

  it.each(["awk '{print $1}' 'npm install.log'", "awk -F: 'NR==1' 'npm install.txt'"])("%s: no manager word and verb as tokens, nothing to hold", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});

describe("3: a constraints or overrides file beside a named package, on every reader", () => {
  it.each([
    "uv tool install ruff -c c.txt",
    "uv tool install ruff --overrides o.txt",
    "uv tool install ruff --with black --constraints c.txt",
    "uv pip install requests -c c.txt",
    "uv add requests --constraints c.txt",
    "pip install requests --constraint c.txt",
    "python -m pip install requests -c c.txt",
  ])("%s: held, name the version; the named version, checked, goes ahead", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    // Round 13: the remedy names the file option; removed, the named package is judged on its own.
    const remedy = followRemedy(command, r.text);
    expect(remedy).toBe(command.replace(/\s+(?:-c|--constraints?|--overrides?)\s+\S+/, ""));
    releasedByTheCall(remedy as string);
  });
});

describe("4: --upgrade-package <name> moves the named package to its newest release", () => {
  it.each(["uv lock --upgrade-package requests", "uv lock -P requests", "uv sync -P requests", "uv pip compile requirements.in -P requests", "pip-compile -P requests requirements.in", "python -m piptools compile --upgrade-package requests requirements.in"])(
    "%s: the request latest, held without its verdict, released by the call",
    (command) => {
      const r = run(command);
      expect(r.decision, r.text).toBe("deny");
      expect(r.items).toEqual([{ ecosystem: "PyPI", package: "requests", to: "latest" }]);
      answerDenial(s, r, "proceed");
      expect(run(command).decision).toBe("allow");
    },
  );

  it("with an avoid on the latest request: held", () => {
    s.ledger([{ ecosystem: "PyPI", package: "requests", version: "2.32.3", requested: "latest", verdict: "avoid", reason: "test avoid" }]);
    expect(run("uv lock -P requests").text).toContain("avoid");
  });
});

describe("5: a manifest's file name is matched case-insensitively, without a stream suffix or trailing dots and blanks", () => {
  const write = (name: string, content: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: `${s.project.replace(/\\/g, "/")}/${name}`, content } });
  const PKG = '{"dependencies":{"lodash":"4.17.20"}}';
  it.each([
    ["Package.json", PKG],
    ["PACKAGE.JSON", PKG],
    ["package.json::$DATA", PKG],
    ["package.json:x", PKG],
    ["package.json.", PKG],
    ["package.json ", PKG],
    ["cargo.toml", '[package]\nname = "p"\nversion = "0.1.0"\n[dependencies]\nserde = "=1.0.0"\n'],
    ["PyProject.toml", '[project]\nname = "p"\nversion = "0.1"\ndependencies = ["requests==2.5.0"]\n'],
    ["GO.MOD", "module example.com/m\n\ngo 1.22\n\nrequire rsc.io/quote v1.5.0\n"],
    ["pnpm-workspace.YAML", "catalog:\n  lodash: 4.17.20\n"],
    ["Requirements.TXT", "requests==2.5.0\n"],
  ])("Write %s: held on its verdict", (name, content) => {
    const r = write(name, content);
    expect(r.decision, r.text).toBe("deny");
    expect(r.items, r.text).not.toBeNull();
  });

  it("another file goes ahead", () => {
    expect(write("package.jsonx", PKG).decision).toBe("allow");
    expect(write("notes.json", PKG).decision).toBe("allow");
  });
});

describe("6: trailing dots and blanks in a path part, which PowerShell and Win32 drop", () => {
  it.each([
    ["Remove-Item -Recurse -Force '<P>./<N>'", "PowerShell"],
    ["Rename-Item '<P> /<N>' gone", "PowerShell"],
    ["rm -rf '<P>../<N>'", "Bash"],
    ["Remove-Item -Recurse -Force '<P>. ./<N>'", "PowerShell"],
  ])("%s: held", (command, tool) => {
    const home = realpathSync(s.home).replace(/\\/g, "/");
    const cut = home.lastIndexOf("/");
    const line = command.replaceAll("<P>", home.slice(0, cut)).replaceAll("<N>", home.slice(cut + 1));
    const r = run(line, tool);
    expect(r.decision, line).toBe("deny");
    expect(r.text).toContain("names the 4da check ledger");
  });

  it("a relative `./` and `../` still read as before", () => {
    expect(run("cat ./README.md ../notes.txt").decision).toBe("allow");
  });
});

describe("7, 8: the header's sentences on files and config, each as written", () => {
  it("a requirements file is read when it is written, and when a command names it (round 25, S2)", () => {
    const req = `${s.project.replace(/\\/g, "/")}/requirements.txt`;
    const w = s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: req, content: "requests==2.5.0\n" } });
    expect(w.decision).toBe("deny");
    // Round 25 (S2): and when a command names it, it is read from disk at the call and judged.
    s.file("requirements.txt", "requests==2.5.0\n");
    expect(run("pip install -r requirements.txt").decision).toBe("deny");
  });

  it("files a later command reads are not read on a Write", () => {
    for (const name of ["constraints.txt", "requirements.in", "package-lock.json"]) {
      const w = s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: `${s.project.replace(/\\/g, "/")}/${name}`, content: "requests==2.5.0\n" } });
      expect(w.decision, name).toBe("allow");
    }
  });

  // Round 25 (S6): a config write is now held (CONFIG_WRITE_VERBS); see the test after this one.
  it.each([
    "npm config set before 2020-01-01 && npm i lodash",
    "pnpm config set registry https://registry.npmjs.org/ && pnpm add lodash",
    "pip config set global.index-url https://pypi.corp.example/simple && pip install requests",
    "poetry source add corp https://pypi.corp.example/simple && poetry add requests",
  ])("a config writer before the install is held (round 25, S6): %s", (command) => {
    expect(run(command).decision).toBe("deny");
    expect(run(command).text).toContain("changes how later installs resolve");
  });
  it.each([
    "HOME=/tmp/other npm i lodash",
    "CARGO_HOME=/tmp/other cargo add serde",
  ])("a config writer or a config-path variable before the install: %s is read as if it were not there", (command) => {
    s.ledger([
      { ecosystem: "npm", package: "lodash", version: "4.17.21", requested: "latest", verdict: "proceed" },
      { ecosystem: "PyPI", package: "requests", version: "2.32.3", requested: "latest", verdict: "proceed" },
      { ecosystem: "Go", package: "rsc.io/quote", version: "v1.5.2", requested: "latest", verdict: "proceed" },
      { ecosystem: "crates.io", package: "serde", version: "1.0.200", requested: "latest", verdict: "proceed" },
    ]);
    expect(run(command).decision, command).toBe("allow");
  });

  it.each(["NPM_CONFIG_USERCONFIG=/tmp/rc npm i lodash", "PIP_CONFIG_FILE=/tmp/pip.conf pip install requests"])("a manager's own setting is held: %s", (command) => {
    expect(run(command).text).toContain("could not be read");
  });
});
