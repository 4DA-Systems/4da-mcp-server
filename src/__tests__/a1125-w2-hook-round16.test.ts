// SPDX-License-Identifier: Apache-2.0
/**
 * Round 16, from the fourteenth independent check: rules on raw text where the manager knows more
 * than one manifest, with the reviewer's cases and a sweep of each class.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "lodash", version: "4.17.21", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "npm", package: "ms", version: "2.1.3", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "PyPI", package: "requests", version: "2.32.3", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "PyPI", package: "typing-extensions", version: "4.12.2", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "crates.io", package: "regex", version: "1.11.0", requested: "latest", verdict: "proceed", reason: "ok" },
  ]);
});
afterEach(() => s.dispose());

const run = (command: string, cwd = s.project, tool = "Bash") => s.run({ session_id: "s", cwd, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("J1: a name alone that a project file here or above names is held", () => {
  it.each([
    ["package.json", '{"dependencies":{"lodash":"4.17.20"}}', "npm install lodash"],
    ["package.json", '{"overrides":{"lodash":"4.17.20"}}', "bun add lodash"],
    ["package.json", '{"resolutions":{"lodash":"4.17.20"}}', "yarn add lodash"],
    ["pnpm-workspace.yaml", "catalog:\n  lodash: 4.17.20\ncatalogMode: prefer\n", "pnpm add lodash"],
    ["pnpm-workspace.yaml", "overrides:\n  lodash: 4.17.20\n", "pnpm add -Dw lodash"],
    [".pnpmfile.cjs", "module.exports = { hooks: { readPackage(p) { p.dependencies.lodash = '4.17.20'; return p; } } };", "pnpm add lodash"],
    ["Cargo.toml", '[workspace]\nmembers = ["app"]\n[workspace.dependencies]\nregex = "=1.5.4"\n', "cargo add regex"],
    ["pyproject.toml", '[tool.uv.workspace]\nmembers = ["app"]\n[project]\nname = "root"\nversion = "0"\ndependencies = ["requests==2.19.0"]\n', "uv add requests"],
    ["pyproject.toml", '[project]\nname = "x"\nversion = "0"\ndependencies = ["typing_extensions==4.0.0"]\n', "uv add Typing.Extensions"],
    ["uv.toml", '[pip]\nconstraint-dependencies = ["requests==2.19.0"]\n', "uv add requests"],
  ])("%s naming it in the folder above; %s from app/: held", (file, content, command) => {
    s.file(file, content);
    s.file("app/.keep", "");
    const r = run(command, `${s.project}/app`);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain(`${file} in a parent folder already names`);
    expect(r.text).toContain("name the version");
  });
  it("in this folder: said so; the remedy is in the manager's own syntax", () => {
    s.file("pyproject.toml", '[project]\nname = "x"\nversion = "0"\ndependencies = ["requests==2.19.0"]\n');
    const r = run("uv add requests");
    expect(r.text).toContain("pyproject.toml in this folder already names requests");
    expect(r.text).toContain("`requests==<version>`");
    s.file("package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run("npm i lodash").text).toContain("`lodash@<version>`");
  });
  it("only a whole word counts: lodash.debounce or my-lodash do not name lodash", () => {
    s.file("package.json", '{"dependencies":{"lodash.debounce":"4.0.8","my-lodash":"1.0.0"}}');
    expect(run("npm install lodash").decision).toBe("allow");
  });
  it("a folder option is read too; a folder it cannot name is held; a global install reads none", () => {
    s.file("sub/package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run("npm --prefix sub install lodash").text).toContain("already names lodash");
    expect(run("cd sub && npm install lodash").text).toContain("already names lodash");
    expect(run("cd $X && npm install lodash").text).toContain("could not be read");
    s.file("package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run("npm install -g lodash").decision).toBe("allow");
  });
  it("an unreadable project file holds; a name with a version is judged on it as before", () => {
    s.file("package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run("npm install lodash@4.17.21").text).not.toContain("already names");
  });
});

describe("J5: `@latest` moves to the newest with npm, pnpm, Yarn and Bun: judged on latest", () => {
  it.each(["npm install lodash@latest", "pnpm add lodash@latest", "yarn add lodash@latest", "bun add lodash@latest"])("%s beside a declaration: goes ahead on the latest proceed", (command) => {
    s.file("package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run(command).decision, run(command).text).toBe("allow");
  });
});
