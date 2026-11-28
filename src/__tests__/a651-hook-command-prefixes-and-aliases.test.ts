// SPDX-License-Identifier: Apache-2.0
/**
 * Install commands the 6.5.1 candidate's guard let through unread (review of the candidate,
 * 2026-11-24, review-scratch/tools/hookshapes.mjs and hs2.mjs):
 * - command prefixes and shell keywords: `timeout 600 npm install x@1`, `nice -n 5`, `nohup`,
 *   `time -p`, `command -p`, `exec`, `env -i`, `sudo -E`, `! npm i`, `if ..; then ..; fi`,
 *   `for/while ..; do ..; done`, a subshell `( .. )`, a group `{ ..; }`, `xargs npm i x@1`;
 * - npm's own aliases and abbreviations of install (`inst`, `isntall`, `it`, `install-test`, ...,
 *   resolved with the table and the unique-prefix rule of npm 10's lib/utils/cmd-list.js), `bun
 *   install x@1` / `bun i` / `bun a`, `yarn workspace <name> add`, `yarn workspaces foreach .. add`,
 *   `pnpx`, `pnpm -c exec '..'` and pnpm's shell mode;
 * - a runner's `--registry` naming the public registry (`npx --registry https://registry.npmjs.org
 *   pnpm add x@1`), and an install's own `--registry` naming it;
 * - PowerShell: `pwsh -Command "& {npm i x@1}"`, `& "C:\Program Files\nodejs\npm.cmd" i x@1`
 *   (a backslash inside double quotes is no escape there), `-CommandWithArgs` / `-cwa`;
 * - `eval '...'`, read like `bash -c`.
 * A global install (`npm i -g`, `pnpm add -g`, `bun add -g`) names its version and is read and
 * checked like any other; the README now says so. Controls: harmless commands stay unread.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { installsIn } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const LODASH = [{ ecosystem: "npm", name: "lodash", spec: "4.17.20" }];

describe("command prefixes and shell keywords", () => {
  it.each([
    "timeout 600 npm install lodash@4.17.20",
    "timeout -k 5 --preserve-status 10m npm install lodash@4.17.20",
    "nice -n 5 npm install lodash@4.17.20",
    "nice -5 npm install lodash@4.17.20",
    "nice npm install lodash@4.17.20",
    "nohup npm install lodash@4.17.20",
    "time npm install lodash@4.17.20",
    "time -p npm install lodash@4.17.20",
    "command npm install lodash@4.17.20",
    "command -p npm install lodash@4.17.20",
    "exec npm i lodash@4.17.20",
    "env VAR=1 npm i lodash@4.17.20",
    "env -i npm i lodash@4.17.20",
    "env -u HOME npm i lodash@4.17.20",
    "sudo -E npm i lodash@4.17.20",
    "sudo -u build npm i lodash@4.17.20",
    "! npm i lodash@4.17.20",
    "if true; then npm i lodash@4.17.20; fi",
    "if test -f package.json; then echo yes; else npm i lodash@4.17.20; fi",
    "for d in a; do npm i lodash@4.17.20; done",
    "while false; do npm i lodash@4.17.20; done",
    "until true; do npm i lodash@4.17.20; done",
    "( npm i lodash@4.17.20 )",
    "(cd app && npm i lodash@4.17.20)",
    "{ npm i lodash@4.17.20; }",
    "xargs -n1 npm i lodash@4.17.20",
    "xargs -I{} npm i lodash@4.17.20",
    "eval 'npm i lodash@4.17.20'",
    'eval "npm i lodash@4.17.20"',
    "timeout 600 bash -c 'npm i lodash@4.17.20'",
  ])("%s", (command) => {
    expect(installsIn(command, "bash")).toEqual(LODASH);
  });
});

describe("package-manager aliases, runners and subcommand prefixes", () => {
  it.each([
    // npm 10 lib/utils/cmd-list.js: aliases of install and install-test, and unique prefixes of them.
    "npm in lodash@4.17.20",
    "npm ins lodash@4.17.20",
    "npm inst lodash@4.17.20",
    "npm insta lodash@4.17.20",
    "npm instal lodash@4.17.20",
    "npm isnt lodash@4.17.20",
    "npm isnta lodash@4.17.20",
    "npm isntal lodash@4.17.20",
    "npm isntall lodash@4.17.20",
    "npm add lodash@4.17.20",
    "npm it lodash@4.17.20",
    "npm install-test lodash@4.17.20",
    "npm install-t lodash@4.17.20",
    "npm installTest lodash@4.17.20",
    "bun install lodash@4.17.20",
    "bun i lodash@4.17.20",
    "bun a lodash@4.17.20",
    "yarn workspace app add lodash@4.17.20",
    "yarn workspaces foreach -A add lodash@4.17.20",
    "yarn workspaces foreach --all -j 4 --include 'pkg-*' add lodash@4.17.20",
    "pnpx pnpm add lodash@4.17.20",
    "pnpm -c exec 'npm i lodash@4.17.20'",
    "pnpm --shell-mode exec 'npm i lodash@4.17.20'",
    "pnpm exec -c 'npm i lodash@4.17.20'",
    "pnpm exec --shell-mode 'npm i lodash@4.17.20'",
    "npm exe -- npm i lodash@4.17.20",
    "npx --registry https://registry.npmjs.org pnpm add lodash@4.17.20",
    "npx --registry=https://registry.npmjs.org/ pnpm add lodash@4.17.20",
    "npm i lodash@4.17.20 --registry=https://registry.npmjs.org/",
    "pnpm add lodash@4.17.20 --registry https://registry.npmjs.org",
  ])("%s", (command) => {
    expect(installsIn(command, "bash")).toEqual(LODASH);
  });

  it("global installs name their version and are read (checked) like any other", () => {
    for (const command of ["npm i -g lodash@4.17.20", "npm install --global lodash@4.17.20", "pnpm add -g lodash@4.17.20", "bun add -g lodash@4.17.20"]) {
      expect([command, installsIn(command, "bash")]).toEqual([command, LODASH]);
    }
  });
});

describe("PowerShell", () => {
  it.each([
    'pwsh -Command "& {npm i lodash@4.17.20}"',
    "pwsh -Command '& { npm i lodash@4.17.20 }'",
    '& "C:\\Program Files\\nodejs\\npm.cmd" i lodash@4.17.20',
    'pwsh -cwa "npm i lodash@4.17.20"',
    "pwsh -CommandWithArgs 'npm i lodash@4.17.20'",
    "& { npm i lodash@4.17.20 }",
  ])("%s", (command) => {
    expect(installsIn(command, "powershell")).toEqual(LODASH);
  });
});

describe("left unread on purpose", () => {
  it.each([
    // npm ci and install-ci-test install the lockfile, never a name given on the command line.
    "npm cit lodash@4.17.20",
    "npm install-ci-test lodash@4.17.20",
    "npm ci",
    // A registry other than the public one: the package is not the public one the hook can name.
    "npm i lodash@4.17.20 --registry=https://npm.internal.example/",
    "npx --registry https://npm.internal.example pnpm add lodash@4.17.20",
    // What xargs reads from its input is not on the command line.
    "echo lodash@4.17.20 | xargs npm i",
  ])("%s", (command) => {
    expect(installsIn(command, "bash")).toEqual([]);
  });
});

describe("controls: harmless commands are not read as installs", () => {
  it.each([
    "npm run build",
    "npm test",
    "npm t",
    "npm install",
    "npm it",
    "npm --version",
    'git commit -m "npm install lodash@4.17.20"',
    "echo npm i lodash@4.17.20",
    "if npm test; then echo ok; fi",
    "( npm run build )",
    "{ npm run lint; }",
    "time npm test",
    "timeout 60 npm test",
    "nice npm run lint",
    "nohup npm start",
    "exec bash",
    'eval "echo npm i lodash@4.17.20"',
    "xargs echo npm i lodash@4.17.20",
    "bun run build",
    "bun install",
    "yarn workspace app run build",
    "yarn workspaces foreach -A run build",
    "pnpm -c exec 'echo npm i lodash@4.17.20'",
    "arr=(npm i lodash@4.17.20)",
    "f() { npm i lodash@4.17.20; }",
    "npm view lodash@4.17.20",
    // (round 26, R2: `npx lodash@4.17.20` fetches that release: judged, a1125-w2-hook-round26)
  ])("%s", (command) => {
    expect(installsIn(command, "bash")).toEqual([]);
  });

  it.each(['pwsh -Command "& {npm run build}"', "& { Write-Output 'npm i lodash@4.17.20' }", 'Write-Output "npm i lodash@4.17.20"'])("powershell: %s", (command) => {
    expect(installsIn(command, "powershell")).toEqual([]);
  });
});

describe("further shapes from the review's table that can be read exactly", () => {
  it.each([
    ["fish -c 'npm i lodash@4.17.20'", "bash"],
    ["busybox sh -c 'npm i lodash@4.17.20'", "bash"],
    ["wsl npm i lodash@4.17.20", "bash"],
    ["wsl -d Ubuntu -e bash -c 'npm i lodash@4.17.20'", "bash"],
    ["Invoke-Expression 'npm i lodash@4.17.20'", "powershell"],
    ["iex 'npm i lodash@4.17.20'", "powershell"],
  ])("%s", (command, dialect) => {
    expect(installsIn(command, dialect as "bash" | "powershell")).toEqual(LODASH);
  });

  it("cargo with a toolchain named first", () => {
    expect(installsIn("cargo +nightly add serde@1.0.100", "bash")).toEqual([{ ecosystem: "crates.io", name: "serde", spec: "1.0.100" }]);
  });

  it("iex in bash is Elixir's shell, not PowerShell's Invoke-Expression", () => {
    expect(installsIn("iex 'npm i lodash@4.17.20'", "bash")).toEqual([]);
  });
});

describe("run as Claude Code runs the hook", () => {
  let s: Sandbox;
  beforeEach(() => {
    s = sandbox();
  });
  afterEach(() => s.dispose());
  const bash = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });

  it("a newly read shape is denied with the call", () => {
    const r = bash("timeout 600 npm isntall lodash@4.17.20");
    expect(r.decision).toBe("deny");
    expect(r.items).toEqual([{ ecosystem: "npm", package: "lodash", to: "4.17.20" }]);
  });

  it.each(["npm run build", "npm test", 'git commit -m "npm install lodash@4.17.20"', "echo npm i lodash@4.17.20", "( npm run build )", "timeout 60 npm test"])("harmless, allowed: %s", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});
