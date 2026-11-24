// SPDX-License-Identifier: Apache-2.0
/**
 * Install commands the guard did not read in 6.5.0 (blind check 2, SF8): a command run through a
 * shell's `-c` (`bash -c "npm install x@1"`, `sh -c`, `bash -lc`, `pwsh -Command`), a package
 * manager started through a runner (`npx pnpm add`, `npx -y pnpm@9 add`, `npm exec`, `bunx`,
 * `pnpm dlx`, `yarn dlx`, `corepack pnpm@9 add`), `pnpm up|update` and `yarn up|upgrade` with an
 * explicit version, and `python -u -m pip install`. Each went ahead unchecked. The inner command is
 * read with the same reader, at most three wrappers deep.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { installsIn } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const LODASH = [{ ecosystem: "npm", name: "lodash", spec: "4.17.20" }];

describe("commands run through a shell or a runner are read", () => {
  it.each([
    'bash -c "npm install lodash@4.17.20"',
    "sh -c 'npm install lodash@4.17.20'",
    'zsh -c "cd web && npm install lodash@4.17.20"',
    'bash -lc "npm install lodash@4.17.20"',
    'bash -e -c "npm install lodash@4.17.20"',
    '/bin/bash -o pipefail -c "npm install lodash@4.17.20 | tail -3"',
    "npx pnpm add lodash@4.17.20",
    "npx -y pnpm@9 add lodash@4.17.20",
    "npx --yes pnpm@9.15.0 add -D lodash@4.17.20",
    "npx -p pnpm@9 pnpm add lodash@4.17.20",
    "npx yarn add lodash@4.17.20",
    "npx -c 'npm install lodash@4.17.20'",
    "npm exec -- pnpm add lodash@4.17.20",
    "npm x -y pnpm add lodash@4.17.20",
    "bunx pnpm add lodash@4.17.20",
    "pnpm dlx pnpm@9 add lodash@4.17.20",
    "yarn dlx pnpm add lodash@4.17.20",
    "corepack pnpm@9.15.0 add lodash@4.17.20",
    "pnpm up lodash@4.17.20",
    "pnpm update -r --depth 2 lodash@4.17.20",
    "yarn up lodash@4.17.20",
    "yarn upgrade lodash@4.17.20",
    'bash -c "npx -y pnpm add lodash@4.17.20"',
  ])("%s", (command) => {
    expect(installsIn(command, "bash")).toEqual(LODASH);
  });

  it("python's own options before -m pip", () => {
    expect(installsIn("python -u -m pip install requests==2.31.0", "bash")).toEqual([{ ecosystem: "PyPI", name: "requests", spec: "==2.31.0" }]);
    expect(installsIn("python3 -B -X utf8 -m pip install requests==2.31.0", "bash")).toEqual([{ ecosystem: "PyPI", name: "requests", spec: "==2.31.0" }]);
  });

  it("PowerShell -Command, from either tool", () => {
    expect(installsIn('pwsh -NoProfile -Command "npm install lodash@4.17.20"', "bash")).toEqual(LODASH);
    expect(installsIn("powershell.exe -NoLogo -ExecutionPolicy Bypass -Command npm install lodash@4.17.20", "powershell")).toEqual(LODASH);
  });

  it("denied as the same command is, with the call", () => {
    const r = s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: 'bash -c "npx -y pnpm@9 add lodash@4.17.20"' } });
    expect(r.decision).toBe("deny");
    expect(r.items).toEqual([{ ecosystem: "npm", package: "lodash", to: "4.17.20" }]);
  });

  it.each([
    // A script, not a command string; a shell reading stdin; a command the reader cannot take apart.
    "bash install.sh",
    "bash -c",
    "bash -s < script.sh",
    'bash -c "npm install lodash@$V"',
    "npx create-react-app my-app",
    "npx -y @4da/mcp-server@6.5.0 --doctor",
    "npx pnpm install",
    "npx pnpm add lodash",
    "pnpm up",
    "pnpm update lodash",
    "pnpm dlx create-vite my-app",
    "python -c 'import pip' -m pip install requests==2.31.0",
    "pwsh -File build.ps1",
    // Global tools, not this project's dependencies: left alone, as before.
    "cargo install ripgrep@14.1.1",
    "yarn global add typescript@5.6.3",
    "go install golang.org/x/tools/gopls@v0.16.2",
  ])("not read, so allowed without comment: %s", (command) => {
    expect(installsIn(command, "bash")).toEqual([]);
  });

  it("wrappers nest at most three deep", () => {
    expect(installsIn(`bash -c "sh -c 'npx pnpm add lodash@4.17.20'"`, "bash")).toEqual(LODASH);
    const deep = (n: number) => `${"npx ".repeat(n)}pnpm add lodash@4.17.20`;
    expect(installsIn(deep(3), "bash")).toEqual(LODASH);
    expect(installsIn(deep(4), "bash")).toEqual([]);
  });
});
