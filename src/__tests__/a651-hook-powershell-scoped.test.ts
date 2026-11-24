// SPDX-License-Identifier: Apache-2.0
/**
 * PowerShell passes a scoped npm spec (`@types/node@20.0.0`) through as written: only a bare
 * `@name` splats a variable, and `@(`, `@{`, `@'`, `@"` open an array, a hashtable or a here-string.
 * Checked on PowerShell 7.5.1 and 5.1.19041: `Write-Output @types/node@20.0.0 @foo/bar@1.0.0`
 * prints both words unchanged, even with `$types` defined (`Write-Output @h/x` prints `@h/x`).
 * The 6.5.1 candidate read any unquoted word starting with `@` as splatting and left the whole
 * command unread, so `npm i @types/node@20.0.0` went ahead from the PowerShell tool (blind review
 * 2026-11-24, item 2).
 */

import { describe, expect, it } from "vitest";

import { installsIn, simpleCommands } from "../../hooks/manifest-edit.mjs";

const names = (command: string) => installsIn(command, "powershell").map((r) => `${r.name}@${r.spec}`);

describe("PowerShell: a scoped package spec is read", () => {
  it.each([
    ["npm i @types/node@20.0.0", ["@types/node@20.0.0"]],
    ["npm i lodash@4.17.20 @types/node@20.0.0", ["lodash@4.17.20", "@types/node@20.0.0"]],
    ["npm i -D @types/node@20.0.0 @typescript-eslint/parser@6.0.0", ["@types/node@20.0.0", "@typescript-eslint/parser@6.0.0"]],
    ["npm install -g @anthropic-ai/claude-code@1.0.0", ["@anthropic-ai/claude-code@1.0.0"]],
    ["pnpm add @tanstack/react-query@5.0.0", ["@tanstack/react-query@5.0.0"]],
  ])("%s", (command, expected) => {
    expect(names(command)).toEqual(expected);
  });

  it("splatting, arrays, hashtables and here-strings still leave the command unread", () => {
    for (const command of ["npm i @args", "npm @splat i lodash@4.17.20", "npm i @(1,2)", "npm i @{a=1}", "npm i @'x'@"]) {
      expect(simpleCommands(command, "powershell"), command).toBeNull();
    }
  });

  it("bash reads the same words as it always did", () => {
    expect(installsIn("npm i @types/node@20.0.0", "bash").map((r) => r.name)).toEqual(["@types/node"]);
  });
});
