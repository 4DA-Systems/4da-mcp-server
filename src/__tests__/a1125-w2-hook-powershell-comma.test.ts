// SPDX-License-Identifier: Apache-2.0
/**
 * PowerShell: a bare comma (an array) or the stop-parsing token `--%` made the whole command unread,
 * and it went ahead, so `npm i lodash@4.17.20; Get-Content package.json | ConvertFrom-Json |
 * Select-Object name, version` installed a version with an `avoid` on record (audit 2026-11-25, D
 * minors; a 6.5.2 Known limit). PowerShell passes an array to a program differently by version
 * (7.5.1: `a@1,b@2` as one argument, `a@1, b@2` as "a@1," and "b@2"; 5.1: `a@1, b@2` as two), so
 * the hook does not read such a command. Now only that simple command is left unread: when the
 * quick look sees an install in it, the call is held as not read, saying which part and to run the
 * install as a command of its own; otherwise it installs nothing and the rest of the line is read.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { simpleCommands } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { record, timedWithin } from "./helpers/a1125-hook-run.js";

const AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "GHSA-35jh-r3h4-6jhm" };
const REMEDY = "Run the install as a command of its own, each package a separate argument, with no comma and no --%";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  // Round 25 (S2): a requirements or constraints file a command names is read at the call: these exist, empty.
  for (const f of ["requirements.txt", "requirements-dev.txt", "constraints.txt", "c.txt", "o.txt", "req.txt"]) s.file(f, "");
});
afterEach(() => s.dispose());

const ps = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "PowerShell", tool_input: { command } });

describe("an install beside a comma or --% is held", () => {
  it("the audit's row: the install is read, the Select-Object after it is not needed", () => {
    s.ledger([AVOID]);
    const run = ps("npm i lodash@4.17.20; Get-Content package.json | ConvertFrom-Json | Select-Object name, version");
    expect(run.decision).toBe("deny");
    expect(run.text).toContain('"lodash" "4.17.20" (npm): dependency_check answered avoid');
  });

  it.each([
    ["a comma list", "npm i lodash@4.17.20,ms@2.0.0", "a comma outside quotes"],
    ["a comma and a blank", "npm i lodash@4.17.20, ms@2.0.0", "a comma outside quotes"],
    ["pnpm", "pnpm add lodash@4.17.20,ms@2.0.0", "a comma outside quotes"],
    ["pip", "pip install requests==2.19.0,idna==3.7", "a comma outside quotes"],
    ["in a script block", "& { npm i lodash@4.17.20,ms@2.0.0 }", "a comma outside quotes"],
    ["beside a variable later on the line", "npm i lodash@4.17.20,ms@2.0.0; Write-Output $x", "a comma outside quotes"],
    ["--% before the subcommand", "npm --% i lodash@4.17.20", "the stop-parsing token --%"],
    ["--% after it", "npm i --% lodash@4.17.20", "the stop-parsing token --%"],
    ["CRLF lines", "Write-Output a\r\nnpm i lodash@4.17.20,ms@2.0.0\r\n", "a comma outside quotes"],
  ])("%s: held as not read, naming the part and the way through", (_label, command, part) => {
    s.ledger([AVOID]);
    const run = ps(command);
    expect(run.decision).toBe("deny");
    expect(run.text).toContain(`could not be read (${part} in a PowerShell command that installs)`);
    expect(run.text).toContain(REMEDY);
  });

  it("--% ends at a pipe: an install after a pipe is read; one after a ; is a word of the --% command in PowerShell 7.5.1 and 5.1, held anyway (the stricter reading)", () => {
    s.ledger([AVOID]);
    expect(ps("Write-Output a | node --% x | npm i lodash@4.17.20").text).toContain("answered avoid");
    expect(ps("Write-Output --% x; npm i lodash@4.17.20").text).toContain("could not be read (the stop-parsing token --%");
    expect(ps("node --% x; npm i lodash@4.17.20").text).toContain("could not be read (the stop-parsing token --%");
    expect(ps("Get-ChildItem --% /s *.ts").decision).toBe("allow");
  });

  it("the command reader decides what installs: an option's value with a comma, a lint list, and quoting are not held", () => {
    s.ledger([AVOID]);
    for (const c of ["yarn workspace web lint --ext .ts,.tsx", "pip install -r requirements.txt --only-binary=:all:,numpy", "uv pip install -r requirements.txt --exclude a,b", "npm run lint -- --ext .ts,.tsx", "pnpm --filter web,api build"]) {
      expect(ps(c).decision, c).toBe("allow");
    }
    expect(ps("pip install requests==2.31.0,idna==3.7").text).toContain("put in quotes");
    expect(ps("pwsh -NoProfile -Command \"pip --% install requests==2.19.0\"").decision).toBe("deny");
  });

  it("following the remedy literally releases it", () => {
    s.ledger([]);
    expect(ps("npm i lodash@4.17.21,ms@2.0.0").text).toContain(REMEDY);
    expect(ps("npm --% i lodash@4.17.21").text).toContain(REMEDY);
    // The install as its own command, each package a separate argument: read, and judged by the ledger.
    const plain = ps("npm i lodash@4.17.21 ms@2.0.0");
    expect(plain.items).toEqual([
      { ecosystem: "npm", package: "lodash", to: "4.17.21" },
      { ecosystem: "npm", package: "ms", to: "2.0.0" },
    ]);
    record(s, [
      { ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed" },
      { ecosystem: "npm", package: "ms", version: "2.0.0", verdict: "review" },
    ]);
    expect(ps("npm i lodash@4.17.21 ms@2.0.0").decision).toBe("allow");
    expect(ps("npm i lodash@4.17.21").decision).toBe("allow");
    expect(ps("npm i lodash@4.17.21; Get-Content package.json | ConvertFrom-Json | Select-Object name, version").decision).toBe("allow");
  });

  it("the tokenizer still gives no words for an install it cannot read", () => {
    for (const line of ["npm i a,b", "npm --% i x"]) expect(simpleCommands(line, "powershell"), line).toBeNull();
  });
});

/** Ordinary PowerShell that installs nothing: commas everywhere, and none of it may be held. */
const ORDINARY = [
  "Get-Content package.json | ConvertFrom-Json | Select-Object name, version",
  "Select-Object -Property Name, Length",
  "Get-ChildItem -Include *.ts, *.js -Recurse",
  "Get-ChildItem src -Recurse -Include *.tsx, *.ts | Measure-Object",
  "Get-ChildItem -Path src, test -Filter *.ts",
  "Write-Output a, b, c",
  "Write-Output npm, install, lodash@4.17.20",
  "echo npm install a,b",
  "Write-Host \"npm install a,b\"",
  "Write-Output \"a, b\", \"c\"",
  "$a = 1, 2, 3",
  "git commit -m \"fix: lint, format, npm install docs\"",
  "git commit -m 'bump deps, then npm install lodash@4.17.20 later'",
  "git log --format=%h,%s -5",
  "git add a.ts, b.ts",
  "Get-Process | Sort-Object CPU, Id -Descending | Select-Object -First 5",
  "Format-Table Name, Version -AutoSize",
  "Copy-Item a.txt, b.txt -Destination out",
  "Remove-Item tmp1, tmp2 -Recurse -Force",
  "Test-Path a, b",
  "New-Item -ItemType Directory -Force out, dist",
  "Get-Item a, b | Select-Object FullName",
  "Get-Content log.txt -Tail 10 | Select-String error, warning",
  "Get-ChildItem | Select-Object Name, @{n='Size';e={$_.Length}}",
  "Get-ChildItem | Where-Object { $_.Extension -in '.ts', '.js' }",
  "npm run build -- --env a,b",
  "npm test -- --reporters=default,junit",
  "npm ci; Get-ChildItem *.ts, *.js",
  "npm install; Get-ChildItem *.ts, *.js",
  "pnpm run lint --filter a,b",
  "npx tsc --lib es2020,dom",
  "node -e \"console.log(1)\" a,b",
  "cargo build --features a,b",
  "cargo test --features x,y --no-run",
  "go test -run TestA,TestB ./...",
  "go build -tags a,b ./...",
  "dotnet build -p:A=1,B=2",
  "python -c \"print(1, 2)\" ; Write-Output x, y",
  "pip list --format=columns; Select-Object a, b",
  "Get-Help Install-Module, Install-Package",
  "Get-Date -Format \"yyyy, MM\"",
  "Select-Object name, version | Out-File npm-install.txt",
  "Rename-Item a.txt b.txt; Get-ChildItem a, b",
  "Get-ChildItem --% /s *.ts",
  "cmd /c --% dir /b a,b",
  "Write-Output a,\r\nb",
];

describe(`${ORDINARY.length} ordinary PowerShell commands that install nothing go ahead, with an avoid on record`, () => {
  it.each(ORDINARY.map((c) => [c]))("%s", (command) => {
    s.ledger([AVOID]);
    expect(ps(command).decision).toBe("allow");
  });
});

describe("size", () => {
  it("60 KB of comma commands: an install among them is read, inside the CPU bound", () => {
    s.ledger([AVOID]);
    const filler = "Select-Object a, b; ".repeat(3000);
    expect(filler.length).toBeGreaterThan(59_000);
    const payload = (command: string) => ({ hook_event_name: "PreToolUse", tool_name: "PowerShell", tool_input: { command } });
    expect(timedWithin(s.home, payload(`${filler}npm i lodash@4.17.20`), 500).text).toContain("answered avoid");
    expect(timedWithin(s.home, payload(`${filler}Write-Output done`), 500).decision).toBe("allow");
    const long = timedWithin(s.home, payload(`npm i ${"a,".repeat(30_000)}lodash@4.17.20`), 500);
    expect(long.text).toContain("could not be read (a comma outside quotes");
  });
});
