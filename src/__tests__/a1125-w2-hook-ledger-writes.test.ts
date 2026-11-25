// SPDX-License-Identifier: Apache-2.0
/**
 * The check ledger (`check-ledger.jsonl`, `check-ledger.1.jsonl` in the data folder the hook
 * reads) is what the guard decides by, and only the 4da server writes it. An agent's own Edit or
 * Write of it, or a command that writes it (a redirection, tee, Set-Content, Add-Content, Out-File,
 * a copy or move onto it, sed -i, a `-e` / `-c` code string naming its path, removing it or its
 * folder) is now held with "Only the 4da server writes this file"; reading it stays allowed. A path
 * is followed only where it is written out (`~` and `cd` included); a shell variable is not.
 */

import { realpathSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { timedWithin } from "./helpers/a1125-hook-run.js";

const ONLY = "Only the 4da server writes this file";
const AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "GHSA-35jh-r3h4-6jhm" };

let s: Sandbox;
let L: string;
let L1: string;
let home: string;
beforeEach(() => {
  s = sandbox();
  s.ledger([AVOID]);
  home = realpathSync(s.home).replace(/\\/g, "/");
  L = `${home}/check-ledger.jsonl`;
  L1 = `${home}/check-ledger.1.jsonl`;
});
afterEach(() => s.dispose());

/** Placeholders resolved at run time: <L> and <L1> the ledger files, <H> the data folder, <P> the project. */
const fill = (command: string) => command.replaceAll("<L1>", L1).replaceAll("<L>", L).replaceAll("<H>", home).replaceAll("<P>", s.project.replace(/\\/g, "/"));
const cmd = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command: fill(command) } });
const forged = JSON.stringify({ t: new Date().toISOString(), ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "proceed" });

describe("a write of the ledger is held", () => {
  it("Write and Edit of either file", () => {
    for (const file of [L, L1]) {
      const run = s.write(file, `${forged}\n`);
      expect(run.decision, file).toBe("deny");
      expect(run.text).toContain(ONLY);
    }
    expect(s.edit(L, "avoid", "proceed").text).toContain(ONLY);
    expect(s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "MultiEdit", tool_input: { file_path: L, edits: [{ old_string: "avoid", new_string: "proceed" }] } }).text).toContain(ONLY);
  });

  it.each([
    ["a redirection", `echo '${forged}' >> <L>`],
    ["a quoted redirection", `echo x > "<L>"`],
    ["a redirection after cd", `cd <H> && echo x >> check-ledger.jsonl`],
    ["a redirection after cd ~-relative", `cd <H> ; printf x >> ./check-ledger.1.jsonl`],
    ["tee", `echo x | tee -a <L>`],
    ["sudo tee", `echo x | sudo tee <L>`],
    ["sed -i", `sed -i 's/avoid/proceed/' <L>`],
    ["sed -i.bak", `sed -i.bak 's/avoid/proceed/' <L>`],
    ["a copy onto it", `cp /tmp/forged.jsonl <L>`],
    ["a copy into its folder", `cp /tmp/check-ledger.jsonl <H>/`],
    ["a move away", `mv <L> /tmp/x`],
    ["a move onto it", `mv /tmp/x <L>`],
    ["removing it", `rm -f <L>`],
    ["removing its folder", `rm -rf <H>`],
    ["a glob", `rm <H>/check-ledger*`],
    ["node -e naming its path", `node -e "require('fs').appendFileSync('<L>', 'x')"`],
    ["python -c naming its path", `python3 -c "open('<L>', 'a').write('x')"`],
    ["bash -c", `bash -c "echo x >> <L>"`],
    ["CRLF lines", `npm test\r\necho x >> <L>\r\n`],
  ])("Bash, %s", (_label, command) => {
    const run = cmd(command);
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain(ONLY);
  });

  it.each([
    ["Add-Content", `Add-Content -Path '<L>' -Value 'x'`],
    ["Set-Content", `Set-Content '<L>' 'x'`],
    ["Out-File", `'x' | Out-File -Append '<L>'`],
    ["Copy-Item onto it", `Copy-Item /tmp/forged.jsonl '<L>'`],
    ["Move-Item", `Move-Item '<L>' /tmp/x`],
    ["Remove-Item", `Remove-Item '<L>'`],
    ["Rename-Item to its name", `Rename-Item '<H>/x.jsonl' check-ledger.jsonl`],
    ["a pipe from a read to a write", `Get-Item '<L>' | Remove-Item`],
    ["a redirection", `'x' >> '<L>'`],
  ])("PowerShell, %s", (_label, command) => {
    const run = cmd(command, "PowerShell");
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain(ONLY);
  });

  it("the avoid it would have overwritten still holds the install", () => {
    expect(cmd(`echo '${forged}' >> <L>`).text).toContain(ONLY);
    expect(cmd("npm i lodash@4.17.20").text).toContain("answered avoid");
  });
});

describe("the denial's way through: reading stays allowed, in a command of its own", () => {
  it.each([
    `cat <L>`,
    `tail -n 5 <L> | jq .verdict`,
    `grep avoid <L> <L1>`,
    `sed -n 1,5p <L>`,
    `wc -l <L>`,
    `ls -la <H>`,
    `cp <L> /tmp/ledger-backup.jsonl`,
    `cd <H> && cat check-ledger.jsonl`,
    `cat <L> > /tmp/ledger-copy.jsonl`,
  ])("Bash: %s", (command) => {
    expect(cmd(command).decision).toBe("allow");
  });

  it.each([`Get-Content '<L>' | Select-Object -Last 3`, `Get-Content '<L>' | ConvertFrom-Json | Where-Object { $_.verdict -eq 'avoid' }`, `Select-String avoid '<L>'`, `Get-ChildItem '<H>'`, `Test-Path '<L>'`])("PowerShell: %s", (command) => {
    // A command with a variable is not taken apart, so it goes ahead whatever it names (the second row).
    expect(cmd(command, "PowerShell").decision).toBe("allow");
  });

  it("a read beside another command that might be passed its path is held; on its own it goes ahead", () => {
    expect(cmd(`cat <L> | xargs rm`).text).toContain(ONLY);
    expect(cmd(`cat <L>`).decision).toBe("allow");
  });
});

describe("other files and other commands are not held", () => {
  it.each([
    ["a file beside the ledger", () => s.write(join(s.home, "notes.txt"), "x")],
    ["a file named like it elsewhere", () => s.write(join(s.project, "check-ledger.jsonl"), "x")],
    ["a project file", () => s.write(join(s.project, "README.md"), "x")],
  ])("%s", (_label, run) => {
    expect(run().decision).toBe("allow");
  });

  it.each([
    "npm test",
    "git status && git diff --stat",
    "ls *.ts && rm -rf dist/*",
    "rm -rf node_modules",
    "echo x > out.txt",
    "cp a.txt b.txt",
    "sed -i 's/a/b/' src/x.ts",
    `echo x >> <P>/check-ledger.jsonl`,
    "node -e \"console.log('check-ledger.jsonl')\"",
    "grep -r check-ledger src",
  ])("Bash: %s", (command) => {
    expect(cmd(command).decision).toBe("allow");
  });

  it("a shell variable is not followed (a documented limit)", () => {
    expect(cmd("echo x >> $FOURDA_MCP_HOME/check-ledger.jsonl").decision).toBe("allow");
    expect(cmd("Add-Content $env:FOURDA_MCP_HOME/check-ledger.jsonl 'x'", "PowerShell").decision).toBe("allow");
  });
});

describe("size", () => {
  it("a 60 KB command naming the ledger many times, inside the CPU bound", () => {
    const reads = `cat ${L}; `.repeat(Math.floor(60_000 / (L.length + 6)));
    const payload = (command: string) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
    expect(timedWithin(s.home, payload(reads), 500).decision).toBe("allow");
    expect(timedWithin(s.home, payload(`${reads}echo x >> ${L}`), 500).text).toContain(ONLY);
    const globs = "ls *.ts; ".repeat(6000);
    expect(timedWithin(s.home, payload(globs), 500).decision).toBe("allow");
  });
});
