// SPDX-License-Identifier: Apache-2.0
/**
 * The check ledger (`check-ledger.jsonl`, `check-ledger.1.jsonl` in the data folder the hook reads)
 * decides what may be installed, and only the 4da server writes it. Round 6 read shell text for the
 * ways a command can write a file; its independent check got 38 of 88 writes through, 9 of them
 * end to end. Round 7 reads no shell for this: a call that NAMES the ledger (its file name or the
 * data folder's path, in the call's raw text, case folded, whatever its size) is held unless it is
 * plainly a read: one plain `cat` / `head` / `tail` / `less` / `more` / `wc` / `type` /
 * `Get-Content` / `ls` / `dir` / `Get-ChildItem` / `du` command with nothing else on the line.
 * An Edit / MultiEdit / Write of a path that names it or reaches the data folder is always held.
 */

import { mkdirSync, realpathSync, symlinkSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { timedWithin } from "./helpers/a1125-hook-run.js";

const NAMES = "it names the 4da check ledger";
const EDIT = "it writes in the 4da data folder";
const AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "GHSA-35jh-r3h4-6jhm" };

let s: Sandbox;
let L: string;
let L1: string;
let home: string;
let HB: string;
beforeEach(() => {
  s = sandbox();
  s.ledger([AVOID]);
  home = realpathSync(s.home).replace(/\\/g, "/");
  HB = home.replace(/\//g, "\\");
  L = `${home}/check-ledger.jsonl`;
  L1 = `${home}/check-ledger.1.jsonl`;
});
afterEach(() => s.dispose());

/** Placeholders resolved at run time: <L> <L1> the ledger files, <H> the data folder, <HB> it with backslashes, <LB> the ledger with backslashes. */
const fill = (command: string) =>
  command.replaceAll("<L1>", L1).replaceAll("<LB>", `${HB}\\check-ledger.jsonl`).replaceAll("<L>", L).replaceAll("<HB>", HB).replaceAll("<H>", home).replaceAll("<F>", forged());
const cmd = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command: fill(command) } });
const tool = (name: string, input: Record<string, unknown>) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: name, tool_input: input });
const forged = () => JSON.stringify({ t: new Date().toISOString(), ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "proceed" });
const msys = (p: string) => (/^[A-Za-z]:/.test(p) ? `/${p[0].toLowerCase()}${p.slice(2)}` : p);

describe("a command that names the ledger is held unless it is plainly a read", () => {
  it.each([
    ["the independent check's 9 end-to-end forgeries: Add-Content with a comma", "Add-Content -Path <LB> -Value '<F>', ''", "PowerShell"],
    ["Remove-Item a, b", "Remove-Item <LB>, <HB>\\check-ledger.1.jsonl -ErrorAction SilentlyContinue", "PowerShell"],
    ["Remove-Item -Confirm:$false", "Remove-Item <LB> -Confirm:$false", "PowerShell"],
    ["if (Test-Path) { Add-Content }", "if (Test-Path <LB>) { Add-Content <LB> '<F>' }", "PowerShell"],
    ["(Get-Content) -replace | Set-Content", "(Get-Content <LB>) -replace '\"avoid\"','\"proceed\"' | Set-Content <LB>", "PowerShell"],
    ["cmd /c --% del", "cmd /c --% del <LB>", "PowerShell"],
    ["echo escaped JSON >> a quoted backslash path", 'echo "{\\"verdict\\":\\"proceed\\"}" >> "<LB>"', "Bash"],
    ["cd /c/... && rm", "", "Bash"],
    ["a heredoc", "cat >> <L> <<'EOF'\n<F>\nEOF", "Bash"],
    ["rm", "rm <L>", "Bash"],
    ["rm -rf the folder", "rm -rf <H>", "Bash"],
    ["find -delete in the folder", "find <H> -name 'check-ledger*' -delete", "Bash"],
    ["a glob on the name", "rm <H>/check-ledger*", "Bash"],
    ["tee", "echo x | tee -a <L>", "Bash"],
    ["sed -i", "sed -i 's/avoid/proceed/' <L>", "Bash"],
    ["node -e", "node -e \"require('fs').appendFileSync('<L>','x')\"", "Bash"],
    ["the name only, after cd", "cd <H> && rm check-ledger.jsonl", "Bash"],
    ["upper case", "RM <L>".toUpperCase(), "Bash"],
    ["a variable, with the name written", "echo x >> $FOURDA_MCP_HOME/check-ledger.jsonl", "Bash"],
    ["[IO.File]::AppendAllText", "[IO.File]::AppendAllText('<LB>', 'x')", "PowerShell"],
    ["Start-Process", "Start-Process cmd -ArgumentList '/c del <LB>' -Wait", "PowerShell"],
    ["Remove-Item the folder", "Remove-Item <HB> -Recurse -Force", "PowerShell"],
    ["a backtick continuation", "Remove-Item `\n  <LB>", "PowerShell"],
    ["a read with a pipe (the accepted price)", "cat <L> | jq .", "Bash"],
    ["a copy out of it (the accepted price)", "cp <L> /tmp/ledger-copy.jsonl", "Bash"],
    ["a read beside another command", "cat <L>; echo done", "Bash"],
    ["a read redirected", "cat <L> > /tmp/copy.jsonl", "Bash"],
    ["Get-Content piped", "Get-Content <LB> | Select-Object -Last 3", "PowerShell"],
    ["a commit message naming it (the accepted price)", 'git commit -m "Mention check-ledger.jsonl in the docs"', "Bash"],
    ["CRLF lines", "npm test\r\nrm <L>\r\n", "Bash"],
  ])("%s", (_label, command, shell) => {
    const run = command === "" ? cmd(`cd ${msys(HB.replace(/\\/g, "/"))} && rm check-ledger.jsonl`, shell) : cmd(command, shell);
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain(NAMES);
    expect(run.text).toContain("To read it, run cat '");
  });

  it("the forged line does not get in, so the avoid still holds the install", () => {
    expect(cmd("echo '<F>' >> <L>").text).toContain(NAMES);
    expect(cmd("npm i lodash@4.17.20").text).toContain("answered avoid");
  });
});

describe("a plain read goes ahead, and each held read is released by the denial's own remedy", () => {
  it.each([
    ["cat <L>", "Bash"],
    ["head -n 5 <L>", "Bash"],
    ["tail -n 20 <L>", "Bash"],
    ["tail -f <L>", "Bash"],
    ["wc -l <L> <L1>", "Bash"],
    ["less <L>", "Bash"],
    ["ls -la <H>", "Bash"],
    ["du -sh <H>", "Bash"],
    ["Get-Content <LB>", "PowerShell"],
    ["Get-Content <LB> -Tail 5", "PowerShell"],
    ["gc <LB>", "PowerShell"],
    ["type <LB>", "PowerShell"],
    ["Get-ChildItem <HB>", "PowerShell"],
    ["dir <HB>", "PowerShell"],
  ])("%s", (command, shell) => {
    expect(cmd(command, shell).decision).toBe("allow");
  });

  it("the remedy literally: run cat <file> as a command of its own", () => {
    const held = cmd("cat <L> | python -m json.tool");
    expect(held.decision).toBe("deny");
    const file = /run cat ('.*?') \(or Get-Content/.exec(held.text)?.[1];
    expect(file).toBeDefined();
    expect(s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `cat ${file}` } }).decision).toBe("allow");
    expect(s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "PowerShell", tool_input: { command: `Get-Content ${file}` } }).decision).toBe("allow");
  });
});

describe("Edit, MultiEdit, Write and NotebookEdit of a path that names it or reaches the data folder: always held", () => {
  it.each([
    ["the ledger", () => L],
    ["the second file", () => L1],
    ["backslashes", () => `${HB}\\check-ledger.jsonl`],
    ["an alternate data stream", () => `${HB}\\check-ledger.jsonl::$DATA`],
    ["a \\\\?\\ prefix", () => `\\\\?\\${HB}\\check-ledger.jsonl`],
    ["upper case", () => `${HB}\\CHECK-LEDGER.JSONL`],
    ["a trailing dot", () => `${HB}\\check-ledger.jsonl.`],
    ["dot-dot", () => `${home}/../${home.split("/").pop()}/check-ledger.jsonl`],
    ["another file in the data folder", () => `${home}/notes.txt`],
    ["a file named like it elsewhere (the accepted price)", () => `${s.project.replace(/\\/g, "/")}/check-ledger.jsonl`],
  ])("%s", (_label, path) => {
    for (const name of ["Write", "Edit", "MultiEdit"]) {
      const input = name === "Write" ? { file_path: path(), content: `${forged()}\n` } : name === "Edit" ? { file_path: path(), old_string: "a", new_string: "b" } : { file_path: path(), edits: [{ old_string: "a", new_string: "b" }] };
      const run = tool(name, input);
      expect(run.decision, `${name} ${path()}`).toBe("deny");
    }
    expect(tool("NotebookEdit", { notebook_path: path(), new_source: "x" }).decision).toBe("deny");
  });

  it("a folder reached by another spelling (a link to the data folder) is held", () => {
    const link = join(s.project, "link-to-home");
    try {
      symlinkSync(realpathSync(s.home), link, "junction");
    } catch {
      return; // no links on this file system
    }
    expect(tool("Write", { file_path: join(link, "anything.jsonl"), content: "x" }).decision).toBe("deny");
  });
});

describe("what does not name it goes ahead", () => {
  it.each([
    "npm test",
    "git add src/check-ledger.ts src/__tests__/check-ledger.test.ts",
    "npx vitest run src/__tests__/check-ledger.test.ts",
    "cat dist/check-ledger.js",
    "rm -rf dist node_modules",
    "echo x > out.txt",
  ])("Bash: %s", (command) => {
    expect(cmd(command).decision).toBe("allow");
  });

  it("an edit of the server's source file check-ledger.ts goes ahead", () => {
    mkdirSync(join(s.project, "src"), { recursive: true });
    expect(tool("Write", { file_path: join(s.project, "src", "check-ledger.ts"), content: "export {};\n" }).decision).toBe("allow");
  });

  it("a path built from a variable and naming neither is not seen (a stated limit)", () => {
    expect(cmd("rm -rf $FOURDA_MCP_HOME").decision).toBe("allow");
  });
});

describe("size: the check reads the raw text, past the command reader's caps too", () => {
  it("over 64 KB and over 8 MB, inside the CPU bound", () => {
    const payload = (command: string, extra: Record<string, unknown> = {}) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd: s.project, tool_input: { command, ...extra } });
    expect(timedWithin(s.home, payload(`rm ${L} # ${"x".repeat(70_000)}`), 500).text).toContain(NAMES);
    expect(timedWithin(s.home, payload(`rm ${L}`, { description: "x".repeat(9 * 1024 * 1024) }), 1000).text).toContain(NAMES);
    expect(timedWithin(s.home, payload(`echo ${"y".repeat(200_000)} > out.txt`), 500).decision).toBe("allow");
    expect(EDIT).toBeTruthy();
  });
});
