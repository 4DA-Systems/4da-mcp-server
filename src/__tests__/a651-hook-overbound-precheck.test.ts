// SPDX-License-Identifier: Apache-2.0
/**
 * A call too big to read whole is held only when it is an install or a manifest edit, and every
 * install is seen (round 4 of the hook review, items 2 and 3).
 *
 * Round 3's pre-check matched a package manager's name and an install word ANYWHERE in the first
 * 128 KB: `go`, `py`, `uv`, `a`, `i`, `x`, `in`, `get`, `edit` occur in any prose, so a 70 KB
 * heredoc of notes, a `python -` script, `node -e`, a long `git commit -m` or PowerShell
 * `Set-Content` were held (6.5.0 and 4afa387 let them through). And it missed installs: one after
 * the first 128 KB, `npm installTest` / `install-test` / `install-t`, `np''m i`, and in a payload
 * over 8 MB anything the first 64 KB of escaped JSON did not show. Now the whole command is read
 * by a linear, quote- and heredoc-aware pass that wants a package manager's name in command
 * position followed by an install word of that tool, and an oversized payload is judged from its
 * parsed fields.
 */

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");
const dir = mkdtempSync(join(tmpdir(), "a651-overbound-"));
const home = join(dir, "home");
mkdirSync(home);
writeFileSync(join(home, LEDGER_FILE), JSON.stringify({ t: new Date().toISOString(), ecosystem: "npm", package: "zzz-unrelated", version: "1.0.0", verdict: "proceed" }) + "\n");
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const PAD = (n: number) => "b".repeat(n);
const decide = (command: string, tool = "Bash") => (respond({ hook_event_name: "PreToolUse", tool_name: tool, cwd: dir, tool_input: { command } }, { FOURDA_MCP_HOME: home }, Date.now()) === "" ? "allow" : "deny");

describe("held: an install in a command too big to read (item 2)", () => {
  it.each([
    `echo ${PAD(140_000)}; npm i lodash@3.10.1`,
    `npm installTest lodash@3.10.1; echo ${PAD(70_000)}`,
    `npm install-test lodash@3.10.1; echo ${PAD(70_000)}`,
    `npm install-t lodash@3.10.1; echo ${PAD(70_000)}`,
    `np''m i lodash@3.10.1; echo ${PAD(70_000)}`,
    `'npm' i lodash@3.10.1; echo ${PAD(70_000)}`,
    `pip3.12 install requests==2.0.0; echo ${PAD(70_000)}`,
    `python3 -m pip install requests==2.0.0; echo ${PAD(70_000)}`,
    `cargo add serde@1.0.0; echo ${PAD(70_000)}`,
    `go get golang.org/x/net@v0.0.1; echo ${PAD(70_000)}`,
    `yarnpkg add lodash@3.10.1; echo ${PAD(70_000)}`,
    `sudo -E npm i lodash@3.10.1; echo ${PAD(70_000)}`,
    `cd app && npx pnpm add lodash@3.10.1 && echo ${PAD(70_000)}`,
    // A package manager run as a script (8e17992 held it; the command-position rule must too).
    `node pnpm.cjs add lodash@3.10.1; echo ${PAD(70_000)}`,
    `node ./node_modules/npm/bin/npm-cli.js install lodash@3.10.1; echo ${PAD(70_000)}`,
  ])("%#", (command) => {
    expect(decide(command)).toBe("deny");
  });
});

describe("goes ahead: long ordinary commands (item 3, the checker's c5-harmless)", () => {
  it.each([
    ["70 KB python heredoc script", `python - <<'EOF'\n${"for i in range(3):\n    print(i)\n".repeat(2500)}EOF`, "Bash"],
    ["70 KB node -e script", `node -e "${"const a = 1; // go\n".repeat(3600)}"`, "Bash"],
    ["70 KB cat > data.csv heredoc", `cat > data.csv <<'EOF'\n${"1,2,3,4,5,6,7,8\n".repeat(4500)}EOF`, "Bash"],
    ["70 KB cat > notes.md heredoc of prose", `cat > notes.md <<'EOF'\n${"We go to a meeting and then review the plan.\n".repeat(1600)}EOF`, "Bash"],
    ["70 KB git commit -F - heredoc mentioning pip install", `git commit -F - <<'EOF'\n${"Docs: run pip install -e . first, then go test.\n".repeat(1500)}EOF`, "Bash"],
    ["75 KB git commit -m prose with ; npm i", `git commit -m "${"We go on; then npm i x and a review. ".repeat(2000)}"`, "Bash"],
    ["70 KB PowerShell Set-Content prose", `Set-Content notes.md '${"We go to a meeting and then review the plan. ".repeat(1600)}'`, "PowerShell"],
    ["70 KB PowerShell here-string", `$t = @'\n${"npm i x; go get y\n".repeat(4000)}'@\nSet-Content notes.md $t`, "PowerShell"],
  ])("%s", (_label, command, tool) => {
    expect(decide(command, tool)).toBe("allow");
  });
});

describe("a payload over 8 MB is judged from its parsed fields (item 2)", { timeout: 120_000 }, () => {
  const proj = join(dir, "big");
  mkdirSync(proj, { recursive: true });
  const pj = join(proj, "package.json");
  writeFileSync(pj, '{"name":"x","dependencies":{}}');
  const big = PAD(8.5 * 1024 * 1024);
  const content = `{"name":"x","dependencies":{"lodash":"3.10.1"},"pad":"${big}"}`;
  const base = { session_id: "s", transcript_path: "x", cwd: proj, hook_event_name: "PreToolUse" };
  function run(payload: unknown): string {
    const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: home };
    delete env.FOURDA_GUARD;
    const r = spawnSync(process.execPath, [HOOK], { input: JSON.stringify(payload), encoding: "utf8", timeout: 60_000, env, maxBuffer: 1 << 26 });
    return r.stdout === "" ? "allow" : (JSON.parse(r.stdout) as { hookSpecificOutput: { permissionDecision: string } }).hookSpecificOutput.permissionDecision;
  }
  it.each([
    ["Write package.json, content before file_path", { ...base, tool_name: "Write", tool_input: { content, file_path: pj } }],
    ["Write, tool_name after tool_input", { session_id: "s", transcript_path: "x", cwd: proj, hook_event_name: "PreToolUse", tool_input: { file_path: pj, content }, tool_name: "Write" }],
    ["Write, a 70 KB transcript_path first", { ...base, transcript_path: "C:/" + PAD(70_000), tool_name: "Write", tool_input: { file_path: pj, content } }],
    ["Bash: a newline before npm i", { ...base, tool_name: "Bash", tool_input: { command: `true\nnpm i lodash@3.10.1\n#${big}` } }],
    ["Bash: a 70 KB description before the command", { ...base, tool_name: "Bash", tool_input: { description: PAD(70_000), command: `npm i lodash@3.10.1 #${big}` } }],
    ["Bash: npm i after 70 KB", { ...base, tool_name: "Bash", tool_input: { command: `echo ${PAD(70_000)}; npm i lodash@3.10.1 #${big}` } }],
    ["Edit package.json, old/new before file_path", { ...base, tool_name: "Edit", tool_input: { old_string: '"dependencies":{}', new_string: `"dependencies":{"lodash":"3.10.1"},"pad":"${big}"`, file_path: pj } }],
  ])("held: %s", (_label, payload) => {
    expect(run(payload)).toBe("deny");
  });

  it.each([
    ["Write README.md", { ...base, tool_name: "Write", tool_input: { file_path: join(proj, "README.md"), content: `npm install${big}` } }],
    ["Bash echo", { ...base, tool_name: "Bash", tool_input: { command: `echo ${big}` } }],
  ])("goes ahead: %s", (_label, payload) => {
    expect(run(payload)).toBe("allow");
  });
});
