// SPDX-License-Identifier: Apache-2.0
/**
 * The guard hook beside a server that keeps no check ledger. The hook comes with the plugin and the
 * server with npm, so the two can be of different releases: a server before 6.5.0 answers
 * dependency_check and records nothing. A hook that denied there would stop every dependency edit
 * for ever, because the call it asks for could never let the edit through.
 *
 * So the hook denies only where a ledger file exists, and a server from 6.5.0 on starts one (empty)
 * when it starts serving. With none, the hook works as it did before 6.5.0: nothing is denied, and
 * the advice follows a manifest edit.
 */

import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { LEDGER_FILE, LEDGER_PREVIOUS_FILE, ledgerWritesSettled, recordVerdicts, startLedger } from "../check-ledger.js";
import { serverEntry } from "./helpers/stdio-session.js";
// The hook's PATH lookups see a stub for each manager and runner word, whatever the machine (Windows).
import "./helpers/a1125-manager-stubs.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const HOOK = path.join(root, "hooks", "manifest-edit.mjs");
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-skew-"));
afterAll(() => {
  try {
    fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    // Windows can hold a just-exited child's files for a moment; left for the OS temp cleaner.
  }
});

let n = 0;
let home: string;
let project: string;
beforeEach(() => {
  n += 1;
  home = path.join(scratch, `home-${n}`);
  project = path.join(scratch, `project-${n}`);
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  // What a server before 6.5.0 leaves in its data folder: its cache, and no ledger.
  fs.writeFileSync(path.join(home, "cache.db"), "");
});

/** Run the hook as Claude Code does: a separate process, the payload on stdin, FOURDA_GUARD unset. */
function hook(payload: unknown): { status: number | null; stdout: string } {
  const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: home };
  delete env.FOURDA_GUARD;
  const res = spawnSync(process.execPath, [HOOK], { input: JSON.stringify(payload), encoding: "utf8", timeout: 20_000, env });
  return { status: res.status, stdout: res.stdout };
}

const event = (hook_event_name: string, tool_name: string, tool_input: Record<string, unknown>) => ({
  session_id: "s",
  transcript_path: "/tmp/t.jsonl",
  cwd: project,
  permission_mode: "default",
  hook_event_name,
  tool_name,
  tool_input,
  tool_use_id: "toolu_1",
});

/** A package.json holding lodash 4.17.21 and the Edit that moves it to `to`. */
function lodashEdit(to: string): Record<string, unknown> {
  const file = path.join(project, "package.json");
  fs.writeFileSync(file, '{\n  "name": "app",\n  "dependencies": {\n    "lodash": "4.17.21"\n  }\n}\n');
  return { file_path: file, old_string: '"lodash": "4.17.21"', new_string: `"lodash": "${to}"`, replace_all: false };
}

/** The denial's reason, or null when the hook let the call go ahead. */
function denial(out: { status: number | null; stdout: string }): string | null {
  expect(out.status).toBe(0);
  if (out.stdout === "") return null;
  const parsed = JSON.parse(out.stdout) as { hookSpecificOutput: { hookEventName: string; permissionDecision: string; permissionDecisionReason: string } };
  expect(parsed.hookSpecificOutput).toMatchObject({ hookEventName: "PreToolUse", permissionDecision: "deny" });
  return parsed.hookSpecificOutput.permissionDecisionReason;
}

describe("a data folder with no ledger: the servers that ran there record no verdict", () => {
  it("an unchecked version is not denied, by edit, by whole-file write or by install command", () => {
    expect(denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))))).toBeNull();
    expect(denial(hook(event("PreToolUse", "Write", { file_path: path.join(project, "new", "package.json"), content: '{ "dependencies": { "lodash": "4.17.20" } }' })))).toBeNull();
    expect(denial(hook(event("PreToolUse", "Bash", { command: "npm install lodash@4.17.20" })))).toBeNull();
    expect(denial(hook(event("PreToolUse", "PowerShell", { command: "cargo add serde@1.0.100" })))).toBeNull();
  });

  it("the advice follows the edit, as it did before 6.5.0", () => {
    const input = lodashEdit("4.17.20");
    fs.writeFileSync(String(input.file_path), '{\n  "name": "app",\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}\n');
    const out = hook(event("PostToolUse", "Edit", input));
    expect(out.status).toBe(0);
    const parsed = JSON.parse(out.stdout) as { hookSpecificOutput: { hookEventName: string; additionalContext: string } };
    expect(parsed.hookSpecificOutput.hookEventName).toBe("PostToolUse");
    expect(parsed.hookSpecificOutput.additionalContext).toContain('"lodash": "4.17.21" -> "4.17.20"');
    expect(parsed.hookSpecificOutput.additionalContext).toContain("dependency_check");
  });

  it("an edit that moves no dependency version still says nothing", () => {
    const file = path.join(project, "package.json");
    fs.writeFileSync(file, '{\n  "name": "app",\n  "dependencies": {\n    "lodash": "4.17.21"\n  }\n}\n');
    const input = { file_path: file, old_string: '"name": "app"', new_string: '"name": "web"' };
    expect(hook(event("PreToolUse", "Edit", input))).toEqual({ status: 0, stdout: "" });
    expect(hook(event("PostToolUse", "Edit", input))).toEqual({ status: 0, stdout: "" });
  });
});

describe("a data folder with a ledger: a server that records verdicts has run there", () => {
  it("an empty ledger, as a server leaves it at its start: the unchecked version is denied", () => {
    fs.writeFileSync(path.join(home, LEDGER_FILE), "");
    const reason = denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))));
    expect(reason).toContain("call the 4da MCP tool dependency_check");
    expect(denial(hook(event("PreToolUse", "Bash", { command: "npm install lodash@4.17.20" })))).toContain('"lodash" "4.17.20" (npm)');
    // The guard held the edit, so nothing follows it.
    expect(hook(event("PostToolUse", "Edit", lodashEdit("4.17.20")))).toEqual({ status: 0, stdout: "" });
  });

  it("only the moved-aside ledger file: still a ledger", () => {
    fs.writeFileSync(path.join(home, LEDGER_PREVIOUS_FILE), "");
    expect(denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))))).toContain("dependency_check");
  });

  it("a version with no entry: the denial says what a second stop would mean, and not to retry", () => {
    fs.writeFileSync(path.join(home, LEDGER_FILE), "");
    const reason = denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))))!;
    expect(reason).toContain(`No dependency_check verdict at all is recorded in ${home}`);
    expect(reason).toContain("If this stops again after dependency_check has answered for it, do not retry");
    expect(reason).toContain("older than this guard needs");
    expect(reason).toContain("FOURDA_MCP_HOME");
    // FOURDA_GUARD is the user's setting, not the agent's (re-check of 0d30b40, S8).
    expect(reason).toContain("FOURDA_GUARD (advise, off) is the user's setting: tell the user, and do not change it yourself");
  });

  it("other verdicts on record, none for this version: the same note, without the empty-ledger sentence", () => {
    const t = new Date(Date.now() - 60_000).toISOString();
    fs.writeFileSync(path.join(home, LEDGER_FILE), JSON.stringify({ sv: "6.6.0", t, ecosystem: "npm", package: "express", version: "4.21.2", verdict: "proceed" }) + "\n");
    const reason = denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))))!;
    expect(reason).not.toContain("No dependency_check verdict at all");
    expect(reason).toContain("do not retry");
  });

  it("an unknown answer on record for the version: that answer is named, and the note is left out", () => {
    const t = new Date(Date.now() - 60_000).toISOString();
    fs.writeFileSync(path.join(home, LEDGER_FILE), JSON.stringify({ sv: "6.6.0", t, ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "unknown", reason: "the registry did not answer" }) + "\n");
    const reason = denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))))!;
    expect(reason).toContain("the last dependency_check answer was unknown");
    expect(reason).toContain("the registry did not answer");
    expect(reason).not.toContain("do not retry");
  });
});

describe("startLedger", () => {
  it("creates the data folder and an empty ledger, and from then on the hook denies", async () => {
    home = path.join(scratch, `fresh-${n}`, "4da-mcp");
    expect(fs.existsSync(home)).toBe(false);
    expect(denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))))).toBeNull();
    await startLedger({ dir: home });
    expect(fs.readFileSync(path.join(home, LEDGER_FILE), "utf8")).toBe("");
    expect(denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))))).toContain("dependency_check");
  });

  it("leaves an existing ledger as it is, and the verdicts in it still count", async () => {
    await recordVerdicts([{ ecosystem: "npm", package: "lodash", to: "4.17.20", verdict: "proceed" }], { dir: home });
    const before = fs.readFileSync(path.join(home, LEDGER_FILE), "utf8");
    await startLedger({ dir: home });
    expect(fs.readFileSync(path.join(home, LEDGER_FILE), "utf8")).toBe(before);
    expect(denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))))).toBeNull();
  });

  it("a folder it cannot write never rejects, and the server's shutdown wait still settles", async () => {
    const blocked = path.join(home, "cache.db", "under-a-file");
    await expect(startLedger({ dir: blocked })).resolves.toBeUndefined();
    await expect(ledgerWritesSettled()).resolves.toBeUndefined();
    expect(fs.existsSync(blocked)).toBe(false);
  });
});

describe.skipIf(!fs.existsSync(serverEntry))("the built server starts the ledger when it starts serving", () => {
  it("a fresh data folder holds an empty ledger before any tool is called, and the hook then denies", { timeout: 60_000 }, async () => {
    home = path.join(scratch, `served-${n}`);
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const k of Object.keys(env)) if (/^FOURDA_/i.test(k) || k === "NODE_OPTIONS") delete env[k];
    Object.assign(env, { FOURDA_MCP_HOME: home, FOURDA_DATA_DIR: path.join(scratch, `no-app-${n}`), FOURDA_OFFLINE: "1" });
    const child = spawn(process.execPath, [serverEntry], { cwd: project, env, stdio: ["pipe", "pipe", "pipe"] });
    const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    child.stderr.resume();
    const initialized = new Promise<void>((resolve) => {
      let buffer = "";
      child.stdout.on("data", (d) => {
        buffer += d;
        if (buffer.includes('"id":1')) resolve();
      });
    });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } } }) + "\n");
    const killer = setTimeout(() => child.kill(), 30_000);
    await initialized;
    // No tool has been called: the host only initialized, then closed stdin (MCP's stdio shutdown).
    child.stdin.end();
    await exited;
    clearTimeout(killer);
    expect(fs.readFileSync(path.join(home, LEDGER_FILE), "utf8")).toBe("");
    expect(denial(hook(event("PreToolUse", "Edit", lodashEdit("4.17.20"))))).toContain("dependency_check");
  });
});
