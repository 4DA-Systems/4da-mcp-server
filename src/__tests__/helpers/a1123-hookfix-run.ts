// SPDX-License-Identifier: Apache-2.0
/**
 * Runs the plugin hook (hooks/manifest-edit.mjs) the way Claude Code runs it, for the manifest
 * tests: a temporary data folder with a started ledger (so the hook can deny), a temporary project,
 * the payload on stdin, the decision read from stdout.
 */

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect } from "vitest";
// The hook's PATH lookups see a stub for each manager and runner word, whatever the machine (Windows).
import "./a1125-manager-stubs.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "hooks", "manifest-edit.mjs");

export interface HookRun {
  /** "deny", "allow" (no output) or "advise" (PostToolUse context). */
  decision: "deny" | "allow" | "advise";
  text: string;
  /** The items of the dependency_check call the text names, or null when it names none. */
  items: Array<Record<string, string>> | null;
}

export interface Sandbox {
  home: string;
  project: string;
  /** Writes `text` at `rel` under the project and returns its absolute path. */
  file(rel: string, text: string): string;
  /** Replaces the ledger with these entries (ecosystem npm unless given, a minute old). */
  ledger(entries: Array<Record<string, string>>): void;
  edit(path: string, oldString: string, newString: string, extra?: Record<string, unknown>): HookRun;
  write(path: string, content: string): HookRun;
  post(path: string, oldString: string, newString: string, env?: Record<string, string>): HookRun;
  run(payload: unknown, env?: Record<string, string>): HookRun;
  dispose(): void;
}

export function sandbox(): Sandbox {
  const home = mkdtempSync(join(tmpdir(), "a1123-hookfix-home-"));
  const project = mkdtempSync(join(tmpdir(), "a1123-hookfix-project-"));
  writeFileSync(join(home, "check-ledger.jsonl"), "");
  const run = (payload: unknown, extraEnv: Record<string, string> = {}): HookRun => {
    const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: home, ...extraEnv };
    if (!("FOURDA_GUARD" in extraEnv)) delete env.FOURDA_GUARD;
    const res = spawnSync(process.execPath, [HOOK], { input: JSON.stringify(payload), encoding: "utf8", timeout: 20_000, env });
    expect(res.status).toBe(0);
    if (res.stdout === "") return { decision: "allow", text: "", items: null };
    const out = (JSON.parse(res.stdout) as { hookSpecificOutput: { permissionDecision?: string; permissionDecisionReason?: string; additionalContext?: string } }).hookSpecificOutput;
    const text = out.permissionDecisionReason ?? out.additionalContext ?? "";
    const m = /dependency_check (\{"items":.*?\]\})/.exec(text);
    return {
      decision: out.permissionDecision === "deny" ? "deny" : "advise",
      text,
      items: m ? (JSON.parse(m[1]) as { items: Array<Record<string, string>> }).items : null,
    };
  };
  const pre = (tool_name: string, tool_input: Record<string, unknown>) => ({ session_id: "s", cwd: project, hook_event_name: "PreToolUse", tool_name, tool_input });
  return {
    home,
    project,
    file(rel, text) {
      const path = join(project, rel);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, text);
      return path;
    },
    ledger(entries) {
      const t = new Date(Date.now() - 60_000).toISOString();
      writeFileSync(join(home, "check-ledger.jsonl"), entries.map((e) => JSON.stringify({ t, sv: "6.6.0", ecosystem: "npm", ...e })).join("\n") + "\n");
    },
    edit: (path, oldString, newString, extra = {}) => run(pre("Edit", { file_path: path, old_string: oldString, new_string: newString, replace_all: false, ...extra })),
    write: (path, content) => run(pre("Write", { file_path: path, content })),
    post: (path, oldString, newString, env = { FOURDA_GUARD: "advise" }) =>
      run({ session_id: "s", cwd: project, hook_event_name: "PostToolUse", tool_name: "Edit", tool_input: { file_path: path, old_string: oldString, new_string: newString } }, env),
    run,
    dispose() {
      rmSync(home, { recursive: true, force: true });
      rmSync(project, { recursive: true, force: true });
    },
  };
}
