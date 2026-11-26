// SPDX-License-Identifier: Apache-2.0
/**
 * Round 12 (tenth independent check, a missing sentence): the server moves check-ledger.jsonl over
 * check-ledger.1.jsonl while a hook may be reading the one after the other. The hook reads both as
 * one snapshot (stat, read, stat again, at most three times); a ledger still changing holds the call.
 */

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { recordVerdicts } from "../check-ledger.js";
import { sandbox } from "./helpers/a1123-hookfix-run.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");
const bash = (command: string) => ({ session_id: "s", cwd: tmpdir(), hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });

describe("a ledger that keeps changing while it is read holds the call", () => {
  it("every stat sees another file (test fault ledger-rotating): held, the verdict unknown", () => {
    const s = sandbox();
    try {
      s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "proceed" }]);
      const r = s.run(bash("npm i lodash@4.17.20"), { FOURDA_HOOK_FAULT: "ledger-rotating" });
      expect(r.decision).toBe("deny");
      expect(r.text).toContain("changed while it was read");
      expect(s.run(bash("npm i lodash@4.17.20")).decision).toBe("allow");
    } finally {
      s.dispose();
    }
  });
});

function ask(home: string): Promise<string> {
  return new Promise((done) => {
    const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: home };
    delete env.FOURDA_GUARD;
    const p = spawn(process.execPath, [HOOK], { env });
    let out = "";
    p.stdout.on("data", (d: Buffer) => (out += d.toString()));
    const kill = setTimeout(() => p.kill(), 15_000);
    p.on("exit", () => {
      clearTimeout(kill);
      done(out);
    });
    p.stdin.end(JSON.stringify(bash("npm i lodash@4.17.20")));
  });
}

const filler = (n: number, tag: string) => Array.from({ length: n }, (_, i) => ({ ecosystem: "npm", package: `filler-${tag}-${i}-${"x".repeat(200)}`, to: "1.0.0", verdict: "proceed" as const, reason: "r".repeat(300) }));

async function fillTo(home: string, bytes: number, tag: string): Promise<void> {
  for (let k = 0; ; k++) {
    let size = 0;
    try {
      size = statSync(join(home, "check-ledger.jsonl")).size;
    } catch {
      size = 0;
    }
    if (size >= bytes) return;
    await recordVerdicts(filler(Math.max(1, Math.min(150, Math.floor((bytes - size) / 560))), `${tag}${k}`), { dir: home });
  }
}

describe("a rotation in flight (the server's own writer), as the tenth check ran it", () => {
  it("12 trials x 6 calls: every call is denied on the avoid", { timeout: 240_000 }, async () => {
    const base = mkdtempSync(join(tmpdir(), "a1125-race-"));
    try {
      let notDenied = 0;
      for (let trial = 0; trial < 12; trial++) {
        const home = join(base, String(trial));
        await recordVerdicts([{ ecosystem: "npm", package: "lodash", to: "4.17.20", verdict: "proceed", reason: "P" }], { dir: home, now: new Date(Date.now() - 3600_000) });
        await fillTo(home, 480 * 1024, "a");
        await recordVerdicts([{ ecosystem: "npm", package: "lodash", to: "4.17.20", verdict: "avoid", reason: "A" }, ...filler(80, "r")], { dir: home });
        await fillTo(home, 480 * 1024, "b");
        const calls = Array.from({ length: 6 }, (_, i) => new Promise<string>((r) => setTimeout(() => void ask(home).then(r), i * 6)));
        await new Promise((r) => setTimeout(r, 30 + Math.floor(Math.random() * 60)));
        await recordVerdicts(filler(90, "c"), { dir: home });
        for (const out of await Promise.all(calls)) if (!out.includes('"deny"')) notDenied++;
      }
      expect(notDenied).toBe(0);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});
