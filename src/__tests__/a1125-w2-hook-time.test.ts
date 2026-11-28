// SPDX-License-Identifier: Apache-2.0
/**
 * Seventh independent check, D1: a runner chain over 512 KB (`npx -y ` repeated, then an install)
 * printed nothing within 10 s, so the call went ahead. The account now stops at the reader's depth
 * (MAX_WRAPS) and holds past it, its loops tick, and a payload over 8 KB is judged in a worker
 * under a hard wall clock: past it the call is held. Each case here runs with a hard 10 s kill and
 * fails on a kill; the reviewer's shapes and 20 generated nestings must come back held.
 */

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
// The hook's PATH lookups see a stub for each manager and runner word, whatever the machine (Windows).
import "./helpers/a1125-manager-stubs.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");

let s: Sandbox;
beforeAll(() => {
  s = sandbox();
  s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }]);
});
afterAll(() => s.dispose());

interface Killed {
  killed: boolean;
  ms: number;
  out: string;
}

/** Runs the hook on a Bash command with a hard 10 s kill. */
function hard(command: string): Promise<Killed> {
  return new Promise((done) => {
    const t0 = Date.now();
    const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: s.home };
    delete env.FOURDA_GUARD;
    const p = spawn(process.execPath, [HOOK], { env });
    let out = "";
    let killed = false;
    p.stdout.on("data", (d: Buffer) => (out += d.toString()));
    const kill = setTimeout(() => {
      killed = true;
      p.kill("SIGKILL");
    }, 10_000);
    p.on("exit", () => {
      clearTimeout(kill);
      done({ killed, ms: Date.now() - t0, out });
    });
    p.stdin.end(JSON.stringify({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } }));
  });
}

const INSTALL = "npm i lodash@4.17.20";
const SHAPES: [string, string][] = [];
for (const [unit, label] of [
  ["npx -y ", "npx -y"],
  ["pdm run ", "pdm run"],
  ["uv run ", "uv run"],
  ["poetry run ", "poetry run"],
  ["npx ", "npx"],
  ["pnpm dlx ", "pnpm dlx"],
  ["bunx ", "bunx"],
]) {
  for (const kb of [512, 2048]) SHAPES.push([`${label} x ${kb} KB`, unit.repeat(Math.floor((kb * 1024 - 100) / unit.length)) + INSTALL]);
}

const UNITS = ["npx -y ", "bash -c '", "sudo ", "env ", "pnpm dlx ", "uv run ", "poetry run ", "pipenv run ", "npm exec -- ", "yarn dlx ", "timeout 5 ", "nice ", "xargs ", "eval ", "( ", "{ ", "cmd /c ", "python -m pip ", "node npm-cli.js ", "corepack "];
const NESTINGS: [string, string][] = Array.from({ length: 20 }, (_, k) => {
  let line = "";
  for (let i = 0; line.length < 1024 * 1024; i++) line += UNITS[(i * 7 + k) % UNITS.length];
  return [`nesting ${k}`, line + INSTALL];
});

/** Runs cases three at a time. */
async function all(cases: [string, string][]): Promise<Array<[string, Killed]>> {
  const out: Array<[string, Killed]> = [];
  for (let i = 0; i < cases.length; i += 3) {
    const batch = cases.slice(i, i + 3);
    const runs = await Promise.all(batch.map(([, c]) => hard(c)));
    batch.forEach(([label], k) => out.push([label, runs[k]]));
  }
  return out;
}

describe("D1: no call outlives its budget; past it the call is held", () => {
  it("the seventh check's runner chains, 512 KB and 2 MB: held, none killed", { timeout: 240_000 }, async () => {
    for (const [label, r] of await all(SHAPES)) {
      expect(r.killed, label).toBe(false);
      expect(r.out, label).toContain('"deny"');
    }
  });

  it("20 generated nestings of 1 MB: none killed", { timeout: 240_000 }, async () => {
    for (const [label, r] of await all(NESTINGS)) expect(r.killed, `${label} after ${r.ms} ms`).toBe(false);
  });
});
