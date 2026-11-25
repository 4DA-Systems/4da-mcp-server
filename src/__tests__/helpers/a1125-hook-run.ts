// SPDX-License-Identifier: Apache-2.0
/**
 * For the a1125 hook tests: following a denial literally (record the verdict dependency_check
 * would give for exactly the items the denial names) and timing a hook run by its own CPU time,
 * the way a651-hook-pathological-inputs.test.ts judges it (the wall clock on a shared machine
 * mostly measures the wait for a core).
 */

import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect } from "vitest";

import type { HookRun, Sandbox } from "./a1123-hookfix-run.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "hooks", "manifest-edit.mjs");

/** Appends ledger lines (a minute old) without replacing what is there. */
export function record(s: Sandbox, entries: Array<Record<string, string>>): void {
  const t = new Date(Date.now() - 60_000).toISOString();
  appendFileSync(join(s.home, "check-ledger.jsonl"), entries.map((e) => JSON.stringify({ t, ...e })).join("\n") + "\n");
}

/**
 * Does what the denial says, literally: the dependency_check call it names, answered `verdict` for
 * each item (an item's `to` is recorded as the version; a constraint as `requested` too, as the
 * server records one). Returns the items.
 */
export function answerDenial(s: Sandbox, run: HookRun, verdict = "proceed"): Array<Record<string, string>> {
  expect(run.decision, run.text).toBe("deny");
  expect(run.items, run.text).not.toBeNull();
  const items = run.items ?? [];
  record(
    s,
    items.map((i) => ({ ecosystem: i.ecosystem, package: i.package, version: i.to, verdict, ...(/^v?\d+(\.\d+)*$/.test(i.to.replace(/^=+/, "")) ? {} : { requested: i.to }) })),
  );
  return items;
}

const CPU_AT_EXIT =
  "data:text/javascript," +
  encodeURIComponent(
    "import { writeSync } from 'node:fs'; process.on('exit', () => { const u = process.cpuUsage(); try { writeSync(2, '\\n@@cpu_ms=' + (u.user + u.system) / 1000 + '@@\\n'); } catch { /* stderr closed */ } });",
  );

export interface TimedRun {
  ms: number;
  cpu: number;
  decision: string;
  text: string;
}

/** One run of the hook with `payload`, its wall-clock and CPU time. */
export function timed(home: string, payload: unknown): TimedRun {
  const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: home };
  delete env.FOURDA_GUARD;
  const t0 = performance.now();
  const r = spawnSync(process.execPath, ["--import", CPU_AT_EXIT, HOOK], { input: JSON.stringify(payload), encoding: "utf8", timeout: 15_000, env, maxBuffer: 1 << 26 });
  const ms = performance.now() - t0;
  const cpu = Number(/@@cpu_ms=([0-9.]+)@@/.exec(r.stderr ?? "")?.[1] ?? Number.NaN);
  expect(r.status).toBe(0);
  const out = r.stdout ? (JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } }).hookSpecificOutput : undefined;
  return { ms, cpu, decision: out ? (out.permissionDecision ?? "other") : "allow", text: out?.permissionDecisionReason ?? "" };
}

/** Within `limit` on the wall clock, or under twice `limit` of the hook's own CPU time (best of up to three runs). */
export function timedWithin(home: string, payload: unknown, limit: number): TimedRun {
  let r = timed(home, payload);
  for (let tries = 1; tries < 3 && r.ms >= limit; tries++) {
    const again = timed(home, payload);
    r = { ...(again.ms < r.ms ? again : r), cpu: Math.min(r.cpu, again.cpu) };
  }
  if (r.ms >= limit) expect(r.cpu, `CPU time (wall clock ${r.ms.toFixed(0)} ms against ${limit} ms)`).toBeLessThan(2 * limit);
  return r;
}
