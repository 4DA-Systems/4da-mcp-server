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

/** A name without its version: `lodash@x` -> `lodash`, `@s/p@1` -> `@s/p`, `requests[socks]>=2 ` -> `requests[socks]`. */
function bareName(token: string): string {
  const t = token.trim();
  if (/^@?[^@\s]+@/.test(t)) return t.slice(0, t.indexOf("@", 1));
  return t.replace(/\s*(?:[=<>!~;]|@).*$/s, "").trim();
}

/** The held options the tests write with a value (the user's knowledge of each tool, not the hook's). */
export const TAKES_VALUE = new Set(
  (
    "--tag --before -c --config --prerelease --resolution --exclude-newer --mode --only-binary --python-version --platform --upgrade-strategy --no-binary " +
    "--implementation --abi --python-platform --cache-min -i --index-url --extra-index-url --index --default-index -f --find-links --registry --source " +
    "--userconfig --globalconfig --config-file --python -p --cert --client-cert --exists-action --use-feature --cache-dir --os --cpu --linker --ca " +
    "--color --allow-insecure-host --resolution-mode --index-strategy --keyring-provider --cache-folder --network-timeout --directory --project -C"
  ).split(" "),
);

/**
 * Round 13: the not-read remedy followed mechanically. "Run the same command without `X`" removes X
 * (and, for find, the `;` / `+` that ends -exec); "with `X` written as <form>" writes X in that form
 * (`value` stands for a variable's or substitution's value). Null when the denial names no part.
 */
export function followRemedy(command: string, text: string, value = "lodash", valueAfter?: (option: string, next: string) => boolean): string | null {
  const tidy = (c: string) => c.replace(/[ \t]{2,}/g, " ").replace(/^\s*(?:;|&&)\s*/, "").trim();
  // The named part as a whole word (`--pre` is not the start of `--prefix`).
  const word = (token: string) => new RegExp(`(^|[\\s'"(])${token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=[\\s'";|&)]|$)`);
  // Round 14: an option named alone ("if that option takes a value, remove its value too"): the user
  // knows its arity; here, the options these tests give a value (TAKES_VALUE).
  const named = /Run the same command without the option `([^`]+)`; if that option takes a value, remove its value too/.exec(text);
  if (named) {
    const o = named[1];
    const next = command.slice(command.indexOf(o) + o.length).trim().split(/\s+/)[0] ?? "";
    const takes = valueAfter ? valueAfter(o, next) : TAKES_VALUE.has(o);
    const tail = !o.includes("=") && takes ? String.raw`(?:\s+(?:'[^']*'|"[^"]*"|[^\s'";|&)]+))?` : "";
    const re = new RegExp(`(^|[\\s'"(])${o.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}${tail}(?=[\\s'";|&)]|$)`);
    return tidy(command.replace(re, "$1"));
  }
  const without = /Run the same command without `([^`]+)`( and the ; or \+ that ends -exec)?/.exec(text);
  if (without) {
    let c = command.replace(word(without[1]), "$1");
    if (without[2]) c = c.replace(/\s+(?:\\;|';'|";"|;|\+)\s*$/, "");
    return tidy(c);
  }
  const w = /Run the same command with `([^`]+)` written as (.+?): the hook then reads it/s.exec(text);
  if (!w) return null;
  const [, token, form] = w;
  if (form.startsWith("an exact version")) return tidy(command.replace(token, bareName(token)));
  if (form.startsWith("one module path")) return tidy(command.replace(token, token.replace(/\/\.\.\.$/, "")));
  if (form.startsWith("its value written out")) return tidy(command.replace(token, value));
  if (form === "a file name") return tidy(command.replace(token, token.replace(/\s+\S+$/, " r.txt")));
  if (form.startsWith("the command inside it")) return tidy(token.replace(/^\$\(|^`|\)$|`$/g, ""));
  // A setting written as the option it stands for: the setting left out, the option on the command.
  const option = /^`([^`]+)` on the package manager's command$/.exec(form);
  if (option) return tidy(`${command.replace(token, "")} ${option[1]}`);
  // An option spelled another way (`--optional=<extra name>`): the placeholder stands for `value`.
  const spelled = /^`([^`]+)`$/.exec(form);
  if (spelled) return tidy(command.replace(word(token), `$1${spelled[1].replace(/<[^>]+>/g, value)}`));
  return tidy(command.replace(token, form));
}
