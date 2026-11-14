// SPDX-License-Identifier: Apache-2.0
/**
 * One time budget per tool call.
 *
 * Every lookup had its own timeout (15 s for OSV, up to 30 s for a registry
 * document, each retried once) and nothing bounded their sum. A cold
 * `dependency_check` for litellm or Django took 21 to 37 s; with OSV.dev
 * stalled one call took 49 s and then said OSV "did not answer within 15 s"
 * (audit 2026-11-11). An agent that waits that long has usually written the
 * version already.
 *
 * Now a call has CALL_BUDGET_MS in all, counted from the moment the request
 * arrived (the first call of a session also pays for the project scan):
 *
 * - The tools that wait for a project scan (vulnerability_scan,
 *   dependency_health, upgrade_planner) size their own waits from what is left
 *   (`withinCallBudget`), and answer with what they have: the parts that did
 *   not finish are NOT CHECKED, as they are for any OSV outage, never clean.
 * - Whatever is still running when the budget ends is cut off by the
 *   dispatcher (`raceCallBudget`), which answers in the tool's place: every
 *   item `unknown`, or NOT CHECKED, with the budget that was actually spent.
 *
 * Nothing is aborted. The lookups a late call started run on to their own
 * timeouts and fill the caches, so the same call made again answers from
 * them. (Aborting them mid-scan would leave advisories without their records,
 * which the scanner grades "unknown" and caches.)
 *
 * FOURDA_CALL_BUDGET_MS overrides the default.
 */

import { AsyncLocalStorage } from "node:async_hooks";

const DEFAULT_CALL_BUDGET_MS = 20_000;

/** The budget of one tool call, in milliseconds. */
export function callBudgetMs(): number {
  const raw = Number(process.env.FOURDA_CALL_BUDGET_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_CALL_BUDGET_MS;
}

interface Budget {
  deadline: number;
  budgetMs: number;
}

const current = new AsyncLocalStorage<Budget>();

/** Run `work` as one tool call whose budget started at `startedAt` (epoch ms). */
export function runWithCallBudget<T>(startedAt: number, work: () => Promise<T>): Promise<T> {
  const budgetMs = callBudgetMs();
  return current.run({ deadline: startedAt + budgetMs, budgetMs }, work);
}

/** Milliseconds left in the running call's budget; Infinity outside a tool call (startup warm-up, tests calling a tool directly). */
export function remainingCallBudgetMs(): number {
  const budget = current.getStore();
  return budget ? Math.max(0, budget.deadline - Date.now()) : Number.POSITIVE_INFINITY;
}

/**
 * `ms`, or less when the running call has less than that left after keeping `reserveMs` back for
 * what the tool still has to do afterwards. Never below zero.
 */
export function withinCallBudget(ms: number, reserveMs = 0): number {
  return Math.max(0, Math.min(ms, remainingCallBudgetMs() - reserveMs));
}

/** `work`, or `late()` when it has not settled within `ms` (it runs on; Infinity waits for it). */
export async function settleWithin<T>(work: Promise<T>, ms: number, late: () => T): Promise<T> {
  if (!Number.isFinite(ms)) return work;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<{ late: true }>((resolve) => {
    timer = setTimeout(() => resolve({ late: true }), Math.max(0, ms));
  });
  const settled = work.then((value) => ({ late: false as const, value }));
  try {
    const first = await Promise.race([settled, expired]);
    if (!first.late) return first.value;
    settled.catch(() => undefined);
    return late();
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** "20 s", "0.3 s", "40 ms": a budget as an answer states it (under 0.05 s it is in ms, never "0 s": blind audit round 3). */
export function secondsText(ms: number): string {
  if (ms < 50) return `${Math.max(0, Math.round(ms))} ms`;
  return `${Math.round(ms / 100) / 10} s`;
}

/**
 * `work`, or `late()` when the running call's budget ends first. `work` is not stopped: it runs on
 * and its result is dropped (its rejection too). Outside a tool call there is no deadline.
 */
export async function raceCallBudget<T>(work: Promise<T>, late: (budgetMs: number) => T): Promise<T> {
  const budget = current.getStore();
  if (!budget) return work;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<{ late: true }>((resolve) => {
    timer = setTimeout(() => resolve({ late: true }), Math.max(0, budget.deadline - Date.now()));
  });
  const settled = work.then((value) => ({ late: false as const, value }));
  try {
    const first = await Promise.race([settled, expired]);
    if (!first.late) return first.value;
    // Left running; whatever it ends with, nobody is waiting for it any more.
    settled.catch(() => undefined);
    return late(budget.budgetMs);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
