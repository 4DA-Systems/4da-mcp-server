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
  /** Facts read once per call (callMemo). */
  memo: Map<string, unknown>;
  /** Concrete negative findings already in hand, per checked item (noteCallFinding). */
  findings: Map<string, CallFinding>;
  /** The registry's own words this call's sentences point to (untrusted-text.ts registryQuote). */
  quotes: Map<string, string>;
}

/**
 * A finding a call already holds about one item before it finishes: the registry unpublished or
 * yanked the release, an advisory record (malware or not) affects it. When the call's budget ends
 * first, the answer keeps it (late-answer.ts, dependency_check's per-item time-budget result):
 * chalk 5.6.1 came back `unknown` though npm's "unpublished" and OSV.dev's MAL- record were both
 * read, because one hanging /v1/vulns request held the call past its budget (r7).
 */
export interface CallFinding {
  verdict: "avoid" | "review";
  /** In this server's words; at most a few findings, each with its source. */
  evidence: string[];
}

/** The key a finding is kept under: the item as the caller wrote it. */
export function callFindingKey(ecosystem: unknown, pkg: unknown, to: unknown): string {
  const t = (v: unknown) => (typeof v === "string" ? v.trim() : "");
  return `${t(ecosystem)}\0${t(pkg)}\0${t(to)}`;
}

/** Keep a finding for this call; the worse verdict stands, and evidence accumulates (deduplicated). */
export function noteCallFinding(key: string, verdict: CallFinding["verdict"], evidence: string): void {
  const findings = current.getStore()?.findings;
  if (!findings) return;
  const had = findings.get(key);
  const worst = had?.verdict === "avoid" || verdict === "avoid" ? "avoid" : "review";
  const all = [...(had?.evidence ?? [])];
  if (!all.includes(evidence)) all.push(evidence);
  findings.set(key, { verdict: worst, evidence: all.slice(0, 4) });
}

/** Keep third-party words for this call's top-level `quoted_from_registry` (first words kept per key). */
export function noteCallQuote(key: string, words: string): void {
  const quotes = current.getStore()?.quotes;
  if (quotes && !quotes.has(key)) quotes.set(key, words);
}

/** The words kept by noteCallQuote, or null when none (or outside a call). */
export function callQuotes(): Record<string, string> | null {
  const quotes = current.getStore()?.quotes;
  return quotes && quotes.size > 0 ? Object.fromEntries(quotes) : null;
}

/** The finding this call holds for an item, if any. */
export function callFinding(key: string): CallFinding | undefined {
  return current.getStore()?.findings.get(key);
}

const current = new AsyncLocalStorage<Budget>();

/** Run `work` as one tool call whose budget started at `startedAt` (epoch ms). */
export function runWithCallBudget<T>(startedAt: number, work: () => Promise<T>): Promise<T> {
  const budgetMs = callBudgetMs();
  return current.run({ deadline: startedAt + budgetMs, budgetMs, memo: new Map(), findings: new Map(), quotes: new Map() }, work);
}

/**
 * `compute()` once per tool call: inside a call the first answer for `key` is kept for the rest of
 * it; outside one (startup, tests calling a function directly) it is computed every time. For
 * facts a call reads as one snapshot, such as whether a lockfile changed: a scan stat-ed the same
 * lockfile thousands of times, a sixth of a fully cached scan (blind audit round 6).
 */
export function callMemo<T>(key: string, compute: () => T): T {
  const memo = current.getStore()?.memo;
  if (!memo) return compute();
  if (memo.has(key)) return memo.get(key) as T;
  const value = compute();
  memo.set(key, value);
  return value;
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

/** Below this, a wait is the budget running out, not a wait worth naming. */
const NEAR_ZERO_WAIT_MS = 100;

/**
 * Why a project's OSV.dev scan is missing from an answer, given how long the call could wait for
 * it. With FOURDA_CALL_BUDGET_MS at 1, 50 or 400 the wait is what is left of the budget, about 0,
 * and the answers said "did not finish within 0 ms" (blind audit round 4). At or near 0 the
 * sentence names the call's budget instead: it was used up before the scan could finish.
 */
export function scanUnfinishedText(waitMs: number, what = "the OSV.dev scan"): string {
  if (waitMs >= NEAR_ZERO_WAIT_MS) return `${what} did not finish within ${secondsText(waitMs)}, the time this call had for it`;
  const budgetMs = current.getStore()?.budgetMs ?? callBudgetMs();
  const source = Number(process.env.FOURDA_CALL_BUDGET_MS) > 0 ? ", from FOURDA_CALL_BUDGET_MS" : "";
  return `this call's time budget (${secondsText(budgetMs)}${source}) was used up before ${what} could finish`;
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
