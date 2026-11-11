// SPDX-License-Identifier: Apache-2.0
/**
 * What a tool call answers when it ran out of its time budget (call-budget.ts).
 *
 * The dispatcher answers in the tool's place, so the answer is built from the
 * request alone and claims nothing: every `dependency_check` item is
 * `unknown`, and every other tool gets an error that starts with NOT CHECKED,
 * the words this server uses wherever a result is incomplete. It states the
 * budget that was actually spent. Never a clean result, and never a partial
 * one passed off as whole.
 */

import { secondsText } from "./call-budget.js";

const AGAIN = "The lookups it started keep running and their answers are cached: make the same call again.";

function text(value: unknown): string {
  return typeof value === "string" ? value.slice(0, 256) : "";
}

/** The answer for `tool`, called with `args`, after `budgetMs` without a result. */
export function lateAnswer(tool: string, args: Record<string, unknown>, budgetMs: number): Record<string, unknown> {
  const spent = secondsText(budgetMs);
  if (tool === "dependency_check" && Array.isArray(args.items)) {
    const items = args.items.filter((i): i is Record<string, unknown> => i !== null && typeof i === "object");
    const reason = `NOT CHECKED: the registry and advisory lookups for this call did not finish within ${spent}, so nothing about this version was verified. This is not a proceed. ${AGAIN}`;
    return {
      checked_at: new Date().toISOString(),
      summary: `NOT CHECKED: dependency_check did not finish within ${spent}; ${items.length} checked: ${items.length} unknown. Write none of these versions on this answer. ${AGAIN}`,
      results: items.map((i) => ({
        ecosystem: text(i.ecosystem),
        package: text(i.package),
        from: text(i.from) || null,
        to: text(i.to),
        verdict: "unknown",
        reason,
        signals: [],
      })),
      _meta: { call_budget_exceeded: true, call_budget_ms: budgetMs },
    };
  }
  const message = `NOT CHECKED: ${tool} did not finish within ${spent}, so this call verified nothing; the absence of findings here is not a clean result. ${AGAIN}`;
  return { error: message, summary: message, call_budget_exceeded: true, call_budget_ms: budgetMs };
}
