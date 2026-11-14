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

import { callFinding, callFindingKey, secondsText, type CallFinding } from "./call-budget.js";
import { unquotePackageName } from "./tools/package-name.js";

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
    // What the call had already read stands: a finding in hand is the item's verdict (r7).
    const found = items.map((i) => callFinding(callFindingKey(i.ecosystem, typeof i.package === "string" ? unquotePackageName(i.package) : i.package, i.to)));
    const counts = (["avoid", "review"] as const).flatMap((v) => {
      const n = found.filter((f) => f?.verdict === v).length;
      return n > 0 ? [`${n} ${v}`] : [];
    });
    const unknown = found.filter((f) => !f).length;
    const tally = [...counts, ...(unknown > 0 ? [`${unknown} unknown`] : [])].join(", ");
    return {
      checked_at: new Date().toISOString(),
      summary: `NOT CHECKED: dependency_check did not finish within ${spent}; ${items.length} checked: ${tally}. Write none of these versions on this answer${counts.length > 0 ? "; an avoid or review stands on what was already read" : ""}. ${AGAIN}`,
      results: items.map((i, k) => ({
        ecosystem: text(i.ecosystem),
        package: text(i.package),
        from: text(i.from) || null,
        to: text(i.to),
        verdict: found[k]?.verdict ?? "unknown",
        reason: found[k] ? findingReason(found[k]!, spent) : reason,
        signals: [],
      })),
      _meta: { call_budget_exceeded: true, call_budget_ms: budgetMs },
    };
  }
  const message = `NOT CHECKED: ${tool} did not finish within ${spent}, so this call verified nothing; the absence of findings here is not a clean result. ${AGAIN}`;
  return { error: message, summary: message, call_budget_exceeded: true, call_budget_ms: budgetMs };
}

/**
 * The reason of an item whose check ran out of time with a finding already in hand: the finding
 * first, then that the rest was not checked. Never a proceed; the verdict is the worst one known.
 */
export function findingReason(f: CallFinding, spent: string): string {
  return `${f.evidence.join(" | ")} | The rest of the check did not finish within ${spent} (NOT CHECKED), but what was already read is enough: this is ${f.verdict === "avoid" ? "avoid" : "at least review"}, never a proceed. ${AGAIN}`;
}
