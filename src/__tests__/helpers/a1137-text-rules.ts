// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14, X5: the emitted text constants of what_should_i_know, each with the levels at which it may appear. The
 * vendored runners (a1137-review12-runner.ts) apply TEXT_RULES to every answer they get: a text said where its rule
 * does not hold fails the run. Adding a text constant means adding its rule here.
 */
import { STAYS_REVIEW } from "../../tools/briefing-command-check.js";
import { BEST_EFFORT_READING, DECLARE_REASON, NO_DECISION_CONFLICT, OUTSIDE_COVERAGE, RESTS_ON_DECLARATION, SCAN_STILL_READS, SOURCE_HELD } from "../../tools/briefing-confirm.js";

type Answer = Record<string, any>;
type Args = Record<string, any>;
export interface TextRule {
  /** The constant (or text family) as the code names it. */
  constant: string;
  /** Where in the answer it is looked for. */
  found: (r: Answer) => boolean;
  /** When it may be said. */
  holds: (r: Answer, args: Args) => boolean;
  /** The rule, in words (THE CONTRACT names this table). */
  when: string;
}
const reason = (r: Answer) => String(r?.delegation_assessment?.reason ?? "");
const level = (r: Answer) => String(r?.delegation_assessment?.level ?? "");
const declared = (a: Args) => Array.isArray(a.packages) && a.packages.length > 0;

export const TEXT_RULES: readonly TextRule[] = [
  { constant: "RESTS_ON_DECLARATION", found: (r) => reason(r).includes(RESTS_ON_DECLARATION), holds: (r) => level(r) === "safe_to_delegate" && reason(r).endsWith(RESTS_ON_DECLARATION), when: "safe_to_delegate only, as the reason's last sentence" },
  {
    constant: "nothing version-confirmed (no project findings)",
    found: (r) => /nothing version-confirmed, no major-version jump/.test(reason(r)),
    holds: (r) => !(r?.advisories ?? []).some((a: Answer) => a.scope === "project" && a.version_confirmed === true && a.signal_type === "security_alert" && !String(a.title).includes("the installed")),
    when: "only when no project-wide finding is listed",
  },
  { constant: "OUTSIDE_COVERAGE", found: (r) => reason(r).includes(OUTSIDE_COVERAGE), holds: (r) => level(r) === "safe_to_delegate", when: "safe_to_delegate, before its last sentence" },
  { constant: "BEST_EFFORT_READING", found: (r) => reason(r).includes(BEST_EFFORT_READING), holds: (r, a) => level(r) === "safe_to_delegate" && declared(a), when: "safe_to_delegate in a call that declared at least one package" },
  { constant: "STAYS_REVIEW", found: (r) => reason(r).includes(STAYS_REVIEW), holds: (r) => level(r) !== "safe_to_delegate", when: "any level but safe_to_delegate" },
  { constant: "DISMISSED_READ", found: (r) => /\byou said \S+ is not a package; (?:it stands|the task writes a version)/i.test(reason(r)), holds: (r) => level(r) !== "safe_to_delegate", when: "any level but safe_to_delegate" },
  { constant: "DISMISSED_INSTEAD", found: (r) => /\byou said \S+ is not a package and declared \S+ instead/i.test(reason(r)), holds: (r) => level(r) !== "safe_to_delegate", when: "any level but safe_to_delegate" },
  { constant: "CREDENTIAL_REFUSAL", found: (r) => JSON.stringify(r?.task_packages?.not_read ?? []).includes("a value of a credential's shape is not a"), holds: (r) => level(r) !== "safe_to_delegate", when: "a refused argument: any level but safe_to_delegate" },
  { constant: "INSTALLED_MALWARE", found: (r) => /installed, which (?:is|are) recorded as malware: a person must deal with that before any task is delegated/.test(reason(r)), holds: (r) => level(r) === "human_only", when: "human_only only: an installed copy whose installed version is malware" },
  { constant: "INSTALLED_PLACEHOLDER", found: (r) => /installed, npm's placeholders? for (?:a name|names) taken down as malware: a person must remove/.test(reason(r)), holds: (r) => level(r) === "human_only", when: "human_only only: an installed npm security placeholder" },
  {
    constant: "PROJECT_FINDINGS_LISTED",
    found: (r) => /nothing version-confirmed for the packages this task touches; \d+ project-wide finding/.test(reason(r)),
    holds: (r) => level(r) === "safe_to_delegate" && (r?.advisories ?? []).some((a: Answer) => a.scope === "project" && a.version_confirmed === true),
    when: "safe_to_delegate, with a version-confirmed project-wide row in advisories",
  },
  { constant: "NO_DECISION_CONFLICT", found: (r) => reason(r).includes(NO_DECISION_CONFLICT), holds: (r) => Array.isArray(r?.decision_conflicts) && r.decision_conflicts.length === 0, when: "only when decisionConflictsFor found none over the declared, read and installed names (decision_conflicts empty)" },
  { constant: "SOURCE_HELD", found: (r) => JSON.stringify(r?.task_packages?.not_read ?? []).includes(SOURCE_HELD), holds: (r) => level(r) !== "safe_to_delegate", when: "a name was held (not looked up): any level but safe_to_delegate" },
  { constant: "unreadableReason", found: (r) => /this briefing could not read whole|This task holds a line longer|This task holds a command this briefing does not read/.test(reason(r)), holds: (r) => level(r) !== "safe_to_delegate", when: "any level but safe_to_delegate" },
  { constant: "split the task (call-budget cut texts)", found: (r) => /split the task and ask for each part/.test(reason(r)), holds: (r) => level(r) !== "safe_to_delegate", when: "any level but safe_to_delegate" },
  { constant: "DECLARE_REASON", found: (r) => reason(r).startsWith(DECLARE_REASON), holds: (r, a) => level(r) === "confirmation_needed" && a.packages === undefined, when: "confirmation_needed, in a call without packages" },
  { constant: "SCAN_STILL_READS", found: (r) => reason(r).includes(SCAN_STILL_READS.replace(/\.$/, "")), holds: (r) => level(r) !== "safe_to_delegate", when: "any level but safe_to_delegate" },
];

/** The rules a given answer breaks (empty: every text it says is true at its level). */
export function brokenTextRules(r: Answer, args: Args): string[] {
  return TEXT_RULES.filter((t) => t.found(r) && !t.holds(r, args)).map((t) => `${t.constant} (${t.when})`);
}
