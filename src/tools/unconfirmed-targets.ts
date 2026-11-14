// SPDX-License-Identifier: Apache-2.0
/**
 * A fix target OSV.dev did not confirm clean is never given in a field an agent pins from.
 *
 * Pre-publish audit 2026-11-14: with the first querybatch answered and the confirmation queries
 * (batch-confirm.ts) failing, vulnerability_scan and upgrade_planner still put the unconfirmed
 * release in `fix_targets[].target`, `fixed_version` and `targetVersion` (qs 6.16.0, which
 * GHSA-6pq8-jhm2-2vcw affects; the confirmed run picks 6.16.1), with "NOT CHECKED" only in the
 * prose beside it. An agent reading the fields alone pins a vulnerable release. Now such a field is
 * null, the release is named in a NOT CHECKED sentence, and no sentence calls it clean or safe.
 */

/** Why a copy names no target although its advisories name a fix: the candidate, NOT CHECKED, in words. */
export function unconfirmedTargetNote(pkg: string, candidate: string | null, detail: string | null): string {
  const head = candidate
    ? `NOT CHECKED: ${candidate} was not confirmed free of ${pkg}'s known advisories, so no target is given`
    : `NOT CHECKED: no release of ${pkg} was confirmed free of its known advisories, so no target is given`;
  const why = detail ? `; ${unconfirmedWords(detail)}` : "";
  return `${head}${why}. Run dependency_check on a release before pinning it`;
}

/** A sentence about a release OSV.dev did not confirm: "smallest clean" never survives in it. */
export function unconfirmedWords(text: string): string;
export function unconfirmedWords(text: string | null): string | null;
export function unconfirmedWords(text: string | null): string | null {
  if (text === null) return null;
  return text
    .replace(/ is the smallest clean release\b/g, " is the smallest installable release past it (NOT CHECKED against every advisory)")
    .replace(/\bsmallest clean\b/g, "smallest installable");
}

/** Commands, less any that names the unconfirmed release (an agent runs the command it reads). */
export function commandsWithout<T extends { command?: string; instruction?: string }>(list: T[] | undefined, candidate: string | null): T[] | undefined {
  if (!list || !candidate) return list;
  const kept = list.filter((c) => !(c.command ?? c.instruction ?? "").includes(candidate));
  return kept.length > 0 ? kept : undefined;
}

/** The planner fields this rewrites. */
interface PlanStep {
  package: string;
  targetVersion: string | null;
  upgradeType: string;
  reasons: string[];
  fixPathChecked?: "all_advisories" | "installed_advisories_only";
  refreshCommands?: Array<{ dir: string; command: string }>;
  upgradeCommands?: Array<{ dir: string; command: string; refresh?: true }>;
  upgradeInstructions?: Array<{ dir: string; instruction: string }>;
}

/**
 * upgrade_planner: every vulnerable step whose target was not checked against every advisory of
 * the package (`fixPathChecked: installed_advisories_only`) names no `targetVersion`; the release
 * is in a NOT CHECKED reason (first, on direct and transitive rows alike), and commands that pin it
 * are dropped.
 */
export function withholdUnconfirmedTargets(steps: PlanStep[]): void {
  for (const step of steps) {
    if (step.fixPathChecked !== "installed_advisories_only" || !step.targetVersion) continue;
    const candidate = step.targetVersion;
    step.targetVersion = null;
    step.upgradeType = "unknown";
    step.reasons = [unconfirmedTargetNote(step.package, candidate, null), ...step.reasons.map((r) => unconfirmedWords(r))];
    const refresh = commandsWithout(step.refreshCommands, candidate);
    const upgrade = commandsWithout(step.upgradeCommands, candidate);
    const instructions = commandsWithout(step.upgradeInstructions, candidate);
    if (refresh) step.refreshCommands = refresh;
    else delete step.refreshCommands;
    if (upgrade) step.upgradeCommands = upgrade;
    else delete step.upgradeCommands;
    if (instructions) step.upgradeInstructions = instructions;
    else delete step.upgradeInstructions;
  }
}
