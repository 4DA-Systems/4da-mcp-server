// SPDX-License-Identifier: Apache-2.0
/**
 * The time budget of the project-tree walk (project-tree.ts).
 *
 * The walk runs synchronously, at startup and on the first tool call, over a
 * directory tree the server did not write. Its directory and project counts
 * were bounded; its time was not, so a tree built to be slow (or simply a huge
 * one on a slow disk) held the event loop, and with it every request: no
 * `tools/list`, no `dependency_check`, no error either (audit 2026-11-11, M4).
 *
 * Past the budget the walk stops where it is and says so: `walkTruncated` with
 * `walkStopped: "time_budget"`, which every tool reports as a partial scan
 * ("coverage not complete"), never as a clean one. The same happens when the
 * repository's ignore rules ran out of their own matching budget
 * (gitignore.ts `exhausted`): going on without them would scan directories
 * the repository excludes and call the result the project's.
 *
 * FOURDA_WALK_BUDGET_MS overrides the default (tests; a very large monorepo
 * on a slow disk).
 */

/** Measured 2026-10-10 on langchain (108 lockfiles): about 2 s, walk and project scans together. */
const DEFAULT_WALK_BUDGET_MS = 10_000;

export function walkBudgetMs(): number {
  const raw = Number(process.env.FOURDA_WALK_BUDGET_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_WALK_BUDGET_MS;
}

export interface WalkBudget {
  /** True once the budget is used up (or the ignore rules gave out); checked once per directory. */
  spent(): boolean;
  /** Whether `spent()` has answered true: the walk stopped on time, not on its directory count. */
  stopped: boolean;
}

/** A budget that starts now. `ignore` is the walk's rule set, whose own exhaustion also ends the walk. */
export function startWalkBudget(ignore?: { exhausted: boolean }): WalkBudget {
  const deadline = Date.now() + walkBudgetMs();
  const budget: WalkBudget = {
    stopped: false,
    spent() {
      if (!budget.stopped && (Date.now() > deadline || ignore?.exhausted === true)) budget.stopped = true;
      return budget.stopped;
    },
  };
  return budget;
}

/** The clause discoveryNote adds for a walk that stopped on its budget. */
export function walkBudgetNote(): string {
  return `the directory walk stopped at its ${Math.round(walkBudgetMs() / 100) / 10} s time budget, so the directories it had not reached were not read and their lockfiles were not counted`;
}
