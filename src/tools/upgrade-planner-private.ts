// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_planner and private parents (review of #64, blocker). A public package that arrives
 * through a private one (`qs` under `@acme/api`, `smallvec` under an Acme registry's crate) has a
 * fix path that runs through the private parent: its releases and requirements are never looked
 * up (private-fix-sources.ts), so whether a parent upgrade or a refresh reaches the clean version
 * is not known. Such a step says so first, and never stands as a proceed: a refresh that was only
 * inferred (no requirement read) waits instead.
 */

import { readLockfileParents } from "../live/lockfile-parents.js";
import type { LiveIntelligence } from "../live/index.js";

interface PlannedStep {
  package: string;
  ecosystem: string;
  currentVersion: string | null;
  targetVersion: string | null;
  scope: "direct" | "transitive";
  action: string;
  reasons: string[];
  refreshInferred?: boolean;
  /** Set here: the private parents this step's fix path runs through, with why each is private. */
  privateParents?: Array<{ parent: string; why: string }>;
}

type PrivateLookup = Pick<LiveIntelligence, "privateReason" | "lockfileFor">;

export function markPrivateParents<T extends PlannedStep>(
  steps: T[],
  dirsOf: (step: T) => string[],
  live: PrivateLookup | null,
): void {
  if (!live) return;
  for (const step of steps) {
    if (step.scope !== "transitive" || !step.currentVersion) continue;
    const found = new Map<string, string>();
    for (const dir of dirsOf(step)) {
      const lockfile = live.lockfileFor(dir, step.ecosystem);
      if (!lockfile) continue;
      for (const edge of readLockfileParents(lockfile, step.package, step.currentVersion)?.edges ?? []) {
        if (edge.local) continue;
        const why = live.privateReason(step.ecosystem, edge.parent);
        if (why) found.set(edge.parent, why);
      }
    }
    if (found.size === 0) continue;
    step.privateParents = [...found].map(([parent, why]) => ({ parent, why }));
    const names = [...found.keys()].join(", ");
    step.reasons.unshift(
      `NOT CHECKED (private): ${step.package} arrives through ${names}, a private package, whose releases and requirements are never looked up; whether upgrading it or refreshing reaches ${step.targetVersion ?? "a clean version"} is not known. Check ${found.size === 1 ? "it" : "them"} in your private registry.`,
    );
    if (step.action === "lockfile_refresh" && step.refreshInferred) {
      step.action = "waiting_on_upstream";
      delete step.refreshInferred;
    }
  }
}
