// SPDX-License-Identifier: Apache-2.0
/**
 * One answer per finding: the fix-path verdict vulnerability_scan and upgrade_planner both give.
 *
 * On 4DA's own src-tauri (audit 2026-11-11, M8) the scan said "Upgrade zip 8.6.0 -> 9.0.5" while the
 * planner said, correctly, that docx-rs 0.4.22 (its newest release) requires `^8.6.0`: blocked
 * upstream, override or replace the parent. The scan named the advisory's fixed version as if the
 * project could bump it; for a transitive copy it cannot. Now the scan builds the same step for
 * every vulnerable copy, from the same inputs, and runs the planner's own fix-path verification on
 * it (verifyFixPaths, then reconcileDirectTargets): lockfile refresh, parent upgrade, override or
 * replace, blocked upstream.
 */

import { groupAdvisories } from "../live/advisory-groups.js";
import { computeSemverDistance } from "../live/semver-utils.js";
import type { VulnerabilityEntry } from "../live/types.js";
import { maxVersion } from "../live/version-compare.js";
import { reconcileDirectTargets, settleTransitiveBreaking, verifyFixPaths, type FixPathInput, type FixPathStep } from "./upgrade-planner-fixpaths.js";

/** The reason a transitive step carries until its fix path is read; verifyFixPaths replaces it with what it finds. */
export const TRANSITIVE_PENDING = "Transitive dependency — not declared in your manifest; the fix arrives via a parent package update or a lockfile refresh";

/** The directories that pin these copies AND build them on this host: where a fix for this host applies. */
export function builtDirs(entries: VulnerabilityEntry[]): string[] {
  const unbuilt = new Set(entries.flatMap((e) => e.platformInactiveDirs ?? []));
  const all = [...new Set(entries.flatMap((e) => e.sourceDirs ?? []))];
  const built = all.filter((d) => !unbuilt.has(d));
  return built.length > 0 ? built : all;
}

/** What fix-path verification reads of one vulnerable copy: its per-advisory fixes, where it is built, and the advisories no fix names. */
export function fixInputOf(entries: VulnerabilityEntry[]): Omit<FixPathInput, "step"> {
  const unfixed = groupAdvisories(entries).filter((g) => !g.members.some((m) => m.fixedVersion));
  return {
    fixes: entries.map((e) => e.fixedVersion).filter((f): f is string => Boolean(f)),
    sourceDirs: builtDirs(entries),
    unfixed: unfixed.map((g) => ({ id: g.best.vulnId, ids: [...g.ids] })),
  };
}

type Intel = Parameters<typeof verifyFixPaths>[1];

/** The scan's step for one vulnerable copy, as the planner builds its row before verification. */
function stepOf(entries: VulnerabilityEntry[]): FixPathStep {
  const first = entries[0];
  const fixes = entries.map((e) => e.fixedVersion).filter((f): f is string => Boolean(f));
  const target = fixes.length > 0 ? maxVersion(fixes, first.ecosystem) : null;
  const direct = entries.some((e) => e.isDirect === true);
  const d = target ? computeSemverDistance(first.currentVersion, target) : null;
  const upgradeType = !d || d.label === "up-to-date" ? "unknown" : d.label;
  return {
    package: first.package,
    ecosystem: first.ecosystem,
    currentVersion: first.currentVersion,
    targetVersion: target,
    upgradeType,
    reasons: direct ? [] : [TRANSITIVE_PENDING],
    breaking: direct && upgradeType === "major",
    scope: direct ? "direct" : "transitive",
    action: !target ? "no_fix_available" : direct ? "upgrade_direct" : "waiting_on_upstream",
    isDev: entries.every((e) => e.isDev),
  };
}

/**
 * The verified step for every vulnerable copy in `groups` (keyed as given), within `budgetMs`.
 * A copy whose verification did not finish keeps its pending step: the caller says so.
 */
export async function scanFixVerdicts(groups: Array<{ key: string; entries: VulnerabilityEntry[] }>, intel: Intel, budgetMs: number): Promise<Map<string, FixPathStep>> {
  const out = new Map<string, FixPathStep>();
  const inputs: FixPathInput[] = [];
  for (const { key, entries } of groups) {
    const step = stepOf(entries);
    out.set(key, step);
    inputs.push({ step, ...fixInputOf(entries) });
  }
  if (inputs.length === 0 || budgetMs <= 0) return out;
  await verifyFixPaths(inputs, intel, budgetMs);
  await reconcileDirectTargets(inputs.map((i) => i.step), inputs, intel);
  settleTransitiveBreaking(inputs.map((i) => i.step));
  return out;
}
