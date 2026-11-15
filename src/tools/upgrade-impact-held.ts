// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_impact and what the target release holds (pre-publish round 10, W6).
 *
 * `{npm, express, from 4.17.1, to 4.21.2}` said `advisories_remaining: []` and "2 advisories
 * fixed", with no word that 4.21.2 exact-pins qs 6.13.0, body-parser 1.20.3 and path-to-regexp
 * 0.1.12, each affected per OSV: installing the target installs them. dependency_check (avoid),
 * vulnerability_scan and upgrade_planner already judged a release by what it holds
 * (held-dependencies.ts, audit 6.2.5 D-4); upgrade_impact judged express's own advisories only.
 *
 * Here the target is judged by the planner's own rule (held-targets.ts withHeldTargets): its
 * exact pins and narrow ranges, in one advisory lookup, and when one is affected the later
 * releases on its line that the package's own advisories leave clean, the first whose held
 * dependencies are clean being named. Fail closed: when the registry or OSV.dev cannot say what
 * the target installs, the answer is NOT CHECKED, never clean.
 */

import { withHeldTargets } from "../live/held-targets.js";
import { andList, heldText, type AdvisoryQuery, type HeldDependency } from "../live/held-dependencies.js";
import type { FixPathSources, FixTargetResult } from "../live/fix-paths.js";
import type { VulnerabilityEntry } from "../live/types.js";

/** The planner's sources and the shared advisory lookup (LiveIntelligence); null when the server has none. */
export interface HeldContext {
  sources: FixPathSources;
  query: AdvisoryQuery;
}

/** Time the held-dependency check of one upgrade_impact call may take. */
const HELD_BUDGET_MS = 10_000;

export type HeldImpact =
  | {
      status: "affected";
      affected: HeldDependency[];
      /** The first later release on the target's line whose own advisories and held dependencies are clean; null when none was found. */
      firstClean: string | null;
      /** Releases searched and found to hold something affected, or not judged (with no clean one found). */
      searched: string[];
      unchecked: string[];
    }
  | { status: "unchecked"; reason: string };

/**
 * What installing `to` brings in at a fixed version; null when it holds nothing affected. Only
 * asked when the registry index says `to` holds something (a release that holds nothing needs no
 * lookup).
 */
export async function judgeTargetHeld(held: HeldContext | null | undefined, name: string, from: string, to: string): Promise<HeldImpact | null> {
  if (!held) return { status: "unchecked", reason: "this server has no advisory lookup for them" };
  // The target as a fix-path result, so the planner's own search judges it (and the releases after it).
  const seed: FixTargetResult = { target: to, basis: "registry", floor: to, floorAffectedBy: [], stillAffectedBy: [], unfixable: [], withheld: [] };
  let result: FixTargetResult | undefined;
  try {
    result = (await withHeldTargets(held.sources, held.query, [{ key: "to", name, installed: from, clean: seed }], Date.now() + HELD_BUDGET_MS)).get("to");
  } catch (err) {
    return { status: "unchecked", reason: `the check failed (${String((err as Error)?.message ?? err).slice(0, 120)})` };
  }
  if (!result) return null;
  if (result.heldUnchecked !== undefined) return { status: "unchecked", reason: result.heldUnchecked };
  if (result.heldBlocked) {
    return { status: "affected", affected: result.heldBlocked.affected, firstClean: null, searched: result.heldBlocked.searched, unchecked: result.heldBlocked.unchecked ?? [] };
  }
  if (result.heldFrom && result.heldPast && result.heldPast.length > 0 && result.target) {
    return { status: "affected", affected: result.heldPast[0].affected, firstClean: result.target, searched: result.heldPast.map((p) => p.version), unchecked: [] };
  }
  return null;
}

/** The held dependencies affected, as dependency_check names them (`held_dependencies_affected`). */
export function heldAffectedRows(affected: HeldDependency[]): Array<{ package: string; spec: string; installs: string; advisories: string[]; severity: VulnerabilityEntry["severity"] }> {
  return affected.map((d) => ({ package: d.name, spec: d.spec, installs: d.version, advisories: d.ids, severity: d.severity }));
}

/**
 * The clause the summary and `held_note` carry. `firstCleanOwn` is OSV.dev's answer for the
 * release named clean (its own advisories, asked of that exact release): one that does not come
 * back empty is not named.
 */
export function heldImpactText(to: string, impact: HeldImpact, firstCleanOwn?: string[] | null): string {
  if (impact.status === "unchecked") {
    return `NOT CHECKED: whether the dependencies ${to} holds (its exact pins and ranges) have known advisories could not be checked (${impact.reason}); installing ${to} installs them, so this is not a clean result`;
  }
  const n = impact.affected.length;
  const base = `${heldText(to, impact.affected)}: installing ${to} installs ${n === 1 ? "it" : "them"}, so ${to} is not a clean target`;
  if (impact.firstClean && firstCleanOwn !== undefined && (firstCleanOwn === null || firstCleanOwn.length > 0)) {
    const why = firstCleanOwn === null ? "OSV.dev could not be asked about it" : `OSV.dev names ${firstCleanOwn.slice(0, 3).join(", ")} against it`;
    return `${base}; ${impact.firstClean} holds nothing affected, but ${why}: confirm a release with dependency_check before pinning it`;
  }
  if (impact.firstClean) return `${base}; ${impact.firstClean} is the first later release on its line whose own advisories and held dependencies are clean`;
  const last = impact.searched[impact.searched.length - 1];
  const upTo = last && last !== to ? `up to ${last} ` : "";
  const partial = impact.unchecked.length > 0 ? ` (${andList(impact.unchecked)} NOT CHECKED)` : "";
  return `${base}; no later release on its line ${upTo}that its own advisories leave clean clears ${n === 1 ? "it" : "them"}${partial}: confirm a release with dependency_check before pinning it`;
}
