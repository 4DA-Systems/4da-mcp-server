// SPDX-License-Identifier: Apache-2.0
/**
 * Whether a vulnerability scan answered for every dependency it was given.
 *
 * Until 6.2.5 an OSV.dev outage, a 503, a timeout or the server's own rate
 * limit turned a scan into `total_vulnerable_packages: 0`, flagged only by
 * `_meta.offline` at the end of the answer, and dependency_health and
 * upgrade_planner then scored and ranked that as a clean project (10,568
 * dependencies of D:\4DA\src-tauri, 0 vulnerable, 2026-10-12). Every scan
 * consumer now asks this module first, and an incomplete scan leads its
 * answer with what was not checked.
 */

import { privateLine } from "./private-packages.js";
import type { VulnerabilityCoverage, VulnerabilityScanResult } from "./types.js";

/** The reason given when live lookups are switched off. */
export const LOOKUPS_DISABLED = "live lookups are disabled (FOURDA_OFFLINE=true)";

/**
 * Null when every dependency the scan was given has an advisory answer.
 * Otherwise how many have none, and why. `result` null means no scan backs
 * the answer at all: `expectedTotal` dependencies are then all unchecked.
 */
export function vulnerabilityCoverage(
  result: VulnerabilityScanResult | null,
  opts: { enabled: boolean; expectedTotal?: number; notLoaded?: string },
): VulnerabilityCoverage | null {
  const coverage = osvCoverage(result, opts);
  const priv = result?.privateExcluded;
  if (!priv || priv.count <= 0) return coverage;
  // Private names were never sent (private-packages.ts): not checked, never clean. Counted apart
  // from the OSV answer, so an incomplete answer here does not read as an OSV.dev outage.
  const line = privateLine(priv.count, priv.dependencies.map((d) => d.name));
  const base: VulnerabilityCoverage = coverage ?? {
    complete: false,
    total_dependencies: result!.totalScanned,
    checked_dependencies: result!.totalScanned,
    unchecked_dependencies: 0,
    reason: "private dependencies were not sent",
    note: line,
  };
  return {
    ...base,
    private_dependencies: priv.count,
    private_dependency_list: priv.dependencies,
    note: coverage ? `${coverage.note} ${line}` : line,
  };
}

function osvCoverage(
  result: VulnerabilityScanResult | null,
  opts: { enabled: boolean; expectedTotal?: number; notLoaded?: string },
): VulnerabilityCoverage | null {
  if (!result) {
    const total = opts.expectedTotal ?? 0;
    const reason = opts.enabled ? (opts.notLoaded ?? "the OSV.dev scan did not finish in time or OSV.dev was unreachable") : LOOKUPS_DISABLED;
    return build(total, total, reason);
  }
  // A stub or an older result that says offline without a count answered for nothing.
  const unchecked = result.unchecked ?? (result.offline ? result.totalScanned : 0);
  const stale = result.staleAnswers ?? 0;
  // Advisories matched whose record never arrived: their severity and fix version are gaps (T7).
  const details = result.detailsUnchecked ?? [];
  if (unchecked <= 0 && stale <= 0 && details.length === 0) return null;
  const detailsGap = details.length > 0 ? { details_unchecked: details.length } : {};
  const withDetails = (note: string) => (details.length > 0 ? `${note} ${detailsLine(details)}` : note);
  if (unchecked > 0) {
    const gap = build(result.totalScanned, unchecked, result.uncheckedReason ?? "OSV.dev could not be queried");
    const note = withDetails(stale > 0 ? `${gap.note} ${staleLine(result, stale)}` : gap.note);
    return { ...gap, ...(stale > 0 ? { stale_dependencies: stale } : {}), ...detailsGap, note };
  }
  if (stale > 0) {
    // Every dependency has an answer, but some only from an expired cache because the fresh query
    // failed. That answer can predate an advisory, so it is not a current all-clear (audit 6.2.5
    // B-2: dependency_check said `proceed` and the scan "0 vulnerable" on a 1 h old answer).
    const reason = result.staleReason ?? "OSV.dev could not be queried";
    return {
      complete: false,
      total_dependencies: result.totalScanned,
      checked_dependencies: result.totalScanned,
      unchecked_dependencies: 0,
      stale_dependencies: stale,
      ...detailsGap,
      reason,
      note: withDetails(`STALE: ${reason}. ${staleLine(result, stale)}`),
    };
  }
  // Every dependency was matched against OSV, but some matched advisories are known by id only.
  return {
    complete: false,
    total_dependencies: result.totalScanned,
    checked_dependencies: result.totalScanned,
    unchecked_dependencies: 0,
    ...detailsGap,
    reason: `OSV.dev did not return the record of ${details.length} matched advisor${details.length === 1 ? "y" : "ies"}`,
    note: `NOT CHECKED (advisory details): ${detailsLine(details)}`,
  };
}

/** "OSV.dev matched N advisories (ids) but did not return their records ..." */
function detailsLine(ids: string[]): string {
  const one = ids.length === 1;
  const listed = `${ids.slice(0, 5).join(", ")}${ids.length > 5 ? ", ..." : ""}`;
  return `OSV.dev matched ${ids.length.toLocaleString("en-US")} advisor${one ? "y" : "ies"} (${listed}) but did not return ${one ? "its record" : "their records"}, so ${one ? "its" : "their"} severity and fix version are unknown: unknown is not low, and no fix version listed is not "no fix published". Call again (force_refresh), or read https://osv.dev/vulnerability/<id>.`;
}

/** "N dependencies were answered only from an expired cached answer (the oldest fetched ...)". */
function staleLine(result: VulnerabilityScanResult, stale: number): string {
  const n = stale.toLocaleString("en-US");
  const oldest = result.staleOldestFetchedAt ? ` (the oldest fetched ${result.staleOldestFetchedAt} UTC)` : "";
  return `${n} dependenc${stale === 1 ? "y was" : "ies were"} answered only from an expired cached answer${oldest}; an advisory published since would not show, so this is not a current all-clear. Call again once OSV.dev answers (force_refresh).`;
}

function build(total: number, unchecked: number, reason: string): VulnerabilityCoverage {
  return {
    complete: false,
    total_dependencies: total,
    checked_dependencies: Math.max(0, total - unchecked),
    unchecked_dependencies: unchecked,
    reason,
    note: notCheckedLine(reason, unchecked, total),
  };
}

/** The first line an incomplete answer leads with. */
export function notCheckedLine(reason: string, unchecked: number, total: number): string {
  const n = (x: number) => x.toLocaleString("en-US");
  const scope = total > 0 ? `${n(unchecked)} of ${n(total)} dependencies have no vulnerability answer` : "no dependency has a vulnerability answer";
  return `NOT CHECKED: ${reason} — ${scope}. Their absence from the findings means nothing: this is not a clean result. Call again once OSV.dev answers (force_refresh), or check them another way.`;
}
