// SPDX-License-Identifier: Apache-2.0
/**
 * One advisory, many records. OSV publishes the same issue as a GHSA record
 * and as an ecosystem record (PYSEC, RUSTSEC, GO), each naming the other in
 * `aliases`. Counting records counted one issue two or three times:
 * - tokio 1.18.0 showed "6 advisories" for 3 (audit A9);
 * - pygoat's django "96 known vulnerabilities" for 51 (readiness audit M1, 2026-10-16).
 * Every count of advisories goes through here.
 */

import type { VulnerabilityEntry } from "./types.js";

const RANK: Record<string, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface AdvisoryGroup {
  /** Every id the group's records carry, aliases included. */
  ids: Set<string>;
  /** The most severe record, so merging never softens a verdict. */
  best: VulnerabilityEntry;
  members: VulnerabilityEntry[];
}

/**
 * Group the records of ONE installed copy by shared ids. The grouping is transitive: a record
 * naming ids of two groups joins them.
 */
export function groupAdvisories(entries: readonly VulnerabilityEntry[] | undefined): AdvisoryGroup[] {
  let groups: AdvisoryGroup[] = [];
  for (const v of entries ?? []) {
    const ids = [v.vulnId, ...(v.aliases ?? [])];
    const hit = groups.filter((g) => ids.some((id) => g.ids.has(id)));
    const merged: AdvisoryGroup = { ids: new Set(ids), best: v, members: [v] };
    for (const g of hit) {
      for (const id of g.ids) merged.ids.add(id);
      merged.members.push(...g.members);
      if ((RANK[g.best.severity] ?? 0) > (RANK[merged.best.severity] ?? 0)) merged.best = g.best;
    }
    groups = [...groups.filter((g) => !hit.includes(g)), merged];
  }
  return groups;
}

/** Distinct advisories among the records of one installed copy. */
export function distinctAdvisoryCount(entries: readonly VulnerabilityEntry[] | undefined): number {
  return groupAdvisories(entries).length;
}
