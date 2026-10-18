// SPDX-License-Identifier: Apache-2.0
/**
 * One advisory, many records. OSV publishes the same issue as a GHSA record
 * and as an ecosystem record (PYSEC, RUSTSEC, GO), each naming the other in
 * `aliases`. Counting records counted one issue two or three times:
 * - tokio 1.18.0 showed "6 advisories" for 3 (audit A9);
 * - pygoat's django "96 known vulnerabilities" for 51 (readiness audit M1, 2026-10-16).
 * Every count of advisories goes through here.
 */

import { isMaintenanceNotice } from "./maintenance.js";
import { isMalware } from "./malware.js";
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

/** One record of an alias group, as the group grade reads it. */
export interface GradedRecord {
  id: string;
  /** Its own grade: the curated label first, the CVSS band second (osv-scanner.ts deriveSeverity); unknown when it has none. */
  own: VulnerabilityEntry["severity"];
  aliases: readonly string[];
  maintenance: boolean;
  /** The record's CWE ids (`database_specific.cwe_ids`), for the malware predicate. */
  cweIds?: readonly string[];
}

/** The grade of one alias group, and where it came from. */
export interface GroupGrade {
  /** Null when nothing grades it, even through its aliases. */
  severity: Exclude<VulnerabilityEntry["severity"], "unknown"> | null;
  /** The GHSA alias an inherited grade came from; null for a grade a record of the group has itself. */
  inheritedFrom: string | null;
  /** The group record whose own grade it is, when it is one. */
  ownFrom: string | null;
  /**
   * The base urgency the Upgrade Plan and the alerts rank by, before the scope rule: the tier
   * (`low` reading `watch`); a group nothing grades is `medium`; a group of maintenance notices only
   * `watch`; a malicious-package record (MAL-) `high`.
   */
  urgency: "critical" | "high" | "medium" | "watch";
}

/**
 * THE grade of one alias group, shared with the 4DA app (`fourda_depengine::severity`, vectors
 * severity.jsonl sv-001..sv-019): the MOST severe OWN grade among the group's records; only when no
 * record has one, the highest grade among their GHSA aliases that can be read (`aliasGrades`, null =
 * held but ungraded), the smallest id on a tie. An unmaintained-package notice is never graded
 * from an alias.
 */
export function gradeGroup(records: readonly GradedRecord[], aliasGrades: ReadonlyMap<string, VulnerabilityEntry["severity"] | null>): GroupGrade {
  let own: { id: string; grade: VulnerabilityEntry["severity"] } | null = null;
  for (const r of records) {
    if (r.own === "unknown") continue;
    if (!own || RANK[r.own] > RANK[own.grade]) own = { id: r.id, grade: r.own };
  }
  let severity: GroupGrade["severity"] = null;
  let inheritedFrom: string | null = null;
  if (own) {
    severity = own.grade as GroupGrade["severity"];
  } else {
    const ids = new Set(records.map((r) => r.id));
    const ghsas = [...new Set(records.filter((r) => !r.maintenance).flatMap((r) => r.aliases.filter((a) => /^GHSA-/i.test(a) && !ids.has(a))))].sort();
    let best: { id: string; grade: VulnerabilityEntry["severity"] } | null = null;
    for (const id of ghsas) {
      const g = aliasGrades.get(id);
      if (!g || g === "unknown") continue;
      if (!best || RANK[g] > RANK[best.grade]) best = { id, grade: g };
    }
    if (best) {
      severity = best.grade as GroupGrade["severity"];
      inheritedFrom = best.id;
    }
  }
  // A malicious-package record (malware.ts) is critical (the 4DA lead, 2026-10-18; sv-010 read high).
  const malicious = records.some((r) => isMalware(r.id, r.aliases, r.cweIds ?? []));
  const urgency: GroupGrade["urgency"] = malicious
    ? "critical"
    : severity === "critical" || severity === "high" || severity === "medium"
      ? severity
      : severity === "low"
        ? "watch"
        : records.every((r) => r.maintenance)
          ? "watch"
          : "medium";
  return { severity, inheritedFrom, ownFrom: own?.id ?? null, urgency };
}

/**
 * One severity per advisory, in every tool (the rule shared with the 4DA app, gradeGroup): within
 * one alias group of one installed copy, every record carries the group's grade. vulnerability_scan
 * kept the "richest" record's grade while dependency_check, dependency_health and upgrade_planner
 * kept the most severe, so CVE-2026-4277 (GHSA-pwjp-ccjc-ghwg rated LOW, PYSEC-2026-52 CVSS 9.8) was
 * low in one tool and critical in the others (final release audit of 6.2.5, 2026-10-18). A record
 * that does not carry the grade itself names where it came from (`severityFrom`: the group record,
 * or the GHSA alias of an inherited grade). A grade a record took from its alias
 * (osv-scanner.ts rateFromAliases) never overrides an own grade in its group.
 */
export function gradeAliasGroups(entries: readonly VulnerabilityEntry[]): VulnerabilityEntry[] {
  const byCopy = new Map<string, VulnerabilityEntry[]>();
  for (const v of entries) {
    const key = `${v.ecosystem}\u0000${v.package}\u0000${v.currentVersion}\u0000${v.installDriftOf ?? ""}`;
    byCopy.set(key, [...(byCopy.get(key) ?? []), v]);
  }
  const regraded = new Map<VulnerabilityEntry, VulnerabilityEntry>();
  for (const copy of byCopy.values()) {
    for (const group of groupAdvisories(copy)) {
      if (group.members.length < 2) continue;
      const inherited = (m: VulnerabilityEntry) => Boolean(m.severityFrom) && m.severityFrom !== m.vulnId;
      const aliasGrades = new Map<string, VulnerabilityEntry["severity"]>();
      for (const m of group.members) if (inherited(m)) aliasGrades.set(m.severityFrom!, m.severity);
      const grade = gradeGroup(
        group.members.map((m) => ({ id: m.vulnId, own: inherited(m) ? "unknown" : m.severity, aliases: [...m.aliases, ...(inherited(m) ? [m.severityFrom!] : [])], maintenance: isMaintenanceNotice(m) })),
        aliasGrades,
      );
      const severity = grade.severity ?? "unknown";
      const from = grade.inheritedFrom ?? grade.ownFrom;
      for (const m of group.members) {
        if (isMaintenanceNotice(m) && grade.inheritedFrom) continue;
        if (m.severity === severity && (!inherited(m) || m.severityFrom === from)) continue;
        const next: VulnerabilityEntry = { ...m, severity };
        if (from && from !== m.vulnId) next.severityFrom = from;
        else delete next.severityFrom;
        regraded.set(m, next);
      }
    }
  }
  return regraded.size === 0 ? [...entries] : entries.map((e) => regraded.get(e) ?? e);
}

/** Distinct advisories among the records of one installed copy. */
export function distinctAdvisoryCount(entries: readonly VulnerabilityEntry[] | undefined): number {
  return groupAdvisories(entries).length;
}
