// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, OSV.dev's batch answer for a pass (dependency-check.ts checkPass): every release
 * judged is asked of the batch query in one request, with a probe per package; the answer is held
 * against each package's own advisory list (/v1/query), and what it says about an item is read only
 * when it is current and not contradicted.
 */

import { groupAdvisories } from "../live/advisory-groups.js";
import { isMaintenanceNotice } from "../live/maintenance.js";
import { advisoryKnownToAffect, type AdvisoryRanges } from "../live/osv-ranges.js";
import type { CheckEcosystem, PackageReleaseIndex } from "../live/release-metadata.js";
import type { ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { isConcreteVersion } from "../live/release-version.js";
import { isSecurityHoldingRelease } from "../live/osv-scanner.js";
import { noteScanFacts } from "./dependency-check-facts.js";
import type { AdvisoryFacts, AdvisoryRef, CheckItem } from "./dependency-check-signals.js";
import { compareIn } from "./dependency-check-versions.js";
import { instanceKey, lookupKey, type Resolved } from "./dependency-check-items.js";
import type { Lookups, PassContext } from "./dependency-check-lookups.js";

/** OSV.dev's batch answer for the releases a pass judges, and the lists it is held against. */
export interface BatchAnswer {
  /** Each package's own advisory list (/v1/query), by lookupKey. */
  known: Map<string, AdvisoryRanges[] | null>;
  /** Per item, a release its list says is affected, asked beside the judged ones as the batch answer's probe (B7). */
  probes: Map<Resolved, string>;
  /** Every release asked of the batch query. */
  osvDeps: ResolvedDependency[];
  scan: VulnerabilityScanResult;
  /** The batch answer's entries, by instanceKey. */
  byInstance: Map<string, VulnerabilityEntry[]>;
}

/** One batch query for every release the pass judges, a probe per package with them. */
export async function queryBatch(ctx: PassContext, lookups: Lookups, items: Resolved[]): Promise<BatchAnswer> {
  const { liveIntel, requested, packageAdvisoryLists } = ctx;
  const { indexes } = lookups;
  // Round 8 (B7): the batch answer is held against what each package's own advisory list (/v1/query)
  // says about the same releases. Where every judged release is clean by the list, one release the
  // list says is affected goes with them as a probe: a batch that answers `{}` for it is not an
  // answer to trust for the rest (every querybatch result `{}` made express 4.17.1 proceed).
  const known = await packageAdvisoryLists(items);
  const probes = new Map<Resolved, string>();
  for (const item of items) {
    const lookup = indexes.get(lookupKey(item));
    const list = known.get(lookupKey(item));
    if (!list || lookup?.status !== "ok") continue;
    if (judgedVersions(item).some((v) => listAffecting(list, v, item.ecosystem).length > 0)) continue;
    const probe = probeRelease(item.ecosystem, lookup.data, list);
    if (probe && !judgedVersions(item).includes(probe)) probes.set(item, probe);
  }
  const osvDeps: ResolvedDependency[] = items.flatMap((item) => {
    const probe = probes.get(item);
    return [...judgedVersions(item), ...(probe ? [probe] : [])].map((version) => osvDep(item, version));
  });
  const scan = await liveIntel.queryAdvisories(osvDeps);
  // Unrated (Go) records carry their GHSA alias's grade from the scanner, as in every tool (severityFrom).
  const byInstance = new Map<string, VulnerabilityEntry[]>();
  for (const v of scan.vulnerabilities) {
    const key = instanceKey(v.ecosystem, v.package, v.currentVersion);
    byInstance.set(key, [...(byInstance.get(key) ?? []), v]);
  }
  items.forEach((item, i) => {
    if (!item.unresolved) noteScanFacts(requested[i], item.to, byInstance.get(instanceKey(item.ecosystem, item.package, item.to)));
  });
  return { known, probes, osvDeps, scan, byInstance };
}

/** The releases of an item asked of the batch query: `to`, `from` and the picks its range check names. */
export const judgedVersions = (item: Resolved) => [...new Set((item.unresolved ? rangePicks(item) : [item.to, item.from, ...rangePicks(item)]).filter((v): v is string => isConcreteVersion(v)))];

/** The ids of each item's advisories its list declares as unmaintained-package notices, read when asked (later stages change the lists). */
export async function readDeclaredNotices(ctx: PassContext, lookups: Lookups, items: Resolved[], batch: BatchAnswer): Promise<(item: CheckItem) => Set<string>> {
  const { packageAdvisoryLists } = ctx;
  const { advisoryLists } = lookups;
  const { byInstance } = batch;
  // An advisory the scan reads as an unmaintained-package notice is passed over only when its
  // record DECLARES that class (maintenance.ts isDeclaredNotice, read from the package's advisory
  // list). Without the list nothing is declared, and the advisory counts (audit 2026-11-11, M11).
  const noticed = items.filter(
    (i) =>
      !i.unresolved &&
      [i.to, i.from].some((v) => v && (byInstance.get(instanceKey(i.ecosystem, i.package, v)) ?? []).some((e) => isMaintenanceNotice(e))),
  );
  for (const [k, v] of await packageAdvisoryLists(noticed.filter((i) => !advisoryLists.has(lookupKey(i))))) advisoryLists.set(k, v);
  const declaredFor = (item: CheckItem) => new Set((advisoryLists.get(lookupKey(item)) ?? []).filter((a) => a.maintenance).map((a) => a.id));
  return declaredFor;
}

/** Why an item's batch answer is contradicted by its package's own advisory list, or null; a contradicted answer is dropped from the cache and distrusted. */
export function findContradictions(ctx: PassContext, items: Resolved[], batch: BatchAnswer): (item: CheckItem) => string | null {
  const { liveIntel, heldAsked, judgeOf } = ctx;
  const { known, probes, osvDeps, scan, byInstance } = batch;
  // Round 8 (B7): a batch answer that leaves out advisories the package's list names for the same
  // release contradicts it. The known advisories win (worst wins: an unread grade counts as high),
  // nothing is named safe from the batch, a clean release is NOT CHECKED, and the contradicting
  // answers are dropped from the cache so a later call asks again.
  // Per package: in the wholesale case (every result `{}`) each package's own probe catches it.
  const contradicted = new Map<string, string>();
  if (!scan.offline && (scan.staleAnswers ?? 0) === 0) {
    for (const item of items) {
      const list = known.get(lookupKey(item));
      if (!list || contradicted.has(lookupKey(item))) continue;
      const probe = probes.get(item);
      const found: string[] = [];
      for (const version of [...judgedVersions(item), ...(probe ? [probe] : [])]) {
        // npm's security placeholders: the scanner drops findings on them by design (isNpmSecurityHolding).
        if (isSecurityHoldingRelease(item.ecosystem, version)) continue;
        const missing = notInBatch(listAffecting(list, version, item.ecosystem), byInstance.get(instanceKey(item.ecosystem, item.package, version)));
        if (missing.length > 0) found.push(`${version}: ${missing.slice(0, 3).map((a) => a.id).join(", ")}${missing.length > 3 ? ` and ${missing.length - 3} more` : ""}`);
      }
      if (found.length > 0) {
        contradicted.set(lookupKey(item), `OSV.dev's batch answer for ${item.package} leaves out advisories its own advisory list names for the same release (${found.slice(0, 2).join("; ")}${found.length > 2 ? `; and ${found.length - 2} more` : ""})`);
      }
    }
  }
  const contradictionOf = (item: CheckItem) => contradicted.get(lookupKey(item)) ?? null;
  if (contradicted.size > 0) {
    liveIntel.forgetAdvisoryAnswers?.([...osvDeps, ...heldAsked]);
    for (const item of items) {
      const why = contradictionOf(item);
      if (why) judgeOf(item.ecosystem)?.distrust(item.package, why);
    }
  }
  return contradictionOf;
}

/** What the batch answer says about an item's `to` and `from`, or why it cannot be read. */
export function advisoryFacts(
  batch: BatchAnswer,
  contradictionOf: (item: CheckItem) => string | null,
  declaredFor: (item: CheckItem) => Set<string>,
): (item: CheckItem) => AdvisoryFacts {
  const { known, scan, byInstance } = batch;
  // A pre-install check needs a current answer: an expired cached one (OSV failed) can predate
  // the advisory that matters, and read as `proceed` (audit 6.2.5 B-2).
  const advisoriesFor = (item: CheckItem): AdvisoryFacts => {
    if (scan.offline) return { available: false, detail: "lookup failed or was rate limited" };
    if ((scan.staleAnswers ?? 0) > 0) return { available: false, detail: `no current answer, only an expired cached one (${scan.staleReason ?? "the fresh query failed"})` };
    const contradiction = contradictionOf(item);
    const at = (version: string) => {
      const batch = byInstance.get(instanceKey(item.ecosystem, item.package, version));
      const missing = contradiction ? notInBatch(listAffecting(known.get(lookupKey(item)) ?? [], version, item.ecosystem), batch) : [];
      return [...refs(batch, declaredFor(item)), ...missing.map(listOnlyRef)];
    };
    const to = at(item.to);
    if (contradiction && !to.some((a) => !a.maintenance)) return { available: false, detail: `NOT CHECKED: ${contradiction}` };
    return { available: true, to, from: item.from ? at(item.from) : [] };
  };
  return advisoriesFor;
}

/**
 * The releases a constraint's range check names as safe (smallest, smallest above `from`, newest):
 * asked of OSV.dev's batch query beside `to`, so a list that left out an advisory affecting one of
 * them is caught (Resolved.listGap) instead of naming it.
 */
export function rangePicks(item: Resolved): string[] {
  const rc = item.rangeCheck;
  if (!rc || rc.basis !== "requested") return [];
  return [rc.smallest_safe_in_range, rc.smallest_safe_upgrade, rc.newest_safe_in_range, rc.newest_safe_outside_range].filter(
    (v): v is string => typeof v === "string" && (Boolean(item.unresolved) || v !== item.to),
  );
}

/** The advisories of a package's list (maintenance notices left out) that affect `version`. */
function listAffecting(list: readonly AdvisoryRanges[], version: string, ecosystem: CheckEcosystem): AdvisoryRanges[] {
  // Known to affect it: a range that cannot be read, or one only presumed, is not held against OSV.dev's own answer for the version.
  return list.filter((a) => !a.maintenance && advisoryKnownToAffect(a, version, ecosystem));
}

/** Those of `known` that the batch answer for the same release does not name, by id or alias. */
function notInBatch(known: AdvisoryRanges[], batch: readonly VulnerabilityEntry[] | undefined): AdvisoryRanges[] {
  const named = new Set((batch ?? []).flatMap((e) => [e.vulnId, ...(e.aliases ?? [])]));
  return known.filter((a) => !named.has(a.id) && !(a.aliases ?? []).some((x) => named.has(x)));
}

/** An advisory known only from the package's list: its grade was not read, so it counts as high (AdvisoryRef.unread). */
function listOnlyRef(a: AdvisoryRanges): AdvisoryRef {
  return { id: a.id, severity: "unknown", summary: "", maintenance: false, unread: true, ...(a.malware ? { malware: [a.id] } : {}) };
}

/** The newest installable release the package's list says an advisory affects: the batch query's consistency probe (B7). */
function probeRelease(ecosystem: CheckEcosystem, index: PackageReleaseIndex, list: readonly AdvisoryRanges[]): string | null {
  const real = list.filter((a) => !a.maintenance);
  if (real.length === 0) return null;
  const versions = Object.values(index.releases)
    .filter((r) => !r.withdrawn && isConcreteVersion(r.version) && !isSecurityHoldingRelease(ecosystem, r.version))
    .map((r) => r.version)
    .sort((a, b) => compareIn(ecosystem, b, a));
  return versions.find((v) => real.some((a) => advisoryKnownToAffect(a, v, ecosystem))) ?? null;
}

export function hasRealAdvisory(facts: AdvisoryFacts): boolean {
  return facts.available && facts.to.some((a) => !a.maintenance);
}

function osvDep(item: CheckItem, version: string): ResolvedDependency {
  return {
    name: item.package,
    version,
    ecosystem: item.ecosystem,
    isDev: false,
    isDirect: true,
    devScopeKnown: true,
    target: null,
    platformActive: true,
    sourceDirs: [],
  };
}

/**
 * One reference per vulnerability: OSV lists GHSA and RUSTSEC/PYSEC records
 * for the same issue, each naming the other in `aliases`. They were counted
 * twice ("6 advisories" for tokio 1.18.0's three, audit A9). The kept record
 * of an alias group is its most severe, so merging never softens a verdict.
 *
 * `declaredNotices`: the ids of the package's advisories whose record declares an informational
 * class with no fixed release. A group is passed over as an unmaintained-package notice only
 * when every record of it reads as a notice, one of them is declared, and none carries a grade
 * (its own or an alias's) or a fixed version. Anything else the scan worded as a notice counts,
 * and says so (`countedNotice`).
 */
export function refs(entries: VulnerabilityEntry[] | undefined, declaredNotices: ReadonlySet<string> = new Set()): AdvisoryRef[] {
  return groupAdvisories(entries).map(({ best: v, members }) => {
    const worded = members.every((m) => isMaintenanceNotice(m));
    const declared =
      worded &&
      members.some((m) => declaredNotices.has(m.vulnId)) &&
      members.every((m) => m.severity === "unknown" && !m.severityFrom && !m.fixedVersion && !m.malware);
    return {
      id: v.vulnId,
      severity: v.severity,
      summary: v.summary,
      maintenance: declared,
      ...(worded && !declared ? { countedNotice: true } : {}),
      ...(v.severityFrom ? { severityFrom: v.severityFrom } : {}),
      // Matched, but no record read: the severity is not known and never reads as low (AdvisoryRef.unread).
      ...(v.severity === "unknown" && members.some((m) => m.detailUnavailable) ? { unread: true as const } : {}),
      // Every malicious-package record of the group, the MAL- one under a GHSA alias included.
      ...(members.some((m) => m.malware) ? { malware: [...new Set(members.filter((m) => m.malware).map((m) => m.vulnId))] } : {}),
    };
  });
}
