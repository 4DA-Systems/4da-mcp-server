// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check: findings already in hand survive the call's time budget (r7).
 *
 * chalk 5.6.1 was `unknown` after a timeout although npm's "unpublished" and OSV.dev's
 * MAL-2025-46969 had both been read: one `/v1/vulns/{id}` request that never answered held the
 * call past its budget, and the dispatcher's answer (late-answer.ts) is built from the request
 * alone. Each concrete negative fact is now kept for the call as soon as it is read
 * (call-budget.ts noteCallFinding): a release the registry withdrew, a malicious-package record
 * or another advisory that affects it. A late answer carries the worst one as the item's verdict,
 * never `unknown` over an avoid already known, and never a proceed.
 */

import { callFindingKey, noteCallFinding } from "../call-budget.js";
import { advisoryAffects, type AdvisoryRanges } from "../live/osv-ranges.js";
import type { ReleaseRecord } from "../live/release-metadata.js";
import { isMaintenanceNotice } from "../live/maintenance.js";
import type { VulnerabilityEntry } from "../live/types.js";

/** The item as the caller wrote it (dependency-check.ts Requested). */
interface Asked {
  ecosystem: string;
  package: string;
  raw: string;
}

const key = (r: Asked) => callFindingKey(r.ecosystem, r.package, r.raw);
const ids = (list: string[]) => `${list.slice(0, 3).join(", ")}${list.length > 3 ? ` and ${list.length - 3} more` : ""}`;

/** The registry withdrew `to` (unpublished, yanked, retracted): avoid. */
export function noteRegistryFacts(r: Asked, to: string, release: ReleaseRecord | undefined): void {
  if (release?.withdrawn) noteCallFinding(key(r), "avoid", `${r.package} ${to} was ${release.withdrawn} from the registry`);
}

/** Advisories of the package's list (OSV.dev /v1/query) that affect `to`: avoid (an unread grade counts as high). */
export function noteListFacts(r: Asked, to: string, list: readonly AdvisoryRanges[] | null | undefined): void {
  if (!list) return;
  const hits = list.filter((a) => !a.maintenance && advisoryAffects(a, to, r.ecosystem));
  const malware = hits.filter((a) => a.malware).map((a) => a.id);
  if (malware.length > 0) noteCallFinding(key(r), "avoid", `MALWARE: ${r.package} ${to} is a malicious release (${ids(malware)})`);
  const other = hits.filter((a) => !a.malware).map((a) => a.id);
  // An advisory whose grade was not read counts as high, as everywhere else (AdvisoryRef.unread): missing
  // data never turns a healthy avoid into review (round 8).
  if (other.length > 0) noteCallFinding(key(r), "avoid", `${ids(other)} ${other.length === 1 ? "affects" : "affect"} ${r.package} ${to} (OSV.dev's advisory list; severity not yet read, so it counts as high)`);
}

/** The batch query's answer for `to`: malware, high or critical is avoid; anything else at least review. */
export function noteScanFacts(r: Asked, to: string, entries: readonly VulnerabilityEntry[] | undefined): void {
  const real = (entries ?? []).filter((e) => !isMaintenanceNotice(e));
  if (real.length === 0) return;
  const malware = real.filter((e) => e.malware).map((e) => e.vulnId);
  if (malware.length > 0) {
    noteCallFinding(key(r), "avoid", `MALWARE: ${r.package} ${to} is a malicious release (${ids([...new Set(malware)])})`);
    return;
  }
  const severe = real.filter((e) => e.severity === "high" || e.severity === "critical").map((e) => e.vulnId);
  const all = [...new Set(real.map((e) => e.vulnId))];
  noteCallFinding(key(r), severe.length > 0 ? "avoid" : "review", `${ids(all)} ${all.length === 1 ? "affects" : "affect"} ${r.package} ${to} (OSV.dev)`);
}
