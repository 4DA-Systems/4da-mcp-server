// SPDX-License-Identifier: Apache-2.0
/**
 * A severity for advisory records that carry none, from their GHSA alias.
 *
 * Go's vulnerability database rates nothing: GO-2024-3333 (golang.org/x/net)
 * has no `severity`, while its alias GHSA-w32m-9786-jp63 is HIGH. OSV returns
 * only the GO record for the module (the GHSA names golang.org/x/net/html),
 * so dependency_check graded x/net v0.20.0 `review` instead of `avoid`
 * (readiness audit M6, 2026-10-16). The alias is the same vulnerability (the
 * two records name each other), so its rating applies.
 *
 * Fail-closed: an alias that cannot be read, or that is itself unrated,
 * leaves the record `unknown`, which is never a proceed.
 */

import { LiveCache } from "../live/cache.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import { deriveSeverity, OsvHttpSource } from "../live/osv-scanner.js";
import type { OsvVulnerability, VulnerabilityEntry } from "../live/types.js";

/** Alias records read per call: an upper bound on the extra requests one check makes. */
export const MAX_ALIAS_LOOKUPS = 25;

export type DetailsFn = (ids: string[]) => Promise<Map<string, OsvVulnerability>>;

let shared: OsvHttpSource | null = null;
/**
 * OSV's record endpoint through the scanner's own reader: the same 24 h
 * `osv:detail:<id>` cache (the server's cache database), in-flight sharing,
 * bounded concurrency, a timeout and one retry.
 */
const osvDetails: DetailsFn = (ids) => {
  shared ??= new OsvHttpSource(new LiveCache(null), new RateLimiter(DEFAULT_RATE_LIMITS));
  return shared.details(ids);
};

/** For each record with no severity that names a GHSA alias: the alias's severity, keyed by the record's id. */
export async function aliasSeverities(
  entries: VulnerabilityEntry[],
  details: DetailsFn = osvDetails,
): Promise<Map<string, { severity: VulnerabilityEntry["severity"]; from: string }>> {
  const wanted = new Map<string, string>(); // record id -> GHSA alias
  const present = new Set(entries.map((e) => e.vulnId));
  for (const e of entries) {
    if (e.severity !== "unknown" || wanted.has(e.vulnId)) continue;
    const ghsa = e.aliases.find((a) => /^GHSA-/i.test(a) && !present.has(a));
    if (ghsa) wanted.set(e.vulnId, ghsa);
  }
  const ids = [...new Set(wanted.values())].slice(0, MAX_ALIAS_LOOKUPS);
  const out = new Map<string, { severity: VulnerabilityEntry["severity"]; from: string }>();
  if (ids.length === 0) return out;
  let records: Map<string, OsvVulnerability>;
  try {
    records = await details(ids);
  } catch {
    return out;
  }
  for (const [id, ghsa] of wanted) {
    const record = records.get(ghsa);
    if (!record) continue;
    const { severity } = deriveSeverity(record);
    if (severity !== "unknown") out.set(id, { severity, from: ghsa });
  }
  return out;
}
