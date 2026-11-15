// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check with live lookups off (FOURDA_OFFLINE): what OSV.dev answered before for an
 * exact version, read from the cache with its age. Offline the check said "nothing about these
 * versions could be checked" even when the cache held the answer (pre-publish round 10, W5).
 *
 * The verdict is never changed here: a cached answer can predate the advisory that matters, so a
 * clean one is not `proceed`, and the caller keeps `unknown`. The note says what the cache holds.
 */

import { ageText } from "../live/scan-coverage.js";
import type { OsvEcosystem, ResolvedDependency, VulnerabilityScanResult } from "../live/types.js";

interface ExactRequest {
  ecosystem: string;
  package: string;
  target: { kind: string; version?: string };
}

interface CacheReader {
  queryAdvisories(deps: ResolvedDependency[]): Promise<VulnerabilityScanResult>;
}

/** Per exact-version request the cache answered for, one line: its advisories (or none) and the oldest answer's age. */
export async function cachedAdvisoryNotes<R extends ExactRequest>(liveIntel: CacheReader, requested: readonly R[]): Promise<Map<R, string>> {
  const out = new Map<R, string>();
  const exact = requested.filter((r) => r.target.kind === "exact" && typeof r.target.version === "string");
  if (exact.length === 0) return out;
  const deps: ResolvedDependency[] = exact.map((r) => ({
    name: r.package,
    version: r.target.version!,
    ecosystem: r.ecosystem as OsvEcosystem,
    isDev: false,
    isDirect: true,
    devScopeKnown: false,
    target: null,
    platformActive: true,
    sourceDirs: [],
  }));
  let answer: VulnerabilityScanResult;
  try {
    answer = await liveIntel.queryAdvisories(deps);
  } catch {
    return out;
  }
  // Only a cache-only answer is described: anything else would not be what this branch reads.
  if (!answer.cacheOnly) return out;
  const unchecked = new Set(answer.uncheckedDependencies ?? []);
  const at = answer.staleOldestFetchedAt ?? null;
  const age = at ? ageText(at) : null;
  const when = at ? `cached at ${at} UTC${age ? ` (${age} ago)` : ""}` : "cached";
  for (const r of exact) {
    const version = r.target.version!;
    if (unchecked.has(`${r.ecosystem}\0${r.package}\0${version}`)) continue;
    const ids = [...new Set(answer.vulnerabilities.filter((v) => v.ecosystem === r.ecosystem && v.package === r.package && v.currentVersion === version).map((v) => v.vulnId))];
    out.set(
      r,
      ids.length > 0
        ? `OSV.dev's last answer for ${r.package} ${version}, ${when}, lists ${ids.length} advisor${ids.length === 1 ? "y" : "ies"} (${ids.slice(0, 5).join(", ")}${ids.length > 5 ? ", ..." : ""}): known affected then, so do not install it; check again online for the current state.`
        : `OSV.dev's last answer for ${r.package} ${version}, ${when}, listed no advisory; an advisory published since would not show, so this is not a current all-clear.`,
    );
  }
  return out;
}
