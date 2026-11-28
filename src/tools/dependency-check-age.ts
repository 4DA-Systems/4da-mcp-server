// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check: how old the OSV.dev data behind each answer is, when it came from the cache
 * (pre-publish audit 2026-11-25, C-3). A batch answer is kept 60 minutes and a package's advisory
 * list 6 hours; a `proceed` read from a 50-minute-old answer said `osv_cached: false` and gave no
 * age, and the guard hook honours a recorded proceed for 24 h. The TTLs are unchanged: the answer
 * now says how old its data is.
 *
 * Read from the cache rows' own fetch times (FixPathSources.advisoryFetchedAt; nothing is asked): a
 * row fetched before this call began was read from the cache, one written during it was read live.
 */

import type { LiveIntelligence } from "../live/index.js";
import type { OsvEcosystem } from "../live/types.js";
import { isConcreteVersion } from "../live/release-version.js";
import { maxOf } from "../array-utils.js";
import type { ItemResult } from "./dependency-check-items.js";

/** An answer with advisory data this many minutes old or older says so in the summary. */
export const AGE_NOTE_MINUTES = 5;
/** SQLite keeps fetch times to the second: a row written in this call can read up to a second before it began. */
const SAME_CALL_SLACK_MS = 1_000;

/**
 * Stamps `advisory_data_age_minutes` on each looked-up item whose batch answer (for `to`, and for
 * every release its resolution judged) came from the cache: the oldest such answer, in whole minutes.
 * Returns whether any batch answer or advisory list behind these answers was read from the cache.
 */
export function stampAdvisoryAges(results: ItemResult[], liveIntel: LiveIntelligence | null, startedMs: number, nowMs = Date.now()): boolean {
  const reader = liveIntel?.getFixPathSources?.()?.advisoryFetchedAt;
  if (!reader) return false;
  const releases: Array<{ at: number; ecosystem: OsvEcosystem; name: string; version: string }> = [];
  results.forEach((r, at) => {
    if (r.not_checked) return;
    const versions = new Set([r.to, ...(r.resolution?.judged ?? []).map((j) => j.version)].filter((v) => isConcreteVersion(v)));
    for (const version of versions) releases.push({ at, ecosystem: r.ecosystem as OsvEcosystem, name: r.package, version });
  });
  if (releases.length === 0) return false;
  const times = reader(releases);
  const fromCache = (fetchedAt: string | null): number | null => {
    if (!fetchedAt) return null;
    const ms = Date.parse(/[Tt]/.test(fetchedAt) ? fetchedAt : `${fetchedAt.replace(" ", "T")}Z`);
    return Number.isFinite(ms) && ms < startedMs - SAME_CALL_SLACK_MS ? ms : null;
  };
  let anyCached = false;
  const oldest = new Map<number, number>();
  releases.forEach((rel, i) => {
    const answer = fromCache(times[i].answer);
    if (answer !== null || fromCache(times[i].list) !== null) anyCached = true;
    if (answer !== null) oldest.set(rel.at, Math.min(oldest.get(rel.at) ?? Number.POSITIVE_INFINITY, answer));
  });
  for (const [at, ms] of oldest) results[at].advisory_data_age_minutes = Math.max(0, Math.floor((nowMs - ms) / 60_000));
  return anyCached;
}

/** The summary's sentence for items whose advisory data is AGE_NOTE_MINUTES or more old, or "". */
export function advisoryAgeText(results: readonly ItemResult[]): string {
  const aged = results.filter((r) => (r.advisory_data_age_minutes ?? 0) >= AGE_NOTE_MINUTES);
  if (aged.length === 0) return "";
  const oldest = maxOf(aged.map((r) => r.advisory_data_age_minutes!));
  return ` The OSV.dev data behind ${aged.length === 1 ? "1 item" : `${aged.length} items`} came from the local cache, up to ${oldest} minutes old (advisory_data_age_minutes on each): an advisory published since then does not show; ask again after the cached answer expires (60 minutes after it was read) for a current one.`;
}
