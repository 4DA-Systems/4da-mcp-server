// SPDX-License-Identifier: Apache-2.0
/**
 * A release named safe from a package's advisory list (POST /v1/query) is confirmed by OSV.dev's
 * batch query (POST /v1/querybatch) before any tool names it.
 *
 * The list alone cannot tell "no advisory" from "the answer was cut short": a proxy answering
 * `{"vulns":[]}` for /v1/query looks exactly like a package with no advisories. Round 4 held the
 * list against the ids the batch query named for the installed copy; with the batch query itself
 * failing (HTTP 500, truncated JSON) there was nothing to hold it against, and `{npm, lodash, "4.x"}`
 * named 4.0.0, which advisories affect, its smallest safe release (blind audit round 5). The rule
 * now: a release is named safe only when the batch answer for that release was read AND the list
 * holds every id that answer named.
 */

import { missingFromList, type FixPathSources, type FixTargetResult } from "./fix-paths.js";
import type { AdvisoryQuery } from "./held-dependencies.js";
import type { OfferedRelease } from "./offered-release.js";
import type { AdvisoryRanges } from "./osv-ranges.js";
import type { OsvEcosystem, ResolvedDependency } from "./types.js";

/** What the batch query said about a set of releases: read, with the ids per release, or not read and why. */
export type BatchAnswer = { read: true; idsAt: (ecosystem: string, name: string, version: string) => string[] } | { read: false; reason: string };

const norm = (ecosystem: string, name: string) => (ecosystem === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name);
const keyOf = (ecosystem: string, name: string, version: string) => `${ecosystem}\0${norm(ecosystem, name)}\0${version}`;

function dep(ecosystem: OsvEcosystem, name: string, version: string): ResolvedDependency {
  return { name, version, ecosystem, isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [] };
}

/** Ask the batch query about these releases, at most until `deadline`. */
export async function batchAnswer(query: AdvisoryQuery, releases: Array<{ ecosystem: OsvEcosystem; name: string; version: string }>, deadline: number): Promise<BatchAnswer> {
  const wanted = new Map<string, ResolvedDependency>();
  for (const r of releases) wanted.set(keyOf(r.ecosystem, r.name, r.version), dep(r.ecosystem, r.name, r.version));
  if (wanted.size === 0) return { read: true, idsAt: () => [] };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), Math.max(0, deadline - Date.now()));
  });
  let answer: Awaited<ReturnType<AdvisoryQuery>> | null;
  try {
    answer = await Promise.race([query([...wanted.values()]).catch(() => null), late]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  if (!answer) return { read: false, reason: "the batch query failed or did not finish in time" };
  if (answer.offline) return { read: false, reason: answer.uncheckedReason ?? "the batch query failed" };
  if ((answer.staleAnswers ?? 0) > 0) return { read: false, reason: `only an expired cached answer (${answer.staleReason ?? "the fresh query failed"})` };
  const ids = new Map<string, string[]>();
  for (const v of answer.vulnerabilities) {
    const k = keyOf(v.ecosystem, v.package, v.currentVersion);
    ids.set(k, [...(ids.get(k) ?? []), v.vulnId]);
  }
  return { read: true, idsAt: (ecosystem, name, version) => ids.get(keyOf(ecosystem, name, version)) ?? [] };
}

/** Why a list-based release is not confirmed, or null when the batch answer was read and the list holds every id it named. */
async function unconfirmedWhy(sources: FixPathSources, answer: BatchAnswer, ecosystem: OsvEcosystem, name: string, version: string): Promise<string | null> {
  if (!answer.read) return `OSV.dev's batch query gave no current answer for it (${answer.reason})`;
  const named = answer.idsAt(ecosystem, name, version);
  if (named.length === 0) return null;
  const list = await sources.packageAdvisories(ecosystem, name).catch(() => null);
  const missing = list ? missingFromList(list, named) : named;
  return missing.length === 0 ? null : `OSV.dev's batch query names ${missing.slice(0, 3).join(", ")}${missing.length > 3 ? ` and ${missing.length - 3} more` : ""} against it, which ${name}'s advisory list (/v1/query) left out`;
}

/**
 * Fix targets worked out from a package's advisory list, each confirmed by the batch query. One
 * not confirmed is kept as the highest-fix answer the tools already give when the list could not be
 * read (`advisoriesUnread`, "not checked against the package's other advisories"), with the reason
 * in `unconfirmed`; a newest safe release not confirmed is dropped.
 */
export async function confirmTargets(
  sources: FixPathSources,
  query: AdvisoryQuery,
  items: Array<{ key: string; ecosystem: OsvEcosystem; name: string; clean: FixTargetResult }>,
  deadline: number,
): Promise<Map<string, FixTargetResult>> {
  const out = new Map<string, FixTargetResult>();
  const todo = items.filter((i) => i.clean.target && !i.clean.advisoriesUnread);
  if (todo.length === 0) return out;
  const answer = await batchAnswer(
    query,
    todo.flatMap((i) => [i.clean.target!, ...(i.clean.newestSafe ? [i.clean.newestSafe] : [])].map((version) => ({ ecosystem: i.ecosystem, name: i.name, version }))),
    deadline,
  );
  for (const i of todo) {
    const why = await unconfirmedWhy(sources, answer, i.ecosystem, i.name, i.clean.target!);
    if (why) {
      const { newestSafe: _n, lineDead: _l, ...rest } = i.clean;
      out.set(i.key, { ...rest, advisoriesUnread: true, unconfirmed: why });
      continue;
    }
    if (i.clean.newestSafe && (await unconfirmedWhy(sources, answer, i.ecosystem, i.name, i.clean.newestSafe))) {
      const { newestSafe: _n, ...rest } = i.clean;
      out.set(i.key, rest);
    }
  }
  return out;
}

/**
 * Offered releases (the newest release, or the safe one offered in its place) that were judged
 * clean from a package's advisory list, each confirmed by the batch query. One not confirmed is
 * offered as unchecked (`checked: false`), with why.
 */
export async function confirmOffers(
  sources: FixPathSources,
  query: AdvisoryQuery,
  items: Array<{ key: string; ecosystem: OsvEcosystem; name: string; vet: OfferedRelease }>,
  deadline: number,
): Promise<Map<string, OfferedRelease>> {
  const out = new Map<string, OfferedRelease>();
  const todo = items.filter((i) => i.vet.checked && i.vet.safe);
  if (todo.length === 0) return out;
  const answer = await batchAnswer(query, todo.map((i) => ({ ecosystem: i.ecosystem, name: i.name, version: i.vet.safe! })), deadline);
  for (const i of todo) {
    const why = await unconfirmedWhy(sources, answer, i.ecosystem, i.name, i.vet.safe!);
    if (!why) continue;
    const unconfirmed = `${i.name} ${i.vet.safe} was not confirmed free of known advisories (${why}): run dependency_check on it before writing it`;
    out.set(i.key, { ...i.vet, checked: false, note: i.vet.note && i.vet.safe !== i.vet.offered ? `${i.vet.note}; but ${unconfirmed}` : unconfirmed });
  }
  return out;
}

/**
 * Whether a package's advisory list may be used to call releases of it clean: the batch query
 * answered for `versions` (the releases about to be judged) and the list holds every id it named.
 * Used where many releases are judged from one list (upgrade_planner's parent and lever checks).
 */
export async function listConfirmed(
  query: AdvisoryQuery | null | undefined,
  list: readonly AdvisoryRanges[],
  ecosystem: OsvEcosystem,
  name: string,
  versions: string[],
  deadline: number,
): Promise<boolean> {
  if (!query) return false;
  const releases = [...new Set(versions)].map((version) => ({ ecosystem, name, version }));
  const answer = await batchAnswer(query, releases, deadline);
  if (!answer.read) return false;
  return releases.every((r) => missingFromList(list, answer.idsAt(ecosystem, name, r.version)).length === 0);
}
