// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, the safe alternatives of a pass (dependency-check.ts checkPass): for an exact
 * `to` that is affected, the safe releases on its own line; for a Go pick, the affected minimums its
 * go.mod requires; for crates.io and PyPI, a clean release outside the range once what it requires
 * has been examined; for npm, what stands in the way when nothing in range is safe.
 */

import type { AdvisoryFacts, CheckItem } from "./dependency-check-signals.js";
import { checkRange, compareIn, isPrereleaseIn, lineOf, ownSafeInRange, type RangeCheck } from "./dependency-check-versions.js";
import { adviseNoSafeRelease, judgedRangeCandidates as rangeCandidates, minimumsCaveat, offerRequirementCleanOutside } from "./dependency-check-held.js";
import { lacksProjectPython, pythonRangeFilter } from "./dependency-check-python.js";
import { installedNotJudged, lookupKey, yieldToEventLoop, type Resolved } from "./dependency-check-items.js";
import type { Lookups, PassContext } from "./dependency-check-lookups.js";
import { isYoung } from "./dependency-check-resolve.js";
import { hasRealAdvisory } from "./dependency-check-batch.js";

/** The exact targets that get the safe releases on their own line, with the advisory lists that takes. */
export async function findAffectedExact(ctx: PassContext, lookups: Lookups, items: Resolved[], advisoriesFor: (item: CheckItem) => AdvisoryFacts): Promise<Resolved[]> {
  const { projectPython, heldAffected, packageAdvisoryLists } = ctx;
  const { indexes, advisoryLists } = lookups;
  /** PyPI: an exact `to` that does not support every Python the project declares. */
  const lacksPython = (i: Resolved) => {
    const lookup = indexes.get(lookupKey(i));
    return lookup?.status === "ok" && lacksProjectPython(projectPython, i.ecosystem, lookup.data.releases[i.to]);
  };
  // An exact `to` an advisory affects (its own, or one it holds), or that does not support the
  // project's Python: the safe releases on its own line.
  const affectedExact = items.filter(
    (i) =>
      !i.unresolved &&
      !i.rangeCheck &&
      ((advisoriesFor(i).available && hasRealAdvisory(advisoriesFor(i))) || heldAffected(i) || lacksPython(i)),
  );
  const moreLists = await packageAdvisoryLists(affectedExact.filter((i) => !advisoryLists.has(lookupKey(i))));
  for (const [k, v] of moreLists) advisoryLists.set(k, v);
  return affectedExact;
}

/** The range check over each affected exact target's own line, what its candidates bring with them judged first. */
export async function checkSameLines(ctx: PassContext, lookups: Lookups, affectedExact: Resolved[], batchRead: (item: CheckItem) => boolean): Promise<void> {
  const { now, projectPython, supportsPython, judgeOf, judgeAll } = ctx;
  const { indexes, advisoryLists } = lookups;
  const lines = affectedExact.flatMap((item) => {
    if (!batchRead(item)) return [];
    const lookup = indexes.get(lookupKey(item))!;
    const advisories = advisoryLists.get(lookupKey(item));
    const line = lineOf(item.ecosystem, item.to);
    return lookup.status === "ok" && advisories && line ? [{ item, index: lookup.data, advisories, line }] : [];
  });
  await judgeAll(
    lines
      .filter((l) => judgeOf(l.item.ecosystem) !== null)
      .map((l) => ({
        ecosystem: l.item.ecosystem,
        pkg: l.item.package,
        versions: rangeCandidates(
          l.item.ecosystem,
          ownSafeInRange({ ecosystem: l.item.ecosystem, index: l.index, range: l.line, advisories: l.advisories, allowPrerelease: isPrereleaseIn(l.item.ecosystem, l.item.to) }).filter(supportsPython(l.item, l.index)),
          (v) => !l.item.from || compareIn(l.item.ecosystem, v, l.item.from) > 0,
          installedNotJudged(l.item),
        ),
      })),
  );
  for (const { item, index, advisories, line } of lines) {
    await yieldToEventLoop();
    const filter = judgeOf(item.ecosystem)?.rangeFilter(item.package) ?? undefined;
    const python = pythonRangeFilter(projectPython, item.ecosystem, index);
    // The safe releases on the line of a stable `to` are stable ones; of a prerelease `to`, prereleases too.
    item.rangeCheck = checkRange({
      ecosystem: item.ecosystem,
      index,
      range: line,
      basis: "same_line",
      advisories,
      from: item.from,
      allowPrerelease: isPrereleaseIn(item.ecosystem, item.to),
      ...(filter ? { held: filter } : {}),
      ...(python ? { python } : {}),
      young: (v) => isYoung(index.releases[v]?.publishedAt, now),
    });
  }
}

/** Go: the affected minimums a named pick's go.mod requires, said beside the pick. */
export async function caveatGoPicks(ctx: PassContext, items: Resolved[]): Promise<void> {
  const { judgeOf } = ctx;
  // Go: a named pick whose own go.mod requires an affected minimum stays a pick, and says so. `to`
  // itself is judged above, and its finding is in the verdict.
  const goJudge = judgeOf("Go");
  const goPicked = goJudge ? items.filter((i) => i.ecosystem === "Go" && i.rangeCheck) : [];
  const picksOf = (item: Resolved) => namedPicks(item.rangeCheck!).filter((v) => v !== item.to);
  if (goJudge && goPicked.length > 0) {
    await goJudge.judge(goPicked.map((item) => ({ pkg: item.package, versions: picksOf(item) })));
    for (const item of goPicked) {
      const caveats = picksOf(item).flatMap((v) => {
        const text = minimumsCaveat(v, goJudge.at(item.package, v));
        return text ? [[v, text] as const] : [];
      });
      if (caveats.length > 0) item.rangeCheck!.requirement_caveats = Object.fromEntries(caveats);
    }
  }
}

/** crates.io, PyPI: a clean release outside the range, named once what it requires has been examined. */
export async function offerCleanOutsideRanges(ctx: PassContext, lookups: Lookups, items: Resolved[]): Promise<void> {
  const { now, supportsPython, judgeOf } = ctx;
  const { indexes, advisoryLists } = lookups;
  // crates.io, PyPI: an alternative outside the range is named only once what it requires has been examined.
  for (const item of items) {
    const lookup = indexes.get(lookupKey(item));
    const judge = item.ecosystem === "npm" || item.ecosystem === "Go" ? null : judgeOf(item.ecosystem);
    if (!judge || !item.rangeCheck || lookup?.status !== "ok") continue;
    await offerRequirementCleanOutside({
      judge,
      ecosystem: item.ecosystem,
      pkg: item.package,
      to: item.to,
      rc: item.rangeCheck,
      index: lookup.data,
      advisories: advisoryLists.get(lookupKey(item)),
      now,
      supported: supportsPython(item, lookup.data),
      installed: installedNotJudged(item),
    });
  }
}

/** npm: when nothing in range is safe, what stands in the way and how to clear it. */
export async function adviseNpmNoSafeRelease(ctx: PassContext, lookups: Lookups, items: Resolved[]): Promise<void> {
  const { now, fixSources, held } = ctx;
  const { indexes, advisoryLists } = lookups;
  // Nothing in range is safe: never point at a release years older when a low or moderate advisory on a
  // held dependency is what stands in the way; say which, and how to clear it (Y3, nx -> 13.2.4).
  const isNpm = (i: Resolved) => i.ecosystem === "npm" && !i.unresolved;
  for (const item of items.filter(isNpm)) {
    const lookup = indexes.get(lookupKey(item));
    if (!item.rangeCheck || lookup?.status !== "ok") continue;
    const advisories = advisoryLists.get(lookupKey(item));
    await adviseNoSafeRelease({ judge: held, pkg: item.package, to: item.to, rc: item.rangeCheck, index: lookup.data, advisories, sources: fixSources, now });
  }
}

/** The releases a range check names (smallest, smallest above `from`, newest, newest outside the range). */
function namedPicks(rc: RangeCheck): string[] {
  return [...new Set([rc.smallest_safe_in_range, rc.smallest_safe_upgrade, rc.newest_safe_in_range, rc.newest_safe_outside_range].filter((v): v is string => typeof v === "string"))];
}
