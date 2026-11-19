// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, resolving a pass's items (dependency-check.ts checkPass): each `to` read as one
 * version (an exact version, "latest", or the release a constraint installs), Go targets read again
 * with their dates, and constraints resolved again once what their releases bring with them is
 * judged.
 */

import type { AdvisoryRanges } from "../live/osv-ranges.js";
import type { CheckEcosystem, PackageReleaseIndex, RegistryLookup } from "../live/release-metadata.js";
import type { ProjectPython } from "../live/project-python.js";
import { noteRegistryFacts } from "./dependency-check-facts.js";
import { WAIT_DAYS } from "./dependency-check-signals.js";
import { checkRange, compareIn, isPrereleaseIn, ownSafeInRange, rangeAdmits, rangeNamesPrerelease } from "./dependency-check-versions.js";
import { judgedRangeCandidates as rangeCandidates, type HeldRangeFilter } from "./dependency-check-held.js";
import { pythonRangeFilter } from "./dependency-check-python.js";
import { npmPick, type NpmWhy } from "./dependency-check-resolution.js";
import { installedNotJudged, lookupKey, provisional, yieldToEventLoop, type Requested, type Resolved } from "./dependency-check-items.js";
import { fetchIndexes, type Lookups, type PassContext } from "./dependency-check-lookups.js";

const DAY_MS = 86_400_000;

/** Each item's `to` resolved to one version, in the order asked. */
export async function resolveItems(ctx: PassContext, lookups: Lookups): Promise<Resolved[]> {
  const { requested, now, pythons } = ctx;
  const { indexes, advisoryLists } = lookups;
  // One package at a time, yielding between them: a package with hundreds of releases and advisories
  // is CPU work, and the event loop must stay free for the call budget's timer and other calls
  // (pre-publish audit 2026-11-12, S1: ping and lodash waited 22 s behind django).
  let items: Resolved[] = [];
  for (const r of requested) {
    const resolved = resolveTarget(r, indexes.get(lookupKey(r))!, advisoryLists.get(lookupKey(r)), now, undefined, pythons.of(r));
    items.push(resolved);
    const index = indexes.get(lookupKey(r));
    if (!resolved.unresolved && index?.status === "ok") noteRegistryFacts(r, resolved.to, index.data.releases[resolved.to]);
    await yieldToEventLoop();
  }
  return items;
}

/** Go: a target chosen from the proxy's list is read again with its date (the list has none), and its constraint resolved again. */
export async function redateGoTargets(ctx: PassContext, lookups: Lookups, items: Resolved[]): Promise<Resolved[]> {
  const { requested, sources, now, pythons } = ctx;
  const { indexes, advisoryLists } = lookups;
  // Go dates come from per-version .info: read them for versions chosen from the list
  // (a constraint, "latest", or `v2.0.0` listed as `v2.0.0+incompatible`).
  const goRedo = items.filter((i) => {
    const lookup = indexes.get(lookupKey(i));
    return i.ecosystem === "Go" && !i.unresolved && lookup?.status === "ok" && lookup.data.releases[i.to] && !lookup.data.releases[i.to].publishedAt;
  });
  if (goRedo.length > 0) {
    // Every item of the same module is read again with them: the new index replaces the shared one.
    const keys = new Set(goRedo.map(lookupKey));
    for (const [key, lookup] of await fetchIndexes(items.filter((i) => i.ecosystem === "Go" && !i.unresolved && keys.has(lookupKey(i))), sources, new Set())) indexes.set(key, lookup);
    // With `to`'s date read, the range's safe picks obey the release-age hold (applyHold) as elsewhere.
    items = items.map((item, i) =>
      item.ecosystem === "Go" && item.rangeCheck?.basis === "requested" && keys.has(lookupKey(item))
        ? resolveTarget(requested[i], indexes.get(lookupKey(item))!, advisoryLists.get(lookupKey(item)), now, undefined, pythons.of(item))
        : item,
    );
  }
  return items;
}

/** What each release brings with it, judged; a constraint is then resolved again among the releases that bring nothing affected. */
export async function judgeReleaseContents(ctx: PassContext, lookups: Lookups, items: Resolved[]): Promise<Resolved[]> {
  const { requested, now, pythons, supportsPython, judgeOf, judgeAll } = ctx;
  const { indexes, advisoryLists } = lookups;
  // What a release installs or requires comes with it (npm, audit 6.2.5 D-4: express 4.20.0
  // exact-pins an affected qs; crates.io and PyPI: a requirement held at an affected release; Go: a
  // required minimum with advisories). Judge `to` and, for a constraint, the smallest and newest
  // safe releases in it, then pick again among the releases that bring nothing affected.
  /** A release the registry lists: a requirement list is read for no other. */
  const isListed = (i: Resolved) => {
    const lookup = indexes.get(lookupKey(i));
    return lookup?.status === "ok" && Boolean(lookup.data.releases[i.to]);
  };
  const isJudged = (i: Resolved) => !i.unresolved && judgeOf(i.ecosystem) !== null && (i.ecosystem === "npm" || isListed(i));
  await judgeAll(
    items.filter(isJudged).map((item) => {
      const eco = item.ecosystem;
      const lookup = indexes.get(lookupKey(item));
      const advisories = advisoryLists.get(lookupKey(item));
      // Only releases that could be picked are worth judging: on PyPI, those supporting the project's Python.
      const ownSafe = item.rangeCheck && lookup?.status === "ok" && advisories
        ? ownSafeInRange({ ecosystem: eco, index: lookup.data, range: item.rangeCheck.range, advisories, allowPrerelease: rangeNamesPrerelease(eco, item.rangeCheck.range) }).filter(supportsPython(item, lookup.data))
        : [];
      return { ecosystem: eco, pkg: item.package, versions: [item.to, ...rangeCandidates(eco, ownSafe, (v) => !item.from || compareIn(eco, v, item.from) > 0, installedNotJudged(item))] };
    }),
  );
  items = items.map((item, i) => {
    const filter = isJudged(item) && item.rangeCheck?.basis === "requested" ? judgeOf(item.ecosystem)!.rangeFilter(item.package) : null;
    if (!filter) return item;
    const r = requested[i];
    return resolveTarget(r, indexes.get(lookupKey(r))!, advisoryLists.get(lookupKey(r)), now, filter, pythons.of(r));
  });
  // `to` is what the constraint installs (resolvedRelease, round 8): judge it too (normally a no-op).
  await judgeAll(items.filter(isJudged).map((item) => ({ ecosystem: item.ecosystem, pkg: item.package, versions: [item.to] })));
  return items;
}

/**
 * One version per item: an exact `to` (Go: `+incompatible` when that is how
 * the proxy lists it), "latest" (newest stable, not withdrawn), or the
 * version a constraint recommends.
 */
export function resolveTarget(
  r: Requested,
  lookup: RegistryLookup<PackageReleaseIndex>,
  advisories: AdvisoryRanges[] | null | undefined,
  now: Date,
  held?: HeldRangeFilter,
  /** PyPI: the Python versions the project declares; a release that does not support them is no safe pick. */
  projectPython: ProjectPython | null = null,
): Resolved {
  const base = provisional(r);
  if (lookup.status !== "ok") return base;
  const index = lookup.data;
  const target = r.target;

  if (target.kind === "exact") {
    let version = target.version;
    if (r.ecosystem === "Go" && !index.releases[version] && index.releases[`${version}+incompatible`]) version = `${version}+incompatible`;
    // PEP 440 spellings differ ("3.1" is 3.1.0, "3.1.06", "1.0-post1"); use the registry's, and
    // say what was asked when it is spelled differently.
    if (r.ecosystem === "PyPI" && !index.releases[version]) {
      version = Object.keys(index.releases).find((v) => compareIn("PyPI", v, version) === 0) ?? version;
    }
    return { ...base, to: version, ...(version !== target.version ? { requested: r.raw } : {}) };
  }
  if (target.kind === "latest") {
    const newest = newestOf(r.ecosystem, Object.values(index.releases).filter((x) => !x.withdrawn).map((x) => x.version));
    return newest ? { ...base, to: newest, requested: "latest" } : base;
  }

  const range = target.range;
  const admitted = Object.values(index.releases)
    .filter((x) => !x.withdrawn && rangeAdmits(r.ecosystem, range, x.version) === true)
    .map((x) => x.version);
  if (admitted.length === 0) {
    return { ...base, requested: r.raw, unresolved: `No published, non-withdrawn release of ${r.package} matches ${range}.` };
  }
  // A prerelease is a candidate only when the constraint names one (">=2.0.0rc1", "^5.0.0-beta.1").
  const allowPrerelease = rangeNamesPrerelease(r.ecosystem, range);
  const onlyPrereleases = !allowPrerelease && admitted.every((v) => isPrereleaseIn(r.ecosystem, v));
  const noStable = () => {
    const sorted = [...admitted].sort((a, b) => compareIn(r.ecosystem, a, b));
    const which = sorted.length === 1 ? sorted[0] : `${sorted[0]} to ${sorted[sorted.length - 1]}`;
    return `No stable release of ${r.package} matches ${range}: the ${sorted.length} release${sorted.length === 1 ? "" : "s"} it admits (${which}) ${sorted.length === 1 ? "is a prerelease" : "are prereleases"}, and a prerelease is never offered as the safe release. Ask for one by its exact version to have it judged.`;
  };
  // npm installs its own pick (the `latest` tag first), which need not be the highest release the
  // range admits; Yarn and pnpm can install the highest. `to` is npm's, and the highest is judged
  // too when it differs (dependency-check-resolution.ts; pre-publish round 10, W2).
  const highest = (fallback: string) => (r.ecosystem === "npm" && !onlyPrereleases ? npmResolution(index, admitted, fallback) : { to: fallback });
  if (!advisories) {
    if (onlyPrereleases) return { ...base, requested: r.raw, unresolved: noStable() };
    // Without the advisory list no release can be called safe; judge the newest one on its own advisories.
    return { ...base, ...highest(newestOf(r.ecosystem, admitted)!), requested: r.raw };
  }
  const python = pythonRangeFilter(projectPython, r.ecosystem, index);
  const rangeCheck = checkRange({
    ecosystem: r.ecosystem,
    index,
    range,
    basis: "requested",
    advisories,
    from: r.from,
    allowPrerelease,
    ...(held ? { held } : {}),
    ...(python ? { python } : {}),
    // The picks it names obey the release-age hold, as `to` alone would (blind audit round 4).
    young: (v) => isYoung(index.releases[v]?.publishedAt, now),
  });
  if (onlyPrereleases) return { ...base, requested: r.raw, rangeCheck, unresolved: noStable() };
  // Pre-publish round 8 (B2): the verdict is about the release the package manager installs for
  // the constraint as written, never the best safe release in it. `{npm, minimist, "<1.2.6"}` said
  // proceed (judged as 0.2.4) while npm installs 1.2.5 (GHSA-xvch-5gv4-984h, critical); cargo
  // resolves smallvec "<1.6.1" to 1.6.0 (RUSTSEC-2021-0003). The safe exact pins stay in
  // range_check, and the reason says to pin one (withAlternatives).
  return { ...base, ...highest(resolvedRelease(r.ecosystem, admitted, allowPrerelease)), requested: r.raw, rangeCheck, resolvesRange: true };
}

/** npm: `to` is npm's pick; `npmAlso` names the highest admitted release when npm picks another. */
function npmResolution(index: PackageReleaseIndex, admitted: string[], highest: string): { to: string; npmAlso?: { highest: string; why: NpmWhy } } {
  const pick = npmPick(index, admitted);
  if (!pick || pick.version === highest) return { to: highest };
  return { to: pick.version, npmAlso: { highest, why: pick.why } };
}

/**
 * The release a package manager installs for a constraint, among the published, non-withdrawn
 * releases it admits: the highest one (npm and pnpm without a lockfile entry, `cargo add` /
 * `cargo update`, pip, `go get`), stable releases only unless the constraint names a prerelease
 * and admits no stable release. npm's `latest` tag wins over a higher release only when that tag
 * is lower; registries here tag the newest stable release, so the highest is what installs.
 */
function resolvedRelease(ecosystem: CheckEcosystem, admitted: string[], allowPrerelease: boolean): string {
  const stable = admitted.filter((v) => !isPrereleaseIn(ecosystem, v));
  const pool = stable.length > 0 || !allowPrerelease ? stable : admitted;
  return pool.reduce((max, v) => (compareIn(ecosystem, v, max) > 0 ? v : max));
}

/** Newest release, stable ones first. */
function newestOf(ecosystem: CheckEcosystem, versions: string[]): string | null {
  const stable = versions.filter((v) => !isPrereleaseIn(ecosystem, v));
  const pool = stable.length > 0 ? stable : versions;
  return pool.reduce<string | null>((max, v) => (max === null || compareIn(ecosystem, v, max) > 0 ? v : max), null);
}

export function isYoung(at: string | null | undefined, now: Date): boolean {
  return Boolean(at) && (now.getTime() - Date.parse(at!)) / DAY_MS < WAIT_DAYS;
}
