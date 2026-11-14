// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check and what an npm release holds (audit 6.2.5 D-4).
 *
 * `{to: "4.20.0"}` for express said proceed, and `{to: "4.x"}` named 4.20.0 the smallest safe
 * release: no advisory of express affects it, but it exact-pins qs 6.11.0, cookie 0.6.0,
 * body-parser 1.20.3 and path-to-regexp 0.1.10, all affected, and installing it installs them.
 * An agent wrote it from that answer. Here the releases a check judges (an exact `to`, a
 * constraint's pick and the smallest and newest safe releases in range) are judged with their held
 * dependencies too (held-dependencies.ts): an affected one makes `to` review or avoid by the same
 * severity rule as its own advisories, and keeps the release out of the safe ones.
 *
 * Fail closed: when the registry or OSV cannot answer, `to` is `unknown` (never proceed), and no
 * release whose held dependencies could not be judged is named safe (the answer says NOT CHECKED,
 * never a wider safe set than a healthy run gives: r7 blocker).
 */

import { heldAdvisories, heldSeverity, HELD_CANDIDATES, type AdvisoryQuery, type HeldCheck, type HeldDependency } from "../live/held-dependencies.js";
import { cleanFixTarget, type FixPathSources } from "../live/fix-paths.js";
import { advisoriesAffecting, advisoryAffects, type AdvisoryRanges } from "../live/osv-ranges.js";
import type { PackageReleaseIndex } from "../live/release-metadata.js";
import { compareVersions } from "../live/version-compare.js";
import { excludedReleases } from "../live/withdrawn-releases.js";
import { isPrereleaseIn, rangeAdmits, versionParts, type HeldAdvice, type RangeCheck } from "./dependency-check-versions.js";

/** Time a dependency_check call may spend judging held dependencies, in all. */
const HELD_CHECK_BUDGET_MS = 10_000;
/** The newest safe releases a range check lists (RangeCheck.safe_versions), judged as well. */
const NEWEST_LISTED = 8;

export const HELD_RANGE_NOTE =
  "releases that exact-pin or narrowly range a dependency with a known advisory (installing them installs it), or whose such dependencies could not be checked, are not counted safe";

export class HeldJudge {
  private readonly checks = new Map<string, HeldCheck>();
  /** The checks that rest on a batch answer (a release that holds nothing needs none). */
  private readonly fromBatch = new Set<string>();
  /** Per package: every release's held specs, or null when the registry could not be read. */
  private readonly specs = new Map<string, Record<string, Record<string, string>> | null>();
  /**
   * When the judging budget runs out: set by the first judge(), not by construction, so the
   * registry reads the call makes first (prefetch() runs beside them) never spend it.
   */
  private deadlineAt: number | null = null;
  private get deadline(): number {
    return this.deadlineAt ?? Date.now() + HELD_CHECK_BUDGET_MS;
  }

  constructor(
    private readonly sources: FixPathSources | null,
    private readonly query: AdvisoryQuery,
  ) {}

  /** Each package's held specs, read once: requested by prefetch() or the first judge(), awaited by every later one. */
  private readonly specsRead = new Map<string, Promise<void>>();

  /**
   * Start reading what these packages' releases hold, without waiting: the call starts it beside
   * its registry reads, and judge() awaits the same request (they were read one package after
   * another, after every registry read had finished).
   */
  prefetch(pkgs: string[]): void {
    for (const pkg of new Set(pkgs)) this.readSpecs(pkg);
  }

  private readSpecs(pkg: string): Promise<void> {
    const running = this.specsRead.get(pkg);
    if (running) return running;
    const sources = this.sources;
    const read = (async () => {
      const facts = sources && Date.now() < this.deadline ? await sources.releaseFacts("npm", pkg).catch(() => null) : null;
      this.specs.set(pkg, facts?.heldSpecs ?? null);
    })();
    this.specsRead.set(pkg, read);
    return read;
  }

  /** Judge these releases (those not judged yet), in one advisory lookup. */
  async judge(requests: Array<{ pkg: string; versions: string[] }>): Promise<void> {
    if (!this.sources) return;
    const sources = this.sources;
    this.deadlineAt ??= Date.now() + HELD_CHECK_BUDGET_MS;
    await Promise.all([...new Set(requests.map((r) => r.pkg))].map((pkg) => this.readSpecs(pkg)));
    const releases: Array<{ key: string; specs: Record<string, string> }> = [];
    for (const { pkg, versions } of requests) {
      const all = this.specs.get(pkg);
      for (const v of new Set(versions)) {
        const key = `${pkg}@${v}`;
        if (this.checks.has(key) || releases.some((r) => r.key === key)) continue;
        if (all === null || all === undefined) this.checks.set(key, { status: "unchecked", reason: "the npm registry could not be read" });
        else if (!all[v]) this.checks.set(key, { status: "checked", affected: [] });
        else releases.push({ key, specs: all[v] });
      }
    }
    if (releases.length === 0) return;
    for (const [key, check] of await heldAdvisories(sources, this.query, releases, this.deadline)) {
      this.checks.set(key, check);
      this.fromBatch.add(key);
    }
  }

  /**
   * The batch answers the clean judgments rest on cannot be trusted (round 8, B7: OSV.dev answered
   * `{}` for releases its own advisory list says are affected): every release judged to hold nothing
   * affected is unchecked from here on, with why. A concrete finding (something affected) stands.
   */
  distrust(pkg: string, reason: string): void {
    for (const [key, check] of this.checks) {
      if (key.startsWith(`${pkg}@`) && this.fromBatch.has(key) && check.status === "checked" && check.affected.length === 0) this.checks.set(key, { status: "unchecked", reason });
    }
  }

  at(pkg: string, version: string): HeldCheck | undefined {
    return this.checks.get(`${pkg}@${version}`);
  }

  affected(pkg: string, version: string): boolean {
    const c = this.at(pkg, version);
    return c?.status === "checked" && c.affected.length > 0;
  }

  /** Whether a judged release holds something affected, and nothing worse than a low or moderate advisory. */
  minorOnly(pkg: string, version: string): boolean {
    return minorOnly(this.at(pkg, version));
  }

  /** Whether a release was judged and holds nothing affected. */
  clean(pkg: string, version: string): boolean {
    const c = this.at(pkg, version);
    return c?.status === "checked" && c.affected.length === 0;
  }

  /**
   * checkRange's held filter for one package. Never undefined (r7 blocker): it was undefined when
   * the registry could not say what the releases hold, or when every held check came back
   * unchecked (OSV failed for the dependencies only), and the safe releases then fell back to the
   * package's own advisories: `{express, "4.x"}` said `unknown` and safe 4.20.0, which a healthy
   * run calls avoid. A release that holds something, or may (the registry could not be read), and
   * was not judged clean is not safe; `notChecked` says which of them were left out unjudged, so
   * the answer says NOT CHECKED instead of "affected".
   */
  rangeFilter(pkg: string): HeldRangeFilter {
    const all = this.specs.get(pkg);
    if (!all) {
      const reason = "what its releases install could not be read from the npm registry";
      return { unsafe: () => true, notChecked: () => true, reason, note: HELD_RANGE_NOTE };
    }
    const unchecked = (v: string) => {
      const c = this.at(pkg, v);
      // A release that holds something and was not judged is not called safe.
      return c ? c.status === "unchecked" : Boolean(all[v]);
    };
    const reasons = [...this.checks.entries()].filter(([k, c]) => k.startsWith(`${pkg}@`) && c.status === "unchecked").map(([, c]) => (c as { reason: string }).reason);
    return {
      unsafe: (v) => unchecked(v) || this.affected(pkg, v),
      notChecked: unchecked,
      reason: reasons[0] ?? "the dependencies they exact-pin or narrowly range were not judged",
      note: HELD_RANGE_NOTE,
    };
  }
}

/** checkRange's held filter (dependency-check-versions.ts RangeCheck.held_not_checked). */
export interface HeldRangeFilter {
  unsafe: (version: string) => boolean;
  /** Left out because what it holds could not be judged (not because it is affected). */
  notChecked: (version: string) => boolean;
  /** Why they could not be judged. */
  reason: string;
  note: string;
}

/** An alternative outside the range is offered only within this distance of `to`'s line... */
const OFFER_MAJORS_BEHIND = 1;
/** ...and this age (about 18 months). */
const OFFER_MAX_AGE_DAYS = 548;
const DAY_MS = 86_400_000;

/**
 * Audit 2026-11-10 (Y3): `{npm, nx, latest}` said review and "Newest safe release outside it:
 * 13.2.4", a December 2021 release eleven majors back, because every 24.x exact-pins minimatch
 * 10.2.5 and GHSA-g3hv-75wg-m249 (a moderate ReDoS) affects it. An agent told to write only safe
 * versions either never installs a current nx or is pushed four years back. nx 21.5.0 (malware,
 * rightly avoid) was sent to 13.2.4 the same way.
 *
 * When no release in range is safe, the newest safe release outside it is offered only when it is
 * at most one major below `to` and under about 18 months old. Otherwise, when what stands in the
 * way is a low or moderate advisory on a dependency a release holds, the answer names it, its
 * advisories and the smallest release of it that clears them (an override), for:
 * (a) `to` itself, when nothing in range is safe ONLY because of what it holds (its own
 *     advisories cover none of the range): the verdict stays review, and the reason says how to
 *     install `to` without the advisory: an override of the child, or a later parent release;
 * (b) else the newest release outside the range that the package's own advisories leave clean,
 *     when it is newer than the far-back one: it is the alternative instead, with its override.
 * A high or critical held advisory is avoid, and is never offered around: there the age of a
 * clean release is no reason to keep the vulnerable one, and the far-back release stays offered.
 *
 * Audit 2026-11-11 (M13): every Next.js 15 release exact-pins postcss 8.4.31, and `{next, "^15.0"}`
 * said avoid and "No release in ^15.0 is free of known advisories", full stop: no word on which
 * dependency, what clears it, or that 16.x is clean. So, whatever the held advisory's grade:
 * - when only what the releases hold keeps the range unsafe, the answer names the dependency,
 *   its advisories and the release of it that clears them (the override), as it did for a low or
 *   moderate one. The verdict still follows the grade: review for low or moderate, avoid for
 *   high or critical, and an avoid says the override is what makes the release installable;
 * - when no clean release outside the range was known only because none had been judged (every
 *   release holds something), the newest settled releases the package's own advisories leave
 *   clean are judged, and the first that holds nothing affected is offered.
 */
export async function adviseNoSafeRelease(input: {
  judge: HeldJudge;
  pkg: string;
  to: string;
  rc: RangeCheck;
  index: PackageReleaseIndex;
  advisories: readonly AdvisoryRanges[] | null | undefined;
  sources: FixPathSources | null;
  now: Date;
}): Promise<void> {
  const { rc, judge, pkg } = input;
  if (rc.smallest_safe_in_range !== null) return;
  // Nothing in range was judged safe only because what the releases hold could not be checked: the
  // answer is NOT CHECKED, and no alternative is looked for in its place (r7).
  if (rc.held_not_checked && (rc.affecting_all_total ?? 0) === 0) return;
  const published = (v: string) => input.index.releases[v]?.publishedAt ?? null;
  // "None known" may only mean none was judged: judge the newest ones before saying there is none.
  if (!rc.newest_safe_outside_range && input.advisories) await offerJudgedOutside(input, published);
  const outside = rc.newest_safe_outside_range ?? null;
  const why = outside ? tooFarBack(input.to, outside, published(outside), input.now) : null;
  const notOffered = outside && why ? { version: outside, published: published(outside), reason: why } : undefined;

  // (a) Only what `to` holds keeps the range unsafe.
  const own = judge.at(pkg, input.to);
  if (rc.held_excluded && (rc.affecting_all_total ?? 0) === 0 && minorOnly(own)) {
    rc.held_advice = { dependencies: await describe(own, input.sources), ...(notOffered ? { not_offered: notOffered } : {}) };
    if (notOffered) rc.newest_safe_outside_range = null;
    return;
  }
  // The same, for a high or critical held advisory: named with its override. The verdict stays
  // avoid, and an alternative outside the range stays on offer.
  if (rc.held_excluded && (rc.affecting_all_total ?? 0) === 0 && own?.status === "checked" && own.affected.length > 0) {
    rc.held_advice = { dependencies: await describe(own, input.sources) };
  }
  if (!notOffered || !input.advisories) return;

  // (b) The newest release clear of the package's own advisories, past the far-back one.
  const excluded = excludedReleases(input.index);
  const candidate = Object.values(input.index.releases)
    .map((r) => r.version)
    .filter(
      (v) =>
        !excluded.has(v) &&
        !isPrereleaseIn("npm", v) &&
        compareVersions(v, notOffered.version, "npm") > 0 &&
        rangeAdmits("npm", rc.range, v) !== true &&
        advisoriesAffecting(input.advisories!, v, "npm").length === 0,
    )
    .sort((a, b) => compareVersions(a, b, "npm"))
    .pop();
  if (!candidate) return;
  await judge.judge([{ pkg, versions: [candidate] }]);
  const check = judge.at(pkg, candidate);
  if (check?.status === "checked" && check.affected.length === 0) {
    // Clean after all: it was passed over only because it had not been judged.
    rc.newest_safe_outside_range = candidate;
    return;
  }
  if (!minorOnly(check)) return;
  rc.held_advice = { dependencies: await describe(check, input.sources), alternative: candidate, not_offered: notOffered };
  rc.newest_safe_outside_range = null;
}

/** How many releases outside the range are judged, newest first, looking for one that holds nothing affected. */
const OUTSIDE_JUDGED = 4;
/** A release younger than this is not offered as the alternative (dependency_check's release-age hold). */
const SETTLED_DAYS = 3;

/**
 * No release outside the range was known to be safe. That is also what "none was judged" looks
 * like: checkRange calls a release that holds anything unsafe until its held dependencies have
 * been checked, and a package whose every release pins something (next: postcss) has no judged
 * release outside the range at all. Judge the newest settled, stable releases that the package's
 * own advisories leave clean, and offer the first that holds nothing affected.
 */
async function offerJudgedOutside(
  input: { judge: HeldJudge; pkg: string; to: string; rc: RangeCheck; index: PackageReleaseIndex; advisories: readonly AdvisoryRanges[] | null | undefined; now: Date },
  published: (v: string) => string | null,
): Promise<void> {
  const { rc, judge, pkg } = input;
  const excluded = excludedReleases(input.index);
  const settled = (v: string) => {
    const at = published(v);
    return !at || (input.now.getTime() - Date.parse(at)) / DAY_MS >= SETTLED_DAYS;
  };
  const candidates = Object.values(input.index.releases)
    .map((r) => r.version)
    .filter(
      (v) =>
        !excluded.has(v) &&
        !isPrereleaseIn("npm", v) &&
        rangeAdmits("npm", rc.range, v) !== true &&
        settled(v) &&
        advisoriesAffecting(input.advisories!, v, "npm").length === 0,
    )
    .sort((a, b) => compareVersions(b, a, "npm"))
    .slice(0, OUTSIDE_JUDGED);
  if (candidates.length === 0) return;
  await judge.judge([{ pkg, versions: candidates }]);
  // Never one that is too far back to be an alternative (the same bar as a release that needed no judging).
  const clean = candidates.find((v) => judge.clean(pkg, v) && tooFarBack(input.to, v, published(v), input.now) === null);
  if (clean) rc.newest_safe_outside_range = clean;
}

/** A held check whose affected dependencies carry only low or moderate advisories. */
function minorOnly(check: HeldCheck | undefined): check is { status: "checked"; affected: HeldDependency[] } {
  if (check?.status !== "checked" || check.affected.length === 0) return false;
  const worst = heldSeverity(check.affected);
  return worst === "low" || worst === "medium";
}

async function describe(check: { affected: HeldDependency[] }, sources: FixPathSources | null): Promise<HeldAdvice["dependencies"]> {
  return Promise.all(
    check.affected.map(async (d) => ({
      package: d.name,
      installs: d.version,
      advisories: d.ids,
      severity: d.severity,
      fixed_in: sources ? await childFix(sources, d.name, d.version) : null,
    })),
  );
}

/** Why a release outside the range is too far behind `to` to offer instead of it; null when it is not. */
function tooFarBack(to: string, outside: string, publishedAt: string | null, now: Date): string | null {
  const a = versionParts("npm", to);
  const b = versionParts("npm", outside);
  const why: string[] = [];
  const behind = a && b && a.major > 0 ? a.major - b.major : 0;
  if (behind > OFFER_MAJORS_BEHIND) why.push(`${behind} majors below ${to}`);
  const age = publishedAt ? (now.getTime() - Date.parse(publishedAt)) / DAY_MS : NaN;
  if (age > OFFER_MAX_AGE_DAYS) why.push(`published ${publishedAt!.slice(0, 10)}, more than 18 months ago`);
  return why.length > 0 ? why.join(" and ") : null;
}

/** The smallest release of a held dependency that clears every advisory affecting `version`; null when none is known. */
async function childFix(sources: FixPathSources, name: string, version: string): Promise<string | null> {
  const advisories = await sources.packageAdvisories("npm", name).catch(() => null);
  if (!advisories) return null;
  const fixes = advisories
    .filter((a) => !a.maintenance && advisoryAffects(a, version, "npm"))
    .flatMap((a) => a.spans.map((s) => s.fixed).filter((f): f is string => f !== null && compareVersions(f, version, "npm") > 0));
  if (fixes.length === 0) return null;
  const clean = await cleanFixTarget(sources, "npm", name, fixes, version).catch(() => null);
  return clean?.target ?? null;
}

/** The releases of a safe list worth judging: the smallest (above `from`) and the newest few. */
export function heldRangeCandidates(ownSafe: string[], above: (v: string) => boolean): string[] {
  return [...new Set([...ownSafe.filter(above).slice(0, HELD_CANDIDATES), ...ownSafe.slice(-NEWEST_LISTED)])];
}
