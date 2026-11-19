// SPDX-License-Identifier: Apache-2.0
/**
 * OSV affected ranges, read as version spans, and the smallest version that
 * is clean against EVERY known advisory of a package.
 *
 * A fix target used to be the highest per-advisory fix among the advisories
 * that affect the INSTALLED version. That target can itself be vulnerable to
 * an advisory the installed version predates: openssl 0.10.38 was sent to
 * 0.10.79, which GHSA-phqj-4mhp-q6mq affects (0.10.50 up to 0.10.80), so the
 * recommended upgrade swapped one advisory for another (fix-path oracle,
 * 2026-10-10). The target is now checked against all of the package's
 * advisories, not only the ones the installed version has.
 */

import type { OsvVulnerability } from "./types.js";
import { compareToLowerBound, compareVersions, isComparable, isComposerOrGemPrerelease, parsePep440, samePackageName } from "./version-compare.js";
import { parseSemverPrecedence } from "./semver-precedence.js";
import { isDeclaredNotice, isMaintenanceRecord } from "./maintenance.js";
import { isMalwareRecord } from "./malware.js";
import { pushAll } from "../array-utils.js";

/**
 * One affected span: [introduced, fixed), or [introduced, lastAffected]
 * when OSV gives a `last_affected` event; both null = still open.
 */
export interface AffectedSpan {
  introduced: string;
  fixed: string | null;
  lastAffected: string | null;
  /**
   * The closing event had no `introduced` before it, as its range lists them. OSV's own evaluation
   * gives such an event no effect; here it reads as affected since the beginning, the cautious
   * reading. It is not knowledge: advisoryKnownToAffect leaves it out, so OSV.dev's answer for an
   * exact version decides wherever there is one.
   */
  presumed?: true;
  /**
   * The span's range has a bound this ecosystem's grammar cannot read, so the span says nothing
   * about any version (it is never compared). "list": its affected entry enumerates versions, and
   * membership in that list decides instead. "nothing": the entry enumerates none, and the advisory
   * cannot be decided from the record (advisoryReading "undecided").
   */
  unread?: "list" | "nothing";
}

/** What one advisory says about one package: its spans plus any versions it lists explicitly. */
export interface AdvisoryRanges {
  id: string;
  spans: AffectedSpan[];
  versions: string[];
  /**
   * A maintenance notice (RustSec "unmaintained" and other informational
   * notices), not an exploitable vulnerability. Absent on entries cached
   * before 6.2.
   */
  maintenance?: boolean;
  /**
   * The notice is one the record itself declares (an `informational` class of unmaintained / notice)
   * and it has no `fixed` event: the only notices dependency_check lets a verdict pass over
   * (maintenance.ts isDeclaredNotice). Absent on a notice read from the summary wording alone and on
   * entries cached before 6.3.
   */
  declaredNotice?: boolean;
  /** A malicious-package record (malware.ts isMalwareRecord). */
  malware?: boolean;
  /** The record's `aliases`: the same issue's ids elsewhere (GHSA, PYSEC, CVE). Absent on entries cached by earlier versions. */
  aliases?: string[];
}

type RangeEvent = { kind: "introduced" | "fixed" | "last_affected"; value: string };

/**
 * Flatten the matching package's version ranges into spans, each range read the way the OSV
 * schema's evaluation algorithm reads it: its events sorted by version, each `introduced` opening
 * a span that the next `fixed` or `last_affected` closes. GIT ranges hold commit hashes, not
 * versions, and are skipped.
 *
 * A range with a bound the ecosystem's grammar cannot read is not read in part (its events cannot
 * be put in order): its spans are kept as written, marked `unread`, and decide nothing.
 */
export function collectAffectedSpans(
  affected: OsvVulnerability["affected"] | undefined,
  packageName: string,
  ecosystem: string,
): AffectedSpan[] {
  const spans: AffectedSpan[] = [];
  for (const a of affected ?? []) {
    // Names compare the registry's way: PEP 503 for PyPI (`Jinja2` is
    // `jinja2`), `-`/`_` folding for crates.
    if (!a.package || a.package.ecosystem !== ecosystem || !samePackageName(a.package.name, packageName, ecosystem)) continue;
    const enumerated = (a.versions ?? []).length > 0;
    for (const range of a.ranges || []) {
      if (range.type === "GIT") continue;
      const events = rangeEvents(range.events || [], ecosystem);
      if (events.every((e) => isComparable(e.value, ecosystem))) {
        pushAll(spans, sortedSpans(events, ecosystem));
        continue;
      }
      // Kept for what they name (a fixed version) and as the mark that the range was not read. A
      // span of it with every bound readable and no fix says nothing, and is dropped.
      const unread = enumerated ? ("list" as const) : ("nothing" as const);
      pushAll(
        spans,
        listedSpans(events)
          .filter((s) => s.fixed !== null || !boundsReadable(s, ecosystem))
          .map(({ presumed: _presumed, ...s }) => ({ ...s, unread })),
      );
    }
  }
  return spans;
}

/** A range's events as bounds (coerceBound); an event that is none of the three (`limit`) is left out. */
function rangeEvents(events: ReadonlyArray<{ introduced?: string; fixed?: string; last_affected?: string }>, ecosystem: string): RangeEvent[] {
  const out: RangeEvent[] = [];
  for (const event of events) {
    if (event.introduced !== undefined) out.push({ kind: "introduced", value: coerceBound(event.introduced, ecosystem) });
    else if (event.fixed !== undefined) out.push({ kind: "fixed", value: coerceBound(event.fixed, ecosystem) });
    else if (event.last_affected !== undefined) out.push({ kind: "last_affected", value: coerceBound(event.last_affected, ecosystem) });
  }
  return out;
}

const closing = (e: RangeEvent) => (e.kind === "fixed" ? { fixed: e.value, lastAffected: null } : { fixed: null, lastAffected: e.value });

/**
 * Events paired in the order the record lists them: each `introduced` opens a span and the next
 * closing event ends it. A closing event with nothing open reads as affected since the beginning
 * ("0", OSV's sentinel), marked `presumed`.
 */
function listedSpans(events: readonly RangeEvent[]): AffectedSpan[] {
  const spans: AffectedSpan[] = [];
  let open: AffectedSpan | null = null;
  for (const e of events) {
    if (e.kind === "introduced") {
      if (open) spans.push(open);
      open = { introduced: e.value, fixed: null, lastAffected: null };
    } else if (open) {
      spans.push({ ...open, ...closing(e) });
      open = null;
    } else {
      spans.push({ introduced: "0", ...closing(e), presumed: true });
    }
  }
  if (open) spans.push(open);
  return spans;
}

/**
 * The OSV schema's evaluation, as spans. With the events sorted by version ("0" first; equal
 * versions keep their listed order), a version is affected from an `introduced` at or below it
 * until a `fixed` at or below it or a `last_affected` below it. So an `introduced` inside an open
 * span changes nothing, and neither does a closing event with no span open, with one reading kept
 * on purpose: a closing event that has no `introduced` before it even as the record lists its
 * events ("fixed in 2.1.0" and nothing else) still reads as affected since the beginning, marked
 * `presumed`. Sorting alone never adds that reading: a range listed `introduced 4.0.0-beta1, fixed
 * 4.0.0-beta.11`, its fix ordered below its own start, presumes nothing below it.
 *
 * Paired in listed order instead, that range was the empty `[4.0.0-beta1, 4.0.0-beta.11)`: npm
 * `derby` 4.2.3 was named the newest safe release on its line while OSV.dev, which sorts, reported
 * it affected by the same advisory (GHSA-82jv-9wjw-pqh6).
 */
function sortedSpans(events: readonly RangeEvent[], ecosystem: string): AffectedSpan[] {
  const unopened = new Set<RangeEvent>();
  let listedOpen = false;
  for (const e of events) {
    if (e.kind === "introduced") listedOpen = true;
    else if (listedOpen) listedOpen = false;
    else unopened.add(e);
  }
  const spans: AffectedSpan[] = [];
  let open: string | null = null;
  for (const e of [...events].sort((x, y) => compareVersions(x.value, y.value, ecosystem))) {
    if (e.kind === "introduced") {
      open ??= e.value;
    } else if (open !== null) {
      spans.push({ introduced: open, ...closing(e) });
      open = null;
    } else if (unopened.has(e)) {
      spans.push({ introduced: "0", ...closing(e), presumed: true });
    }
  }
  if (open !== null) spans.push({ introduced: open, fixed: null, lastAffected: null });
  return spans;
}

/** Whether every bound of a span is a version this ecosystem orders ("0" is OSV's since-the-beginning). */
function boundsReadable(s: AffectedSpan, ecosystem: string): boolean {
  const ok = (v: string | null) => v === null || isComparable(v, ecosystem);
  return ok(s.introduced) && ok(s.fixed) && ok(s.lastAffected);
}

const SEMVER_FAMILY = new Set(["npm", "crates.io", "Go"]);
const LOOSE_SEMVER = /^(v?)(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:([-+])?([0-9A-Za-z][0-9A-Za-z.+-]*))?$/;

/**
 * A range bound as OSV evaluates it, for the semver ecosystems (npm, crates.io, Go). Advisory
 * data is hand-written and sometimes not semver: GHSA-92cp-5422-2mw7 (go-redis v9) opens a range
 * at `9.6.0b1`. Read as unreadable, it made vulnerability_scan say no release clears the advisory
 * ("9.6.3 is still affected") while dependency_check read the bound as 0 and called 9.6.3 clean,
 * and called 9.5.5 affected, which OSV does not. OSV's own reading (its semver coercion: missing
 * minor and patch are 0, a bare suffix is a prerelease) puts `9.6.0b1` just below 9.6.0, which is
 * what api.osv.dev answers per version: 9.6.0 to 9.6.2 affected, 9.5.5 and 9.6.3 not
 * (2026-11-10). So a bound that does not parse is coerced that way, and kept as written when
 * even that does not parse (then readableAdvisory still calls it unreadable, as before).
 * Every reader of ranges goes through here, so every tool reads the same bound the same way.
 */
export function coerceBound(bound: string, ecosystem: string): string {
  if (bound === "0" || !SEMVER_FAMILY.has(ecosystem) || isComparable(bound, ecosystem)) return bound;
  const m = LOOSE_SEMVER.exec(bound.trim());
  if (!m) return bound;
  const [, v, major, minor, patch, sep, rest] = m;
  const core = `${v}${major}.${minor ?? "0"}.${patch ?? "0"}`;
  const coerced = rest === undefined ? core : sep === "+" ? `${core}+${rest}` : `${core}-${rest}`;
  return isComparable(coerced, ecosystem) ? coerced : bound;
}

/** Versions an advisory lists explicitly for this package (`affected[].versions`). */
function listedVersions(affected: OsvVulnerability["affected"] | undefined, packageName: string, ecosystem: string): string[] {
  const out: string[] = [];
  for (const a of affected ?? []) {
    if (!a.package || a.package.ecosystem !== ecosystem || !samePackageName(a.package.name, packageName, ecosystem)) continue;
    pushAll(out, a.versions ?? []);
  }
  return out;
}

/** One advisory's ranges for one package; null when the advisory is withdrawn. */
export function advisoryRanges(vuln: OsvVulnerability, packageName: string, ecosystem: string): AdvisoryRanges | null {
  if (vuln.withdrawn) return null;
  // THE malware predicate (malware.ts) over the whole record: ids, CWE-506, a malware title, malware-only details wording.
  const malware = isMalwareRecord(vuln);
  return {
    id: vuln.id,
    spans: collectAffectedSpans(vuln.affected, packageName, ecosystem),
    versions: listedVersions(vuln.affected, packageName, ecosystem),
    maintenance: isMaintenanceRecord(vuln, packageName, ecosystem),
    ...(isDeclaredNotice(vuln, packageName, ecosystem) ? { declaredNotice: true } : {}),
    ...(malware ? { malware: true } : {}),
    ...(vuln.aliases && vuln.aliases.length > 0 ? { aliases: [...vuln.aliases] } : {}),
  };
}

/**
 * One id per advisory: OSV publishes one issue as a GHSA record and an ecosystem record
 * (PYSEC, RUSTSEC, GO) naming each other in `aliases`, so counting ids counted one issue
 * twice (advisory-groups.ts does the same for scan entries). Grouping is transitive; the
 * first id of each group, in input order, stands for it.
 */
export function oneIdPerAdvisory(ids: readonly string[], advisories: readonly AdvisoryRanges[]): string[] {
  const links = new Map<string, string[]>();
  for (const a of advisories) links.set(a.id, [...(links.get(a.id) ?? []), ...(a.aliases ?? [])]);
  const reverse = new Map<string, string[]>();
  for (const [id, aliases] of links) for (const alias of aliases) reverse.set(alias, [...(reverse.get(alias) ?? []), id]);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    if (seen.has(id)) continue;
    out.push(id);
    const stack = [id];
    while (stack.length > 0) {
      const next = stack.pop()!;
      if (seen.has(next)) continue;
      seen.add(next);
      pushAll(pushAll(stack, links.get(next) ?? []), reverse.get(next) ?? []);
    }
  }
  return out;
}

/**
 * What one advisory's record says about one version:
 * - "affected": the version is listed, or lies in a span an `introduced` event opens.
 * - "presumed": it lies only in a span presumed from a closing event (AffectedSpan.presumed).
 * - "undecided": nothing readable covers it, and a range of the advisory could not be read with no
 *   enumerated list to decide in its place. The record alone cannot say; OSV.dev's own answer for
 *   the exact version can.
 * - "clear": the record was read and does not cover it.
 *
 * A listed version matches when it is the same version in the ecosystem's
 * order, not only the same string: OSV lists certifi `2020.12.05` (from the
 * git tag) and pip installs `2020.12.5`, the same PEP 440 version, which OSV
 * reports as affected by PYSEC-2024-230 (4DA conformance corpus, 2026-10-12).
 */
export type AdvisoryReading = "affected" | "presumed" | "undecided" | "clear";

export function advisoryReading(advisory: AdvisoryRanges, version: string, ecosystem: string): AdvisoryReading {
  const index = readIndex(advisory, ecosystem);
  if (index.exact.has(version)) return "affected";
  const comparable = isComparable(version, ecosystem);
  if (comparable) {
    // Only the listed versions that can equal it are compared: OSV lists every affected PyPI release
    // (hundreds per Django advisory), and comparing each against each candidate took 25-30 s of CPU
    // for one dependency_check of django 4.2.0 (pre-publish audit 2026-11-12, S1).
    const key = releaseKey(version);
    const near = key === null ? index.all : [...(index.byKey.get(key) ?? []), ...index.unkeyed];
    if (near.some((v) => compareVersions(v, version, ecosystem) === 0)) return "affected";
  }
  // Every bound in `firm` and `presumed` was read, so a comparison below is never the "0 for
  // unreadable" of compareVersions. A version the ecosystem cannot order is inside any span that
  // names no fix, as before.
  const inside = (s: AffectedSpan) =>
    comparable
      ? compareToLowerBound(version, s.introduced, ecosystem) >= 0 &&
        (s.fixed !== null ? compareVersions(version, s.fixed, ecosystem) < 0 : s.lastAffected === null || compareVersions(version, s.lastAffected, ecosystem) <= 0)
      : s.fixed === null;
  if (index.firm.some(inside)) return "affected";
  if (index.presumed.some(inside)) return "presumed";
  return index.undecidable ? "undecided" : "clear";
}

/**
 * True unless the advisory's record was read and does not cover `version`: the question every
 * "is this release clean?" decision asks. A version the record cannot decide (an unreadable bound,
 * a presumed span) is never called clear of the advisory, so no release is named safe on it.
 */
export function advisoryAffects(advisory: AdvisoryRanges, version: string, ecosystem: string): boolean {
  return advisoryReading(advisory, version, ecosystem) !== "clear";
}

/**
 * True only when the record itself places `version` among the affected: the question asked before
 * a release is called affected on the record's word, or OSV.dev's per-version answer is held to
 * it. A bound that cannot be read is never compared, so it never makes a version affected: PYSEC-2024-264
 * ends at `last_affected: "2.9.0-NA"`, and read as equal to every version it made every release of
 * apache-airflow affected, the newest included, which OSV.dev's own answer does not.
 */
export function advisoryKnownToAffect(advisory: AdvisoryRanges, version: string, ecosystem: string): boolean {
  return advisoryReading(advisory, version, ecosystem) === "affected";
}

/**
 * The leading release numbers with trailing zeros dropped ("v1.2.0rc1" -> "1.2"): two versions equal
 * in any ecosystem's order share it. Null for a form that may not (an epoch "1!2.0", no digits).
 */
const RELEASE_KEYS = new Map<string, string | null>();

/** The release numbers of a version without trailing zeros ("1.2.0" -> "1.2"), or null; exported for tests. */
export function releaseKey(version: string): string | null {
  const hit = RELEASE_KEYS.get(version);
  if (hit !== undefined) return hit;
  const key = releaseKeyOf(version);
  if (RELEASE_KEYS.size >= 20_000) RELEASE_KEYS.delete(RELEASE_KEYS.keys().next().value!);
  RELEASE_KEYS.set(version, key);
  return key;
}

function releaseKeyOf(version: string): string | null {
  if (version.includes("!")) return null;
  // `\d`, not `d`: written without the backslashes (#68) the key never matched, every version fell
  // into `unkeyed`, and each release was compared with every listed version again: a cold
  // dependency_check of django 4.2.0 held the event loop 1.4-2.0 s (black-box round 8).
  const m = /^v?(\d+(?:\.\d+)*)/.exec(version.trim());
  if (!m) return null;
  const parts = m[1].split(".").map((n) => String(Number(n)));
  while (parts.length > 1 && parts[parts.length - 1] === "0") parts.pop();
  return parts.join(".");
}

interface ReadIndex {
  exact: Set<string>;
  /** Comparable listed versions by releaseKey. */
  byKey: Map<string, string[]>;
  /** Comparable listed versions with no key: compared against every candidate. */
  unkeyed: string[];
  all: string[];
  /** Spans whose every bound was read, opened by an `introduced` event. */
  firm: AffectedSpan[];
  /** Spans whose every bound was read, presumed from a closing event alone. */
  presumed: AffectedSpan[];
  /** A range could not be read and no enumerated list decides in its place. */
  undecidable: boolean;
}

/** One index per advisory and ecosystem, built on first use (an advisory's lists and spans never change once read). */
const READ = new WeakMap<AdvisoryRanges, Map<string, ReadIndex>>();

function readIndex(advisory: AdvisoryRanges, ecosystem: string): ReadIndex {
  let perEco = READ.get(advisory);
  if (!perEco) READ.set(advisory, (perEco = new Map()));
  const hit = perEco.get(ecosystem);
  if (hit) return hit;
  const index: ReadIndex = { exact: new Set(advisory.versions), byKey: new Map(), unkeyed: [], all: [], firm: [], presumed: [], undecidable: false };
  for (const v of advisory.versions) {
    if (v === "0" || !isComparable(v, ecosystem)) continue;
    index.all.push(v);
    const key = releaseKey(v);
    if (key === null) index.unkeyed.push(v);
    else index.byKey.set(key, [...(index.byKey.get(key) ?? []), v]);
  }
  for (const s of advisory.spans) {
    // A span with an unreadable bound and no mark (one cached before the mark existed) decides nothing either.
    const unread = s.unread ?? (boundsReadable(s, ecosystem) ? null : "nothing");
    if (unread === "nothing") index.undecidable = true;
    else if (unread === null) (s.presumed ? index.presumed : index.firm).push(s);
  }
  perEco.set(ecosystem, index);
  return index;
}

/**
 * The advisories (maintenance notices left out) that `version` cannot be called clear of
 * (advisoryAffects): the predicate dependency_check
 * decides `proceed` by over a package's advisory list (checkRange), and the one every other tool
 * runs on a release it offers (offered-release.ts). One predicate, so no tool offers a release
 * dependency_check would refuse (final release audit of 6.2.5: upgrade_planner offered crossenv
 * 1.0.1, which GHSA-c2m4-w5hm-vqjw lists as malware).
 */
export function advisoriesAffecting(advisories: readonly AdvisoryRanges[], version: string, ecosystem: string): string[] {
  return [...new Set(advisories.filter((a) => !a.maintenance && advisoryAffects(a, version, ecosystem)).map((a) => a.id))];
}

/**
 * Whether an advisory's record decides every version of this package: at least one span or listed
 * version, and no range left unread without an enumerated list to decide in its place
 * (AffectedSpan.unread; "0" is OSV's since-the-beginning and is always read).
 */
export function readableAdvisory(a: AdvisoryRanges, ecosystem: string): boolean {
  if (a.spans.length === 0 && a.versions.length === 0) return false;
  return !readIndex(a, ecosystem).undecidable;
}

/**
 * The advisory as its readable ranges and listed versions alone state it: what it is KNOWN to
 * cover. Null when nothing of it could be read.
 */
function readablePart(a: AdvisoryRanges, ecosystem: string): AdvisoryRanges | null {
  if (readableAdvisory(a, ecosystem)) return a;
  const spans = a.spans.filter((s) => s.unread === undefined && boundsReadable(s, ecosystem));
  return spans.length === 0 && a.versions.length === 0 ? null : { ...a, spans };
}

/** Every "clean release" decision, over one package's advisories (CleanReleases). */
export interface CleanReleases {
  /** Advisories whose ranges cannot be read: the decision is UNKNOWN, no release is named, and the reason says so. */
  unreadable: string[];
  /** Malware advisories: any release one affects is never clean, never a target, never "newest". */
  malware: string[];
  /** Genuinely unfixed, non-malware advisories (they affect the highest release too): skipped when choosing. */
  unfixed: string[];
  /** No advisory that counts (every readable one but the unfixed) affects `version`. False for all when `unreadable` is not empty. */
  clean: (version: string) => boolean;
  /** The highest stable release no malicious advisory affects; null when none (or the decision is unknown). */
  newest: string | null;
  /** The unfixed advisories that still affect `version`: its text says "remains affected by <id> (no fix published)". */
  remains: (version: string) => string[];
  /** The malicious advisories that affect `version`: an installed copy they affect names no release at all. */
  maliciousAt: (version: string) => string[];
  /** The non-malicious advisories that affect `version` but not the installed version (a move would bring them in); empty without `installed`. */
  introducedAt: (version: string) => string[];
  /** `clean`, except that advisories the installed version does not have are ignored: whether only those block `version`. */
  cleanButIntroduced: (version: string) => boolean;
}

/**
 * THE predicate for every "clean release" decision a tool makes, the rule of the 4DA #981
 * re-review (2026-10-18): the newest release, a parent's or lever's own advisories, the child copy,
 * parent standing, and the release a row offers. Underneath, the advisory-window function
 * dependency_check decides `proceed` by (advisoryAffects, maintenance notices left out).
 * (a) A malware advisory (MAL-, or a malicious-package record) is never skipped: a release it
 *     affects is never clean, never a target, never "newest"; the advice is to remove or replace.
 * (b) An advisory with no ranges, or ranges that cannot be parsed, makes the decision unknown.
 * (c) A genuinely unfixed, non-malware advisory (it also affects the highest release) may be
 *     skipped, and the chosen release says it remains affected.
 * Skipping ANY advisory that affects the newest release, as before, was wrong for (a) and (b).
 * `releases` are the candidates (installable; prereleases are left out of "highest").
 */
export function cleanReleases(advisories: readonly AdvisoryRanges[], ecosystem: string, releases: readonly string[], installed?: string | null): CleanReleases {
  const real = advisories.filter((a) => !a.maintenance);
  const unreadable = [...new Set(real.filter((a) => !readableAdvisory(a, ecosystem)).map((a) => a.id))];
  const readable = real.filter((a) => readableAdvisory(a, ecosystem));
  const malware = [...new Set(readable.filter((a) => a.malware).map((a) => a.id))];
  const cmp = (a: string, b: string) => compareVersions(a, b, ecosystem);
  const stable = releases.filter((v) => isComparable(v, ecosystem) && !isPrereleaseVersion(v, ecosystem)).sort(cmp);
  // #981 round 3: newest = the highest stable, non-withdrawn release no MALICIOUS advisory affects;
  // usable(v) = no malicious advisory affects v, and every other advisory affecting v also affects
  // newest (no fix is published for it), so an unfixed advisory never blocks a move that fixes the rest.
  const malicious = readable.filter((a) => a.malware);
  const benign = readable.filter((a) => !a.malware);
  const notMalicious = (v: string) => !malicious.some((a) => advisoryAffects(a, v, ecosystem));
  const newest = unreadable.length > 0 ? null : ([...stable].reverse().find(notMalicious) ?? null);
  // Skipped only when the installed version already has it: a move never brings an advisory in.
  const unfixedAdv = newest ? benign.filter((a) => advisoryAffects(a, newest, ecosystem) && (!installed || advisoryAffects(a, installed, ecosystem))) : [];
  const clean = (v: string) => unreadable.length === 0 && notMalicious(v) && benign.every((a) => !advisoryAffects(a, v, ecosystem) || unfixedAdv.includes(a));
  return {
    unreadable,
    malware,
    unfixed: [...new Set(unfixedAdv.map((a) => a.id))],
    clean,
    newest,
    remains: (v) => [...new Set(unfixedAdv.filter((a) => advisoryAffects(a, v, ecosystem)).map((a) => a.id))],
    maliciousAt: (v) => [...new Set(malicious.filter((a) => advisoryAffects(a, v, ecosystem)).map((a) => a.id))],
    introducedAt: (v) =>
      installed ? [...new Set(benign.filter((a) => advisoryAffects(a, v, ecosystem) && !advisoryAffects(a, installed, ecosystem)).map((a) => a.id))] : [],
    cleanButIntroduced: (v) =>
      !!installed &&
      unreadable.length === 0 &&
      notMalicious(v) &&
      benign.every((a) => !advisoryAffects(a, v, ecosystem) || unfixedAdv.includes(a) || !advisoryAffects(a, installed, ecosystem)),
  };
}

/** "remains affected by GHSA-x (no fix published)", or "" when nothing remains. */
export function remainsText(ids: string[]): string {
  return ids.length === 0 ? "" : `remains affected by ${ids.join(", ")} (no fix published)`;
}

/** Whether a version is a prerelease in its ecosystem's own terms. */
export function isPrereleaseVersion(version: string, ecosystem: string): boolean {
  if (ecosystem === "PyPI") {
    const p = parsePep440(version);
    return p ? p.pre !== null || p.dev !== null : false;
  }
  // Gem prereleases are letter segments (`4.2.0.beta3`), not `-` suffixes.
  const own = isComposerOrGemPrerelease(version, ecosystem);
  if (own !== null) return own;
  const p = parseSemverPrecedence(version.replace(/^v(?=\d)/, ""));
  return p ? p.prerelease.length > 0 : false;
}

export interface CleanTarget {
  /** The smallest candidate at or above every per-advisory fix that no fixable advisory affects; null when none is clean. */
  target: string | null;
  /**
   * True when no advisory named a fixed version (only `last_affected`) and
   * `target` is the first published release above the installed version that
   * no known advisory affects (fix-paths.ts cleanFixTarget).
   */
  noAdvisoryFix?: boolean;
  /** True when `floor` is published but deprecated or yanked, so it is never the target. */
  floorWithdrawn?: boolean;
  /** Where the candidates came from. */
  basis: "registry" | "advisory_fixes";
  /** The highest per-advisory fix. */
  floor: string;
  /** Advisories that affect the floor (why the target can be above it). */
  floorAffectedBy: string[];
  /**
   * Advisories that still affect the returned target (only unfixable ones:
   * every candidate has them), or, when `target` is null, the floor.
   */
  stillAffectedBy: string[];
  /**
   * Advisories no release fixes: they affect the newest candidate too
   * (braces GHSA-vfj7-8cjw-p6xm, last_affected 3.0.3 = the newest release).
   * No target can clear them, so they do not disqualify one; they are
   * reported instead.
   */
  unfixable: string[];
  /**
   * Releases the registry withdrew (yanked, deprecated: `excluded`) that the
   * target would otherwise have been: each one at or above the floor and
   * below the target (every one, when there is no target) that the advisories
   * the target is judged against do not affect, and the per-advisory fixes
   * below it that the registry does not list although it lists a later
   * release (audit A-1, node-ipc 10.1.3). Ascending. With no target, a
   * non-empty list means no fix can be installed (withdrawn, or never
   * published): "no installable fix", not "no fix published" (4DA FX-H5
   * `WalkOutcome.withheld`); left without the unlisted ones when malware or an
   * advisory every fix brings in is the reason instead.
   */
  withheld: string[];
  /**
   * The target is above every release the registry listed when read: an advisory's fixed version
   * newer than the facts (4DA `Known::unlisted`, the ceiling rule). Said, so nobody takes it for a
   * release the registry was seen to serve.
   */
  aboveListed?: boolean;
  /** Advisories whose ranges cannot be read: no target is named, and the reason says so (#981 rule b). */
  unreadable?: string[];
  /**
   * With `unreadable` and no target: the answer as the readable ranges alone give it. It is NOT a
   * release to name. It becomes the answer only when OSV.dev, asked about `ifConfirmed.target`
   * itself, names none of the unread advisories against it (batch-confirm.ts confirmTargets);
   * every reader that does not ask sees no target.
   */
  ifConfirmed?: CleanTarget;
  /** No target: every fixing release brings in these advisories, which the installed version does not have. */
  introduces?: string[];
  /**
   * No target, and malware advisories (the malware predicate) affect releases a fix could land
   * on: reported as malware ("<pkg> is flagged malicious (<id>): remove or replace <pkg>"), never
   * as "brings in MAL-x" (#994 review). Sorted.
   */
  maliciousLanding?: string[];
}

/** Whether `version` is one of `listed`, as a version (build metadata ignored), not only as a string. */
export function isListedVersion(listed: readonly string[], version: string, ecosystem: string): boolean {
  if (listed.includes(version)) return true;
  if (!isComparable(version, ecosystem)) return false;
  return listed.some((l) => isComparable(l, ecosystem) && compareVersions(l, version, ecosystem) === 0);
}

/**
 * The smallest version at or above the highest per-advisory fix that none
 * of the package's fixable advisories affects.
 *
 * Candidates are the package's published releases when known (prereleases
 * only when the floor is one), otherwise every fix event the advisories
 * name. An advisory that affects the newest candidate has no fixed release
 * and does not disqualify a target (it is listed in `unfixable`). Null when
 * `fixes` is empty.
 *
 * `excluded`: releases the registry withdrew (withdrawn-releases.ts). They
 * stay in the pool so the result can say it passed one (`withheld`), but are
 * never the target, exactly as a prerelease is not; an advisory whose every
 * way out is withdrawn then has none, like an unfixed one (FX-H5).
 */
export function smallestCleanVersion(input: {
  ecosystem: string;
  fixes: string[];
  advisories: AdvisoryRanges[];
  published: string[] | null;
  excluded?: readonly string[];
  /**
   * The installed version. An advisory no release fixes may be skipped only when the installed
   * version already has it: a target never brings in an advisory, fixed or not, that the installed
   * version does not have (the 4DA lead, 2026-10-18). Without it, as before (vectors that name none).
   */
  installed?: string | null;
  /**
   * Versions the registry was asked for by name and does not serve (fix-paths.ts versionExists): an
   * advisory's fixed version above every listed release that turned out not to exist for this
   * package or module path (go.etcd.io/etcd "3.4.44": Go major 3 is another module). Never a
   * candidate, and named in `withheld`. Without it, as before (the shared vectors name none).
   */
  absent?: readonly string[];
}): CleanTarget | null {
  // #994 review (both engines): a maintenance notice (unmaintained / deprecated package) never
  // blocks a target, never makes a release unclean, and never "introduces": it is not judged here.
  input = { ...input, advisories: input.advisories.filter((a) => !a.maintenance) };
  const { ecosystem } = input;
  const fixes = input.fixes.filter((f) => isComparable(f, ecosystem));
  if (fixes.length === 0) return null;
  const cmp = (a: string, b: string) => compareVersions(a, b, ecosystem);
  const floor = fixes.reduce((max, v) => (cmp(v, max) > 0 ? v : max), fixes[0]);
  const allowPre = isPrereleaseVersion(floor, ecosystem);
  const excluded = input.excluded ?? [];
  const withdrawn = (v: string) => excluded.length > 0 && isListedVersion(excluded, v, ecosystem);

  const fromRegistry = input.published !== null && input.published.length > 0;
  // Audit A-1 (4DA FX `unlisted`): with registry facts, a version the advisory data names that the
  // registry does not list, below a release it does list, is no release at all: never a step, and
  // named in `withheld` (node-ipc's GHSA-97m3-w2cp-4xx6 "fixed" 10.1.3; npm serves 10.1.0, then
  // 11.0.0). A version above every listed release may be newer than the facts: the advisory's word stands.
  const listed = fromRegistry ? input.published!.filter((v) => isComparable(v, ecosystem)) : [];
  const ceiling = listed.length > 0 ? listed.reduce((max, v) => (cmp(v, max) > 0 ? v : max), listed[0]) : null;
  // A Go pseudo-version is never in the proxy's list, yet installable: never "unlisted" (second review W2).
  const absent = input.absent ?? [];
  const isAbsent = (v: string) => absent.length > 0 && isListedVersion(absent, v, ecosystem);
  const unlisted = (v: string) =>
    isAbsent(v) || (ceiling !== null && cmp(v, ceiling) <= 0 && !isListedVersion(listed, v, ecosystem) && !isGoPseudoVersion(v, ecosystem));
  const pool = fromRegistry
    ? [...input.published!, ...fixes.filter((f) => ceiling !== null && cmp(f, ceiling) > 0 && !isAbsent(f))]
    : [floor, ...input.advisories.flatMap((a) => a.spans.map((s) => s.fixed).filter((f): f is string => f !== null))];
  const releases = [...new Set(pool)]
    .filter((v) => isComparable(v, ecosystem) && cmp(v, floor) >= 0 && (allowPre || !isPrereleaseVersion(v, ecosystem)))
    .sort(cmp);
  const candidates = releases.filter((v) => !withdrawn(v));
  const basis = fromRegistry ? "registry" : "advisory_fixes";
  const newest = candidates[candidates.length - 1];
  // The #981 rule (cleanReleases): an advisory whose ranges cannot be read leaves the decision
  // unknown, no release named; a malware advisory is never "unfixable", so a release it affects is
  // never the target.
  const unread = input.advisories.filter((a) => !a.maintenance && !readableAdvisory(a, ecosystem));
  const unreadable = [...new Set(unread.map((a) => a.id))];
  if (unreadable.length > 0) {
    // What the readable ranges and lists alone decide. An advisory with no ranges at all leaves
    // nothing to hold OSV.dev's per-version answer against, so nothing is worked out past it.
    const decided = unread.some((a) => a.spans.length === 0 && a.versions.length === 0)
      ? null
      : smallestCleanVersion({ ...input, advisories: input.advisories.flatMap((a) => readablePart(a, ecosystem) ?? []) });
    if (!decided) return { target: null, basis, floor, floorAffectedBy: unreadable, stillAffectedBy: unreadable, unfixable: [], withheld: [], unreadable };
    // No release even so: the reasons are the known ones, and the unread advisories are named beside them.
    if (decided.target === null) return { ...decided, unreadable };
    return { target: null, basis, floor, floorAffectedBy: [], stillAffectedBy: [], unfixable: [], withheld: [], unreadable, ifConfirmed: decided };
  }
  const has = (a: AdvisoryRanges) => !input.installed || advisoryAffects(a, input.installed, ecosystem);
  const unfixable = newest ? input.advisories.filter((a) => !a.malware && advisoryAffects(a, newest, ecosystem) && has(a)) : [];
  // Unfixed, and the installed version does not have it: every fixing release would bring it in.
  const introduced = newest ? input.advisories.filter((a) => !a.malware && advisoryAffects(a, newest, ecosystem) && !has(a)) : [];
  const fixable = input.advisories.filter((a) => !unfixable.includes(a));
  const unfixableIds = [...new Set(unfixable.map((a) => a.id))];
  const affecting = (v: string) => [...new Set(input.advisories.filter((a) => advisoryAffects(a, v, ecosystem)).map((a) => a.id))];
  const clear = (judged: AdvisoryRanges[]) => (v: string) => !judged.some((a) => advisoryAffects(a, v, ecosystem));
  // The withdrawn releases that would have been the target (clean against `judged`), and the fixes
  // the registry does not list (A-1), below `target`; ascending. `unlistedToo: false` when there is no
  // target for a stated reason (malware, an advisory every fix brings in): "no installable fix" must
  // not take its place (delta audit F2, second review N3). The installed version is never a fix (F6).
  const passed = (judged: AdvisoryRanges[], target: string | null, unlistedToo = true) => {
    const below = (v: string) => target === null || cmp(v, target) < 0;
    const isInstalled = (v: string) => Boolean(input.installed) && isComparable(input.installed!, ecosystem) && cmp(v, input.installed!) === 0;
    const out = [
      ...releases.filter((v) => withdrawn(v) && below(v) && clear(judged)(v)),
      ...(unlistedToo ? [...new Set(fixes)].filter((f) => unlisted(f) && below(f) && !isInstalled(f)) : []),
    ];
    return [...new Set(out)].sort(cmp);
  };
  // Clean against everything if any candidate is; otherwise against every advisory a release fixes.
  for (const judged of [input.advisories, fixable]) {
    // A prerelease fix event (docker/distribution v2.8.2-beta.1) lets prereleases in, but a clean
    // stable release still comes first: v2.8.2+incompatible, not the beta (audit 6.2.5 A-7).
    const candidate =
      (allowPre ? candidates.find((v) => !isPrereleaseVersion(v, ecosystem) && clear(judged)(v)) : undefined) ?? candidates.find(clear(judged));
    if (candidate) {
      return {
        ...(ceiling !== null && cmp(candidate, ceiling) > 0 ? { aboveListed: true } : {}),
        target: candidate,
        basis,
        floor,
        floorAffectedBy: affecting(floor),
        stillAffectedBy: affecting(candidate),
        unfixable: unfixableIds,
        withheld: passed(judged, candidate),
      };
    }
  }
  // #994 review: the ids are the UNION, over every candidate blocked only by advisories the
  // installed version lacks, of those advisories (sorted), not the smallest such release's alone.
  const lacks = (a: AdvisoryRanges) => !a.malware && !has(a);
  const blockedOnlyByNew = candidates.filter(
    (v) =>
      input.advisories.every((a) => !advisoryAffects(a, v, ecosystem) || unfixable.includes(a) || lacks(a)) &&
      input.advisories.some((a) => lacks(a) && advisoryAffects(a, v, ecosystem)),
  );
  const unionIds = new Set(blockedOnlyByNew.flatMap((v) => input.advisories.filter((a) => lacks(a) && advisoryAffects(a, v, ecosystem)).map((a) => a.id)));
  const introduces = [...(unionIds.size > 0 ? unionIds : new Set(introduced.map((a) => a.id)))].sort();
  const maliciousLanding = [...new Set(input.advisories.filter((a) => a.malware && candidates.some((v) => advisoryAffects(a, v, ecosystem))).map((a) => a.id))].sort();
  return {
    ...(introduces.length > 0 ? { introduces } : {}),
    ...(maliciousLanding.length > 0 ? { maliciousLanding } : {}),
    target: null,
    basis,
    floor,
    floorAffectedBy: affecting(floor),
    stillAffectedBy: affecting(floor),
    unfixable: unfixableIds,
    withheld: passed(fixable, null, introduces.length === 0 && maliciousLanding.length === 0),
  };
}

/** A Go pseudo-version (`v0.0.0-20220314234659-1baeb1ce4c0b`, `+incompatible` allowed). */
export function isGoPseudoVersion(version: string, ecosystem: string): boolean {
  return ecosystem === "Go" && /\d{14}-[0-9a-f]{12}(\+incompatible)?$/.test(version);
}

/**
 * One advisory's own fix as a release the registry still offers (4DA
 * `installable_fix`): `fix` itself, or, when the registry withdrew it, the
 * lowest published release above it that is not withdrawn and that
 * `advisories` (the ones that fix at `fix`) do not affect. `fix: null` with
 * `withheld` set: the fix was published and withdrawn, and no installable
 * release past it is known.
 */
export function installableFix(input: {
  ecosystem: string;
  fix: string;
  advisories: AdvisoryRanges[];
  published: string[] | null;
  excluded: readonly string[];
}): { fix: string | null; withheld: string[] } {
  const { ecosystem, fix } = input;
  if (!isListedVersion(input.excluded, fix, ecosystem)) return { fix, withheld: [] };
  const cmp = (a: string, b: string) => compareVersions(a, b, ecosystem);
  const allowPre = isPrereleaseVersion(fix, ecosystem);
  const above = [...new Set(input.published ?? [])]
    .filter((v) => isComparable(v, ecosystem) && cmp(v, fix) > 0 && (allowPre || !isPrereleaseVersion(v, ecosystem)))
    .filter((v) => !input.advisories.some((a) => !a.maintenance && advisoryAffects(a, v, ecosystem)))
    .sort(cmp);
  const next = above.find((v) => !isListedVersion(input.excluded, v, ecosystem)) ?? null;
  const skipped = above.filter((v) => isListedVersion(input.excluded, v, ecosystem) && (next === null || cmp(v, next) < 0));
  return { fix: next, withheld: [fix, ...skipped.filter((v) => v !== fix)] };
}
