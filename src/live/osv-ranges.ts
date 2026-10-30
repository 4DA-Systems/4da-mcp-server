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
import { isMaintenanceRecord } from "./maintenance.js";
import { cweIdsOf, isMalware } from "./malware.js";

/**
 * One affected span: [introduced, fixed), or [introduced, lastAffected]
 * when OSV gives a `last_affected` event; both null = still open.
 */
export interface AffectedSpan {
  introduced: string;
  fixed: string | null;
  lastAffected: string | null;
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
  /** A malicious-package record (malware.ts isMalware: a MAL- id or alias, or CWE-506). */
  malware?: boolean;
}

/**
 * Flatten the matching package's version ranges into spans. OSV sorts events
 * within a range; each `introduced` opens a span and the next `fixed` or
 * `last_affected` closes it. GIT ranges hold commit hashes, not versions,
 * and are skipped.
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
    for (const range of a.ranges || []) {
      if (range.type === "GIT") continue;
      let open: AffectedSpan | null = null;
      for (const event of range.events || []) {
        if (event.introduced !== undefined) {
          if (open) spans.push(open);
          open = { introduced: event.introduced, fixed: null, lastAffected: null };
        } else if (event.fixed !== undefined || event.last_affected !== undefined) {
          const close = { fixed: event.fixed ?? null, lastAffected: event.fixed === undefined ? (event.last_affected ?? null) : null };
          if (open) {
            spans.push({ ...open, ...close });
            open = null;
          } else {
            // A closing event with no preceding `introduced`: affected since
            // inception ("0" = OSV's since-the-beginning sentinel).
            spans.push({ introduced: "0", ...close });
          }
        }
      }
      if (open) spans.push(open);
    }
  }
  return spans;
}

/** Versions an advisory lists explicitly for this package (`affected[].versions`). */
function listedVersions(affected: OsvVulnerability["affected"] | undefined, packageName: string, ecosystem: string): string[] {
  const out: string[] = [];
  for (const a of affected ?? []) {
    if (!a.package || a.package.ecosystem !== ecosystem || !samePackageName(a.package.name, packageName, ecosystem)) continue;
    out.push(...(a.versions ?? []));
  }
  return out;
}

/** One advisory's ranges for one package; null when the advisory is withdrawn. */
export function advisoryRanges(vuln: OsvVulnerability, packageName: string, ecosystem: string): AdvisoryRanges | null {
  if (vuln.withdrawn) return null;
  // THE malware predicate (malware.ts): a MAL- id or alias, or CWE-506; never summary wording.
  const malware = isMalware(vuln.id, vuln.aliases ?? [], cweIdsOf(vuln), vuln.summary ?? "");
  return {
    id: vuln.id,
    spans: collectAffectedSpans(vuln.affected, packageName, ecosystem),
    versions: listedVersions(vuln.affected, packageName, ecosystem),
    maintenance: isMaintenanceRecord(vuln, packageName, ecosystem),
    ...(malware ? { malware: true } : {}),
  };
}

/**
 * True when `version` lies in a span (or the explicit list) of this advisory.
 *
 * A listed version matches when it is the same version in the ecosystem's
 * order, not only the same string: OSV lists certifi `2020.12.05` (from the
 * git tag) and pip installs `2020.12.5`, the same PEP 440 version, which OSV
 * reports as affected by PYSEC-2024-230 (4DA conformance corpus, 2026-10-12).
 */
export function advisoryAffects(advisory: AdvisoryRanges, version: string, ecosystem: string): boolean {
  if (advisory.versions.includes(version)) return true;
  const cmp = (a: string, b: string) => compareVersions(a, b, ecosystem);
  if (isComparable(version, ecosystem) && advisory.versions.some((v) => v !== "0" && isComparable(v, ecosystem) && cmp(v, version) === 0)) {
    return true;
  }
  return advisory.spans.some(
    (s) =>
      compareToLowerBound(version, s.introduced, ecosystem) >= 0 &&
      (s.fixed !== null ? cmp(version, s.fixed) < 0 : s.lastAffected !== null ? cmp(version, s.lastAffected) <= 0 : true),
  );
}

/**
 * The advisories (maintenance notices left out) that affect `version`: the predicate dependency_check
 * decides `proceed` by over a package's advisory list (checkRange), and the one every other tool
 * runs on a release it offers (offered-release.ts). One predicate, so no tool offers a release
 * dependency_check would refuse (final release audit of 6.2.5: upgrade_planner offered crossenv
 * 1.0.1, which GHSA-c2m4-w5hm-vqjw lists as malware).
 */
export function advisoriesAffecting(advisories: readonly AdvisoryRanges[], version: string, ecosystem: string): string[] {
  return [...new Set(advisories.filter((a) => !a.maintenance && advisoryAffects(a, version, ecosystem)).map((a) => a.id))];
}

/**
 * Whether an advisory's ranges can decide anything for this package: at least one span or listed
 * version, and every bound a version this ecosystem orders ("0" is OSV's since-the-beginning).
 */
export function readableAdvisory(a: AdvisoryRanges, ecosystem: string): boolean {
  if (a.spans.length === 0 && a.versions.length === 0) return false;
  const ok = (v: string | null) => v === null || v === "0" || isComparable(v, ecosystem);
  return a.spans.every((s) => ok(s.introduced) && ok(s.fixed) && ok(s.lastAffected));
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
  const unlisted = (v: string) => ceiling !== null && cmp(v, ceiling) <= 0 && !isListedVersion(listed, v, ecosystem) && !isGoPseudoVersion(v, ecosystem);
  const pool = fromRegistry
    ? [...input.published!, ...fixes.filter((f) => ceiling !== null && cmp(f, ceiling) > 0)]
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
  const unreadable = [...new Set(input.advisories.filter((a) => !a.maintenance && !readableAdvisory(a, ecosystem)).map((a) => a.id))];
  if (unreadable.length > 0) {
    return { target: null, basis, floor, floorAffectedBy: unreadable, stillAffectedBy: unreadable, unfixable: [], withheld: [], unreadable };
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
