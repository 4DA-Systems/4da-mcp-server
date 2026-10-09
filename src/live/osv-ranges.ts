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
import { compareVersions, isComparable, parsePep440, samePackageName } from "./version-compare.js";
import { parseSemverPrecedence } from "./semver-precedence.js";

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
    if (a.package.ecosystem !== ecosystem || !samePackageName(a.package.name, packageName, ecosystem)) continue;
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
    if (a.package.ecosystem !== ecosystem || !samePackageName(a.package.name, packageName, ecosystem)) continue;
    out.push(...(a.versions ?? []));
  }
  return out;
}

/** One advisory's ranges for one package; null when the advisory is withdrawn. */
export function advisoryRanges(vuln: OsvVulnerability, packageName: string, ecosystem: string): AdvisoryRanges | null {
  if (vuln.withdrawn) return null;
  return {
    id: vuln.id,
    spans: collectAffectedSpans(vuln.affected, packageName, ecosystem),
    versions: listedVersions(vuln.affected, packageName, ecosystem),
  };
}

/** True when `version` lies in a span (or the explicit list) of this advisory. */
export function advisoryAffects(advisory: AdvisoryRanges, version: string, ecosystem: string): boolean {
  if (advisory.versions.includes(version)) return true;
  const cmp = (a: string, b: string) => compareVersions(a, b, ecosystem);
  return advisory.spans.some(
    (s) =>
      cmp(version, s.introduced) >= 0 &&
      (s.fixed !== null ? cmp(version, s.fixed) < 0 : s.lastAffected !== null ? cmp(version, s.lastAffected) <= 0 : true),
  );
}

/** Whether a version is a prerelease in its ecosystem's own terms. */
export function isPrereleaseVersion(version: string, ecosystem: string): boolean {
  if (ecosystem === "PyPI") {
    const p = parsePep440(version);
    return p ? p.pre !== null || p.dev !== null : false;
  }
  const p = parseSemverPrecedence(version.replace(/^v(?=\d)/, ""));
  return p ? p.prerelease.length > 0 : false;
}

export interface CleanTarget {
  /** The smallest candidate at or above every per-advisory fix that no fixable advisory affects; null when none is clean. */
  target: string | null;
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
 */
export function smallestCleanVersion(input: {
  ecosystem: string;
  fixes: string[];
  advisories: AdvisoryRanges[];
  published: string[] | null;
}): CleanTarget | null {
  const { ecosystem } = input;
  const fixes = input.fixes.filter((f) => isComparable(f, ecosystem));
  if (fixes.length === 0) return null;
  const cmp = (a: string, b: string) => compareVersions(a, b, ecosystem);
  const floor = fixes.reduce((max, v) => (cmp(v, max) > 0 ? v : max), fixes[0]);
  const allowPre = isPrereleaseVersion(floor, ecosystem);

  const fromRegistry = input.published !== null && input.published.length > 0;
  const pool = fromRegistry
    ? input.published!
    : [floor, ...input.advisories.flatMap((a) => a.spans.map((s) => s.fixed).filter((f): f is string => f !== null))];
  const candidates = [...new Set(pool)]
    .filter((v) => isComparable(v, ecosystem) && cmp(v, floor) >= 0 && (allowPre || !isPrereleaseVersion(v, ecosystem)))
    .sort(cmp);
  const basis = fromRegistry ? "registry" : "advisory_fixes";
  const newest = candidates[candidates.length - 1];
  const unfixable = newest ? input.advisories.filter((a) => advisoryAffects(a, newest, ecosystem)) : [];
  const fixable = input.advisories.filter((a) => !unfixable.includes(a));
  const unfixableIds = [...new Set(unfixable.map((a) => a.id))];
  const affecting = (v: string) => [...new Set(input.advisories.filter((a) => advisoryAffects(a, v, ecosystem)).map((a) => a.id))];
  // Clean against everything if any candidate is; otherwise against every advisory a release fixes.
  for (const pool of [input.advisories, fixable]) {
    const candidate = candidates.find((v) => !pool.some((a) => advisoryAffects(a, v, ecosystem)));
    if (candidate) return { target: candidate, basis, floor, floorAffectedBy: affecting(floor), stillAffectedBy: affecting(candidate), unfixable: unfixableIds };
  }
  return { target: null, basis, floor, floorAffectedBy: affecting(floor), stillAffectedBy: affecting(floor), unfixable: unfixableIds };
}
