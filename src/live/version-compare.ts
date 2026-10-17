// SPDX-License-Identifier: Apache-2.0
/**
 * Version ordering per ecosystem, for advisory ranges and fix selection.
 *
 * `compareSemver` reads MAJOR.MINOR.PATCH and calls anything else "equal".
 * That is wrong outside npm and crates.io, and it was wrong in practice
 * (measured 2026-10-02 against pip-audit and osv-scanner):
 * - PyPI versions are PEP 440, not semver. `5.1` and `4.2` are ordinary
 *   releases; read as "equal" to everything, django 3.2.0 was sent to the 5.1
 *   line's fix (5.1.1) instead of its own line's (3.2.25 / 4.2.16).
 * - Go versions carry a `v`, OSV's Go ranges do not, and pseudo-versions
 *   (`v0.0.0-20200622213623-75b288015ac9`) order as semver prereleases.
 *
 * `0` is OSV's "since the beginning" bound and orders below every version.
 */

import type { OsvEcosystem } from "./types.js";
import { compareSemver, parseSemver } from "./semver-utils.js";
import { compareVersionPrecedence, parseSemverPrecedence } from "./semver-precedence.js";

// ---------------------------------------------------------------------------
// PEP 440
// ---------------------------------------------------------------------------

interface Pep440 {
  epoch: number;
  release: number[];
  /** Pre-release: [rank, n] with a=0, b=1, rc=2; null for none. */
  pre: [number, number] | null;
  post: number | null;
  dev: number | null;
  /** Local label segments ("1.0+ubuntu.1" -> ["ubuntu", 1]); empty for none. */
  local: Array<number | string>;
}

const PEP440 =
  /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?(?:(?:[-_.]?(?:post|rev|r)[-_.]?(\d*))|-(\d+))?(?:[-_.]?dev[-_.]?(\d*))?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/i;

export function parsePep440(version: string): Pep440 | null {
  const m = PEP440.exec(version.trim());
  if (!m) return null;
  const preRank: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };
  return {
    epoch: m[1] ? Number(m[1]) : 0,
    release: m[2].split(".").map(Number),
    pre: m[3] ? [preRank[m[3].toLowerCase()], m[4] ? Number(m[4]) : 0] : null,
    post: m[5] !== undefined ? (m[5] ? Number(m[5]) : 0) : m[6] !== undefined ? Number(m[6]) : null,
    dev: m[7] !== undefined ? (m[7] ? Number(m[7]) : 0) : null,
    local: m[8] ? m[8].split(/[-_.]/).map((seg) => (/^\d+$/.test(seg) ? Number(seg) : seg.toLowerCase())) : [],
  };
}

export function comparePep440(a: Pep440, b: Pep440): number {
  if (a.epoch !== b.epoch) return a.epoch > b.epoch ? 1 : -1;
  const len = Math.max(a.release.length, b.release.length);
  for (let i = 0; i < len; i++) {
    const x = a.release[i] ?? 0;
    const y = b.release[i] ?? 0;
    if (x !== y) return x > y ? 1 : -1;
  }
  // PEP 440's sort key within one release:
  //   X.devN < X.aN.devM < X.aN < X.aN.postM < X.bN < X.rcN < X < X.postN.devM < X.postN
  // pre: a/b/rc rank, a dev-only release below every pre-release, a final above;
  // then post (none lowest); then dev (none highest).
  const key = (v: Pep440): number[] => [
    v.pre ? v.pre[0] : v.post === null && v.dev !== null ? -1 : 3,
    v.pre ? v.pre[1] : 0,
    v.post === null ? -1 : v.post,
    v.dev === null ? Number.POSITIVE_INFINITY : v.dev,
  ];
  const ka = key(a);
  const kb = key(b);
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) return ka[i] > kb[i] ? 1 : -1;
  }
  return compareLocal(a.local, b.local);
}

/**
 * PEP 440 local labels, which decide only between otherwise equal versions:
 * none sorts below any (1.0 < 1.0+abc.5); segment by segment, numbers compare
 * numerically and sort above strings, strings compare case-folded; a label
 * that extends another sorts above it (1.0+abc.5 < 1.0+abc.7 < 1.0+5).
 * Dropping the label made these compare equal, so a `last_affected` bound
 * equal to a local-labelled install was misread.
 */
function compareLocal(a: Array<number | string>, b: Array<number | string>): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const [x, y] = [a[i], b[i]];
    if (x === y) continue;
    if (typeof x !== typeof y) return typeof x === "number" ? 1 : -1;
    return x > y ? 1 : -1;
  }
  return Math.sign(a.length - b.length);
}

// ---------------------------------------------------------------------------
// Composer (Packagist)
// ---------------------------------------------------------------------------

/**
 * A Composer version as `VersionParser::normalize` reads it: an optional `v`,
 * up to four (here: any number of) numeric parts padded with zeros, then a
 * stability suffix. OSV's Packagist ranges use two-part bounds
 * (`introduced: "6.4"`, symfony/process GHSA-r39x-jcww-82v6), which
 * MAJOR.MINOR.PATCH could not read: compared as "equal" to everything, the
 * 5.4 line's fix 5.4.51 counted as inside [6.4, 6.4.33) and the target jumped
 * to 8.0.5 (readiness audit H2, 2026-10-16). `1.2` is `1.2.0.0`.
 */
interface ComposerVersion {
  release: number[];
  /** dev=0 < alpha=1 < beta=2 < RC=3 < stable=4 < patch=5. */
  stability: number;
  stabilityNum: number[];
  /** A trailing `-dev` (`1.0.0-beta2-dev`): below the same version without it. */
  dev: boolean;
}

const COMPOSER =
  /^v?(\d+(?:\.\d+){0,3})(?:[._-]?(stable|beta|b|alpha|a|rc|patch|pl|p)((?:[.-]?\d+)*))?(?:[.-]?(dev))?(?:\+[0-9a-z.-]+)?$/i;

const COMPOSER_RANK: Record<string, number> = { alpha: 1, a: 1, beta: 2, b: 2, rc: 3, stable: 4, patch: 5, pl: 5, p: 5 };

export function parseComposerVersion(version: string): ComposerVersion | null {
  const m = COMPOSER.exec(version.trim());
  if (!m) return null;
  const token = m[2]?.toLowerCase();
  const devOnly = !token && m[4] !== undefined;
  return {
    release: m[1].split(".").map(Number),
    stability: devOnly ? 0 : token ? COMPOSER_RANK[token] : 4,
    stabilityNum: m[3] ? m[3].split(/[.-]/).filter(Boolean).map(Number) : [],
    dev: !devOnly && m[4] !== undefined,
  };
}

function comparePadded(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y ? 1 : -1;
  }
  return 0;
}

export function compareComposer(a: ComposerVersion, b: ComposerVersion): number {
  const byRelease = comparePadded(a.release, b.release) || Math.sign(a.stability - b.stability);
  if (byRelease !== 0) return byRelease;
  // A bare tag sorts below a numbered one: `beta` < `beta0` (composer/semver, by version_compare).
  const bareA = a.stabilityNum.length === 0;
  const bareB = b.stabilityNum.length === 0;
  if (bareA !== bareB) return bareA ? -1 : 1;
  return comparePadded(a.stabilityNum, b.stabilityNum) || (a.dev === b.dev ? 0 : a.dev ? -1 : 1);
}

// ---------------------------------------------------------------------------
// Gem::Version (RubyGems)
// ---------------------------------------------------------------------------

/** Gem::Version::ANCHORED_VERSION_PATTERN. */
const GEM = /^[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/**
 * Gem::Version's canonical segments: `-` reads as `.pre.`, the text splits
 * into runs of digits and letters, and trailing zeros of the release part
 * and of the prerelease part are dropped, so `3.0` equals `3.0.0` (OSV's
 * RubyGems bounds are two-part: rack GHSA-6xw4-3v39-52mm `introduced: "3.0"`).
 */
export function parseGemVersion(version: string): Array<number | string> | null {
  const v = version.trim();
  if (!GEM.test(v)) return null;
  const segments = (v.replace(/-/g, ".pre.").match(/[0-9]+|[a-z]+/gi) ?? []).map((s) => (/^\d/.test(s) ? Number(s) : s));
  const firstString = segments.findIndex((s) => typeof s === "string");
  const cut = firstString < 0 ? segments.length : firstString;
  const trim = (part: Array<number | string>) => {
    let end = part.length;
    while (end > 0 && part[end - 1] === 0) end--;
    return part.slice(0, end);
  };
  return [...trim(segments.slice(0, cut)), ...trim(segments.slice(cut))];
}

/** Gem::Version#<=>: a missing segment is 0, a letter run sorts below a number. */
export function compareGem(a: Array<number | string>, b: Array<number | string>): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x === y) continue;
    if (typeof x !== typeof y) return typeof x === "string" ? -1 : 1;
    return x > y ? 1 : -1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const stripGoV = (v: string) => v.replace(/^v(?=\d)/, "");

/** Whether `version` is readable for this ecosystem's ordering. */
export function isComparable(version: string, ecosystem: OsvEcosystem | string): boolean {
  if (version === "0") return true;
  switch (ecosystem) {
    case "PyPI":
      return parsePep440(version) !== null;
    case "Go":
      return parseSemverPrecedence(stripGoV(version)) !== null;
    case "npm":
    case "crates.io":
      return parseSemverPrecedence(version) !== null;
    case "Packagist":
      return parseComposerVersion(version) !== null;
    case "RubyGems":
      return parseGemVersion(version) !== null;
    default:
      return parseSemver(version) !== null;
  }
}

/** Whether a readable version is a prerelease in Composer's or Gem::Version's own terms; null for other ecosystems or unreadable text. */
export function isComposerOrGemPrerelease(version: string, ecosystem: OsvEcosystem | string): boolean | null {
  if (ecosystem === "Packagist") {
    const c = parseComposerVersion(version);
    return c ? c.stability < 4 || c.dev : null;
  }
  if (ecosystem === "RubyGems") {
    const g = parseGemVersion(version);
    return g ? g.some((s) => typeof s === "string") : null;
  }
  return null;
}

/**
 * Order two versions of one ecosystem: 1, -1, or 0 for equal OR unreadable
 * (the same contract as compareSemver, so an unreadable bound never decides).
 */
export function compareVersions(a: string, b: string, ecosystem: OsvEcosystem | string): number {
  if (a === b) return 0;
  if (a === "0") return isComparable(b, ecosystem) ? -1 : 0;
  if (b === "0") return isComparable(a, ecosystem) ? 1 : 0;
  switch (ecosystem) {
    case "PyPI": {
      const pa = parsePep440(a);
      const pb = parsePep440(b);
      return pa && pb ? comparePep440(pa, pb) : 0;
    }
    case "Go":
      return compareVersionPrecedence(stripGoV(a), stripGoV(b)) ?? 0;
    case "npm":
    case "crates.io":
      return compareVersionPrecedence(a, b) ?? compareSemver(a, b);
    case "Packagist": {
      const ca = parseComposerVersion(a);
      const cb = parseComposerVersion(b);
      return ca && cb ? compareComposer(ca, cb) : 0;
    }
    case "RubyGems": {
      const ga = parseGemVersion(a);
      const gb = parseGemVersion(b);
      return ga && gb ? compareGem(ga, gb) : 0;
    }
    default:
      return compareSemver(a, b);
  }
}

/**
 * `version` against an advisory window's LOWER bound (`introduced`). As
 * Composer reads a constraint, a Packagist bound with no stability suffix
 * opens at that release's dev stability (`>=8.0` is `>= 8.0.0.0-dev`), so the
 * line's own prereleases are inside it: GHSA-r39x-jcww-82v6 opens at `8.0`
 * and lists v8.0.0-BETA1 and v8.0.0-RC1 as affected. Compared as a plain
 * version they fell below it (review of 6.2.5 H2, 2026-10-18). The upper
 * bound keeps the plain order on purpose: a prerelease of the fix release
 * (8.0.5-RC1) stays affected, the safe reading (Composer would exclude it).
 * Every other ecosystem: compareVersions.
 */
export function compareToLowerBound(version: string, bound: string, ecosystem: OsvEcosystem | string): number {
  if (ecosystem === "Packagist" && bound !== "0") {
    const v = parseComposerVersion(version);
    const b = parseComposerVersion(bound);
    if (v && b && b.stability === 4 && !/stable/i.test(bound)) return compareComposer(v, { ...b, stability: 0, stabilityNum: [], dev: false });
  }
  return compareVersions(version, bound, ecosystem);
}

/** Highest of `versions` in this ecosystem's order, or null when empty. */
export function maxVersion(versions: string[], ecosystem: OsvEcosystem | string): string | null {
  if (versions.length === 0) return null;
  return versions.reduce((max, v) => (compareVersions(v, max, ecosystem) > 0 ? v : max), versions[0]);
}

/** Package-name equality as the ecosystem's registry defines it. */
export function samePackageName(a: string, b: string, ecosystem: OsvEcosystem | string): boolean {
  if (a === b) return true;
  if (ecosystem === "PyPI") {
    const n = (s: string) => s.toLowerCase().replace(/[-_.]+/g, "-");
    return n(a) === n(b);
  }
  if (ecosystem === "crates.io") {
    const n = (s: string) => s.toLowerCase().replace(/_/g, "-");
    return n(a) === n(b);
  }
  return false;
}

/** Whether a user-typed package name (`package` parameters) names this dependency: registry rules, then case-insensitive. */
export function namesPackage(query: string, name: string, ecosystem: OsvEcosystem | string): boolean {
  const q = query.trim();
  return samePackageName(q, name, ecosystem) || q.toLowerCase() === name.toLowerCase();
}
