// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check version handling across npm, crates.io, PyPI and Go:
 * reading `to` as an exact version, "latest", or a constraint, and finding
 * the safe releases a constraint admits.
 *
 * Why a constraint: an agent told "pin ws 7.x" writes the 7.x release it
 * remembers. In the G7 agent evaluation (2026-10-11) that was ws 7.5.10 and
 * body-parser 1.20.3, both affected by an advisory their next patch fixes.
 * Asked with `to: "7.x"`, the check answers with the smallest and newest
 * release in the constraint that no known advisory affects.
 *
 * Constraint syntax is the ecosystem's own (npm ranges, Cargo requirements,
 * PEP 440 specifiers), plus the shorthand every agent writes: "7.x", "3.1.*",
 * "v1" for a Go major. Pure functions, no I/O.
 */

import { cargoReqAdmits, npmRangeAdmits } from "../live/range-satisfies.js";
import { advisoryAffects, isPrereleaseVersion, type AdvisoryRanges } from "../live/osv-ranges.js";
import { compareVersions, parsePep440 } from "../live/version-compare.js";
import { parseSemverPrecedence } from "../live/semver-precedence.js";
import type { CheckEcosystem, PackageReleaseIndex } from "../live/release-metadata.js";
import { GO_VERSION, goVersion } from "../live/go-releases.js";
import { excludedReleases, withheldNote } from "../live/withdrawn-releases.js";

export type Target =
  | { kind: "exact"; version: string }
  | { kind: "latest" }
  | { kind: "range"; range: string }
  /** PyPI "3.1": the release 3.1 when it is published, else the 3.1.* series. */
  | { kind: "exact_or_series"; version: string; range: string };

const FULL_SEMVER = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** Read a `to` value; null when it is neither a version nor a constraint this ecosystem understands. */
export function parseTarget(ecosystem: CheckEcosystem, raw: string): Target | null {
  const text = raw.trim();
  if (!text) return null;
  if (text.toLowerCase() === "latest") return { kind: "latest" };
  switch (ecosystem) {
    case "npm":
    case "crates.io": {
      // "1.2.3", and the exact-pin spellings "=1.2.3" / "==1.2.3" / "v1.2.3".
      const bare = text.replace(/^={1,2}\s*/, "");
      if (FULL_SEMVER.test(bare)) return { kind: "exact", version: bare.replace(/^v(?=\d)/, "") };
      return rangeAdmits(ecosystem, text, "1.0.0") === null ? null : { kind: "range", range: text };
    }
    case "PyPI": {
      const pinned = /^={2,3}\s*([^,*\s]+)$/.exec(text);
      if (pinned && parsePep440(pinned[1])) return { kind: "exact", version: pinned[1] };
      const p = parsePep440(text);
      if (p) {
        // "3.1.4" is a release; "3.1" may be a release (PyPI has "2.0"s) or mean the 3.1 series.
        const plain = p.release.length < 3 && p.pre === null && p.post === null && p.dev === null && !text.includes("+");
        return plain ? { kind: "exact_or_series", version: text, range: `==${text}.*` } : { kind: "exact", version: text };
      }
      const range = pypiShorthand(text);
      return pep440SpecAdmits(range, "1.0") === null ? null : { kind: "range", range };
    }
    case "Go": {
      const v = goVersion(text);
      if (GO_VERSION.test(v)) return { kind: "exact", version: v };
      return rangeAdmits("Go", text, "v1.0.0") === null ? null : { kind: "range", range: text };
    }
  }
}

/** "3.1.x" / "3.x" / "3.1.*" (no operator) -> "==3.1.*". */
function pypiShorthand(text: string): string {
  const m = /^v?(\d+(?:\.\d+)*)\.[xX*]$/.exec(text);
  return m ? `==${m[1]}.*` : text;
}

/** Whether a constraint admits a version, in the ecosystem's own syntax. Null = unreadable constraint or version. */
export function rangeAdmits(ecosystem: CheckEcosystem, range: string, version: string): boolean | null {
  switch (ecosystem) {
    case "npm":
      return npmRangeAdmits(range, version);
    case "crates.io":
      // Cargo's own syntax first ("0.17" means ^0.17); then npm-style spellings agents also write ("0.17.x").
      return cargoReqAdmits(range, version) ?? npmRangeAdmits(range, version);
    case "PyPI":
      return pep440SpecAdmits(pypiShorthand(range.trim()), version);
    case "Go": {
      // Go has no range syntax of its own; read semver ranges over `v`-less versions ("v1" = the v1 major).
      const unv = range.replace(/(^|[\s,<>=~^|-])v(?=\d)/g, "$1");
      return npmRangeAdmits(unv.replace(/,\s*/g, " "), version.replace(/^v(?=\d)/, "").replace(/\+incompatible$/, ""));
    }
  }
}

type Pep440 = NonNullable<ReturnType<typeof parsePep440>>;

/**
 * PEP 440 version specifiers: comma-separated clauses of `==`, `!=` (both
 * with optional `.*` prefix matching), `>=`, `<=`, `>`, `<`, `~=` and `===`.
 * Null when a clause or the version is unreadable.
 */
export function pep440SpecAdmits(spec: string, version: string): boolean | null {
  const v = parsePep440(version);
  if (!v) return null;
  const clauses = spec.split(",").map((c) => c.trim()).filter(Boolean);
  if (clauses.length === 0) return null;
  for (const clause of clauses) {
    const m = /^(===|~=|==|!=|>=|<=|>|<)\s*(\S+)$/.exec(clause);
    if (!m) return null;
    const [, op, rawTarget] = m;
    if (op === "===") {
      if (rawTarget !== version) return false;
      continue;
    }
    const prefix = rawTarget.endsWith(".*");
    const target = parsePep440(prefix ? rawTarget.slice(0, -2) : rawTarget);
    if (!target) return null;
    let ok: boolean;
    if (prefix) {
      if (op !== "==" && op !== "!=") return null;
      ok = matchesPrefix(v, target) === (op === "==");
    } else if (op === "~=") {
      if (target.release.length < 2) return null;
      const series = { ...target, release: target.release.slice(0, -1), pre: null, post: null, dev: null };
      ok = cmp(v, target) >= 0 && matchesPrefix(v, series);
    } else {
      const d = cmp(v, target);
      ok = op === "==" ? d === 0 : op === "!=" ? d !== 0 : op === ">=" ? d >= 0 : op === "<=" ? d <= 0 : op === ">" ? d > 0 : d < 0;
    }
    if (!ok) return false;
  }
  return true;
}

function cmp(a: Pep440, b: Pep440): number {
  return compareVersions(fmtPep440(a), fmtPep440(b), "PyPI");
}

function fmtPep440(v: Pep440): string {
  const pre = v.pre ? `${["a", "b", "rc"][v.pre[0]]}${v.pre[1]}` : "";
  return `${v.epoch ? `${v.epoch}!` : ""}${v.release.join(".")}${pre}${v.post !== null ? `.post${v.post}` : ""}${v.dev !== null ? `.dev${v.dev}` : ""}`;
}

/** `==X.Y.*`: same epoch and the release starts with X.Y (missing parts read as 0). */
function matchesPrefix(v: Pep440, prefix: Pep440): boolean {
  if (v.epoch !== prefix.epoch) return false;
  return prefix.release.every((n, i) => (v.release[i] ?? 0) === n);
}

/** Order two versions of one ecosystem. */
export function compareIn(ecosystem: CheckEcosystem, a: string, b: string): number {
  return compareVersions(a, b, ecosystem);
}

export function isPrereleaseIn(ecosystem: CheckEcosystem, version: string): boolean {
  if (ecosystem === "Go" && /\d{14}-[0-9a-f]{12}/.test(version)) return true; // pseudo-version
  return isPrereleaseVersion(version, ecosystem);
}

/** MAJOR.MINOR.PATCH of a version in any of the four ecosystems (PEP 440 release parts; missing ones 0). */
export function versionParts(ecosystem: CheckEcosystem, version: string): { major: number; minor: number; patch: number } | null {
  if (ecosystem === "PyPI") {
    const p = parsePep440(version);
    return p ? { major: p.release[0] ?? 0, minor: p.release[1] ?? 0, patch: p.release[2] ?? 0 } : null;
  }
  const p = parseSemverPrecedence(version.replace(/\+incompatible$/, ""));
  return p ? { major: p.major, minor: p.minor, patch: p.patch } : null;
}

/**
 * The release line a version belongs to, as a constraint: the same major (the
 * same 0.minor below 1.0) on npm and crates.io; the same module major on Go,
 * where v0 is one line (`go get -u` moves freely within a module path); the
 * same X.Y series on PyPI, where many projects do not follow semver (Django
 * 4.2 LTS, Jinja2 3.1).
 */
export function lineOf(ecosystem: CheckEcosystem, version: string): string | null {
  const p = versionParts(ecosystem, version);
  if (!p) return null;
  if (ecosystem === "PyPI") return `==${p.major}.${p.minor}.*`;
  if (ecosystem === "Go") return `v${p.major}`;
  return p.major === 0 ? `0.${p.minor}.x` : `${p.major}.x`;
}

export interface RangeCheck {
  /** The constraint evaluated. */
  range: string;
  /** "requested" (the caller's `to`) or "same_line" (the line of an affected exact `to`). */
  basis: "requested" | "same_line";
  /** Installable, non-prerelease releases the constraint admits. */
  releases_in_range: number;
  /** How many of them a known advisory affects. */
  vulnerable_in_range: number;
  smallest_safe_in_range: string | null;
  newest_safe_in_range: string | null;
  /** Up to 8 of the newest safe releases, ascending. */
  safe_versions: string[];
  /** Advisories that affect every release in range (no safe choice inside it); at most 10 named. */
  affecting_all?: string[];
  /** When nothing in range is safe: the newest release of the package that is, outside the range. */
  newest_safe_outside_range?: string | null;
  /** When `from` is given: the smallest safe release above it (the minimal fixing upgrade). */
  smallest_safe_upgrade?: string | null;
  /**
   * Releases in range that no advisory affects but the registry withdrew (yanked; npm
   * deprecated with a later clean release on its line), below the smallest safe pick (all of
   * them when none is safe), and why in plain words (FX-H5).
   */
  withheld?: string[];
  withheld_note?: string;
}

/**
 * The releases a constraint admits, judged against every advisory OSV.dev
 * lists for the package. Withdrawn releases (yanked / unpublished /
 * retracted, and npm deprecations the 4DA rule withdraws: withdrawn-releases.ts)
 * are not candidates; neither are prereleases, unless the constraint admits
 * nothing else. A whole-line npm deprecation notice (glob 10.x, tar 6.x)
 * withdraws nothing. Maintenance notices do not make a release unsafe.
 */
export function checkRange(input: {
  ecosystem: CheckEcosystem;
  index: PackageReleaseIndex;
  range: string;
  basis: RangeCheck["basis"];
  advisories: AdvisoryRanges[];
  from?: string;
}): RangeCheck {
  const { ecosystem, index, range, basis } = input;
  const excluded = excludedReleases(index);
  const installable = Object.values(index.releases).filter((r) => !excluded.has(r.version)).map((r) => r.version);
  const admitted = installable.filter((v) => rangeAdmits(ecosystem, range, v) === true);
  const stable = admitted.filter((v) => !isPrereleaseIn(ecosystem, v));
  const candidates = (stable.length > 0 ? stable : admitted).sort((a, b) => compareIn(ecosystem, a, b));
  const real = input.advisories.filter((a) => !a.maintenance);
  const affecting = (v: string) => real.filter((a) => advisoryAffects(a, v, ecosystem)).map((a) => a.id);
  const safe = candidates.filter((v) => affecting(v).length === 0);
  const out: RangeCheck = {
    range,
    basis,
    releases_in_range: candidates.length,
    vulnerable_in_range: candidates.length - safe.length,
    smallest_safe_in_range: safe[0] ?? null,
    newest_safe_in_range: safe[safe.length - 1] ?? null,
    safe_versions: safe.slice(-8),
  };
  if (candidates.length > 0 && safe.length === 0) {
    out.affecting_all = [...new Set(candidates.flatMap(affecting))].filter((id) => candidates.every((v) => affecting(v).includes(id))).slice(0, 10);
    const outside = installable
      .filter((v) => !isPrereleaseIn(ecosystem, v) && affecting(v).length === 0)
      .sort((a, b) => compareIn(ecosystem, a, b));
    out.newest_safe_outside_range = outside[outside.length - 1] ?? null;
  }
  if (input.from) {
    out.smallest_safe_upgrade = safe.find((v) => compareIn(ecosystem, v, input.from!) > 0) ?? null;
  }
  // The withdrawn releases that would otherwise have been the smallest safe pick (FX-H5).
  const pick = input.from ? out.smallest_safe_upgrade : out.smallest_safe_in_range;
  const withheld = [...excluded.keys()]
    .filter(
      (v) =>
        rangeAdmits(ecosystem, range, v) === true &&
        (stable.length === 0 || !isPrereleaseIn(ecosystem, v)) &&
        (!input.from || compareIn(ecosystem, v, input.from) > 0) &&
        (!pick || compareIn(ecosystem, v, pick) < 0) &&
        affecting(v).length === 0,
    )
    .sort((a, b) => compareIn(ecosystem, a, b));
  if (withheld.length > 0) {
    out.withheld = withheld;
    out.withheld_note = withheldNote(withheld, pick ?? null, Object.fromEntries(excluded), ecosystem)!;
  }
  return out;
}
