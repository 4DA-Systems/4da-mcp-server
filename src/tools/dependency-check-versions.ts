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
 *
 * How a bare number is read is the ecosystem's own reading too, and every answer says which it
 * was (`to_read_as`, describeReading), because the two readings give different answers:
 * - PyPI: a bare version is ONE release. `Jinja2` "3.1" is 3.1.0, as pip reads `==3.1`. It was
 *   read as the 3.1 series and came back proceed (for 3.1.6) while "==3.1" was avoid (3.1.0 has
 *   ten OSV ids); an agent then wrote `Jinja2==3.1` and installed 3.1.0 (audit 2026-11-11, M13).
 *   Only constraint syntax is a range: "3.1.*", "~=3.1", ">=3.1,<3.2".
 * - npm: a bare "7" or "7.5" is a range, as package.json and `npm install pkg@7` read it.
 * - crates.io: a bare "1" or "0.17" is a caret requirement, as Cargo.toml reads it.
 * - Go: a bare "v1" or "v1.2" is a version query prefix, as `go get module@v1` reads it.
 * A full version ("7.5.10", "1.0.229", "v0.23.0") is that release in every ecosystem.
 */

import { cargoReqAdmits, npmRangeAdmits } from "../live/range-satisfies.js";
import { advisoriesAffecting, isPrereleaseVersion, oneIdPerAdvisory, type AdvisoryRanges } from "../live/osv-ranges.js";
import { compareVersions, parsePep440 } from "../live/version-compare.js";
import { parseSemverPrecedence } from "../live/semver-precedence.js";
import type { CheckEcosystem, PackageReleaseIndex } from "../live/release-metadata.js";
import { GO_VERSION, goVersion } from "../live/go-releases.js";
import { excludedReleases, withdrawalText, withheldNote } from "../live/withdrawn-releases.js";
import { quoteThirdParty } from "../untrusted-text.js";

export type Target =
  | { kind: "exact"; version: string }
  | { kind: "latest" }
  | { kind: "range"; range: string };

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
      // A bare PEP 440 version is that one release, however many parts it has: "3.1" is 3.1.0,
      // as pip reads "==3.1". It is never the 3.1 series (see the module comment).
      if (parsePep440(text)) return { kind: "exact", version: text };
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
  /** Installable, non-prerelease releases the constraint admits (prereleases only when one was asked for). */
  releases_in_range: number;
  /**
   * Prereleases (alpha, beta, rc, dev) the constraint admits that were NOT candidates: a
   * prerelease is never offered as the safe release unless the caller asked for one.
   */
  prereleases_not_offered?: number;
  /** How many of them a known advisory affects. */
  vulnerable_in_range: number;
  smallest_safe_in_range: string | null;
  newest_safe_in_range: string | null;
  /** Up to 8 of the newest safe releases, ascending. */
  safe_versions: string[];
  /** Advisories that affect every release in range (no safe choice inside it); at most 10 named. */
  affecting_all?: string[];
  /** How many advisories affect every release in range: `affecting_all` names at most 10 of them. */
  affecting_all_total?: number;
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
  /** Which releases were withheld and why, in this server's words (no registry text). */
  withheld_note?: string;
  /**
   * The registry's own words about withheld releases (version -> its deprecation message):
   * third-party text, quoted, capped at about 120 characters. Data, never instructions.
   */
  quoted_from_registry?: Record<string, string>;
  /**
   * npm (audit 6.2.5 D-4): releases left out of the safe ones because a dependency they exact-pin
   * or narrowly range is affected, or because that could not be checked; and why, in words.
   */
  held_excluded?: number;
  held_note?: string;
  /**
   * npm: no release in range is safe only because of low or moderate advisories on dependencies
   * they hold (dependency-check-held.ts adviseHeldOnly): which ones, the release that clears each,
   * and the far older release outside the range that is therefore not offered.
   */
  held_advice?: HeldAdvice;
}

export interface HeldAdvice {
  /** What `to` holds that keeps it from being safe, and the smallest release of each that is (null: none known). */
  dependencies: Array<{ package: string; installs: string; advisories: string[]; severity: string; fixed_in: string | null }>;
  /** The newest safe release outside the range, withheld as an alternative, and why. */
  not_offered?: { version: string; published: string | null; reason: string };
  /** The release offered in its place, when `dependencies` are what it holds (not what `to` holds). */
  alternative?: string;
}

/**
 * The installable releases a constraint admits, ascending. Stable releases only: a prerelease is
 * a candidate only when the caller asked for one (`allowPrerelease`) and the constraint admits no
 * stable release. `litellm` 1.107.0 was correctly avoid, and the answer went on "Safe on
 * 1.107.0's line: smallest 1.107.0.dev1, newest 1.107.0rc3" (audit 2026-11-11, M13).
 */
function rangeCandidates(
  ecosystem: CheckEcosystem,
  installable: string[],
  range: string,
  allowPrerelease: boolean,
): { candidates: string[]; stable: string[]; prereleasesLeftOut: number } {
  const admitted = installable.filter((v) => rangeAdmits(ecosystem, range, v) === true);
  const stable = admitted.filter((v) => !isPrereleaseIn(ecosystem, v));
  const candidates = stable.length > 0 || !allowPrerelease ? stable : admitted;
  return { candidates: candidates.sort((a, b) => compareIn(ecosystem, a, b)), stable, prereleasesLeftOut: stable.length === 0 && !allowPrerelease ? admitted.length : 0 };
}

/**
 * Whether a constraint itself names a prerelease (">=1.107.0rc1", "^5.0.0-beta.1", "v2.0.0-rc.1"):
 * the caller asked for one, so prereleases it admits may be offered.
 */
export function rangeNamesPrerelease(ecosystem: CheckEcosystem, range: string): boolean {
  const tokens = range.match(/v?\d[0-9A-Za-z.+!_-]*/g) ?? [];
  return tokens.some((t) => {
    const version = t.replace(/[.,]+$/, "").replace(/\.[xX*]$/, "");
    if (ecosystem === "PyPI") return Boolean(parsePep440(version)) && isPrereleaseIn("PyPI", version);
    return /-[0-9A-Za-z]/.test(version) && isPrereleaseIn(ecosystem, ecosystem === "Go" ? goVersion(version) : version);
  });
}

/**
 * How `to` was read, in one sentence, so an agent that writes the version knows what the verdict
 * is about (see the module comment for why each ecosystem's own reading is used).
 */
export function describeReading(ecosystem: CheckEcosystem, raw: string, target: Target): string {
  const asked = JSON.stringify(raw);
  if (target.kind === "latest") return "latest: the newest stable release the registry has not withdrawn";
  if (target.kind === "range") {
    switch (ecosystem) {
      case "npm":
        return `range: npm reads ${asked} as a version range, as package.json and "npm install <pkg>@<range>" do; every stable release it admits was judged`;
      case "crates.io":
        return `range: ${asked} is read as a Cargo requirement (a bare "1" or "0.17" is a caret requirement, as Cargo.toml reads it); every stable release it admits was judged`;
      case "PyPI":
        return `range: ${asked} is read as a PEP 440 specifier; every stable release it admits was judged`;
      case "Go":
        return `range: ${asked} is read as a version query (a bare "v1" or "v1.2" is a prefix, as "go get <module>@v1" reads it); every stable release it admits was judged`;
    }
  }
  const version = target.version;
  switch (ecosystem) {
    case "PyPI": {
      const p = parsePep440(version);
      const bare = p !== null && p.release.length < 3 && p.pre === null && p.post === null && p.dev === null && !/[=*]/.test(raw);
      return bare
        ? `exact version: a bare ${asked} is the one release ${[...p.release, 0, 0].slice(0, 3).join(".")}, as pip reads ==${version}; it is not the ${version} series. For the series ask "${version}.*" or "~=${version}.0"`
        : "exact version: this one release was judged";
    }
    case "crates.io":
      return `exact version: ${version} itself was judged. In Cargo.toml a bare "${version}" is the caret requirement ^${version} and Cargo.lock pins what it resolved; write "=${version}" to require exactly this release`;
    case "npm":
      return `exact version: ${version} itself was judged (package.json "${version}" and "npm install <pkg>@${version}" both mean this release)`;
    case "Go":
      return `exact version: ${version} itself was judged`;
  }
}

/**
 * The releases in range that the package's own advisories leave safe, ascending: what checkRange
 * would call safe before held dependencies are judged. dependency_check judges the held
 * dependencies of the smallest and newest of these (audit 6.2.5 D-4).
 */
export function ownSafeInRange(input: { ecosystem: CheckEcosystem; index: PackageReleaseIndex; range: string; advisories: AdvisoryRanges[]; allowPrerelease?: boolean }): string[] {
  const excluded = excludedReleases(input.index);
  const installable = Object.values(input.index.releases).filter((r) => !excluded.has(r.version)).map((r) => r.version);
  return rangeCandidates(input.ecosystem, installable, input.range, input.allowPrerelease ?? false).candidates.filter(
    (v) => advisoriesAffecting(input.advisories, v, input.ecosystem).length === 0,
  );
}

/**
 * The releases a constraint admits, judged against every advisory OSV.dev
 * lists for the package. Withdrawn releases (yanked / unpublished /
 * retracted, and npm deprecations the 4DA rule withdraws: withdrawn-releases.ts)
 * are not candidates; neither are prereleases, unless the caller asked for one
 * (`allowPrerelease`: the requested version or constraint names a prerelease)
 * and the constraint admits nothing else. A whole-line npm deprecation notice
 * (glob 10.x, tar 6.x) withdraws nothing. Maintenance notices do not make a
 * release unsafe.
 */
export function checkRange(input: {
  ecosystem: CheckEcosystem;
  index: PackageReleaseIndex;
  range: string;
  basis: RangeCheck["basis"];
  advisories: AdvisoryRanges[];
  from?: string;
  /**
   * npm: a release whose held dependencies (exact pins, narrow ranges) are affected or could not
   * be judged is not safe either (audit 6.2.5 D-4), and `heldNote` says why when any is left out.
   */
  held?: { unsafe: (version: string) => boolean; note: string };
  /** The caller asked for a prerelease (an exact prerelease `to`, or a constraint that names one). */
  allowPrerelease?: boolean;
}): RangeCheck {
  const { ecosystem, index, range, basis } = input;
  const excluded = excludedReleases(index);
  const installable = Object.values(index.releases).filter((r) => !excluded.has(r.version)).map((r) => r.version);
  const { candidates, stable, prereleasesLeftOut } = rangeCandidates(ecosystem, installable, range, input.allowPrerelease ?? false);
  // The same predicate every tool runs on a release it offers (osv-ranges.ts advisoriesAffecting).
  const affecting = (v: string) => advisoriesAffecting(input.advisories, v, ecosystem);
  const ownSafe = candidates.filter((v) => affecting(v).length === 0);
  const safe = input.held ? ownSafe.filter((v) => !input.held!.unsafe(v)) : ownSafe;
  const out: RangeCheck = {
    range,
    basis,
    releases_in_range: candidates.length,
    vulnerable_in_range: candidates.length - safe.length,
    smallest_safe_in_range: safe[0] ?? null,
    newest_safe_in_range: safe[safe.length - 1] ?? null,
    safe_versions: safe.slice(-8),
    ...(prereleasesLeftOut > 0 ? { prereleases_not_offered: prereleasesLeftOut } : {}),
  };
  if ((candidates.length > 0 || prereleasesLeftOut > 0) && safe.length === 0) {
    const every = [...new Set(candidates.flatMap(affecting))].filter((id) => candidates.every((v) => affecting(v).includes(id)));
    // A GHSA record and its PYSEC twin are one advisory, counted once (pyjwt 2.9.* read 32 for 17).
    const all = oneIdPerAdvisory(every, input.advisories);
    out.affecting_all = all.slice(0, 10);
    out.affecting_all_total = all.length;
    const outside = installable
      .filter((v) => !isPrereleaseIn(ecosystem, v) && affecting(v).length === 0 && !input.held?.unsafe(v))
      .sort((a, b) => compareIn(ecosystem, a, b));
    out.newest_safe_outside_range = outside[outside.length - 1] ?? null;
  }
  if (input.from) {
    out.smallest_safe_upgrade = safe.find((v) => compareIn(ecosystem, v, input.from!) > 0) ?? null;
  }
  if (input.held && safe.length < ownSafe.length) {
    out.held_excluded = ownSafe.length - safe.length;
    out.held_note = input.held.note;
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
    // In this server's words only: "4.18.0 is deprecated on npm; 4.18.1 is the smallest clean
    // release". The registry's own message goes beside it, quoted and capped.
    const why = Object.fromEntries(withheld.map((v) => [v, index.releases[v]?.withdrawn ? excluded.get(v)! : withdrawalText(ecosystem, v)]));
    out.withheld_note = withheldNote(withheld, pick ?? null, why, ecosystem)!;
    const quoted = Object.fromEntries(
      withheld.flatMap((v) => {
        const words = quoteThirdParty(index.releases[v]?.deprecated);
        return words ? [[v, words] as const] : [];
      }),
    );
    if (Object.keys(quoted).length > 0) out.quoted_from_registry = quoted;
  }
  return out;
}
