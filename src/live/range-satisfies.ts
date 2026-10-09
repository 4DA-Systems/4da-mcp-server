// SPDX-License-Identifier: Apache-2.0
/**
 * Does a declared requirement admit a version? npm ranges (package.json,
 * package-lock `dependencies`, yarn) and Cargo version requirements.
 *
 * Used to tell "the parent already allows the fixed version, so a lockfile
 * refresh is enough" from "waiting on upstream". The planner labelled
 * minimist 1.2.5, braces 3.0.2 and mio 0.8.0 "waiting on upstream" although
 * every parent's range admitted the fix, and a refresh fixed each one
 * (fix-path oracle, 2026-10-10).
 *
 * Unknown syntax (git and file specs, `npm:` aliases, dist-tags) yields null,
 * never a guess.
 */

import { comparePrecedence, parseSemverPrecedence, type SemverPrecedence } from "./semver-precedence.js";

type Op = ">=" | ">" | "<" | "<=" | "=";
interface Comparator {
  op: Op;
  v: SemverPrecedence;
}

/** A version that may be partial: "1", "1.2", "1.2.x", "1.2.3-rc.1". Null parts are wildcards. */
interface Partial {
  major: number | null;
  minor: number | null;
  patch: number | null;
  prerelease: string[];
}

const WILD = /^[xX*]$/;

function parsePartial(raw: string): Partial | null {
  const text = raw.trim().replace(/^v/, "").replace(/\+.*$/, "");
  if (text === "" || WILD.test(text)) return { major: null, minor: null, patch: null, prerelease: [] };
  const m = /^(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(text);
  if (!m) return null;
  const num = (s: string | undefined) => (s === undefined || WILD.test(s) ? null : Number(s));
  const major = num(m[1]);
  const minor = major === null ? null : num(m[2]);
  const patch = minor === null ? null : num(m[3]);
  return { major, minor, patch, prerelease: m[4] && patch !== null ? m[4].split(".") : [] };
}

const sv = (major: number, minor: number, patch: number, prerelease: string[] = []): SemverPrecedence => ({ major, minor, patch, prerelease });
/** The lowest version of the next line: the `-0` prerelease, so 2.0.0-beta is excluded by "<2.0.0-0". */
const below = (major: number, minor: number, patch: number): Comparator => ({ op: "<", v: sv(major, minor, patch, ["0"]) });

function floorOf(p: Partial): SemverPrecedence {
  return sv(p.major ?? 0, p.minor ?? 0, p.patch ?? 0, p.prerelease);
}

function caret(p: Partial): Comparator[] {
  if (p.major === null) return [];
  const lo: Comparator = { op: ">=", v: floorOf(p) };
  if (p.major > 0) return [lo, below(p.major + 1, 0, 0)];
  if (p.minor === null) return [lo, below(1, 0, 0)];
  if (p.minor > 0) return [lo, below(0, p.minor + 1, 0)];
  if (p.patch === null) return [lo, below(0, 1, 0)];
  return [lo, below(0, 0, p.patch + 1)];
}

function tilde(p: Partial): Comparator[] {
  if (p.major === null) return [];
  const lo: Comparator = { op: ">=", v: floorOf(p) };
  if (p.minor === null) return [lo, below(p.major + 1, 0, 0)];
  return [lo, below(p.major, p.minor + 1, 0)];
}

/** An x-range or partial version as a range: "1.2" = >=1.2.0 <1.3.0-0. */
function xrange(p: Partial): Comparator[] {
  if (p.major === null) return [];
  if (p.minor === null) return [{ op: ">=", v: sv(p.major, 0, 0) }, below(p.major + 1, 0, 0)];
  if (p.patch === null) return [{ op: ">=", v: sv(p.major, p.minor, 0) }, below(p.major, p.minor + 1, 0)];
  return [{ op: "=", v: floorOf(p) }];
}

function primitive(op: Op, p: Partial): Comparator[] | null {
  if (op === "=") return xrange(p);
  if (p.major === null) return op === "<" || op === ">" ? null : [];
  const full = p.patch !== null;
  if (full) return [{ op, v: floorOf(p) }];
  // Partial bounds widen or narrow to the whole line, as node-semver does.
  const next = p.minor === null ? sv(p.major + 1, 0, 0) : sv(p.major, p.minor + 1, 0);
  switch (op) {
    case ">=":
      return [{ op: ">=", v: floorOf(p) }];
    case ">":
      return [{ op: ">=", v: next }];
    case "<":
      return [{ op: "<", v: sv(p.major, p.minor ?? 0, 0, ["0"]) }];
    case "<=":
      return [{ op: "<", v: { ...next, prerelease: ["0"] } }];
  }
}

/** One comparator token: "^1.2", ">=1.0.0", "~0.3", "1.x". `bareIsCaret` = Cargo's reading of "1.2.3". */
function comparatorSet(token: string, bareIsCaret: boolean): Comparator[] | null {
  const m = /^(\^|~>?|>=|<=|>|<|=)?\s*(.*)$/.exec(token.trim());
  if (!m) return null;
  const p = parsePartial(m[2]);
  if (!p) return null;
  switch (m[1]) {
    case "^":
      return caret(p);
    case "~":
    case "~>":
      return tilde(p);
    case ">=":
    case "<=":
    case ">":
    case "<":
      return primitive(m[1], p);
    case "=":
      return xrange(p);
    default:
      return bareIsCaret && p.major !== null ? caret(p) : xrange(p);
  }
}

function test(set: Comparator[], version: SemverPrecedence): boolean {
  for (const c of set) {
    const d = comparePrecedence(version, c.v);
    const ok = c.op === ">=" ? d >= 0 : c.op === ">" ? d > 0 : c.op === "<" ? d < 0 : c.op === "<=" ? d <= 0 : d === 0;
    if (!ok) return false;
  }
  if (version.prerelease.length === 0) return true;
  // A prerelease satisfies only a set that names a prerelease of the same
  // MAJOR.MINOR.PATCH (node-semver and Cargo agree on this).
  return set.some(
    (c) =>
      c.v.prerelease.length > 0 &&
      !(c.v.prerelease.length === 1 && c.v.prerelease[0] === "0" && c.op === "<") &&
      c.v.major === version.major &&
      c.v.minor === version.minor &&
      c.v.patch === version.patch,
  );
}

/**
 * Whether an npm range admits `version`. Null when the range is not a
 * registry semver range (git, file, link, workspace, alias, tag) or the
 * version is unreadable.
 */
export function npmRangeAdmits(range: string, version: string): boolean | null {
  const v = parseSemverPrecedence(version);
  if (!v) return null;
  // yarn berry writes "npm:^1.2.0"; an alias ("npm:other@^1") names another package.
  const text = range.trim().replace(/^npm:(?=[\^~<>=\dvxX*\s]|$)/, "");
  // Protocols (git+https:, file:, link:, workspace:, npm:alias@), paths, GitHub shorthand.
  if (/^[a-z][a-z+]*:/i.test(text) || text.includes("/")) return null;
  // A dist-tag ("latest", "next", "beta").
  if (/^[a-z][\w.-]*$/i.test(text) && !WILD.test(text)) return null;
  for (const alt of text.split("||")) {
    const part = alt.trim();
    let set: Comparator[] = [];
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(part);
    if (hyphen) {
      const lo = parsePartial(hyphen[1]);
      const hi = parsePartial(hyphen[2]);
      if (!lo || !hi) return null;
      set.push({ op: ">=", v: floorOf(lo) });
      const upper = hi.patch !== null ? [{ op: "<=" as Op, v: floorOf(hi) }] : primitive("<=", hi);
      if (!upper) return null;
      set.push(...upper);
    } else {
      // ">= 1.2.3" with a space after the operator is one comparator.
      for (const token of part.replace(/([<>=~^])\s+/g, "$1").split(/\s+/).filter(Boolean)) {
        const c = comparatorSet(token, false);
        if (c === null) return null;
        set = set.concat(c);
      }
    }
    if (test(set, v)) return true;
  }
  return false;
}

/** Whether a Cargo version requirement ("0.8", "^1.2", ">=0.10, <0.11", "=1.0.5") admits `version`. Null when unreadable. */
export function cargoReqAdmits(req: string, version: string): boolean | null {
  const v = parseSemverPrecedence(version);
  if (!v) return null;
  let set: Comparator[] = [];
  for (const token of req.split(",").map((t) => t.trim()).filter(Boolean)) {
    const c = comparatorSet(token, true);
    if (c === null) return null;
    set = set.concat(c);
  }
  return test(set, v);
}
