// SPDX-License-Identifier: Apache-2.0
/**
 * Enough of .gitignore to decide whether a directory or lockfile belongs to
 * the project, for the standalone project-tree walk.
 *
 * A directory the repository ignores is not part of the project: scratch
 * clones, generated output, a sibling tool checked out inside the tree.
 * Measured 2026-10-02: walking 4DA's root without this scanned the ignored
 * `victauri-gauntlet/` and `cli/` and reported their advisories (rustls, h2,
 * scc) as the project's, where osv-scanner, which honours .gitignore, did not.
 *
 * Read from the files, never by running git: `git check-ignore` in a cloned
 * repository honours that repository's config, and a config can name programs
 * for git to run (core.fsmonitor). Reading a scanned folder must not execute
 * anything it names.
 *
 * Supported: comments, blank lines, `dir/` (directory only), leading `/` and
 * inner `/` anchoring, `*`, `?`, `**`, nested .gitignore files and
 * .git/info/exclude. A negation (`!pattern`) is treated conservatively: a
 * path that any negation could re-include is never skipped.
 *
 * A .gitignore is the scanned repository's own text: hostile input. Patterns
 * used to be translated to regular expressions (`*` -> `[^/]*`), and the walk
 * runs synchronously at startup, so two lines (`a*a*...*b` with 20 stars, and
 * a 40-character directory name) hung the whole server: `dependency_check`
 * and then `tools/list` timed out, and the pre-write safety check was gone
 * (audit 2026-11-11, M4). Nothing here builds a regular expression from a
 * pattern any more:
 *
 * - A pattern is split on `/` into segments and each segment on `*` into
 *   literal pieces. A name matches a segment when the first piece is its
 *   prefix, the last its suffix, and every piece between is found, in order,
 *   at its leftmost position. No star is ever revisited, so there is no
 *   backtracking: O(name + pattern) per (segment, name) pair with a
 *   failure-table search for plain pieces; a piece holding `?` is searched
 *   naively and is capped at MAX_WILDCARD_PIECE characters, so it stays linear
 *   in the name.
 * - A path is matched by one forward pass over its segments that carries the
 *   set of pattern positions reached (`**` may consume any number of
 *   segments). Each (pattern segment, path segment) pair is tested at most
 *   once per pass.
 * - Everything a file can contribute is capped: its size, its rule count and
 *   each pattern's length. What is over a cap is never applied as an ignore
 *   rule, and a negation that cannot be applied re-includes everything below
 *   its file, so a cap can only make the walk scan MORE, never hide a lockfile.
 * - The time spent matching is counted. Past MATCH_BUDGET_MS the rules stop
 *   answering (`exhausted`), and the walk reports itself incomplete instead of
 *   continuing on rules it could not apply.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { walkBudgetMs } from "./walk-budget.js";

/** A .gitignore larger than this is not read (the largest in the wild are a few hundred KB). */
export const MAX_IGNORE_FILE_BYTES = 1_048_576;
/** Rules applied per ignore file; the rest are not applied (see the module notes). */
export const MAX_RULES_PER_FILE = 5_000;
/** Characters in one pattern; a longer one is not applied. */
export const MAX_PATTERN_LENGTH = 1_024;
/** Characters in one `*`-separated piece that holds a `?` (searched naively). */
export const MAX_WILDCARD_PIECE = 64;
/** Total time one rule set may spend matching before it stops answering (never more than the walk's own budget). */
const MATCH_BUDGET_MS = 5_000;

const caseless = process.platform === "win32" || process.platform === "darwin";

/** One literal run of a segment pattern; `?` inside it matches any one character. */
interface Piece {
  text: string;
  wild: boolean;
  /** Failure table for a plain piece of two or more characters (Knuth-Morris-Pratt). */
  fail: Int32Array | null;
}

type Segment =
  /** `**`: any number of path segments. */
  | { kind: "globstar" }
  /** No `*`: the name must have exactly this length. */
  | { kind: "exact"; piece: Piece }
  /** One or more `*`: `pieces[0]` is the prefix, the last one the suffix. */
  | { kind: "glob"; pieces: Piece[]; minLength: number };

interface Rule {
  segments: Segment[];
  /** Matches only from the first segment below its file's directory. An unanchored rule has one segment. */
  anchored: boolean;
  /** Holds a `**` segment: matched by the forward pass, not position by position. */
  globstar: boolean;
  dirOnly: boolean;
  negated: boolean;
}

/** What a plain name (no `/`, `*` or `?`: `node_modules`, `target/`) does, as bit flags. */
const IGNORE = 1;
const IGNORE_DIR = 2;
const REINCLUDE = 4;
const REINCLUDE_DIR = 8;

/** The rules of one ignore file. */
interface RuleSet {
  /** Plain names, looked up per path segment instead of tested one rule at a time (most rules are these). */
  names: Map<string, number>;
  /** Every other rule. */
  rules: Rule[];
  /** Rules read, of both kinds (the cap counts them all). */
  count: number;
  /**
   * A negation (or a part of the file) could not be applied: nothing below
   * this file's directory is ever skipped.
   */
  reincludeAll: boolean;
}

function makePiece(text: string): Piece {
  const wild = text.includes("?");
  let fail: Int32Array | null = null;
  if (!wild && text.length > 1) {
    fail = new Int32Array(text.length);
    for (let i = 1, k = 0; i < text.length; i++) {
      while (k > 0 && text[i] !== text[k]) k = fail[k - 1];
      if (text[i] === text[k]) k++;
      fail[i] = k;
    }
  }
  return { text, wild, fail };
}

/** Whether `piece` matches `name` at `at` (the caller guarantees it fits). */
function pieceAt(piece: Piece, name: string, at: number): boolean {
  const { text } = piece;
  if (!piece.wild) return name.startsWith(text, at);
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== "?" && text[i] !== name[at + i]) return false;
  }
  return true;
}

/** The leftmost position in [from, limit - piece length] where `piece` matches, or -1. */
function findPiece(piece: Piece, name: string, from: number, limit: number): number {
  const { text, fail } = piece;
  const m = text.length;
  if (m === 0) return from;
  if (limit - from < m) return -1;
  if (piece.wild) {
    for (let at = from; at + m <= limit; at++) if (pieceAt(piece, name, at)) return at;
    return -1;
  }
  if (!fail) {
    const at = name.indexOf(text, from);
    return at >= 0 && at + m <= limit ? at : -1;
  }
  for (let i = from, k = 0; i < limit; i++) {
    while (k > 0 && name[i] !== text[k]) k = fail[k - 1];
    if (name[i] === text[k]) k++;
    if (k === m) return i - m + 1;
  }
  return -1;
}

function segmentMatches(segment: Exclude<Segment, { kind: "globstar" }>, name: string): boolean {
  if (segment.kind === "exact") return name.length === segment.piece.text.length && pieceAt(segment.piece, name, 0);
  const { pieces } = segment;
  if (name.length < segment.minLength) return false;
  const first = pieces[0];
  const last = pieces[pieces.length - 1];
  if (!pieceAt(first, name, 0)) return false;
  const limit = name.length - last.text.length;
  if (!pieceAt(last, name, limit)) return false;
  let at = first.text.length;
  for (let i = 1; i < pieces.length - 1; i++) {
    const found = findPiece(pieces[i], name, at, limit);
    if (found < 0) return false;
    at = found + pieces[i].text.length;
  }
  return true;
}

/** One `/`-separated part of a pattern; null when it cannot be applied (a `?` piece over the cap). */
function compileSegment(text: string): Segment | null {
  if (text === "**") return { kind: "globstar" };
  // Consecutive stars inside a segment are one star, as in git.
  const parts = text.split(/\*+/);
  if (parts.some((p) => p.includes("?") && p.length > MAX_WILDCARD_PIECE)) return null;
  if (parts.length === 1) return { kind: "exact", piece: makePiece(parts[0]) };
  const pieces = parts.map(makePiece);
  return { kind: "glob", pieces, minLength: parts.reduce((n, p) => n + p.length, 0) };
}

function parseRules(content: string): RuleSet {
  const set: RuleSet = { names: new Map(), rules: [], count: 0, reincludeAll: false };
  let start = 0;
  while (start <= content.length) {
    let end = content.indexOf("\n", start);
    if (end < 0) end = content.length;
    // trimEnd is linear; a `\s+$` regular expression over a line of spaces is not.
    let line = content.slice(start, end).trimEnd();
    start = end + 1;
    if (!line || line.startsWith("#")) continue;
    if (set.count >= MAX_RULES_PER_FILE) {
      // The rest is not read. One of those lines may be a negation, so nothing below this file is skipped.
      set.reincludeAll = true;
      break;
    }
    const negated = line.startsWith("!");
    if (negated) line = line.slice(1);
    const dirOnly = line.endsWith("/");
    if (dirOnly) line = line.slice(0, -1);
    const anchored = line.startsWith("/") || line.includes("/");
    if (line.startsWith("/")) line = line.slice(1);
    if (!line) continue;
    const segments = line.length <= MAX_PATTERN_LENGTH ? (caseless ? line.toLowerCase() : line).split("/").map(compileSegment) : null;
    if (!segments || segments.some((s) => s === null)) {
      // Not applied. An ignore rule that is dropped scans more; a negation that is dropped could hide a path it re-includes.
      if (negated) set.reincludeAll = true;
      continue;
    }
    set.count++;
    const [only] = segments as Segment[];
    if (!anchored && only.kind === "exact" && !only.piece.wild) {
      const flag = negated ? (dirOnly ? REINCLUDE_DIR : REINCLUDE) : dirOnly ? IGNORE_DIR : IGNORE;
      set.names.set(only.piece.text, (set.names.get(only.piece.text) ?? 0) | flag);
      continue;
    }
    set.rules.push({ segments: segments as Segment[], anchored, globstar: segments.some((x) => x!.kind === "globstar"), dirOnly, negated });
  }
  return set;
}

/**
 * Whether `rule` matches `names[from..end)` for some `end <= maxEnd`: the path
 * itself or a directory above it. An unanchored rule may start at any segment.
 */
function ruleMatches(rule: Rule, names: string[], from: number, maxEnd: number): boolean {
  const { segments } = rule;
  const k = segments.length;
  if (!rule.anchored) {
    // One segment (a pattern with a `/` in it is anchored), at any depth.
    const [only] = segments;
    if (only.kind === "globstar") return true;
    for (let j = from; j < maxEnd; j++) if (segmentMatches(only, names[j])) return true;
    return false;
  }
  if (!rule.globstar) {
    if (maxEnd - from < k) return false;
    for (let i = 0; i < k; i++) if (!segmentMatches(segments[i] as Exclude<Segment, { kind: "globstar" }>, names[from + i])) return false;
    return true;
  }
  // Pattern positions reached so far (position i: segments[0..i) matched).
  let reached = new Uint8Array(k + 1);
  let next = new Uint8Array(k + 1);
  // A `**` that is not the last segment may match no path segment at all.
  const settle = (set: Uint8Array) => {
    for (let i = 0; i < k - 1; i++) if (set[i] && segments[i].kind === "globstar") set[i + 1] = 1;
  };
  reached[0] = 1;
  settle(reached);
  for (let j = from; j < maxEnd; j++) {
    next.fill(0);
    let any = false;
    for (let i = 0; i < k; i++) {
      if (!reached[i]) continue;
      const segment = segments[i];
      if (segment.kind === "globstar") {
        // Consumes this path segment and stays; a trailing `**` also completes (it needs one segment at least).
        next[i] = 1;
        if (i === k - 1) next[k] = 1;
        any = true;
      } else if (segmentMatches(segment, names[j])) {
        next[i + 1] = 1;
        any = true;
      }
    }
    if (next[k]) return true;
    if (!any) return false;
    settle(next);
    [reached, next] = [next, reached];
  }
  return false;
}

/** Ignore rules gathered while walking down from a root. */
export class IgnoreRules {
  /** Rules by the directory their file lives in, relative to the walk root ("" for the root). */
  private sets = new Map<string, RuleSet[]>();
  private loaded = new Set<string>();
  private spentMs = 0;
  private readonly budgetMs: number;
  /**
   * True once matching has used its time budget. From then on nothing is
   * reported ignored; the walk reads this and stops, reporting itself
   * incomplete, instead of going on without the repository's rules.
   */
  exhausted = false;

  constructor(
    private readonly root: string,
    options: { budgetMs?: number } = {},
  ) {
    this.budgetMs = options.budgetMs ?? Math.min(MATCH_BUDGET_MS, walkBudgetMs());
    this.load("");
    this.read(path.join(root, ".git", "info", "exclude"), "");
  }

  private read(file: string, base: string): void {
    let content: string;
    try {
      // A file over the cap is not read at all: its rules are unknown, so nothing below it is skipped.
      if (fs.statSync(file).size > MAX_IGNORE_FILE_BYTES) {
        this.add(base, { names: new Map(), rules: [], count: 0, reincludeAll: true });
        return;
      }
      content = fs.readFileSync(file, "utf-8");
    } catch {
      return; // no such file
    }
    this.add(base, parseRules(content));
  }

  private add(base: string, set: RuleSet): void {
    if (set.count === 0 && !set.reincludeAll) return;
    const at = this.sets.get(base);
    if (at) at.push(set);
    else this.sets.set(base, [set]);
  }

  /** Read the .gitignore of a directory (relative to the root) once. */
  load(relDir: string): void {
    if (this.loaded.has(relDir)) return;
    this.loaded.add(relDir);
    this.read(path.join(this.root, relDir, ".gitignore"), relDir);
  }

  /**
   * Whether an absolute directory below the root lies in, or is, an ignored
   * directory. Every ancestor is checked, loading nested .gitignore files on
   * the way down. A directory outside the root is never "ignored" here.
   */
  ignoresDirectory(absDir: string): boolean {
    const rel = path.relative(this.root, absDir).replace(/\\/g, "/");
    if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) return false;
    const segments = rel.split("/");
    for (let i = 1; i <= segments.length; i++) {
      this.load(segments.slice(0, i - 1).join("/"));
      if (this.ignores(segments.slice(0, i).join("/"), true)) return true;
    }
    return false;
  }

  /** Whether a path (relative to the root, `/`-separated) is ignored. */
  ignores(relPath: string, isDir: boolean): boolean {
    if (this.exhausted || this.sets.size === 0) return false;
    const started = Date.now();
    const answer = this.match(relPath, isDir, started);
    this.spentMs += Date.now() - started;
    if (this.spentMs > this.budgetMs) this.exhausted = true;
    return this.exhausted ? false : answer;
  }

  private match(relPath: string, isDir: boolean, started: number): boolean {
    const names = (caseless ? relPath.toLowerCase() : relPath).split("/");
    const n = names.length;
    let ignored = false;
    let checked = 0;
    // Every ignore file in a directory above the path, the root's first.
    let slash = -1;
    for (let depth = 0; depth < n; depth++) {
      const sets = this.sets.get(depth === 0 ? "" : relPath.slice(0, slash));
      slash = relPath.indexOf("/", slash + 1);
      if (!sets) continue;
      for (const set of sets) {
        // A path a negation could re-include is never skipped.
        if (set.reincludeAll) return false;
        if (set.names.size > 0) {
          for (let j = depth; j < n; j++) {
            const flags = set.names.get(names[j]);
            if (flags === undefined) continue;
            // Every segment above the last is a directory.
            const dir = j < n - 1 || isDir;
            if (flags & REINCLUDE || (dir && flags & REINCLUDE_DIR)) return false;
            if (flags & IGNORE || (dir && flags & IGNORE_DIR)) ignored = true;
          }
        }
        for (const rule of set.rules) {
          // One long call (a path against thousands of rules) must not outrun the budget.
          if ((++checked & 255) === 0 && this.spentMs + (Date.now() - started) > this.budgetMs) {
            this.exhausted = true;
            return false;
          }
          // A `dir/` rule ignores a file only through a directory above it:
          // `docs/api_reference/*/` matched docs/api_reference/requirements.txt
          // itself, so langchain's docs requirements were never read.
          const maxEnd = rule.dirOnly && !isDir ? n - 1 : n;
          if (maxEnd <= depth || !ruleMatches(rule, names, depth, maxEnd)) continue;
          if (rule.negated) return false;
          ignored = true;
        }
      }
    }
    return ignored;
  }
}
