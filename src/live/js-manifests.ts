// SPDX-License-Identifier: Apache-2.0
/**
 * What a JavaScript project's own manifests declare: each package.json's
 * dependencies by section, for the project and for its workspace members.
 *
 * A lockfile says what is installed; which of it is a direct dependency, and
 * which of it a production install needs, is decided by these declarations.
 * `dependencies`, `optionalDependencies` and `peerDependencies` are runtime
 * roots; `devDependencies` are not.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { pushAll } from "../array-utils.js";
import { readManifestText } from "./text-file.js";

export const DEPENDENCY_SECTIONS = ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"] as const;
export type DependencySection = (typeof DEPENDENCY_SECTIONS)[number];

/** One dependency as a package.json states it. */
export interface DeclaredSpec {
  name: string;
  spec: string;
  section: DependencySection;
}

/** A section a production install includes. */
export function isRuntimeSection(section: DependencySection): boolean {
  return section !== "devDependencies";
}

/**
 * A dependency spec that installs local code (`link:`, `portal:`,
 * `workspace:`): not every lockfile writes an entry for one.
 */
export function isLocalSpec(spec: string): boolean {
  return /^(?:link|portal|workspace):/i.test(spec.trim());
}

/** A package.json's own name and what each of its dependency sections declares. */
export interface ManifestDeclarations {
  name: string | null;
  declared: DeclaredSpec[];
  /** The `workspaces` patterns (an array, or Yarn's `{ packages: [...] }`). */
  workspaces: string[];
}

/** Sections with more entries than this are not a real manifest's; the rest are not read. */
const MAX_DECLARED = 20_000;

/** The declarations of the package.json at `file`, or null when it is missing or is not a JSON object. */
export function readManifestDeclarations(file: string): ManifestDeclarations | null {
  let pkg: unknown;
  try {
    pkg = JSON.parse(readManifestText(file));
  } catch {
    return null;
  }
  if (!pkg || typeof pkg !== "object" || Array.isArray(pkg)) return null;
  const record = pkg as Record<string, unknown>;
  const declared: DeclaredSpec[] = [];
  for (const section of DEPENDENCY_SECTIONS) {
    const entries = record[section];
    if (!entries || typeof entries !== "object" || Array.isArray(entries)) continue;
    for (const [name, spec] of Object.entries(entries as Record<string, unknown>)) {
      if (declared.length >= MAX_DECLARED) break;
      if (typeof spec === "string") declared.push({ name, spec, section });
    }
  }
  const raw = record.workspaces;
  const list = Array.isArray(raw) ? raw : Array.isArray((raw as { packages?: unknown } | null | undefined)?.packages) ? (raw as { packages: unknown[] }).packages : [];
  const workspaces = list.filter((p): p is string => typeof p === "string" && p.trim() !== "" && p.length <= MAX_PATTERN_LENGTH).slice(0, MAX_WORKSPACE_PATTERNS);
  return { name: typeof record.name === "string" ? record.name : null, declared, workspaces };
}

const MAX_WORKSPACE_PATTERNS = 200;
const MAX_PATTERN_LENGTH = 512;
/** Directories listed while expanding workspace patterns, and the levels a `**` descends. */
const MAX_WORKSPACE_DIRS = 5_000;
const MAX_GLOBSTAR_DEPTH = 4;
/** Never a workspace member, whatever a pattern says. */
const NEVER_MEMBERS = new Set(["node_modules", ".git"]);

/** `*` and `?` within one path segment, without a regular expression: a pattern is the scanned project's own text. */
function segmentMatches(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (p < pattern.length && (pattern[p] === "?" || pattern[p] === text[t])) {
      p++;
      t++;
    } else if (p < pattern.length && pattern[p] === "*") {
      star = p++;
      mark = t;
    } else if (star >= 0) {
      p = star + 1;
      t = ++mark;
    } else return false;
  }
  while (p < pattern.length && pattern[p] === "*") p++;
  return p === pattern.length;
}

/** Patterns one brace pattern expands to; more than this is not expanded (the member list is then incomplete). */
const MAX_BRACE_EXPANSIONS = 256;

/**
 * `packages/{a,b}` -> `packages/a`, `packages/b`; sets may nest and repeat. The pattern itself
 * when it has no braces; null when a brace is unbalanced or the expansion exceeds its bound.
 */
export function expandBraces(pattern: string): string[] | null {
  const open = pattern.indexOf("{");
  if (open < 0) return pattern.includes("}") ? null : [pattern];
  if (pattern.slice(0, open).includes("}")) return null;
  let depth = 0;
  let close = -1;
  const commas: number[] = [];
  for (let i = open; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) {
      close = i;
      break;
    } else if (c === "," && depth === 1) commas.push(i);
  }
  if (close < 0) return null;
  const cuts = [open, ...commas, close];
  const out: string[] = [];
  for (let k = 0; k + 1 < cuts.length; k++) {
    const rest = expandBraces(pattern.slice(0, open) + pattern.slice(cuts[k] + 1, cuts[k + 1]) + pattern.slice(close + 1));
    if (rest === null) return null;
    pushAll(out, rest);
    if (out.length > MAX_BRACE_EXPANSIONS) return null;
  }
  return out;
}

/** Whether `name` is one of `patterns` (exact names, or `*`/`?` wildcards as pnpm settings allow). */
export function nameMatchesAny(patterns: Iterable<string>, name: string): boolean {
  for (const pattern of patterns) if (pattern === name || (/[*?]/.test(pattern) && segmentMatches(pattern, name))) return true;
  return false;
}

/**
 * The string items of a top-level YAML key in a pnpm settings file (pnpm-workspace.yaml, or the
 * `ignoredOptionalDependencies:` a pnpm-lock.yaml records): a block list (`- a`) or a flow list (`[a, b]`).
 */
export function pnpmYamlList(content: string, key: string): string[] {
  const items: string[] = [];
  const unquote = (v: string) => v.trim().replace(/^'([^']*)'$|^"([^"]*)"$/, "$1$2");
  const add = (v: string) => {
    if (unquote(v) !== "" && items.length < MAX_WORKSPACE_PATTERNS) items.push(unquote(v));
  };
  let inside = false;
  for (const line of content.split(/\r?\n/)) {
    if (line.length > MAX_PATTERN_LENGTH * 8) continue;
    const text = line.replace(/\s#.*$/, "");
    if (/^\S/.test(text)) {
      inside = false;
      if (!text.startsWith(`${key}:`)) continue;
      const rest = text.slice(key.length + 1).trim();
      if (rest === "") inside = true;
      else if (rest.startsWith("[") && rest.endsWith("]")) rest.slice(1, -1).split(",").forEach(add);
      continue;
    }
    const item = inside ? /^\s*-\s*(.*?)\s*$/.exec(text) : null;
    if (item) add(item[1]);
  }
  return items;
}

/** Member manifests read for one project; past this, the member list is incomplete. */
export const MAX_MEMBER_MANIFESTS = 2_000;

/**
 * The package names of the workspace members in `dirs`; `complete` is false when one could not be
 * read (`unreadable`, by directory) or there are too many.
 */
export function memberNamesOf(cwd: string, dirs: string[]): { names: Set<string>; complete: boolean; unreadable: string[] } {
  const names = new Set<string>();
  const unreadable: string[] = [];
  for (const dir of dirs.slice(0, MAX_MEMBER_MANIFESTS)) {
    const member = readManifestDeclarations(path.join(cwd, dir, "package.json"));
    if (!member) unreadable.push(dir);
    else if (member.name !== null) names.add(member.name);
  }
  return { names, complete: dirs.length <= MAX_MEMBER_MANIFESTS && unreadable.length === 0, unreadable };
}

/** Why a workspace member list is not whole, in words for a note. */
export interface MemberListGap {
  /** Member directories whose package.json could not be read. */
  unreadable: string[];
  /** A pattern could not be expanded, or a member lies outside the project. */
  unlisted: boolean;
  /** More members than MAX_MEMBER_MANIFESTS. */
  tooMany: boolean;
}

export function memberListGapText(gap: MemberListGap): string {
  const parts: string[] = [];
  if (gap.unreadable.length > 0) {
    const shown = gap.unreadable.slice(0, 3).map((d) => `${d}/package.json`);
    parts.push(`${shown.join(", ")}${gap.unreadable.length > 3 ? ` and ${gap.unreadable.length - 3} more` : ""} could not be read`);
  }
  if (gap.unlisted) parts.push("a workspaces pattern could not be expanded, or names a directory outside the project");
  if (gap.tooMany) parts.push(`more than ${MAX_MEMBER_MANIFESTS} members are listed, and only that many were read`);
  return parts.length > 0 ? parts.join("; ") : "the member list could not be read whole";
}

/** The workspace member directories of a project, relative to it with `/`, and whether every pattern could be expanded. */
export interface WorkspaceMembers {
  dirs: string[];
  /** False when a pattern uses syntax this does not expand (braces, classes) or the walk hit its bound: members may be missing. */
  complete: boolean;
}

/**
 * The directories `patterns` (package.json `workspaces`) name that hold a
 * package.json. Patterns are expanded segment by segment against the
 * directory tree: a literal segment is one lookup, `*`/`?` list one
 * directory, `**` descends at most MAX_GLOBSTAR_DEPTH levels. Bounded, and the
 * bound is reported.
 */
export function expandWorkspaces(cwd: string, patterns: string[]): WorkspaceMembers {
  const found = new Set<string>();
  const excluded: string[][] = [];
  let complete = true;
  let listed = 0;
  const children = (rel: string): string[] => {
    if (++listed > MAX_WORKSPACE_DIRS) {
      complete = false;
      return [];
    }
    try {
      // A symlink or junction to a directory is a member too, as npm and pnpm read it (re-check
      // 2026-11-24: `packages/sym` pointing at a member was not one, and its name was sent).
      const linkedDir = (name: string) => {
        try {
          return fs.statSync(path.join(cwd, rel, name)).isDirectory();
        } catch {
          return false;
        }
      };
      return fs
        .readdirSync(path.join(cwd, rel), { withFileTypes: true })
        .filter((d) => (d.isDirectory() || (d.isSymbolicLink() && linkedDir(d.name))) && !NEVER_MEMBERS.has(d.name))
        .map((d) => d.name);
    } catch {
      return [];
    }
  };
  const isDir = (rel: string): boolean => {
    try {
      return fs.statSync(path.join(cwd, rel)).isDirectory();
    } catch {
      return false;
    }
  };
  const walk = (rel: string, segments: string[], at: number, depth: number): void => {
    if (!complete) return;
    if (at === segments.length) {
      if (rel !== "" && fs.existsSync(path.join(cwd, rel, "package.json"))) found.add(rel);
      return;
    }
    const segment = segments[at];
    const join = (name: string) => (rel ? `${rel}/${name}` : name);
    if (segment === "**") {
      walk(rel, segments, at + 1, depth);
      if (depth >= MAX_GLOBSTAR_DEPTH) return;
      for (const name of children(rel)) walk(join(name), segments, at, depth + 1);
    } else if (/[*?]/.test(segment)) {
      for (const name of children(rel)) if (segmentMatches(segment, name)) walk(join(name), segments, at + 1, depth);
    } else if (!NEVER_MEMBERS.has(segment) && segment !== ".." && isDir(join(segment))) {
      walk(join(segment), segments, at + 1, depth);
    }
  };
  const expandedPatterns: string[] = [];
  for (const raw of patterns) {
    const negated = raw.trim().startsWith("!");
    const sets = expandBraces(raw.trim().replace(/^!/, ""));
    if (sets === null) complete = false;
    else for (const one of sets) expandedPatterns.push(negated ? `!${one}` : one);
  }
  for (const raw of expandedPatterns) {
    const negated = raw.startsWith("!");
    const pattern = raw.replace(/^!/, "").replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
    // Character classes are not expanded: say the member list may be short, never guess.
    if (/[{}[\]]/.test(pattern) || path.isAbsolute(pattern)) {
      complete = false;
      continue;
    }
    // `**/**` is `**`: one segment, so a run of them costs one descent.
    const segments = pattern.split("/").filter((s, i, all) => s !== "" && s !== "." && !(s === "**" && all[i - 1] === "**"));
    if (segments.length === 0) continue;
    if (negated) excluded.push(segments);
    else walk("", segments, 0, 0);
  }
  // reachable[j]: the pattern so far can end at have[0..j). One pass per segment, no backtracking.
  const matches = (segments: string[], rel: string): boolean => {
    const have = rel.split("/");
    let reachable = new Array<boolean>(have.length + 1).fill(false);
    reachable[0] = true;
    for (const segment of segments) {
      const next = new Array<boolean>(have.length + 1).fill(false);
      if (segment === "**") {
        let seen = false;
        for (let j = 0; j <= have.length; j++) {
          seen ||= reachable[j];
          next[j] = seen;
        }
      } else {
        for (let j = 0; j < have.length; j++) if (reachable[j] && segmentMatches(segment, have[j])) next[j + 1] = true;
      }
      reachable = next;
    }
    return reachable[have.length];
  };
  const dirs = [...found].filter((rel) => !excluded.some((segments) => matches(segments, rel))).sort();
  return { dirs, complete };
}
