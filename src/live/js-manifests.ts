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
import { readTextFile } from "./text-file.js";

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
    pkg = JSON.parse(readTextFile(file));
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
      return fs
        .readdirSync(path.join(cwd, rel), { withFileTypes: true })
        .filter((d) => d.isDirectory() && !NEVER_MEMBERS.has(d.name))
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
  for (const raw of patterns) {
    const negated = raw.trim().startsWith("!");
    const pattern = raw.trim().replace(/^!/, "").replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
    // Brace sets and character classes are not expanded: say the member list may be short, never guess.
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
