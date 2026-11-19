// SPDX-License-Identifier: Apache-2.0
/**
 * Dev-only or runtime, for lockfiles that do not record it themselves
 * (pnpm lockfile 9, yarn classic and berry).
 *
 * One rule for every reader: a copy is dev-only only when no runtime root
 * reaches it. The runtime roots are the `dependencies`,
 * `optionalDependencies` and `peerDependencies` of the project and of every
 * workspace member; a copy a runtime root installs, directly or through any
 * chain of dependencies, is runtime whatever else lists it. Dev-only is
 * claimed for what only `devDependencies` reach, and only when the runtime
 * closure was read whole: where a root or an edge could not be followed, the
 * copies it might have reached keep an unknown scope, which every tool
 * treats as runtime.
 */

import * as path from "node:path";
import { exactVersion, MAX_LOCKFILE_LINE, yarnHeaderSpecs, yarnPackageName } from "./js-lockfile-readers.js";
import { expandWorkspaces, isLocalSpec, MAX_MEMBER_MANIFESTS, isRuntimeSection, readManifestDeclarations, type ManifestDeclarations } from "./js-manifests.js";
import type { DeclaredDependency } from "./lockfile-types.js";
import { ScopeGraph } from "./scope-graph.js";

/** What a lockfile's own graph and the project's manifests establish about its copies. */
export interface LockGrade {
  /** `name\0version` to true (dev-only) or false (runtime). A copy not in the map has no established scope. */
  scopes: Map<string, boolean>;
  /** Every copy a manifest of the project or of a workspace member declares. */
  declared: DeclaredDependency[];
  /** True when the runtime roots could be read at all; false leaves every scope as the lockfile gave it. */
  graded: boolean;
}

/** The descriptor name of a yarn spec (`@scope/a@npm:^1.0.0` is `@scope/a`). */
function specName(spec: string): string {
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  return at > 0 ? spec.slice(0, at) : spec;
}

/**
 * A dependency line of a yarn.lock entry: v1 `name "range"`, berry
 * `name: "npm:range"`, `"@scope/x": ^1.0.0`. Read by position, with no
 * pattern that can backtrack over a long line.
 */
function yarnDependencyLine(text: string): [string, string] | null {
  if (text.length > MAX_LOCKFILE_LINE) return null;
  let name: string;
  let rest: string;
  if (text.startsWith('"')) {
    const end = text.indexOf('"', 1);
    if (end < 0) return null;
    name = text.slice(1, end);
    rest = text.slice(end + 1);
  } else {
    let end = 0;
    while (end < text.length && text[end] !== " " && text[end] !== "\t" && text[end] !== ":") end++;
    name = text.slice(0, end);
    rest = text.slice(end);
  }
  if (rest.startsWith(":")) rest = rest.slice(1);
  rest = rest.trim();
  if (rest.startsWith('"') && rest.endsWith('"') && rest.length >= 2) rest = rest.slice(1, -1);
  return name === "" || rest === "" ? null : [name, rest];
}

interface YarnEntry {
  specs: string[];
  /** `name\0version` of what the entry installs, when it states a version. */
  identity: string | null;
  /** berry: the directory of a `workspace:` entry, relative to the lockfile. */
  workspaceDir: string | null;
  deps: Array<[string, string]>;
  /** berry `peerDependencies`: names, provided by whichever copy the parent brings. */
  peers: string[];
}

/** The entries of a yarn.lock; `whole` is false when an entry or one of its lines was too long to read. */
function readYarnEntries(content: string): { entries: YarnEntry[]; whole: boolean } {
  const entries: YarnEntry[] = [];
  let whole = true;
  for (const block of content.split(/\r?\n(?=\S)/)) {
    const lines = block.split(/\r?\n/);
    const firstLine = lines[0];
    if (firstLine.length > MAX_LOCKFILE_LINE) {
      whole = false;
      continue;
    }
    if (firstLine.startsWith("#")) continue;
    const header = /^"?(@?[^@\s"]+)@/.exec(firstLine);
    if (!header || header[1].startsWith("__")) continue;
    const entry: YarnEntry = { specs: yarnHeaderSpecs(firstLine), identity: null, workspaceDir: null, deps: [], peers: [] };
    let version: string | null = null;
    let section = "";
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > MAX_LOCKFILE_LINE) {
        whole = false;
        continue;
      }
      const text = line.trim();
      if (text === "") continue;
      const indent = line.length - line.trimStart().length;
      if (indent <= 2) {
        section = text.endsWith(":") ? text.slice(0, -1) : "";
        if (section !== "") continue;
        const field = yarnDependencyLine(text);
        if (!field) continue;
        if (field[0] === "version") version = exactVersion(field[1]);
        else if (field[0] === "resolution") {
          const at = field[1].indexOf("@workspace:");
          if (at > 0) entry.workspaceDir = field[1].slice(at + "@workspace:".length);
        }
        continue;
      }
      if (section === "dependencies" || section === "optionalDependencies") {
        const dep = yarnDependencyLine(text);
        if (dep) entry.deps.push(dep);
      } else if (section === "peerDependencies") {
        const dep = yarnDependencyLine(text);
        if (dep) entry.peers.push(dep[0]);
      }
    }
    if (version) entry.identity = `${yarnPackageName(block, firstLine, header[1])}\0${version}`;
    entries.push(entry);
  }
  return { entries, whole };
}

/** A workspace directory a lockfile names, when it stays inside the project. */
function insideProject(dir: string): string | null {
  const clean = dir.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
  if (clean === "" || clean === ".") return ".";
  if (path.isAbsolute(clean) || /^[A-Za-z]:/.test(clean) || clean.split("/").includes("..")) return null;
  return clean;
}


/** What reading a yarn.lock against the project's package.json files establishes. */
export interface YarnInspection {
  grade: LockGrade;
  /**
   * Packages some entry names as a dependency that no entry installs, sorted.
   * Every yarn.lock yarn writes holds an entry for each dependency of each
   * entry, so one without is past where the file stops.
   */
  dangling: string[];
  /** Whether some entry answers a descriptor of this name (registry release or not). */
  hasEntry(name: string): boolean;
  /** The names of the project's own packages: the root's and each workspace member's. */
  memberNames: ReadonlySet<string>;
  /** False when some member could not be read or listed: a name not in `memberNames` may still be a member. */
  membersComplete: boolean;
}

/**
 * Reads a yarn.lock (classic or berry) as a graph and grades it from the
 * project's package.json files. `isInstance` says which `name\0version`
 * copies the lockfile reader took as registry releases.
 *
 * Roots are the project's package.json and each workspace member's: berry
 * names the members in its `workspace:` entries; classic does not, so the
 * `workspaces` patterns are expanded. An entry's dependency resolves to the
 * entry that answers that exact descriptor; when none does (berry
 * `resolutions`, a patched or peer dependency) it reaches EVERY entry of that
 * name, which can only make more copies runtime, never fewer.
 */
export function inspectYarnLock(content: string, cwd: string, isInstance: (key: string) => boolean): YarnInspection {
  const { entries, whole } = readYarnEntries(content);
  const bySpec = new Map<string, number>();
  const byName = new Map<string, number[]>();
  entries.forEach((entry, index) => {
    const names = new Set<string>();
    for (const spec of entry.specs) {
      bySpec.set(spec, index);
      names.add(specName(spec));
    }
    for (const name of names) {
      const list = byName.get(name);
      if (list) list.push(index);
      else byName.set(name, [index]);
    }
  });
  // The entries one declared or required dependency can install.
  const targets = (name: string, range: string): number[] => {
    const exact = bySpec.get(`${name}@${range}`) ?? bySpec.get(`${name}@npm:${range}`);
    return exact !== undefined ? [exact] : (byName.get(name) ?? []);
  };
  const graph = new ScopeGraph();
  const dangling = new Set<string>();
  entries.forEach((_, index) => graph.node(String(index)));
  entries.forEach((entry, index) => {
    for (const [name, range] of entry.deps) {
      const found = targets(name, range);
      if (found.length === 0 && !isLocalSpec(range)) dangling.add(name);
      // A workspace entry lists its devDependencies with the rest: its own package.json is the root that says which is which.
      if (entry.workspaceDir === null) for (const target of found) graph.edge(index, target);
    }
    if (entry.workspaceDir === null) for (const name of entry.peers) for (const target of byName.get(name) ?? []) graph.edge(index, target);
  });
  // A dependency on a workspace member has no entry in classic, which links the member instead.
  const inspection = (grade: LockGrade, memberNames: ReadonlySet<string>, membersComplete: boolean): YarnInspection => ({
    grade,
    dangling: [...dangling].filter((name) => !memberNames.has(name)).sort(),
    hasEntry: (name) => byName.has(name),
    memberNames,
    membersComplete,
  });

  const root = readManifestDeclarations(path.join(cwd, "package.json"));
  if (!root) return inspection({ scopes: new Map(), declared: [], graded: false }, new Set(), false);

  // The members: the entries berry writes for them, else the patterns package.json states.
  // An unreadable entry or line is part of the graph that cannot be followed.
  let complete = whole;
  let membersComplete = true;
  const berryDirs = entries.map((e) => e.workspaceDir).filter((d): d is string => d !== null);
  let memberDirs: string[];
  if (berryDirs.length > 0) {
    memberDirs = [];
    for (const dir of berryDirs) {
      const inside = insideProject(dir);
      if (inside === null) membersComplete = false;
      else if (inside !== ".") memberDirs.push(inside);
    }
  } else {
    const expanded = expandWorkspaces(cwd, root.workspaces);
    memberDirs = expanded.dirs;
    membersComplete &&= expanded.complete;
  }
  const manifests: ManifestDeclarations[] = [root];
  for (const dir of memberDirs.slice(0, MAX_MEMBER_MANIFESTS)) {
    const member = readManifestDeclarations(path.join(cwd, dir, "package.json"));
    if (member) manifests.push(member);
    else membersComplete = false;
  }
  if (memberDirs.length > MAX_MEMBER_MANIFESTS) membersComplete = false;
  complete &&= membersComplete;
  const memberNames = new Set(manifests.map((m) => m.name).filter((n): n is string => n !== null));
  // An edge to a package no entry installs (and no member provides) is where a damaged file stops.
  for (const name of dangling) if (!memberNames.has(name)) complete = false;

  const runtimeRoots: number[] = [];
  const devRoots: number[] = [];
  const declaredRuntime = new Map<string, boolean>();
  for (const manifest of manifests) {
    for (const spec of manifest.declared) {
      const found = targets(spec.name, spec.spec);
      // Nothing in the lockfile answers it: a sibling workspace member (classic writes no entry for one) or a link.
      // A peer the project names but does not install has no entry either, and nothing to grade.
      if (found.length === 0 && spec.section !== "peerDependencies" && !memberNames.has(spec.name) && !isLocalSpec(spec.spec)) complete = false;
      for (const target of found) (isRuntimeSection(spec.section) ? runtimeRoots : devRoots).push(target);
      // Direct where it is declared: the one entry the declaration resolves to.
      const identity = found.length === 1 ? entries[found[0]].identity : null;
      if (identity && isInstance(identity)) declaredRuntime.set(identity, (declaredRuntime.get(identity) ?? false) || isRuntimeSection(spec.section));
    }
  }

  const runtime = graph.reach(runtimeRoots);
  const dev = graph.reach(devRoots);
  const scopes = new Map<string, boolean>();
  entries.forEach((entry, index) => {
    if (!entry.identity) return;
    if (runtime[index] === 1) scopes.set(entry.identity, false);
    else if (dev[index] === 1 && complete && !scopes.has(entry.identity)) scopes.set(entry.identity, true);
  });
  const declared = [...declaredRuntime].map(([key, isRuntime]) => {
    const cut = key.indexOf("\0");
    return { name: key.slice(0, cut), version: key.slice(cut + 1), runtime: isRuntime };
  });
  return inspection({ scopes, declared, graded: true }, memberNames, membersComplete);
}
