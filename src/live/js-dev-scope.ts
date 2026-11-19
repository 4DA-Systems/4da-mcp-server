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
import { expandWorkspaces, isRuntimeSection, readManifestDeclarations, type DeclaredSpec, type ManifestDeclarations } from "./js-manifests.js";
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

function readYarnEntries(content: string): YarnEntry[] {
  const entries: YarnEntry[] = [];
  for (const block of content.split(/\r?\n(?=\S)/)) {
    const lines = block.split(/\r?\n/);
    const firstLine = lines[0];
    if (firstLine.length > MAX_LOCKFILE_LINE || firstLine.startsWith("#")) continue;
    const header = /^"?(@?[^@\s"]+)@/.exec(firstLine);
    if (!header || header[1].startsWith("__")) continue;
    const entry: YarnEntry = { specs: yarnHeaderSpecs(firstLine), identity: null, workspaceDir: null, deps: [], peers: [] };
    let version: string | null = null;
    let section = "";
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > MAX_LOCKFILE_LINE) continue;
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
  return entries;
}

/** A workspace directory a lockfile names, when it stays inside the project. */
function insideProject(dir: string): string | null {
  const clean = dir.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
  if (clean === "" || clean === ".") return ".";
  if (path.isAbsolute(clean) || /^[A-Za-z]:/.test(clean) || clean.split("/").includes("..")) return null;
  return clean;
}

/** Workspace manifests read for one lockfile; a project with more is graded as incomplete. */
const MAX_MEMBER_MANIFESTS = 2_000;

/**
 * Grades a yarn.lock (classic or berry) from its graph and the project's
 * package.json files. `isInstance` says which `name\0version` copies the
 * lockfile reader took as registry releases.
 *
 * Roots are the project's package.json and each workspace member's: berry
 * names the members in its `workspace:` entries; classic does not, so the
 * `workspaces` patterns are expanded. An entry's dependency resolves to the
 * entry that answers that exact descriptor; when none does (berry
 * `resolutions`, a patched or peer dependency) it reaches EVERY entry of that
 * name, which can only make more copies runtime, never fewer.
 */
export function gradeYarnLock(content: string, cwd: string, isInstance: (key: string) => boolean): LockGrade {
  const ungraded: LockGrade = { scopes: new Map(), declared: [], graded: false };
  const root = readManifestDeclarations(path.join(cwd, "package.json"));
  if (!root) return ungraded;
  const entries = readYarnEntries(content);
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

  // The members: the entries berry writes for them, else the patterns package.json states.
  let complete = true;
  const berryDirs = entries.map((e) => e.workspaceDir).filter((d): d is string => d !== null);
  let memberDirs: string[];
  if (berryDirs.length > 0) {
    memberDirs = [];
    for (const dir of berryDirs) {
      const inside = insideProject(dir);
      if (inside === null) complete = false;
      else if (inside !== ".") memberDirs.push(inside);
    }
  } else {
    const expanded = expandWorkspaces(cwd, root.workspaces);
    memberDirs = expanded.dirs;
    complete &&= expanded.complete;
  }
  const manifests: ManifestDeclarations[] = [root];
  for (const dir of memberDirs.slice(0, MAX_MEMBER_MANIFESTS)) {
    const member = readManifestDeclarations(path.join(cwd, dir, "package.json"));
    if (member) manifests.push(member);
    else complete = false;
  }
  if (memberDirs.length > MAX_MEMBER_MANIFESTS) complete = false;
  const memberNames = new Set(manifests.map((m) => m.name).filter((n): n is string => n !== null));

  // The entries one declared or required dependency can install.
  const targets = (name: string, range: string): number[] => {
    const exact = bySpec.get(`${name}@${range}`) ?? bySpec.get(`${name}@npm:${range}`);
    return exact !== undefined ? [exact] : (byName.get(name) ?? []);
  };
  const graph = new ScopeGraph();
  entries.forEach((_, index) => graph.node(String(index)));
  entries.forEach((entry, index) => {
    // A workspace entry lists its devDependencies with the rest: its own package.json is the root that says which is which.
    if (entry.workspaceDir !== null) return;
    for (const [name, range] of entry.deps) for (const target of targets(name, range)) graph.edge(index, target);
    for (const name of entry.peers) for (const target of byName.get(name) ?? []) graph.edge(index, target);
  });

  const runtimeRoots: number[] = [];
  const devRoots: number[] = [];
  const declaredRuntime = new Map<string, boolean>();
  for (const manifest of manifests) {
    for (const spec of manifest.declared) {
      const found = targets(spec.name, spec.spec);
      // Nothing in the lockfile answers it: a sibling workspace member (classic writes no entry for one) or a link.
      // A peer the project names but does not install has no entry either, and nothing to grade.
      if (found.length === 0 && spec.section !== "peerDependencies" && !memberNames.has(spec.name) && !localSpec(spec)) complete = false;
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
  return { scopes, declared, graded: true };
}

/** A declaration that installs local code (`link:`, `portal:`, `workspace:`, a `file:` directory): no lockfile entry is owed for some of these. */
function localSpec(spec: DeclaredSpec): boolean {
  return /^(?:link|portal|workspace|file):/i.test(spec.spec.trim());
}
