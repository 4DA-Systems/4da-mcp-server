// SPDX-License-Identifier: Apache-2.0
/**
 * Who pulls in one installed copy of a package, and with which declared
 * requirement: the input to "is a lockfile refresh enough?".
 *
 * npm (package-lock), yarn and bun lockfiles record each parent's declared
 * range. pnpm and Cargo lockfiles record only the resolved version, so their
 * edges carry `range: null` and the caller looks the requirement up in the
 * parent's registry metadata.
 *
 * One lockfile is read and indexed once (child -> parents) and kept while its
 * size and modification time stay the same: every lookup after that is a map
 * read. Until round 6 every lookup re-read, re-parsed and re-walked the whole
 * file, so a fully cached vulnerability_scan of a 1,889-entry lockfile spent
 * 3.7 s in here and a 107,000-entry one blocked `ping` for 20.8 s (blind audit
 * round 6). The index is built in steps; `prepareLockfileParents` yields to the
 * event loop between them, so the server keeps answering while it builds.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { callMemo } from "../call-budget.js";
import { stripTrailingCommas } from "./bun-lockfile.js";
import { exactVersion, MAX_LOCKFILE_LINE, parsePnpmKey, pnpmEntryIdentities, pnpmKeyRef, textLines, yarnBlockVersion, yarnPackageName } from "./js-lockfile-readers.js";
import { packageNameFromNodeModulesPath, parseCargoLockPackages } from "./lockfile-parsers.js";

export type LockfileFormat = "package-lock" | "pnpm" | "yarn" | "yarn-berry" | "bun" | "cargo";

export interface ParentEdge {
  /** The parent package, or the manifest's own name / directory for a project or workspace member. */
  parent: string;
  /** The parent's installed version; null for a project or workspace member. */
  parentVersion: string | null;
  /** The requirement as declared; null when the lockfile does not record it (pnpm, Cargo). */
  range: string | null;
  /** True when the parent is the project itself or a workspace member (then the package is direct there). */
  local: boolean;
  /**
   * True when the copy ships inside `parent`'s tarball (package-lock `inBundle`): `range` is then the
   * exact version shipped. No refresh moves it and no override reaches it (both checked with npm
   * 10.9.2, 2026-10-15); only a new `parent` release, or replacing `parent`, does (audit E8).
   */
  bundled?: boolean;
  /**
   * For a local edge: the declaring manifest's directory relative to the lockfile's ("." for the
   * project itself, "packages/a" for a workspace member), when the lockfile names it.
   */
  dir?: string;
  /** For a local edge: the manifest section that declares it. */
  section?: "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies";
}

export interface LockfileParents {
  format: LockfileFormat;
  edges: ParentEdge[];
}

/** Every copy's parents in one lockfile, looked up by (name, version). */
export interface ParentIndex {
  format: LockfileFormat;
  parents(name: string, version: string): ParentEdge[];
}

const DEP_FIELDS = ["dependencies", "optionalDependencies", "peerDependencies"] as const;
/**
 * The project's own manifest and each workspace member's also declare devDependencies, which a
 * dependency's lockfile entry never carries. Leaving them out read a dev-only transitive's lever
 * as "no declared dependency above" (navcal: @vitest/mocker and tinypool arrive through the
 * devDependency vitest) and a member's devDependency as undeclared (final release audit, finding 3).
 */
const LOCAL_DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;

/** The lockfile format of a path, or null for a file this module does not read. */
export function lockfileFormat(file: string, content: string): LockfileFormat | null {
  const base = path.basename(file);
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") return "package-lock";
  if (base === "pnpm-lock.yaml") return "pnpm";
  if (base === "yarn.lock") return /^__metadata:/m.test(content) ? "yarn-berry" : "yarn";
  if (base === "bun.lock") return "bun";
  if (base === "Cargo.lock") return "cargo";
  return null;
}

/**
 * The lockfile format of a file on disk, or null when it is unreadable or not one this module reads.
 * Only a yarn.lock is read (berry or classic); the answer is kept per tool call. Reading the whole
 * file for its name's sake cost 0.9 s of a 107,000-entry scan (blind audit round 6).
 */
export function lockfileFormatOf(file: string): LockfileFormat | null {
  const sig = signature(file);
  if (sig === null) return null;
  const base = path.basename(file);
  if (base !== "yarn.lock") return lockfileFormat(file, "");
  const hit = cachedFor(file, sig);
  if (hit?.index) return hit.index.format;
  return callMemo(`lockfile-format:${sig}:${file}`, () => {
    try {
      return lockfileFormat(file, fs.readFileSync(file, "utf-8"));
    } catch {
      return null;
    }
  });
}

// ---------------------------------------------------------------------------
// The index and its cache
// ---------------------------------------------------------------------------

/** Entries (or lines) indexed between two yields to the event loop. */
const INDEX_STEP = 2_000;
/** Lockfiles whose index is kept; the least recently used is dropped past this. */
const MAX_CACHED_INDEXES = 8;

/** child key -> its parent edges, in the order the lockfile lists them. */
type EdgeMap = Map<string, ParentEdge[]>;
/** Builds an EdgeMap, yielding every INDEX_STEP units of work. */
type IndexBuild = Generator<void, EdgeMap, void>;

const childKey = (name: string, version: string) => `${name}\0${version}`;

function push(map: EdgeMap, name: string, version: string, edge: ParentEdge): void {
  const key = childKey(name, version);
  const list = map.get(key);
  if (list) list.push(edge);
  else map.set(key, [edge]);
}

function indexOf(format: LockfileFormat, edges: EdgeMap): ParentIndex {
  return { format, parents: (name, version) => [...(edges.get(childKey(name, version)) ?? [])] };
}

function runSync(build: IndexBuild): EdgeMap {
  for (;;) {
    const step = build.next();
    if (step.done) return step.value;
  }
}

async function runYielding(build: IndexBuild): Promise<EdgeMap> {
  for (;;) {
    const step = build.next();
    if (step.done) return step.value;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

/**
 * The file's identity for the cache: a rewrite changes its modification time or size. Taken once per
 * tool call (callMemo): one call reads one version of the lockfile.
 */
function signature(file: string): string | null {
  return callMemo(`lockfile-parents-signature:${file}`, () => statSignature(file));
}

function statSignature(file: string): string | null {
  try {
    const st = fs.statSync(file);
    return `${st.mtimeMs}:${st.ctimeMs}:${st.size}`;
  } catch {
    return null;
  }
}

/** Read and parse once, then the build that indexes it; null when unreadable or not a lockfile this module reads. */
function startBuild(file: string): { format: LockfileFormat; build: IndexBuild } | null {
  let content: string;
  try {
    content = fs.readFileSync(file, "utf-8");
  } catch {
    return null;
  }
  parseCount++;
  const format = lockfileFormat(file, content);
  if (!format) return null;
  try {
    switch (format) {
      case "package-lock":
        return { format, build: packageLockIndex(JSON.parse(content)) };
      case "pnpm":
        return { format, build: pnpmIndex(content) };
      case "yarn":
      case "yarn-berry":
        return { format, build: yarnIndex(content) };
      case "bun":
        return { format, build: bunIndex(JSON.parse(stripTrailingCommas(content))) };
      case "cargo":
        return { format, build: cargoIndex(content) };
    }
  } catch {
    return null;
  }
}

interface Cached {
  sig: string;
  index: ParentIndex | null;
}
const cache = new Map<string, Cached>();
const building = new Map<string, { sig: string; done: Promise<ParentIndex | null> }>();
let parseCount = 0;

/** How many times a lockfile has been read for its parents in this process (tests hold it to one per file). */
export function lockfileParentReads(): number {
  return parseCount;
}

/** Forget every cached index (tests). */
export function clearLockfileParentCache(): void {
  cache.clear();
  building.clear();
}

function remember(file: string, sig: string, index: ParentIndex | null): ParentIndex | null {
  cache.delete(file);
  cache.set(file, { sig, index });
  while (cache.size > MAX_CACHED_INDEXES) cache.delete(cache.keys().next().value!);
  return index;
}

function cachedFor(file: string, sig: string): Cached | null {
  const hit = cache.get(file);
  if (!hit || hit.sig !== sig) return null;
  // Most recently used last.
  cache.delete(file);
  cache.set(file, hit);
  return hit;
}

/**
 * The parent index of one lockfile, built while yielding to the event loop, then kept. Call it
 * from async code before a run of lookups: the synchronous readers below then answer from the
 * cache. Concurrent calls for the same file share one build.
 */
export async function prepareLockfileParents(file: string): Promise<ParentIndex | null> {
  const sig = signature(file);
  if (sig === null) return null;
  const hit = cachedFor(file, sig);
  if (hit) return hit.index;
  const running = building.get(file);
  if (running && running.sig === sig) return running.done;
  const done = (async () => {
    const started = startBuild(file);
    let index: ParentIndex | null = null;
    if (started) {
      try {
        index = indexOf(started.format, await runYielding(started.build));
      } catch {
        index = null;
      }
    }
    return remember(file, sig, index);
  })().finally(() => {
    if (building.get(file)?.done === done) building.delete(file);
  });
  building.set(file, { sig, done });
  return done;
}

/** The parent index of one lockfile: from the cache, else built now without yielding. Null when unreadable or not supported. */
export function lockfileParentIndex(file: string): ParentIndex | null {
  const sig = signature(file);
  if (sig === null) return null;
  const hit = cachedFor(file, sig);
  if (hit) return hit.index;
  const started = startBuild(file);
  let index: ParentIndex | null = null;
  if (started) {
    try {
      index = indexOf(started.format, runSync(started.build));
    } catch {
      index = null;
    }
  }
  return remember(file, sig, index);
}

/** The parents of `name@version` in one lockfile, or null when the file is unreadable or not supported. */
export function readLockfileParents(file: string, name: string, version: string): LockfileParents | null {
  const index = lockfileParentIndex(file);
  return index ? { format: index.format, edges: index.parents(name, version) } : null;
}

// ---------------------------------------------------------------------------
// package-lock.json (v1, v2, v3)
// ---------------------------------------------------------------------------

interface LockEntry {
  name?: string;
  version?: string;
  link?: boolean;
  inBundle?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, string> | Record<string, LockEntry>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

type PackageLock = { packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry>; name?: string };

/** Node's lookup from install path `from`: its own node_modules, then each ancestor's, then the root's. */
function resolveInstallPath(packages: Record<string, LockEntry>, from: string, name: string): string | null {
  let dir = from;
  for (;;) {
    const candidate = `${dir ? `${dir}/` : ""}node_modules/${name}`;
    if (Object.hasOwn(packages, candidate)) return candidate;
    if (dir === "") return null;
    const cut = dir.lastIndexOf("/node_modules/");
    dir = cut >= 0 ? dir.slice(0, cut) : "";
  }
}

/**
 * The package a bundled copy at install path `at` ships inside: the nearest enclosing entry that is
 * not itself `inBundle`. A level the lockfile does not list is passed over. Null when none is found.
 */
function bundleOwner(packages: Record<string, LockEntry>, at: string): string | null {
  let dir = at;
  for (;;) {
    const cut = dir.lastIndexOf("/node_modules/");
    if (cut < 0) return null;
    dir = dir.slice(0, cut);
    const entry = Object.hasOwn(packages, dir) ? packages[dir] : undefined;
    if (entry && !entry.inBundle) return dir;
  }
}

/** A key that installs a DEPENDENCY (under some `node_modules/`), not the root or a workspace member's folder. */
function isDependencyKey(key: string): boolean {
  return key.startsWith("node_modules/") || key.includes("/node_modules/");
}

/**
 * Whether the entry at `key` is a copy bundled inside a DEPENDENCY's tarball. A project's or workspace
 * member's own `bundleDependencies` also set `inBundle` (Arborist's bundler can be the root), but those
 * copies sit in the user's tree, where `npm update` and overrides reach them like any other.
 */
function bundledInDependency(packages: Record<string, LockEntry>, key: string): boolean {
  if (!packages[key]?.inBundle) return false;
  const owner = bundleOwner(packages, key);
  return owner !== null && isDependencyKey(owner);
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function* packageLockIndex(lock: PackageLock): IndexBuild {
  const out: EdgeMap = new Map();
  if (lock.packages && Object.keys(lock.packages).length > 0) {
    const packages = lock.packages;
    const entries = Object.entries(packages);
    // A bundled copy hangs off its bundle owner, pinned to the version shipped: the ranges the
    // bundle's own packages declare say nothing about what a refresh can reach (audit E8:
    // NodeGoat's debug 4.1.1 inside fsevents read "npm update debug" from needle's ^4.1.0).
    // Listed before the ordinary edges, as one owner per copy.
    const owners = new Map<string, Set<string>>();
    let n = 0;
    for (const [key, entry] of entries) {
      if (++n % INDEX_STEP === 0) yield;
      if (typeof entry?.version !== "string" || !bundledInDependency(packages, key)) continue;
      const name = packageNameFromNodeModulesPath(key);
      const owner = bundleOwner(packages, key);
      if (!owner) continue;
      const k = childKey(name, entry.version);
      const seen = owners.get(k) ?? new Set<string>();
      owners.set(k, seen);
      if (seen.has(owner)) continue;
      seen.add(owner);
      push(out, name, entry.version, { parent: packageNameFromNodeModulesPath(owner), parentVersion: packages[owner]?.version ?? null, range: entry.version, local: false, bundled: true });
    }
    for (const [key, entry] of entries) {
      if (++n % INDEX_STEP === 0) yield;
      if (!entry || entry.link) continue;
      const local = !isDependencyKey(key);
      // Per dependency, the first section that declares it (as a range) names the edge.
      const taken = new Set<string>();
      for (const field of local ? LOCAL_DEP_FIELDS : DEP_FIELDS) {
        const declared = entry[field];
        if (!isRecord(declared)) continue;
        for (const [dep, range] of Object.entries(declared)) {
          if (typeof range !== "string" || taken.has(dep)) continue;
          taken.add(dep);
          const at = resolveInstallPath(packages, key, dep);
          const installed = at ? packages[at]?.version : undefined;
          if (!at || typeof installed !== "string" || bundledInDependency(packages, at)) continue;
          push(out, dep, installed, {
            parent: local ? entry.name ?? (key || lock.name || ".") : packageNameFromNodeModulesPath(key),
            parentVersion: local ? null : entry.version ?? null,
            range,
            local,
            ...(local ? { dir: key === "" ? "." : key, section: field } : {}),
          });
        }
      }
    }
    return out;
  }

  // v1: nested `dependencies` trees; each entry's `requires` names its ranges.
  let n = 0;
  function* walk(deps: Record<string, LockEntry>, ancestors: Array<Record<string, LockEntry>>): Generator<void, void, void> {
    for (const [parentName, entry] of Object.entries(deps)) {
      if (++n % INDEX_STEP === 0) yield;
      if (!isRecord(entry)) continue;
      const nested = (isRecord(entry.dependencies) ? entry.dependencies : {}) as Record<string, LockEntry>;
      const scopes = [nested, ...ancestors];
      if (isRecord(entry.requires)) {
        for (const [dep, range] of Object.entries(entry.requires)) {
          if (typeof range !== "string") continue;
          const scope = scopes.find((s) => Object.hasOwn(s, dep) && s[dep]);
          const resolved = scope?.[dep]?.version;
          if (typeof resolved === "string") push(out, dep, resolved, { parent: parentName, parentVersion: typeof entry.version === "string" ? entry.version : null, range, local: false });
        }
      }
      if (Object.keys(nested).length > 0) yield* walk(nested, [nested, ...ancestors]);
    }
  }
  if (isRecord(lock.dependencies)) yield* walk(lock.dependencies, [lock.dependencies]);
  return out;
}

export function packageLockParents(lock: PackageLock, name: string, version: string): ParentEdge[] {
  return indexOf("package-lock", runSync(packageLockIndex(lock))).parents(name, version);
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml (v5, v6, v9)
// ---------------------------------------------------------------------------

/**
 * Parents from `packages:` (v5/v6) or `snapshots:` (v9) entries whose
 * dependency blocks resolve a package to a version. pnpm records resolved
 * versions only, so `range` is null. Importers (the project's own manifests)
 * become local edges with their `specifier` when the lockfile records one.
 *
 * Entries and dependency values are named the way the package reader names
 * them (pnpmEntryIdentities): a pnpm 5 entry keyed by its tarball URL is the
 * package its `name:`/`version:` fields say, and a dependency value that is a
 * key rather than a version (that tarball key, or an alias's
 * `/real/1.2.3`, `/real@1.2.3`, `real@1.2.3`) is an edge to the package it points at.
 */
function* pnpmIndex(content: string): IndexBuild {
  const ids = pnpmEntryIdentities(content);
  /** The (name, version) a dependency line installs: `dep: 1.2.3`, or a value that points at an entry. */
  const installs = (dep: string, value: string): [string, string] | null => {
    const exact = exactVersion(value);
    if (exact) return [dep, exact];
    const ref = pnpmKeyRef(value);
    return ids.get(ref) ?? parsePnpmKey(ref);
  };
  const out: EdgeMap = new Map();
  const seen = new Set<string>();
  const add = (child: [string, string] | null, edge: ParentEdge) => {
    if (!child) return;
    const key = `${childKey(child[0], child[1])}\0${edge.parent}\0${edge.parentVersion}`;
    if (seen.has(key)) return;
    seen.add(key);
    push(out, child[0], child[1], edge);
  };
  let section = "";
  let parent: [string, string] | null = null;
  let importer: string | null = null;
  let inDeps = false;
  let depIndent = -1;
  let pendingDep: string | null = null;
  let importerSpecifier: string | null = null;

  let n = 0;
  for (const line of textLines(content)) {
    if (++n % (INDEX_STEP * 4) === 0) yield;
    const text = line.trim();
    if (text === "" || text.startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      section = text.endsWith(":") ? text.slice(0, -1) : "";
      parent = null;
      importer = section === "dependencies" || section === "devDependencies" || section === "optionalDependencies" ? "." : null;
      inDeps = importer !== null;
      depIndent = inDeps ? 2 : -1;
      continue;
    }
    if (section === "packages" || section === "snapshots") {
      if (indent === 2 && text.endsWith(":")) {
        parent = ids.get(pnpmKeyRef(text.slice(0, -1))) ?? null;
        inDeps = false;
      } else if (indent === 4 && parent) {
        inDeps = /^(?:dependencies|optionalDependencies):$/.test(text);
      } else if (indent === 6 && parent && inDeps) {
        const m = /^(?:'([^']+)'|"([^"]+)"|([^\s:'"]+)):\s*(.+)$/.exec(text);
        if (m) add(installs(m[1] ?? m[2] ?? m[3], m[4]), { parent: parent[0], parentVersion: parent[1], range: null, local: false });
      }
      continue;
    }
    if (section === "importers") {
      if (indent === 2 && text.endsWith(":")) {
        importer = text.slice(0, -1).replace(/^['"]|['"]$/g, "");
        inDeps = false;
        continue;
      }
      if (indent === 4) {
        inDeps = /^(?:dependencies|devDependencies|optionalDependencies):$/.test(text);
        depIndent = 4;
        continue;
      }
    }
    if (!inDeps || importer === null) continue;
    // A dependency of the project itself: v5 `name: 1.2.3`, v6/v9 `name:` + `specifier:` + `version:`.
    if (indent === depIndent + 2) {
      const m = /^(?:'([^']+)'|"([^"]+)"|([^\s:'"]+)):(?:\s+(.*))?$/.exec(text);
      pendingDep = m ? m[1] ?? m[2] ?? m[3] : null;
      importerSpecifier = null;
      if (pendingDep && m?.[4]) {
        add(installs(pendingDep, m[4]), { parent: importer, parentVersion: null, range: null, local: true, dir: importer });
        pendingDep = null;
      }
    } else if (indent === depIndent + 4 && pendingDep) {
      const spec = /^specifier:\s*(.+)$/.exec(text);
      if (spec) importerSpecifier = spec[1].replace(/^['"]|['"]$/g, "");
      const ver = /^version:\s*(.+)$/.exec(text);
      if (ver) {
        add(installs(pendingDep, ver[1]), { parent: importer, parentVersion: null, range: importerSpecifier, local: true, dir: importer });
        pendingDep = null;
      }
    }
  }
  return out;
}

export function pnpmParents(content: string, name: string, version: string): ParentEdge[] {
  return indexOf("pnpm", runSync(pnpmIndex(content))).parents(name, version);
}

// ---------------------------------------------------------------------------
// yarn.lock (v1 and berry)
// ---------------------------------------------------------------------------

const unquote = (s: string) => s.trim().replace(/^"|"$/g, "");

interface YarnBlock {
  name: string;
  version: string;
  specs: string[];
  deps: Array<[string, string]>;
}

/**
 * A yarn dependency line: v1 `name "range"`, berry `name: "npm:range"` or
 * `"@scope/x": range`. The name by regex, the range by hand: the single regex
 * this replaces had a lazy group before `"?\s*$` and was quadratic, ~5 s on a
 * hostile 64 KB line (audit 2026-10-12, B-10). Same results otherwise.
 */
function yarnDepLine(text: string): [string, string] | null {
  if (text.length > MAX_LOCKFILE_LINE) return null;
  const head = /^"?((?:@[^\s"/]+\/)?[^\s":]+)"?:?\s+/.exec(text);
  if (!head) return null;
  let range = text.slice(head[0].length).trimEnd();
  if (range.startsWith('"')) range = range.slice(1);
  if (range.endsWith('"')) range = range.slice(0, -1);
  if (range === "" || range.includes('"')) return null;
  return [head[1], range];
}

function* parseYarnBlocks(content: string, blocks: YarnBlock[]): Generator<void, void, void> {
  let n = 0;
  for (const block of content.split(/\r?\n(?=\S)/)) {
    if (++n % INDEX_STEP === 0) yield;
    const lines = block.split(/\r?\n/);
    const header = lines[0];
    if (header.length > MAX_LOCKFILE_LINE) continue;
    const headerName = /^"?(@?[^@\s"]+)@/.exec(header)?.[1];
    if (!headerName || headerName.startsWith("__")) continue;
    // An npm alias block (`string-width-cjs@npm:string-width@^4.2.0`) installs the real package.
    const name = yarnPackageName(block, header, headerName);
    const version = yarnBlockVersion(block);
    if (!version) continue;
    const specs = header.replace(/:\s*$/, "").split(",").map((s) => unquote(s).replace(/@npm:/, "@"));
    const deps: Array<[string, string]> = [];
    let inDeps = false;
    let depIndent = -1;
    for (const line of lines.slice(1)) {
      if (!line.trim()) continue;
      const indent = line.length - line.trimStart().length;
      const text = line.trim();
      if (/^(?:dependencies|optionalDependencies):?$/.test(text)) {
        inDeps = true;
        depIndent = indent;
        continue;
      }
      if (inDeps && indent > depIndent) {
        // v1: `name "range"`; berry: `name: "npm:range"` or `"@scope/x": range`.
        const dep = yarnDepLine(text);
        if (dep) deps.push(dep);
      } else {
        inDeps = false;
      }
    }
    blocks.push({ name, version, specs, deps });
  }
}

/**
 * Blocks whose dependencies resolve a package to a version. An npm alias edge
 * (`string-width-cjs: "npm:string-width@^4.2.0"`) is an edge to the real
 * package, with the real package's range; it resolves through the block whose
 * spec is `string-width-cjs@npm:string-width@^4.2.0`.
 */
function* yarnIndex(content: string): IndexBuild {
  const blocks: YarnBlock[] = [];
  yield* parseYarnBlocks(content, blocks);
  const resolved = new Map<string, YarnBlock>();
  for (const b of blocks) for (const spec of b.specs) resolved.set(spec, b);
  const out: EdgeMap = new Map();
  let n = 0;
  for (const b of blocks) {
    if (++n % INDEX_STEP === 0) yield;
    for (const [dep, rawRange] of b.deps) {
      const spec = rawRange.replace(/^npm:/, "");
      const target = resolved.get(`${dep}@${spec}`);
      if (!target) continue;
      const alias = /^npm:((?:@[^\s/@]+\/)?[^\s/@]+)@(.+)$/.exec(rawRange);
      push(out, target.name, target.version, { parent: b.name, parentVersion: b.version, range: alias ? alias[2] : spec, local: false });
    }
  }
  return out;
}

export function yarnParents(content: string, name: string, version: string): ParentEdge[] {
  return indexOf("yarn", runSync(yarnIndex(content))).parents(name, version);
}

// ---------------------------------------------------------------------------
// bun.lock
// ---------------------------------------------------------------------------

type BunLock = { packages?: Record<string, unknown>; workspaces?: Record<string, Record<string, Record<string, string>>> };

function* bunIndex(lock: BunLock): IndexBuild {
  const packages = lock.packages ?? {};
  const entryOf = (key: string) => {
    const value = Object.hasOwn(packages, key) ? packages[key] : undefined;
    if (!Array.isArray(value) || typeof value[0] !== "string") return null;
    const at = value[0].lastIndexOf("@");
    if (at <= 0) return null;
    const meta = value[2] && typeof value[2] === "object" ? (value[2] as Record<string, Record<string, string>>) : {};
    return { name: value[0].slice(0, at), version: value[0].slice(at + 1), meta };
  };
  const segments = (key: string) => {
    const parts = key.split("/");
    const segs: string[] = [];
    for (let i = 0; i < parts.length; i++) segs.push(parts[i].startsWith("@") && i + 1 < parts.length ? `${parts[i]}/${parts[++i]}` : parts[i]);
    return segs;
  };
  const resolve = (segs: string[], name: string): string | null => {
    for (let n = segs.length; n > 0; n--) {
      const candidate = [...segs.slice(0, n), name].join("/");
      if (Object.hasOwn(packages, candidate)) return candidate;
    }
    return Object.hasOwn(packages, name) ? name : null;
  };
  const out: EdgeMap = new Map();
  let n = 0;
  for (const key of Object.keys(packages)) {
    if (++n % INDEX_STEP === 0) yield;
    const e = entryOf(key);
    if (!e) continue;
    const { dependencies: deps, optionalDependencies: opt, peerDependencies: peer } = e.meta;
    const names = new Set<string>([...Object.keys(isRecord(deps) ? deps : {}), ...Object.keys(isRecord(opt) ? opt : {}), ...Object.keys(isRecord(peer) ? peer : {})]);
    if (names.size === 0) continue;
    const segs = segments(key);
    for (const dep of names) {
      const range = deps?.[dep] ?? opt?.[dep] ?? peer?.[dep];
      if (typeof range !== "string") continue;
      const at = resolve(segs, dep);
      const installed = at ? entryOf(at)?.version : undefined;
      if (installed === undefined) continue;
      push(out, dep, installed, { parent: e.name, parentVersion: e.version, range, local: false });
    }
  }
  for (const [dir, ws] of Object.entries(lock.workspaces ?? {})) {
    if (!isRecord(ws)) continue;
    const names = new Set<string>([...Object.keys(ws.dependencies ?? {}), ...Object.keys(ws.devDependencies ?? {}), ...Object.keys(ws.optionalDependencies ?? {})]);
    for (const dep of names) {
      const range = ws.dependencies?.[dep] ?? ws.devDependencies?.[dep] ?? ws.optionalDependencies?.[dep];
      const installed = entryOf(dep)?.version;
      if (typeof range === "string" && installed !== undefined) push(out, dep, installed, { parent: dir || ".", parentVersion: null, range, local: true });
    }
  }
  return out;
}

export function bunParents(lock: BunLock, name: string, version: string): ParentEdge[] {
  return indexOf("bun", runSync(bunIndex(lock))).parents(name, version);
}

// ---------------------------------------------------------------------------
// Cargo.lock
// ---------------------------------------------------------------------------

/**
 * Packages whose `dependencies` list a copy: "name" when only one version
 * of it is in the lockfile, "name version" (optionally with a source) when
 * several are. Cargo records no requirement, so `range` is null.
 */
function* cargoIndex(content: string): IndexBuild {
  const packages = parseCargoLockPackages(content);
  const versionsOf = new Map<string, string[]>();
  for (const p of packages) versionsOf.set(p.name, [...(versionsOf.get(p.name) ?? []), p.version]);
  const cargoWritten = packages.some((p) => p.source !== null);
  const out: EdgeMap = new Map();
  let n = 0;
  for (const pkg of packages) {
    if (++n % INDEX_STEP === 0) yield;
    for (const dep of pkg.dependencies) {
      const [depName, depVersion] = dep.split(" ");
      const versions = versionsOf.get(depName) ?? [];
      const resolved = depVersion ?? (versions.length === 1 ? versions[0] : null);
      if (resolved === null) continue;
      const local = cargoWritten && pkg.source === null;
      push(out, depName, resolved, { parent: pkg.name, parentVersion: local ? null : pkg.version, range: null, local });
    }
  }
  return out;
}

export function cargoParents(content: string, name: string, version: string): ParentEdge[] {
  return indexOf("cargo", runSync(cargoIndex(content))).parents(name, version);
}
