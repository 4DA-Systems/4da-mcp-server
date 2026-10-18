// SPDX-License-Identifier: Apache-2.0
/**
 * Who pulls in one installed copy of a package, and with which declared
 * requirement: the input to "is a lockfile refresh enough?".
 *
 * npm (package-lock), yarn and bun lockfiles record each parent's declared
 * range. pnpm and Cargo lockfiles record only the resolved version, so their
 * edges carry `range: null` and the caller looks the requirement up in the
 * parent's registry metadata.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { stripTrailingCommas } from "./bun-lockfile.js";
import { exactVersion, MAX_LOCKFILE_LINE, parsePnpmKey, pnpmEntryIdentities, pnpmKeyRef, yarnBlockVersion, yarnPackageName } from "./js-lockfile-readers.js";
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

/** The parents of `name@version` in one lockfile, or null when the file is unreadable or not supported. */
export function readLockfileParents(file: string, name: string, version: string): LockfileParents | null {
  let content: string;
  try {
    content = fs.readFileSync(file, "utf-8");
  } catch {
    return null;
  }
  const format = lockfileFormat(file, content);
  if (!format) return null;
  try {
    switch (format) {
      case "package-lock":
        return { format, edges: packageLockParents(JSON.parse(content), name, version) };
      case "pnpm":
        return { format, edges: pnpmParents(content, name, version) };
      case "yarn":
      case "yarn-berry":
        return { format, edges: yarnParents(content, name, version) };
      case "bun":
        return { format, edges: bunParents(JSON.parse(stripTrailingCommas(content)), name, version) };
      case "cargo":
        return { format, edges: cargoParents(content, name, version) };
    }
  } catch {
    return null;
  }
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

/** Node's lookup from install path `from`: its own node_modules, then each ancestor's, then the root's. */
function resolveInstallPath(packages: Record<string, LockEntry>, from: string, name: string): string | null {
  let dir = from;
  for (;;) {
    const candidate = `${dir ? `${dir}/` : ""}node_modules/${name}`;
    if (candidate in packages) return candidate;
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
    const entry = packages[dir];
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

export function packageLockParents(
  lock: { packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry>; name?: string },
  name: string,
  version: string,
): ParentEdge[] {
  const edges: ParentEdge[] = [];
  if (lock.packages && Object.keys(lock.packages).length > 0) {
    const packages = lock.packages;
    // A bundled copy hangs off its bundle owner, pinned to the version shipped: the ranges the
    // bundle's own packages declare say nothing about what a refresh can reach (audit E8:
    // NodeGoat's debug 4.1.1 inside fsevents read "npm update debug" from needle's ^4.1.0).
    const owners = new Set<string>();
    for (const [key, entry] of Object.entries(packages)) {
      if (entry?.version !== version || packageNameFromNodeModulesPath(key) !== name || !bundledInDependency(packages, key)) continue;
      const owner = bundleOwner(packages, key);
      if (!owner || owners.has(owner)) continue;
      owners.add(owner);
      edges.push({ parent: packageNameFromNodeModulesPath(owner), parentVersion: packages[owner]?.version ?? null, range: version, local: false, bundled: true });
    }
    for (const [key, entry] of Object.entries(packages)) {
      if (!entry || entry.link) continue;
      const local = !key.startsWith("node_modules/") && !key.includes("/node_modules/");
      for (const field of local ? LOCAL_DEP_FIELDS : DEP_FIELDS) {
        const declared = entry[field] as Record<string, string> | undefined;
        const range = declared?.[name];
        if (typeof range !== "string") continue;
        const at = resolveInstallPath(packages, key, name);
        if (!at || packages[at]?.version !== version || bundledInDependency(packages, at)) continue;
        edges.push({
          parent: local ? entry.name ?? (key || lock.name || ".") : packageNameFromNodeModulesPath(key),
          parentVersion: local ? null : entry.version ?? null,
          range,
          local,
          ...(local ? { dir: key === "" ? "." : key, section: field } : {}),
        });
        break;
      }
    }
    return edges;
  }

  // v1: nested `dependencies` trees; each entry's `requires` names its ranges.
  const walk = (deps: Record<string, LockEntry>, ancestors: Array<Record<string, LockEntry>>) => {
    for (const [parentName, entry] of Object.entries(deps)) {
      const nested = (entry.dependencies ?? {}) as Record<string, LockEntry>;
      const range = entry.requires?.[name];
      if (typeof range === "string") {
        const scopes = [nested, ...ancestors];
        const resolved = scopes.find((s) => s[name])?.[name];
        if (resolved?.version === version) {
          edges.push({ parent: parentName, parentVersion: entry.version ?? null, range, local: false });
        }
      }
      if (Object.keys(nested).length > 0) walk(nested, [nested, ...ancestors]);
    }
  };
  if (lock.dependencies) walk(lock.dependencies, [lock.dependencies]);
  return edges;
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml (v5, v6, v9)
// ---------------------------------------------------------------------------

/**
 * Parents from `packages:` (v5/v6) or `snapshots:` (v9) entries whose
 * dependency blocks resolve `name` to `version`. pnpm records resolved
 * versions only, so `range` is null. Importers (the project's own manifests)
 * become local edges with their `specifier` when the lockfile records one.
 *
 * Entries and dependency values are named the way the package reader names
 * them (pnpmEntryIdentities): a pnpm 5 entry keyed by its tarball URL is the
 * package its `name:`/`version:` fields say, and a dependency value that is a
 * key rather than a version (that tarball key, or an alias's
 * `/real/1.2.3`, `/real@1.2.3`, `real@1.2.3`) is an edge to the package it points at.
 */
export function pnpmParents(content: string, name: string, version: string): ParentEdge[] {
  const ids = pnpmEntryIdentities(content);
  /** The (name, version) a dependency line installs: `dep: 1.2.3`, or a value that points at an entry. */
  const installs = (dep: string, value: string): [string, string] | null => {
    const exact = exactVersion(value);
    if (exact) return [dep, exact];
    const ref = pnpmKeyRef(value);
    return ids.get(ref) ?? parsePnpmKey(ref);
  };
  const isTarget = (dep: string, value: string) => {
    const id = installs(dep, value);
    return id !== null && id[0] === name && id[1] === version;
  };
  const edges: ParentEdge[] = [];
  const seen = new Set<string>();
  let section = "";
  let parent: [string, string] | null = null;
  let importer: string | null = null;
  let inDeps = false;
  let depIndent = -1;
  let pendingDep: string | null = null;
  let importerSpecifier: string | null = null;

  const add = (edge: ParentEdge) => {
    const key = `${edge.parent}\0${edge.parentVersion}`;
    if (!seen.has(key)) {
      seen.add(key);
      edges.push(edge);
    }
  };

  for (const line of content.split(/\r?\n/)) {
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
        if (m && isTarget(m[1] ?? m[2] ?? m[3], m[4])) {
          add({ parent: parent[0], parentVersion: parent[1], range: null, local: false });
        }
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
        if (isTarget(pendingDep, m[4])) add({ parent: importer, parentVersion: null, range: null, local: true, dir: importer });
        pendingDep = null;
      }
    } else if (indent === depIndent + 4 && pendingDep) {
      const spec = /^specifier:\s*(.+)$/.exec(text);
      if (spec) importerSpecifier = spec[1].replace(/^['"]|['"]$/g, "");
      const ver = /^version:\s*(.+)$/.exec(text);
      if (ver) {
        if (isTarget(pendingDep, ver[1])) add({ parent: importer, parentVersion: null, range: importerSpecifier, local: true, dir: importer });
        pendingDep = null;
      }
    }
  }
  return edges;
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

function parseYarnBlocks(content: string): YarnBlock[] {
  const blocks: YarnBlock[] = [];
  for (const block of content.split(/\r?\n(?=\S)/)) {
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
  return blocks;
}

/**
 * Blocks whose dependencies resolve `name` to `version`. An npm alias edge
 * (`string-width-cjs: "npm:string-width@^4.2.0"`) is an edge to the real
 * package, with the real package's range; it resolves through the block whose
 * spec is `string-width-cjs@npm:string-width@^4.2.0`.
 */
export function yarnParents(content: string, name: string, version: string): ParentEdge[] {
  const blocks = parseYarnBlocks(content);
  const resolved = new Map<string, YarnBlock>();
  for (const b of blocks) for (const spec of b.specs) resolved.set(spec, b);
  const edges: ParentEdge[] = [];
  for (const b of blocks) {
    for (const [dep, rawRange] of b.deps) {
      const spec = rawRange.replace(/^npm:/, "");
      const target = resolved.get(`${dep}@${spec}`);
      if (!target || target.name !== name || target.version !== version) continue;
      const alias = /^npm:((?:@[^\s/@]+\/)?[^\s/@]+)@(.+)$/.exec(rawRange);
      edges.push({ parent: b.name, parentVersion: b.version, range: alias ? alias[2] : spec, local: false });
    }
  }
  return edges;
}

// ---------------------------------------------------------------------------
// bun.lock
// ---------------------------------------------------------------------------

export function bunParents(
  lock: { packages?: Record<string, unknown>; workspaces?: Record<string, Record<string, Record<string, string>>> },
  name: string,
  version: string,
): ParentEdge[] {
  const packages = lock.packages ?? {};
  const entryOf = (key: string) => {
    const value = packages[key];
    if (!Array.isArray(value) || typeof value[0] !== "string") return null;
    const at = value[0].lastIndexOf("@");
    if (at <= 0) return null;
    const meta = value[2] && typeof value[2] === "object" ? (value[2] as Record<string, Record<string, string>>) : {};
    return { name: value[0].slice(0, at), version: value[0].slice(at + 1), meta };
  };
  const segments = (key: string) => {
    const parts = key.split("/");
    const out: string[] = [];
    for (let i = 0; i < parts.length; i++) out.push(parts[i].startsWith("@") && i + 1 < parts.length ? `${parts[i]}/${parts[++i]}` : parts[i]);
    return out;
  };
  const resolve = (fromKey: string): string | null => {
    const segs = segments(fromKey);
    for (let n = segs.length; n > 0; n--) {
      const candidate = [...segs.slice(0, n), name].join("/");
      if (candidate in packages) return candidate;
    }
    return name in packages ? name : null;
  };
  const edges: ParentEdge[] = [];
  for (const key of Object.keys(packages)) {
    const e = entryOf(key);
    if (!e) continue;
    const range = e.meta.dependencies?.[name] ?? e.meta.optionalDependencies?.[name] ?? e.meta.peerDependencies?.[name];
    if (typeof range !== "string") continue;
    const at = resolve(key);
    if (!at || entryOf(at)?.version !== version) continue;
    edges.push({ parent: e.name, parentVersion: e.version, range, local: false });
  }
  for (const [dir, ws] of Object.entries(lock.workspaces ?? {})) {
    const range = ws.dependencies?.[name] ?? ws.devDependencies?.[name] ?? ws.optionalDependencies?.[name];
    if (typeof range === "string" && entryOf(name)?.version === version) {
      edges.push({ parent: dir || ".", parentVersion: null, range, local: true });
    }
  }
  return edges;
}

// ---------------------------------------------------------------------------
// Cargo.lock
// ---------------------------------------------------------------------------

/**
 * Packages whose `dependencies` list this copy: "name" when only one version
 * of it is in the lockfile, "name version" (optionally with a source) when
 * several are. Cargo records no requirement, so `range` is null.
 */
export function cargoParents(content: string, name: string, version: string): ParentEdge[] {
  const packages = parseCargoLockPackages(content);
  const versionsOf = packages.filter((p) => p.name === name).map((p) => p.version);
  const cargoWritten = packages.some((p) => p.source !== null);
  const edges: ParentEdge[] = [];
  for (const pkg of packages) {
    for (const dep of pkg.dependencies) {
      const [depName, depVersion] = dep.split(" ");
      if (depName !== name) continue;
      const resolved = depVersion ?? (versionsOf.length === 1 ? versionsOf[0] : null);
      if (resolved !== version) continue;
      const local = cargoWritten && pkg.source === null;
      edges.push({ parent: pkg.name, parentVersion: local ? null : pkg.version, range: null, local });
    }
  }
  return edges;
}
