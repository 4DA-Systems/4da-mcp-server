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
import { parsePnpmKey } from "./js-lockfile-readers.js";
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
}

export interface LockfileParents {
  format: LockfileFormat;
  edges: ParentEdge[];
}

const DEP_FIELDS = ["dependencies", "optionalDependencies", "peerDependencies"] as const;

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
  requires?: Record<string, string>;
  dependencies?: Record<string, string> | Record<string, LockEntry>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
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

export function packageLockParents(
  lock: { packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry>; name?: string },
  name: string,
  version: string,
): ParentEdge[] {
  const edges: ParentEdge[] = [];
  if (lock.packages && Object.keys(lock.packages).length > 0) {
    const packages = lock.packages;
    for (const [key, entry] of Object.entries(packages)) {
      if (!entry || entry.link) continue;
      for (const field of DEP_FIELDS) {
        const declared = entry[field] as Record<string, string> | undefined;
        const range = declared?.[name];
        if (typeof range !== "string") continue;
        const at = resolveInstallPath(packages, key, name);
        if (!at || packages[at]?.version !== version) continue;
        const local = !key.startsWith("node_modules/") && !key.includes("/node_modules/");
        edges.push({
          parent: local ? entry.name ?? (key || lock.name || ".") : packageNameFromNodeModulesPath(key),
          parentVersion: local ? null : entry.version ?? null,
          range,
          local,
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

function exactVersion(raw: string): string | null {
  const unquoted = raw.trim().replace(/^['"]|['"]$/g, "");
  const v = unquoted.split("(")[0].split("_")[0].trim();
  return /^\d/.test(v) ? v : null;
}

/**
 * Parents from `packages:` (v5/v6) or `snapshots:` (v9) entries whose
 * dependency blocks resolve `name` to `version`. pnpm records resolved
 * versions only, so `range` is null. Importers (the project's own manifests)
 * become local edges with their `specifier` when the lockfile records one.
 */
export function pnpmParents(content: string, name: string, version: string): ParentEdge[] {
  const edges: ParentEdge[] = [];
  const seen = new Set<string>();
  let section = "";
  let parent: [string, string] | null = null;
  let importer: string | null = null;
  let inDeps = false;
  let depIndent = -1;
  let pendingImporterDep = false;
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
        parent = parsePnpmKey(text.slice(0, -1));
        inDeps = false;
      } else if (indent === 4 && parent) {
        inDeps = /^(?:dependencies|optionalDependencies):$/.test(text);
      } else if (indent === 6 && parent && inDeps) {
        const m = /^(?:'([^']+)'|"([^"]+)"|([^\s:'"]+)):\s*(.+)$/.exec(text);
        if (m && (m[1] ?? m[2] ?? m[3]) === name && exactVersion(m[4]) === version) {
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
      pendingImporterDep = !!m && (m[1] ?? m[2] ?? m[3]) === name;
      importerSpecifier = null;
      if (pendingImporterDep && m?.[4] && exactVersion(m[4]) === version) {
        add({ parent: importer, parentVersion: null, range: null, local: true });
        pendingImporterDep = false;
      }
    } else if (indent === depIndent + 4 && pendingImporterDep) {
      const spec = /^specifier:\s*(.+)$/.exec(text);
      if (spec) importerSpecifier = spec[1].replace(/^['"]|['"]$/g, "");
      const ver = /^version:\s*(.+)$/.exec(text);
      if (ver && exactVersion(ver[1]) === version) {
        add({ parent: importer, parentVersion: null, range: importerSpecifier, local: true });
        pendingImporterDep = false;
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

function parseYarnBlocks(content: string): YarnBlock[] {
  const blocks: YarnBlock[] = [];
  for (const block of content.split(/\r?\n(?=\S)/)) {
    const lines = block.split(/\r?\n/);
    const header = lines[0];
    const name = /^"?(@?[^@\s"]+)@/.exec(header)?.[1];
    if (!name || name.startsWith("__")) continue;
    const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/m.exec(block)?.[1];
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
        const m = /^"?((?:@[^\s"/]+\/)?[^\s":]+)"?:?\s+"?([^"]+?)"?\s*$/.exec(text);
        if (m) deps.push([m[1], m[2]]);
      } else {
        inDeps = false;
      }
    }
    blocks.push({ name, version, specs, deps });
  }
  return blocks;
}

export function yarnParents(content: string, name: string, version: string): ParentEdge[] {
  const blocks = parseYarnBlocks(content);
  const resolved = new Map<string, string>();
  for (const b of blocks) for (const spec of b.specs) resolved.set(spec, b.version);
  const edges: ParentEdge[] = [];
  for (const b of blocks) {
    for (const [dep, rawRange] of b.deps) {
      if (dep !== name) continue;
      const range = rawRange.replace(/^npm:/, "");
      if (resolved.get(`${name}@${range}`) !== version) continue;
      edges.push({ parent: b.name, parentVersion: b.version, range, local: false });
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
