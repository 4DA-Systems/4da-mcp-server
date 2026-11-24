// SPDX-License-Identifier: Apache-2.0
/**
 * bun.lock reader (Bun 1.2+ text lockfile).
 *
 * Measured 2026-10-03 on the pre-publish held-out benchmark: the FastAPI
 * full-stack template's frontend is locked by bun.lock only, and the server
 * read nothing from it — 52 advisories osv-scanner reports (axios 1.18.0,
 * next 16.2.6, @babel/core 7.28.6, ...) were never scanned.
 *
 * Format: JSONC (trailing commas). `workspaces` lists each workspace's
 * declared dependencies; `packages` maps a resolution key to
 * `["name@version", registry, { dependencies, optionalDependencies, ... }, integrity]`.
 * The key is the package name for the hoisted copy and a path for a nested
 * one ("next/postcss" is the postcss next resolves to; scoped names keep their
 * slash: "@tanstack/router-plugin/@babel/core"). Workspace, link, file, git and
 * github entries do not name a registry version and are skipped.
 */

import { nonRegistrySource, type LockReadReport } from "./js-lockfile-readers.js";
import { DEPENDENCY_SECTIONS, isRuntimeSection } from "./js-manifests.js";
import type { DeclaredDependency, InstanceSet } from "./lockfile-types.js";

interface BunWorkspace {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface BunLock {
  workspaces?: Record<string, BunWorkspace>;
  packages?: Record<string, unknown>;
}

interface BunMeta {
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COMMA = 0x2c;
const CLOSE_BRACE = 0x7d;
const CLOSE_BRACKET = 0x5d;
const SPACE_LIKE = /\s/;

function isSpace(code: number): boolean {
  if (code === 0x20 || (code >= 0x09 && code <= 0x0d)) return true;
  return code > 0x7f && SPACE_LIKE.test(String.fromCharCode(code));
}

/**
 * JSONC to JSON: drops trailing commas outside strings (bun.lock has no comments).
 *
 * One pass that copies the text between dropped commas as slices. The earlier version appended one
 * character at a time and ran a regex per character after a comma: 38 MB (150,000 entries) took
 * most of a 10.9 s first call (pre-publish round 7).
 */
export function stripTrailingCommas(text: string): string {
  const parts: string[] = [];
  const n = text.length;
  let start = 0;
  let i = 0;
  while (i < n) {
    const code = text.charCodeAt(i);
    if (code === QUOTE) {
      // Skip the string: an escape takes the next character with it, whatever it is.
      i++;
      while (i < n) {
        const c = text.charCodeAt(i);
        if (c === BACKSLASH) i += 2;
        else if (c === QUOTE) {
          i++;
          break;
        } else i++;
      }
      continue;
    }
    if (code === COMMA) {
      let j = i + 1;
      while (j < n && isSpace(text.charCodeAt(j))) j++;
      const next = j < n ? text.charCodeAt(j) : -1;
      if (next === CLOSE_BRACE || next === CLOSE_BRACKET) {
        parts.push(text.slice(start, i));
        start = i + 1;
      }
    }
    i++;
  }
  if (start === 0) return text;
  parts.push(text.slice(start));
  return parts.join("");
}

/** "next/@babel/core" -> ["next", "@babel/core"]: a scope and its name are one segment. */
function keySegments(key: string): string[] {
  const parts = key.split("/");
  const segments: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    segments.push(parts[i].startsWith("@") && i + 1 < parts.length ? `${parts[i]}/${parts[++i]}` : parts[i]);
  }
  return segments;
}

/**
 * Reads a bun.lock into `versions` (the hoisted copy of each name) and
 * `instances` (every copy). Scope is derived for every copy a workspace
 * reaches: runtime when a `dependencies`, `optionalDependencies` or
 * `peerDependencies` entry of the project or of a workspace member reaches
 * it, dev-only when only their `devDependencies` do. Bun installs peer
 * dependencies, so the peers a package names are followed like its
 * dependencies; one that is not installed (an optional peer) has no entry.
 */
export function readBunLock(content: string, versions: Map<string, string>, instances?: InstanceSet, report?: LockReadReport): void {
  const lock = JSON.parse(stripTrailingCommas(content)) as BunLock;
  const packages = lock.packages ?? {};
  if (report) {
    // `name@github:user/repo#sha`, `name@git+ssh://…`, `name@https://…/x.tgz`: installed, but not a registry release.
    for (const value of Object.values(packages)) {
      if (!Array.isArray(value) || typeof value[0] !== "string") continue;
      const at = value[0].indexOf("@", value[0].startsWith("@") ? 1 : 0);
      if (at <= 0) continue;
      const kind = nonRegistrySource(value[0].slice(at + 1), value[0].slice(at + 1));
      if (kind && kind !== "local") report.uncheckable.push({ name: value[0].slice(0, at), version: null, kind });
      // `name@workspace:packages/x`, `name@file:../x`, `name@link:x` too: local code, never a registry release.
      if (kind) (report.elsewhere ??= []).push(value[0].slice(0, at));
    }
  }

  const entry = (key: string): { name: string; version: string } | null => {
    const value = packages[key];
    if (!Array.isArray(value) || typeof value[0] !== "string") return null;
    const at = value[0].lastIndexOf("@");
    if (at <= 0) return null;
    const version = value[0].slice(at + 1);
    if (!/^\d/.test(version)) return null;
    return { name: value[0].slice(0, at), version };
  };
  // What an entry requires, registry release or not: a git or tarball entry keeps its metadata one place earlier.
  const requires = (key: string): string[] => {
    const value = packages[key];
    if (!Array.isArray(value)) return [];
    const meta = [value[2], value[1]].find((part) => part && typeof part === "object" && !Array.isArray(part)) as BunMeta | undefined;
    return meta ? Object.keys({ ...meta.dependencies, ...meta.optionalDependencies, ...meta.peerDependencies }) : [];
  };

  // Node-style resolution: the nearest nested copy, walking up the key, else the hoisted one.
  const resolve = (fromKey: string, dep: string): string | null => {
    const segments = keySegments(fromKey);
    for (let n = segments.length; n > 0; n--) {
      const candidate = [...segments.slice(0, n), dep].join("/");
      if (Object.hasOwn(packages, candidate)) return candidate;
    }
    return Object.hasOwn(packages, dep) ? dep : null;
  };

  // Every dependency and optional dependency bun resolved has an entry: one without is damage, and
  // the graph that loses it cannot prove anything dev-only. A peer without one is simply not installed.
  let whole = true;
  const installed = (key: string): Set<string> => {
    const value = packages[key];
    if (!Array.isArray(value)) return new Set();
    const meta = [value[2], value[1]].find((part) => part && typeof part === "object" && !Array.isArray(part)) as BunMeta | undefined;
    return new Set(meta ? Object.keys({ ...meta.dependencies, ...meta.optionalDependencies }) : []);
  };
  const reach = (roots: Iterable<string>): Set<string> => {
    const seen = new Set<string>();
    const stack = [...roots];
    while (stack.length > 0) {
      const key = stack.pop() as string;
      if (seen.has(key)) continue;
      seen.add(key);
      const required = installed(key);
      for (const dep of requires(key)) {
        const next = resolve(key, dep);
        if (next && !seen.has(next)) stack.push(next);
        else if (!next && required.has(dep)) whole = false;
      }
    }
    return seen;
  };

  // The roots are package keys. A workspace member's own copy of a dependency is keyed under the
  // member's name ("ws-a/ms"); anything else it declares is the hoisted copy.
  const runtimeRoots = new Set<string>();
  const devRoots = new Set<string>();
  const declared = new Map<string, DeclaredDependency>();
  for (const [dir, ws] of Object.entries(lock.workspaces ?? {})) {
    if (!ws || typeof ws !== "object") continue;
    const member = dir !== "" && typeof ws.name === "string" && ws.name !== "" ? ws.name : null;
    for (const section of DEPENDENCY_SECTIONS) {
      const deps = ws[section];
      if (!deps || typeof deps !== "object") continue;
      for (const dep of Object.keys(deps)) {
        const key = member ? resolve(member, dep) : Object.hasOwn(packages, dep) ? dep : null;
        if (!key) continue;
        (isRuntimeSection(section) ? runtimeRoots : devRoots).add(key);
        const e = entry(key);
        if (!e) continue;
        const id = `${e.name}\0${e.version}`;
        const prior = declared.get(id);
        if (prior) prior.runtime ||= isRuntimeSection(section);
        else declared.set(id, { name: e.name, version: e.version, runtime: isRuntimeSection(section) });
      }
    }
  }
  const runtime = reach(runtimeRoots);
  const dev = reach(devRoots);
  if (report) {
    report.declared = [...declared.values()];
    report.scopeGraded = true;
    report.rootEntries = new Set(Object.keys(packages));
  }

  for (const key of Object.keys(packages)) {
    const e = entry(key);
    if (!e) continue;
    if (key === e.name && !versions.has(e.name)) versions.set(e.name, e.version);
    instances?.add(e.name, e.version, runtime.has(key) ? false : dev.has(key) && whole ? true : undefined);
  }
}
