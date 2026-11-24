// SPDX-License-Identifier: Apache-2.0
/**
 * The catalogs a `catalog:` dependency is read from, as the package manager reads them: pnpm's
 * pnpm-workspace.yaml (`catalog:` and `catalogs:`) in the project directory or the nearest
 * directory above it that has one, else Bun's root package.json (`catalog` / `catalogs`, at the
 * top level or under `workspaces`).
 *
 * Review of the 6.5.1 candidate (2026-11-24): every `catalog:` was taken for a registry range
 * without reading the catalog, and a catalog may hold `link:`, `file:`, `workspace:`, git or a
 * URL, so a local package's name went to registry.npmjs.org, api.npmjs.org, api.osv.dev and
 * hn.algolia.com. A catalog that cannot be parsed is reported as unreadable and answers nothing:
 * the caller withholds every name it could not resolve.
 *
 * pnpm-workspace.yaml is YAML, and no YAML parser is a dependency of this server: the catalog
 * blocks are read with a small parser for the forms pnpm writes and documents (a block mapping of
 * `name: spec` lines, one level for `catalog:`, two for `catalogs:`, or a one-line flow mapping);
 * anything else in those blocks makes the file unreadable rather than guessed at.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { readTextFile } from "./text-file.js";

/** What a directory's `catalog:` dependencies resolve to. */
export interface NpmCatalogs {
  /** The file the catalogs were read from, or null when none was found. */
  file: string | null;
  /** Why the file's catalogs could not be read (then `lookup` answers nothing). */
  error?: string;
  /** The spec the catalog `catalog` ("default" for `catalog:`) gives `name`, or undefined. */
  lookup(catalog: string, name: string): string | undefined;
}

/** Directories walked up from a project looking for its workspace file. */
const MAX_LEVELS = 32;
/** Entries one catalog holds at most; past this the file is not read as a catalog. */
const MAX_ENTRIES = 20_000;

type Catalog = Map<string, string>;

const none = (file: string | null, error?: string): NpmCatalogs => ({ file, ...(error ? { error } : {}), lookup: () => undefined });

function fromMaps(file: string, byName: Map<string, Catalog>): NpmCatalogs {
  return { file, lookup: (catalog, name) => byName.get(catalog)?.get(name) };
}

/** The catalogs that apply to the npm project in `dir`. Reads files only when called. */
export function npmCatalogsFor(dir: string): NpmCatalogs {
  let at = path.resolve(dir);
  for (let level = 0; level < MAX_LEVELS; level++) {
    const yaml = path.join(at, "pnpm-workspace.yaml");
    if (isFile(yaml)) return readPnpmCatalogs(yaml);
    const bun = readBunCatalogs(path.join(at, "package.json"));
    if (bun) return bun;
    const up = path.dirname(at);
    if (up === at) break;
    at = up;
  }
  return none(null);
}

function isFile(file: string): boolean {
  try {
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
}

const unquote = (v: string): string => {
  const t = v.trim();
  if (t.length >= 2 && ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"')))) return t.slice(1, -1);
  return t;
};

/** YAML anchors (`&name value`) seen so far, for aliases (`*name`); a scalar anchor only. */
type Anchors = Map<string, string>;

/**
 * A catalog value: a plain or quoted scalar, an anchored scalar (`&react ^18.2.0`, recorded) or an
 * alias of one (`*react`); null for anything else (a nested block, a tag, an unclosed quote, an alias
 * of an anchor not defined above it), which makes the file unreadable rather than guessed at.
 */
function scalar(value: string, anchors: Anchors = new Map()): string | null {
  let t = value.trim();
  const alias = /^\*([^\s,[\]{}]+)$/.exec(t);
  if (alias) return anchors.get(alias[1]) ?? null;
  const anchor = /^&([^\s,[\]{}]+)\s+(.+)$/.exec(t);
  if (anchor) t = anchor[2].trim();
  if (t === "" || /^[{[|>&*!]/.test(t)) return null;
  if (/^['"]/.test(t) && (t.length < 2 || t[t.length - 1] !== t[0])) return null;
  const out = unquote(t);
  if (anchor) anchors.set(anchor[1], out);
  return out;
}

/** A comment starts at `#` after whitespace (a `#` inside a spec, `org/repo#ref`, is not one). */
const stripComment = (line: string): string => {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === "'" || c === '"') quote = c;
    else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
};

/** `key: value` with an optionally quoted key; null when the line is not one. */
function keyValue(text: string): { key: string; value: string } | null {
  const m = /^\s*('(?:[^']*)'|"(?:[^"]*)"|[^\s'"{}[\],:][^:]*?)\s*:(?:\s+(.*?))?\s*$/.exec(text);
  if (!m) return null;
  return { key: unquote(m[1]), value: m[2] ?? "" };
}

/** `{ a: b, 'c': "d" }` on one line; null when it is not a flat flow mapping. */
function flowMapping(text: string, anchors: Anchors = new Map()): Catalog | null {
  const t = text.trim();
  if (!t.startsWith("{") || !t.endsWith("}")) return null;
  const inner = t.slice(1, -1).trim();
  const out: Catalog = new Map();
  if (inner === "") return out;
  for (const part of inner.split(",")) {
    if (part.trim() === "") continue;
    const kv = keyValue(part);
    const value = kv ? scalar(kv.value, anchors) : null;
    if (!kv || value === null || out.has(kv.key)) return null;
    out.set(kv.key, value);
  }
  return out;
}

/** pnpm-workspace.yaml's `catalog:` and `catalogs:`. */
function readPnpmCatalogs(file: string): NpmCatalogs {
  let content: string;
  try {
    content = readTextFile(file);
  } catch (error) {
    return none(file, `it could not be read (${error instanceof Error ? error.message.slice(0, 120) : String(error)})`);
  }
  const byName = new Map<string, Catalog>();
  const fail = (line: number, why = "could not be parsed") => none(file, `its catalog ${why} (line ${line})`);
  // pnpm refuses a mapping that repeats a key; taking the last would guess (re-check 2026-11-24).
  const duplicate = (line: number) => fail(line, "repeats a key, which pnpm refuses");
  const anchors: Anchors = new Map();
  // Anchors defined anywhere in the file (above the catalog) are what an alias in it refers to.
  for (const raw of content.split(/\r?\n/)) {
    const kv = keyValue(stripComment(raw).replace(/\s+$/, ""));
    if (kv && /^&/.test(kv.value.trim())) scalar(kv.value, anchors);
  }
  const lines = content.split(/\r?\n/);
  let section: "catalog" | "catalogs" | null = null;
  let sectionIndent = -1;
  let current: Catalog | null = null;
  let currentIndent = -1;
  let count = 0;
  for (let i = 0; i < lines.length; i++) {
    const text = stripComment(lines[i]).replace(/\s+$/, "");
    if (text.trim() === "") continue;
    const indent = text.length - text.trimStart().length;
    if (indent === 0) {
      section = null;
      current = null;
      const kv = keyValue(text);
      if (!kv || (kv.key !== "catalog" && kv.key !== "catalogs")) continue;
      section = kv.key;
      sectionIndent = -1;
      currentIndent = -1;
      if (kv.value !== "") {
        const flow = flowMapping(kv.value, anchors);
        if (flow === null) return fail(i + 1);
        if (section === "catalog") byName.set("default", flow);
        else if (flow.size > 0) return fail(i + 1);
        section = null;
      } else if (section === "catalog") {
        current = byName.get("default") ?? new Map();
        byName.set("default", current);
      }
      continue;
    }
    if (section === null) continue;
    if (/\t/.test(text.slice(0, indent))) return fail(i + 1);
    const kv = keyValue(text);
    if (!kv) return fail(i + 1);
    if (section === "catalog") {
      if (sectionIndent < 0) sectionIndent = indent;
      const value = scalar(kv.value, anchors);
      if (indent !== sectionIndent || value === null) return fail(i + 1);
      if (current?.has(kv.key)) return duplicate(i + 1);
      current?.set(kv.key, value);
    } else {
      if (sectionIndent < 0) sectionIndent = indent;
      if (indent === sectionIndent) {
        if (kv.value === "") {
          if (byName.has(kv.key) && kv.key !== "default") return duplicate(i + 1);
          current = byName.get(kv.key) ?? new Map();
          byName.set(kv.key, current);
          currentIndent = -1;
        } else {
          const flow = flowMapping(kv.value, anchors);
          if (flow === null) return fail(i + 1);
          if (byName.has(kv.key)) return duplicate(i + 1);
          byName.set(kv.key, flow);
          current = null;
        }
      } else if (indent > sectionIndent && current) {
        if (currentIndent < 0) currentIndent = indent;
        const value = scalar(kv.value, anchors);
        if (indent !== currentIndent || value === null) return fail(i + 1);
        if (current.has(kv.key)) return duplicate(i + 1);
        current.set(kv.key, value);
      } else return fail(i + 1);
    }
    if (++count > MAX_ENTRIES) return fail(i + 1);
  }
  return fromMaps(file, byName);
}

/** Bun's catalogs in a root package.json, or null when this package.json declares none (or there is none). */
function readBunCatalogs(file: string): NpmCatalogs | null {
  if (!isFile(file)) return null;
  let pkg: unknown;
  try {
    pkg = JSON.parse(readTextFile(file));
  } catch {
    return null;
  }
  if (!pkg || typeof pkg !== "object" || Array.isArray(pkg)) return null;
  const record = pkg as Record<string, unknown>;
  const ws = record.workspaces && typeof record.workspaces === "object" && !Array.isArray(record.workspaces) ? (record.workspaces as Record<string, unknown>) : {};
  const single = ws.catalog ?? record.catalog;
  const named = ws.catalogs ?? record.catalogs;
  if (single === undefined && named === undefined) return null;
  const byName = new Map<string, Catalog>();
  const asCatalog = (value: unknown): Catalog | null => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const out: Catalog = new Map();
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) if (typeof v === "string") out.set(k, v);
    return out;
  };
  if (single !== undefined) {
    const c = asCatalog(single);
    if (!c) return none(file, "its catalog is not an object");
    byName.set("default", c);
  }
  if (named !== undefined) {
    if (!named || typeof named !== "object" || Array.isArray(named)) return none(file, "its catalogs are not an object");
    for (const [name, value] of Object.entries(named as Record<string, unknown>)) {
      const c = asCatalog(value);
      if (c) byName.set(name, c);
    }
  }
  return fromMaps(file, byName);
}

/** A lazy, memoized catalog reader for one directory: no file is touched until a `catalog:` spec asks. */
export function lazyNpmCatalogs(dir: string): NpmCatalogs & { read(): NpmCatalogs | null } {
  let got: NpmCatalogs | null = null;
  const get = () => (got ??= npmCatalogsFor(dir));
  return {
    get file() {
      return get().file;
    },
    get error() {
      return get().error;
    },
    lookup: (catalog, name) => get().lookup(catalog, name),
    read: () => got,
  };
}
