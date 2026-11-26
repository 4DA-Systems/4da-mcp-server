// SPDX-License-Identifier: Apache-2.0
/**
 * Package names that are private, and so never leave the machine.
 *
 * Until 6.3.0 every dependency name went to OSV.dev and the public registries, private ones
 * included, and the only way to stop it was FOURDA_OFFLINE, which stops everything (audit
 * 2026-11-11 W1 M2-2). A name is private here when the machine already says so, with no
 * configuration:
 *
 * - npm: a scope mapped to a registry other than the public one, in `.npmrc` (the project's and
 *   the user's) or `.yarnrc.yml` (`npmScopes`): `@acme:registry=https://npm.acme.dev/`.
 * - Go: a module path matching GOPRIVATE, GONOPROXY or GONOSUMDB, from the environment or the
 *   file `go env -w` writes (GOENV, else the user config directory's `go/env`).
 * - Cargo: a crate whose Cargo.lock `source` is a registry other than crates.io, or git (path
 *   dependencies are local code and were never sent).
 * - PyPI: a package the lockfile installs from an index other than pypi.org (uv.lock
 *   `source = { registry = ... }`, a poetry.lock `legacy` source, a Pipfile.lock `index`).
 *
 * - Every ecosystem (R7): a default registry, index or proxy that is not public and is consulted for
 *   any name makes the project's packages of that ecosystem private (PrivatePackageRules
 *   .ecosystemWide), unless FOURDA_PUBLIC_MIRRORS declares the host a mirror; a direct reference or
 *   git source to a host that is not public makes that name private (private-configs.ts).
 *
 * plus an explicit list, FOURDA_PRIVATE_PACKAGES: comma- or space-separated globs, `*` matching
 * anything (`/` included), each optionally prefixed with its ecosystem (`npm:@acme/*`,
 * `crates.io:acme-*`, `PyPI:acme-*`, `Go:github.com/acme/*`; unprefixed applies to all).
 *
 * A private name is never sent and is reported as "not checked (private)", never as clean.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { stripTrailingCommas } from "./bun-lockfile.js";
import { anySignatureChanged, fileSignature, signatureMap, type FileSignature } from "./file-signature.js";
import { pushAll } from "../array-utils.js";
import { exactVersion, MAX_LOCKFILE_LINE, parsePnpmKey, textLines } from "./js-lockfile-readers.js";
import { readRuleFile } from "./text-file.js";
import { tomlTable } from "../project-manifests.js";
import { workspaceSearchDirs } from "../project-tree.js";
import { runSteps, STEP_MASK, type Steps } from "./yield-point.js";
import {
  CODE_HOSTS,
  hostOf,
  inlineKey,
  isPublicCratesSource,
  isPublicExtraPypiIndex,
  isPublicNpmHost,
  isPublicNpmRegistry,
  isPublicPypiIndex,
  sourceLabel,
  stripComment,
  tomlHeader,
  tomlKeyValue,
  tomlLines,
  tomlString,
} from "./private-hosts.js";
import {
  cargoConfigFiles,
  cargoConfigPrivate,
  cargoWorkspaceManifests,
  pep508DirectReferences,
  privateDirectReference,
  declaredMirror,
  findLinksLabel,
  goProxyPrivate,
  isPublicFindLinks,
  npmEnvConfig,
  npmGlobalConfigFiles,
  pipEnvIndexes,
  pipfilePrivate,
  publicMirrorHosts,
  pythonIndexConfig,
  resolvePipOption,
  uvConfigFiles,
  UV_NO_INDEX_LABEL,
  uvEnvIndexes,
  uvFindLinksConfig,
  yarnEnvConfig,
  yarnRcFilename,
  yarnrcRegistry,
  type PrivateSetting,
} from "./private-configs.js";

export { isPublicCratesSource, isPublicExtraPypiIndex, isPublicNpmRegistry, isPublicPypiIndex, sourceLabel } from "./private-hosts.js";

/** A dependency left out of every lookup because its name is private, and why. */
export interface PrivateDependency {
  ecosystem: string;
  name: string;
  version: string | null;
  /** In this server's words: which file or setting says it is private. */
  why: string;
  /**
   * `registry`: private because the package manager fetches ANY name of this ecosystem from a source
   * that is not public here (a default registry, index or proxy, a requirements `--index-url`, an
   * extra index or find-links location, a Cargo source replacement, GOPROXY, a lockfile that installs
   * every package from one private host), so a name not installed yet is private too. `name`: a rule
   * that covers this name only (a scope, GOPRIVATE, a per-package index, FOURDA_PRIVATE_PACKAGES).
   * Carried as data so no caller reads it back out of `why` (pre-publish round 10, W4).
   */
  kind: PrivateKind;
  /**
   * Set when the only reason is a lockfile or manifest of its folder that is there and could not be
   * read (not valid JSON, truncated, too large): where the name is installed from is not known, so
   * it is withheld as possibly private. The file's path.
   */
  unreadable_file?: string;
}

/** What makes a name private: a source that serves any name (`registry`), or a rule for the name (`name`). */
export type PrivateKind = "registry" | "name";

/** Said with every registry-kind reason: how to have a host that only mirrors the public registry checked. */
/**
 * The words that mark a reason as "not a registry release" (a path, git, a URL, a workspace member,
 * an alias key): such a name is not a private package, and the answer says what it is instead.
 */
export const NOT_REGISTRY_MARK = "not a registry release";

/** The words that mark a name declared through a catalog that could not be read: not private, not known. */
export const UNREAD_CATALOG_MARK = "declared through a catalog that could not be read";

/** How the words for an `npm:<x>` that npm and Yarn read differently start (resolution.ts specWords). */
export const AMBIGUOUS_SPEC_START = "the spec npm:";
/** The words that mark such a reason. */
export const AMBIGUOUS_SPEC_MARK = "so neither was looked up";

export const PUBLIC_MIRRORS_HINT = "set FOURDA_PUBLIC_MIRRORS to its host if it only mirrors the public registry";

/** A lockfile entry installed from a registry that is not the public one (or from git). */
export interface PrivateIndexEntry {
  name: string;
  version: string | null;
  /** The registry, index or git URL the lockfile names. */
  registry: string;
  /** Absolute path of the lockfile. */
  file: string;
  /**
   * Local code (a path dependency, a workspace member, a Go `replace` to a directory): never a
   * registry release, so its name is never sent, but it does not make a registry copy of the same
   * name private (R8).
   */
  local?: true;
  /**
   * The directory a local entry's code is in, when the file says (a Cargo `path =`, the crate's own
   * manifest, a uv `editable` / `directory` / `path` source, a `go.work` `use`): code inside the
   * project is the project's own package, not a dependency (LiveIntelligence.getOwnPackageCount).
   */
  at?: string;
  /** An npm alias key (or a key an override replaces with an alias): private only inside its own project. */
  aliasKey?: true;
  /** Declared through a catalog that could not be read: where it comes from is not known. */
  unknownSource?: true;
  /** A `go.work` workspace module: the workspace's copy is built whatever version a go.mod requires. */
  workspace?: true;
  /**
   * The requirements option that makes every name of the file private (`--index-url`,
   * `--extra-index-url`, `--find-links`): a registry-kind reason, which the answer names with the
   * FOURDA_PUBLIC_MIRRORS escape (pre-publish round 10, W4).
   */
  wide?: string;
  /**
   * Set on an entry that stands for a whole file (`file`) that is there and could not be read, with
   * why: the entry names no package (`name` is empty). What the folder installs from is then not
   * known, so every name of the group is private (lockfileRegistryWide), never only the names a
   * readable file happened to list.
   */
  unread?: string;
  /** On an `unread` entry: the file was not parsed, but its text names a source that is not public. */
  privateSeen?: true;
}

/** The entry that stands for a lockfile or manifest that could not be read (PrivateIndexEntry.unread). */
const unreadEntry = (file: string, reason: string): PrivateIndexEntry => ({ name: "", version: null, registry: "a file that could not be read", file, unread: reason });

/** Scopes one `.npmrc` maps to a non-public registry (`@acme:registry=...`). */
export function npmrcPrivateScopes(content: string): string[] {
  return npmrcRead(content).scopes;
}

/** One `.npmrc`: the scopes it maps to a non-public registry, and its own default `registry=` host (a mirror). */
function npmrcRead(content: string): { scopes: string[]; defaultHost: string | null; defaultRegistry: string | null } {
  const scopes: string[] = [];
  let defaultRegistry: string | null = null;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    // ini keys may be quoted: `"@acme:registry"=https://...` maps the scope as surely as the bare key (R7, 5).
    const kv = /^(?:"([^"]*)"|'([^']*)'|([^=]+?))\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    const key = (kv[1] ?? kv[2] ?? kv[3] ?? "").trim();
    const value = kv[4].trim();
    const m = /^(@[^:\s=]+):registry$/i.exec(key);
    if (m && !isPublicNpmRegistry(value)) scopes.push(m[1].toLowerCase());
    if (/^registry$/i.test(key)) defaultRegistry = value.replace(/^["']|["']$/g, "");
  }
  return { scopes, defaultHost: defaultRegistry ? hostOf(defaultRegistry) : null, defaultRegistry };
}

// ---------------------------------------------------------------------------------------------
// .yarnrc.yml: a small YAML reader (block mappings at any indentation, flow mappings, quoted and
// plain scalars, comments). No YAML library is a dependency; this is the subset yarnrc files use.
// ---------------------------------------------------------------------------------------------

type YamlValue = string | YamlMap | YamlValue[];
interface YamlMap {
  [key: string]: YamlValue;
}

const unquote = (s: string) => {
  const t = s.trim();
  return (t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) ? t.slice(1, -1) : t;
};

/** A flow collection (`{ a: { b: "c" } }`, `[x, y]`) or a scalar, from `text` at `pos`. */
function parseFlow(text: string, start = 0): { value: YamlValue; end: number } {
  let i = start;
  const ws = () => {
    while (i < text.length && /\s/.test(text[i])) i++;
  };
  const scalar = (stops: string): string => {
    ws();
    if (text[i] === '"' || text[i] === "'") {
      const q = text[i++];
      const from = i;
      while (i < text.length && text[i] !== q) i++;
      const out = text.slice(from, i);
      i++;
      return out;
    }
    const from = i;
    while (i < text.length && !stops.includes(text[i])) i++;
    return text.slice(from, i).trim();
  };
  const value = (): YamlValue => {
    ws();
    if (text[i] === "{") {
      i++;
      const map: YamlMap = {};
      for (;;) {
        ws();
        if (text[i] === "}") {
          i++;
          return map;
        }
        if (i >= text.length) return map;
        const key = scalar(":,}");
        ws();
        if (text[i] === ":") {
          i++;
          map[key] = value();
        } else map[key] = "";
        ws();
        if (text[i] === ",") i++;
      }
    }
    if (text[i] === "[") {
      i++;
      const list: YamlValue[] = [];
      for (;;) {
        ws();
        if (text[i] === "]" || i >= text.length) {
          i++;
          return list;
        }
        list.push(value());
        ws();
        if (text[i] === ",") i++;
      }
    }
    return scalar(",}]");
  };
  const v = value();
  return { value: v, end: i };
}

/** Where the quoted scalar that opens `text` ends (the index after its closing quote), or -1. A double-quoted one may escape with a backslash. */
function quotedEnd(text: string): number {
  const quote = text[0];
  if (quote !== '"' && quote !== "'") return -1;
  for (let i = 1; i < text.length; i++) {
    if (quote === '"' && text[i] === "\\") i++;
    else if (text[i] === quote) return i + 1;
  }
  return -1;
}

const isSpaceChar = (c: string | undefined): boolean => c !== undefined && /\s/.test(c);

/**
 * `key: value` or `key:` on one YAML line: the key quoted, or plain up to its first `:`, which the
 * line's end or whitespace must follow. Null for any other line. Read by position, so a long run of
 * blanks in a line is walked once.
 */
function yamlMapEntry(line: string): { key: string; rest: string } | null {
  const text = line.trim();
  const after = (colon: number): string | null => {
    const rest = text.slice(colon + 1);
    return rest === "" || isSpaceChar(rest[0]) ? rest.trim() : null;
  };
  const closed = quotedEnd(text);
  if (closed > 0) {
    let i = closed;
    while (isSpaceChar(text[i])) i++;
    const rest = text[i] === ":" ? after(i) : null;
    if (rest !== null) return { key: text.slice(0, closed), rest };
  }
  const colon = text.indexOf(":");
  if (colon <= 0) return null;
  const rest = after(colon);
  return rest === null ? null : { key: text.slice(0, colon), rest };
}

/** The mappings of a YAML document (the subset above). */
export function parseYamlSubset(content: string): YamlMap {
  const root: YamlMap = {};
  const stack: Array<{ indent: number; map: YamlMap }> = [{ indent: -1, map: root }];
  const lines = content.split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    const line = stripComment(lines[n]);
    if (!line.trim() || line.trim().startsWith("-")) continue;
    const indent = line.length - line.trimStart().length;
    const entry = yamlMapEntry(line);
    if (!entry) continue;
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    const parent = stack[stack.length - 1].map;
    const key = unquote(entry.key);
    let rest = entry.rest;
    if (!rest) {
      const child: YamlMap = {};
      parent[key] = child;
      stack.push({ indent, map: child });
      continue;
    }
    if (rest.startsWith("{") || rest.startsWith("[")) {
      // A flow collection may span lines: read until its brackets balance.
      let depth = 0;
      const count = (s: string) => {
        for (const c of s) depth += c === "{" || c === "[" ? 1 : c === "}" || c === "]" ? -1 : 0;
      };
      count(rest);
      while (depth > 0 && n + 1 < lines.length) {
        const next = stripComment(lines[++n]);
        count(next);
        rest += ` ${next.trim()}`;
      }
      parent[key] = parseFlow(rest).value;
      continue;
    }
    parent[key] = unquote(rest);
  }
  return root;
}

/** Scopes a `.yarnrc.yml` maps to a registry server other than the public one (`npmScopes.<scope>.npmRegistryServer`). */
export function yarnrcPrivateScopes(content: string): string[] {
  const scopes = parseYamlSubset(content).npmScopes;
  if (!scopes || typeof scopes !== "object" || Array.isArray(scopes)) return [];
  const out: string[] = [];
  for (const [scope, conf] of Object.entries(scopes)) {
    if (!conf || typeof conf !== "object" || Array.isArray(conf)) continue;
    const server = conf.npmRegistryServer;
    if (typeof server === "string" && server && !isPublicNpmRegistry(server)) out.push(`@${scope.replace(/^@/, "").toLowerCase()}`);
  }
  return out;
}

/** `"@acme"`, `'acme'`, `acme`: a scope as `@acme`. */
const bunScope = (raw: string): string => `@${(tomlString(raw) ?? raw.trim()).replace(/^@/, "").toLowerCase()}`;

/**
 * bunfig.toml: the scopes `[install.scopes]` maps to a registry other than the public one (a URL
 * string, `{ url = ... }`, or an `[install.scopes.<scope>]` table), and the `[install] registry`
 * (bun's default registry: a mirror, as an `.npmrc` `registry=` is). Bun installed `@acme/ui` from
 * a private registry and the server sent it to OSV.dev and npm (blind audit round 4).
 */
export function bunfigRegistries(content: string): { scopes: string[]; registry: string | null } {
  const scopes: string[] = [];
  let registry: string | null = null;
  let section = "";
  let tableScope: string | null = null;
  for (const raw of content.split(/\r?\n/)) {
    const line = stripComment(raw).trim();
    if (!line) continue;
    const header = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
    if (header) {
      section = header[1];
      const sub = /^install\.scopes\.(.+)$/.exec(section);
      tableScope = sub ? bunScope(sub[1]) : null;
      continue;
    }
    const kv = /^("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_@.-]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    const key = tomlString(kv[1]) ?? kv[1];
    const value = kv[2].trim();
    const url = value.startsWith("{") ? inlineKey(value, "url") : tomlString(value);
    if (section === "install.scopes") {
      if (url && !isPublicNpmRegistry(url)) scopes.push(bunScope(kv[1]));
    } else if (tableScope && key === "url") {
      if (url && !isPublicNpmRegistry(url)) scopes.push(tableScope);
    } else if (section === "install" && key === "registry" && url) {
      registry = url;
    }
  }
  return { scopes: [...new Set(scopes)], registry };
}

/** The registry label of a pnpm-workspace.yaml setting this reader cannot follow and that names no URL. */
const UNREAD_REGISTRY = "a registry pnpm-workspace.yaml sets";

/** What pnpmWorkspaceRegistries read from one pnpm-workspace.yaml. */
export interface PnpmWorkspaceRegistries {
  /** Scopes mapped to a registry that is not public. */
  scopes: string[];
  /** The default registry (null when none is set). */
  registry: string | null;
  /**
   * Set when a `registry`, `registries` or `namedRegistries` value is in a form this reader does not
   * fully understand (an anchor or alias, a block scalar, a tag, a key it does not know): pnpm may
   * fetch every name from a registry this server cannot name, so the caller treats npm as having a
   * non-public default registry (fail closed). `url` is the first non-public URL in that value, if any.
   */
  unread?: { url: string | null };
}

/** `key: value`, the key quoted or plain; a plain key ends at the first `:` followed by a space or the line's end, so a URL key (`https://npm.acme.dev/:`) is read whole. */
function yamlKeyValue(l: string): { key: string; value: string } | null {
  const text = l.trim();
  const ends = (colon: number) => colon + 1 === text.length || isSpaceChar(text[colon + 1]);
  const closed = quotedEnd(text);
  if (closed > 0 && text[closed] === ":" && ends(closed)) return { key: unquote(text.slice(0, closed)), value: text.slice(closed + 1).trim() };
  for (let colon = text.indexOf(":", 1); colon > 0; colon = text.indexOf(":", colon + 1)) {
    if (ends(colon)) return { key: unquote(text.slice(0, colon)), value: text.slice(colon + 1).trim() };
  }
  return null;
}

/** Whether a flow collection's brackets (outside quotes) balance. */
function flowDepth(text: string): number {
  let depth = 0;
  let quote: string | null = null;
  for (const c of text) {
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") depth--;
  }
  return depth;
}

/** A YAML feature this reader does not follow: an anchor, alias, tag, block scalar, complex key or directive. */
const UNFOLLOWED = /^[&*!|>?%`]/;
const followedKey = (k: string) => k !== "<<" && !UNFOLLOWED.test(k);

/** A whole flow collection, else undefined (unbalanced, trailing text, or an anchor, alias or tag inside). */
function strictFlow(text: string): YamlValue | undefined {
  if (flowDepth(text) !== 0) return undefined;
  const { value, end } = parseFlow(text);
  if (text.slice(end).trim()) return undefined;
  const plain = (v: YamlValue): boolean => (typeof v === "string" ? !UNFOLLOWED.test(v) : Array.isArray(v) ? v.every(plain) : Object.entries(v).every(([k, x]) => followedKey(k) && plain(x)));
  return plain(value) ? value : undefined;
}

const indentOf = (l: string) => l.length - l.trimStart().length;
const isItem = (l: string) => /^-(?:\s|$)/.test(l.trimStart());
const hasContent = (lines: readonly string[], from: number, to: number) => lines.slice(from, to).some((l) => l.trim());

/** The end (exclusive) of the node on line `at` with inline `text`: the lines below it indented past `indent`, and (no inline text) a same-indent block sequence. */
function nodeEnd(lines: readonly string[], at: number, to: number, indent: number, text: string, items = !text): number {
  let j = at + 1;
  // A flow collection runs to the line its brackets balance on, whatever that line's indentation
  // (`registries: {` ... `}` at column 0), then any lines indented below it (trailing text, unread).
  if (text.startsWith("{") || text.startsWith("[")) {
    let depth = flowDepth(text);
    while (depth > 0 && j < to) depth += flowDepth(lines[j++]);
    while (j < to && (!lines[j].trim() || indentOf(lines[j]) > indent)) j++;
    return j;
  }
  while (j < to && (!lines[j].trim() || indentOf(lines[j]) > indent)) j++;
  if (!items || hasContent(lines, at + 1, j)) return j;
  while (j < to && (!lines[j].trim() || indentOf(lines[j]) > indent || (indentOf(lines[j]) === indent && isItem(lines[j])))) j++;
  return j;
}

/** The value of the node on line `at` whose inline text is `text` and whose lines end at `end`. */
function yamlNodeValue(lines: readonly string[], at: number, end: number, text: string): YamlValue | undefined {
  if (text.startsWith("{") || text.startsWith("[")) return strictFlow([text, ...lines.slice(at + 1, end).map((l) => l.trim())].join(" "));
  // A plain scalar continued on the next lines, or an anchor, alias, tag or block scalar: not followed.
  if (text) return hasContent(lines, at + 1, end) || UNFOLLOWED.test(text) ? undefined : unquote(text);
  return yamlBlock(lines, at + 1, end);
}

/**
 * The value of a block YAML node: the lines `from`..`to` (comment-stripped), every one indented more
 * than its parent. Block maps, block sequences of scalars or flow collections, flow collections that
 * span lines, plain and quoted scalars. Undefined for anything else, so the caller can fail closed.
 */
function yamlBlock(lines: readonly string[], from: number, to: number): YamlValue | undefined {
  let i = from;
  while (i < to && !lines[i].trim()) i++;
  if (i >= to) return "";
  const indent = indentOf(lines[i]);
  const sequence = isItem(lines[i]);
  const map: YamlMap = {};
  const list: YamlValue[] = [];
  while (i < to) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    if (indentOf(line) !== indent) return undefined;
    let text: string;
    let key: string | null = null;
    if (sequence) {
      if (!isItem(line)) return undefined;
      text = line.trimStart().slice(1).trim();
    } else {
      const kv = yamlKeyValue(line);
      if (!kv || !followedKey(kv.key)) return undefined;
      key = kv.key;
      text = kv.value;
    }
    // The node's own lines: those below it indented further, and (a map entry with no inline value)
    // a block sequence at its own indentation, which YAML allows (`scopes:` then `- "@acme"`).
    const j = nodeEnd(lines, i, to, indent, text, !sequence && !text);
    const value = yamlNodeValue(lines, i, j, text);
    if (value === undefined) return undefined;
    if (sequence) list.push(value);
    else map[key as string] = value;
    i = j;
  }
  return sequence ? list : map;
}

const isUrl = (v: YamlValue | undefined): boolean => typeof v === "string" && /^https?:\/\/[^\s/]+/i.test(v);

/**
 * pnpm-workspace.yaml: pnpm v10+ reads registry settings from it (pnpm.io/settings: "Env variables
 * are not expanded in settings of pnpm-workspace.yaml that define registry URLs: registry and the URL
 * values of registries and namedRegistries"), in either shape of `registries` (pnpm.io/registries):
 * scope to URL (`default: <url>`, `"@acme": <url>`) or URL-keyed (`<url>: { scopes: ["@acme"] }`,
 * where a bare `"@"` routes the default registry). Only `.npmrc` was read, so a scope or default
 * registry set here let private names reach OSV.dev and npm (pre-publish round 10, W4). A flow map
 * or sequence that spans lines was not read either, and `zqx-newlib` went to OSV.dev and npm; any
 * value of these keys this reader cannot follow is now `unread` and the caller fails closed
 * (pre-publish round 10, W10).
 */
export function pnpmWorkspaceRegistries(content: string): PnpmWorkspaceRegistries {
  const scopes: string[] = [];
  let registry: string | null = null;
  let unread = false;
  const raw: string[] = [];
  const lines = content.split(/\r?\n/).map((l) => stripComment(l).trimEnd());
  const note = (scope: string, url: string) => {
    const s = scope.trim();
    if (s === "default" || s === "@") registry = url;
    else if (s.startsWith("@")) {
      if (!isPublicNpmRegistry(url)) scopes.push(s.toLowerCase());
    } else unread = true;
  };
  const registries = (value: YamlValue) => {
    if (value === "") return;
    if (typeof value === "string" || Array.isArray(value)) return void (unread = true);
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === "string" && isUrl(v)) note(k, v);
      else if (isUrl(k) && (v === "" || (typeof v === "object" && !Array.isArray(v)))) {
        // URL-keyed: the registry's own fields; `scopes` a list of strings, or absent.
        const listed = typeof v === "object" ? v.scopes : undefined;
        if (listed === undefined) continue;
        if (!Array.isArray(listed) || !listed.every((s) => typeof s === "string")) unread = true;
        else for (const s of listed as string[]) note(s, k);
      } else unread = true;
    }
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || /^\s/.test(line)) continue;
    const top = yamlKeyValue(line);
    if (!top || !["registry", "registries", "namedRegistries"].includes(top.key)) continue;
    const end = nodeEnd(lines, i, lines.length, 0, top.value);
    pushAll(raw, lines.slice(i, end));
    const value = yamlNodeValue(lines, i, end, top.value);
    i = end - 1;
    if (value === undefined) unread = true;
    else if (top.key === "registry") {
      if (typeof value === "string" && isUrl(value)) registry = value;
      else if (value !== "") unread = true;
    } else if (top.key === "registries") registries(value);
    // namedRegistries: aliases (`work:pkg@1`) mapped to URLs, which no default or scope follows.
    else if (value !== "" && (typeof value !== "object" || Array.isArray(value) || !Object.values(value).every(isUrl))) unread = true;
  }
  if (!unread) return { scopes: [...new Set(scopes)], registry };
  const url = (raw.join("\n").match(/https?:\/\/[^\s"',}\]]+/gi) ?? []).find((u) => !isPublicNpmRegistry(u)) ?? null;
  return { scopes: [...new Set(scopes)], registry, unread: { url } };
}

/** The `go env -w` file: GOENV, else the user config directory's `go/env`; null when off. */
function goEnvPath(env: NodeJS.ProcessEnv): string | null {
  if (env.GOENV === "off") return null;
  return env.GOENV || defaultGoEnvFile(env);
}

/** KEY=VALUE pairs of a `go env -w` file's text. */
function goEnvPairs(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

function defaultGoEnvFile(env: NodeJS.ProcessEnv): string | null {
  const home = env.HOME || env.USERPROFILE || os.homedir();
  if (process.platform === "win32") return env.APPDATA ? path.join(env.APPDATA, "go", "env") : null;
  if (process.platform === "darwin") return home ? path.join(home, "Library", "Application Support", "go", "env") : null;
  const config = env.XDG_CONFIG_HOME || (home ? path.join(home, ".config") : null);
  return config ? path.join(config, "go", "env") : null;
}

/**
 * A pattern from the environment or a configuration file longer than this is cut there and ends in
 * `*`: whatever the whole pattern could match, the cut one matches too, so a name is only ever
 * more private for it.
 */
const MAX_PATTERN = 1024;

type GlobToken = { kind: "star" } | { kind: "any" } | { kind: "literal"; char: string } | { kind: "class"; negated: boolean; ranges: Array<[string, string]> };

/**
 * One path element of a Go path.Match pattern as tokens: `*` (any run), `?` (any one character),
 * `[a-z]` and `[^a-z]` classes, a backslash before a character (that character). Null for a
 * malformed pattern (a class left open or empty), which path.Match rejects; `open` (a pattern cut
 * at MAX_PATTERN) reads what is left of an unfinished class or escape as `*`.
 */
function elementTokens(pattern: string, open: boolean): GlobToken[] | null {
  const chars = Array.from(pattern);
  const tokens: GlobToken[] = [];
  const star = () => {
    if (tokens[tokens.length - 1]?.kind !== "star") tokens.push({ kind: "star" });
  };
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c === "*") star();
    else if (c === "?") tokens.push({ kind: "any" });
    else if (c === "\\") {
      if (i + 1 >= chars.length) {
        if (!open) return null;
        star();
      } else tokens.push({ kind: "literal", char: chars[++i] });
    } else if (c === "[") {
      let j = i + 1;
      const negated = chars[j] === "^";
      if (negated) j++;
      const ranges: Array<[string, string]> = [];
      let closed = false;
      while (j < chars.length) {
        if (chars[j] === "]" && ranges.length > 0) {
          closed = true;
          break;
        }
        let lo = chars[j++];
        if (lo === "\\" && j < chars.length) lo = chars[j++];
        let hi = lo;
        if (chars[j] === "-" && j + 1 < chars.length && chars[j + 1] !== "]") {
          hi = chars[j + 1];
          j += 2;
          if (hi === "\\" && j < chars.length) hi = chars[j++];
        }
        ranges.push([lo, hi]);
      }
      if (!closed) {
        if (!open) return null;
        star();
        break;
      }
      tokens.push({ kind: "class", negated, ranges });
      i = j;
    } else tokens.push({ kind: "literal", char: c });
  }
  if (open) star();
  return tokens;
}

const tokenTakes = (token: GlobToken, char: string): boolean =>
  token.kind === "any" || (token.kind === "literal" ? token.char === char : token.kind === "class" && token.ranges.some(([lo, hi]) => lo <= char && char <= hi) !== token.negated);

/**
 * Whether the tokens match the whole of `chars`: one position in each, and the last `*` to return
 * to. At most pattern x text steps, whatever the pattern (a regular expression built from the same
 * pattern took time exponential in its number of `*` against a name that does not match).
 */
function tokensMatch(tokens: readonly GlobToken[], chars: readonly string[]): boolean {
  let p = 0;
  let t = 0;
  let starAt = -1;
  let starText = 0;
  while (t < chars.length) {
    const token = tokens[p];
    if (token?.kind === "star") {
      starAt = p++;
      starText = t;
    } else if (token && tokenTakes(token, chars[t])) {
      p++;
      t++;
    } else if (starAt >= 0) {
      p = starAt + 1;
      t = ++starText;
    } else return false;
  }
  while (tokens[p]?.kind === "star") p++;
  return p === tokens.length;
}

/** Go's path.Match for one path element: `*` and `?` never cross `/` (an element holds none), `[...]` classes. */
function elementMatch(pattern: string, value: string, open = false): boolean {
  const tokens = elementTokens(pattern, open);
  return tokens !== null && tokensMatch(tokens, Array.from(value));
}

/**
 * Go's module.MatchPrefixPatterns: a glob list matched against the leading elements of a module
 * path, case-insensitively. Module paths differ only in case name the same repository on the code
 * hosts GOPRIVATE is written for, and the request guard (nameForms) already read them lowercased:
 * `github.com/Zqxcorp/Other` under GOPRIVATE=github.com/zqxcorp was scanned as public, the guard
 * refused the whole OSV batch, and every public dependency came back NOT CHECKED (blind audit round 5, 2).
 */
export function goPrivateMatch(patterns: string, modulePath: string): string | null {
  const parts = modulePath.toLowerCase().split("/");
  for (const raw of patterns.split(",")) {
    const pattern = trimSlashes(raw.trim());
    if (!pattern) continue;
    const cut = pattern.length > MAX_PATTERN;
    const elements = (cut ? pattern.slice(0, MAX_PATTERN) : pattern).toLowerCase().split("/");
    if (elements.length > parts.length) continue;
    if (elements.every((e, i) => elementMatch(e, parts[i], cut && i === elements.length - 1))) return cut ? `${pattern.slice(0, 80)}... (cut at ${MAX_PATTERN.toLocaleString("en-US")} characters)` : pattern;
  }
  return null;
}

/** `text` without the `/` characters it ends with. */
function trimSlashes(text: string): string {
  let end = text.length;
  while (end > 0 && text[end - 1] === "/") end--;
  return end === text.length ? text : text.slice(0, end);
}

/** PEP 503: lowercase, runs of `-`, `_` and `.` are one `-`. */
export const pep503 = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");

/**
 * A package name as its registry compares it, so every spelling of a private name is caught
 * (review of #64, X1: `acme_core` and `Acme-Core` reached crates.io and OSV for the private
 * `acme-core`). PyPI: PEP 503. crates.io: case-insensitive, `_` and `-` the same crate. npm,
 * RubyGems, Packagist: lowercase. Go module paths are case-sensitive (the proxy escapes capitals).
 */
export function normName(ecosystem: string, name: string): string {
  if (ecosystem === "PyPI") return pep503(name);
  if (ecosystem === "crates.io") return name.toLowerCase().replaceAll("_", "-");
  if (ecosystem === "Go") return name;
  return name.toLowerCase();
}

/**
 * A FOURDA_PRIVATE_PACKAGES entry: `*` matches anything, `/` included; a bare npm scope (`@acme`)
 * is the whole scope (`@acme/*`). PyPI names are compared PEP 503-normalised on both sides.
 */
function listGlob(pattern: string, normalise: (s: string) => string = (s) => s): NameMatcher {
  const scope = pattern.length > 1 && pattern.startsWith("@") && !pattern.includes("/") && !pattern.includes("*");
  const body = normalise(pattern.length > MAX_PATTERN ? `${pattern.slice(0, MAX_PATTERN)}*` : pattern).toLowerCase();
  const parts = body.split("*");
  return {
    test: (name: string): boolean => {
      const n = name.toLowerCase();
      return wildcardMatch(parts, n) || (scope && n.startsWith(`${body}/`));
    },
  };
}

/** Something a name is tested against (a FOURDA_PRIVATE_PACKAGES entry). */
interface NameMatcher {
  test(name: string): boolean;
}

/**
 * Whether `text` is the literal `parts` in order with anything (nothing included) between them:
 * the first part at its start, the last at its end, each one between at the earliest place after
 * the one before. A pattern whose only wildcard is `*` never needs an earlier choice retried.
 */
function wildcardMatch(parts: readonly string[], text: string): boolean {
  if (parts.length === 1) return text === parts[0];
  const first = parts[0];
  const last = parts[parts.length - 1];
  if (text.length < first.length + last.length || !text.startsWith(first) || !text.endsWith(last)) return false;
  const end = text.length - last.length;
  let at = first.length;
  for (let i = 1; i < parts.length - 1; i++) {
    const found = text.indexOf(parts[i], at);
    if (found < 0 || found + parts[i].length > end) return false;
    at = found + parts[i].length;
  }
  return true;
}

const ECOSYSTEM_PREFIXES: Record<string, string> = { npm: "npm", "crates.io": "crates.io", cargo: "crates.io", pypi: "PyPI", go: "Go" };
/**
 * pip's own configuration files, every one pip reads (pip/_internal/configuration.py), in its
 * order: site-wide (Windows `%ProgramData%\pip\pip.ini`, found by pip through the Windows API, so
 * `C:\ProgramData` when the variable is absent; POSIX `$XDG_CONFIG_DIRS/pip/pip.conf` and
 * `/etc/pip.conf`; macOS `/Library/Application Support/pip/pip.conf`), then the user's (legacy
 * `~/pip/pip.ini` on Windows and `~/.pip/pip.conf` on POSIX, then `%APPDATA%\pip\pip.ini`,
 * `~/Library/Application Support/pip/pip.conf`, `$XDG_CONFIG_HOME/pip/pip.conf`), then the
 * virtualenv's (`$VIRTUAL_ENV/pip.ini` on Windows, `pip.conf` elsewhere), then PIP_CONFIG_FILE.
 * Only the APPDATA file and PIP_CONFIG_FILE were read, and a private index set in any of the others
 * (which the real pip loads) let the private names reach OSV.dev and the registries (blind audit
 * round 4). Paths come from `env` (and `platform`), so tests name their own.
 *
 * More than pip's own list, on purpose: a file is read whenever ANY pip on any platform could read it.
 * On Windows a private index in `%USERPROFILE%\.config\pip\pip.conf` (the XDG location, which pip
 * reads through platformdirs when it is there) was not read and the private PyPI name reached
 * OSV.dev and pypi.org in 13 requests (second black-box audit, 2026-11-14). Both file names (`pip.ini`,
 * `pip.conf`) are read in every directory, and the XDG directories on every platform: reading a file
 * pip would not can only make more names private.
 */
export function pipConfigFiles(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): string[] {
  // pip's own switch: PIP_CONFIG_FILE=os.devnull loads no configuration file at all.
  if (env.PIP_CONFIG_FILE === "os.devnull") return [];
  const win = platform === "win32";
  const p = win ? path.win32 : path.posix;
  const both = (dir: string) => (win ? [p.join(dir, "pip.ini"), p.join(dir, "pip.conf")] : [p.join(dir, "pip.conf"), p.join(dir, "pip.ini")]);
  const home = (win ? env.USERPROFILE || env.HOME : env.HOME || env.USERPROFILE) || os.homedir();
  const files: string[] = [];
  // Site-wide.
  if (win) pushAll(files, both(p.join(env.ProgramData || env.PROGRAMDATA || env.ALLUSERSPROFILE || "C:\\ProgramData", "pip")));
  const configDirs = (env.XDG_CONFIG_DIRS || (win ? "" : "/etc/xdg")).split(win ? ";" : ":").filter(Boolean);
  for (const dir of configDirs) pushAll(files, both(p.join(dir, "pip")));
  if (platform === "darwin") files.push("/Library/Application Support/pip/pip.conf");
  if (!win) files.push("/etc/pip.conf");
  // The user's: legacy, then APPDATA, macOS, XDG (both the variable's and the default ~/.config).
  if (home) pushAll(files, [...both(p.join(home, "pip")), ...both(p.join(home, ".pip"))]);
  if (env.APPDATA) pushAll(files, both(p.join(env.APPDATA, "pip")));
  if (platform === "darwin" && home) files.push(p.join(home, "Library", "Application Support", "pip", "pip.conf"));
  if (env.XDG_CONFIG_HOME) pushAll(files, both(p.join(env.XDG_CONFIG_HOME, "pip")));
  if (home) pushAll(files, both(p.join(home, ".config", "pip")));
  if (env.VIRTUAL_ENV) pushAll(files, both(env.VIRTUAL_ENV));
  if (env.PIP_CONFIG_FILE) files.push(env.PIP_CONFIG_FILE);
  return [...new Set(files)];
}

/**
 * `index-url`, `extra-index-url` and `find-links` from a pip config file's [global] and [install]
 * sections. A value may continue on indented lines, for every key (INI continuation, as Python's
 * configparser reads it): `index-url =` with the URL on the next line set a private index that was
 * never read, and the requirements' names reached OSV.dev and pypi.org (R8, B4). A `find-links`
 * location that is not public counts as an extra index. Keys are read as pip's options are, an
 * unambiguous prefix included (resolvePipOption).
 */
export function pipConfigIndexes(content: string): { index: string | null; extra: string[] } {
  let section = "";
  let index: string | null = null;
  const extra: string[] = [];
  let current: { option: string | null; values: string[] } | null = null;
  const flush = () => {
    if (!current) return;
    if (current.option === "index-url" && current.values[0]) index = current.values[0];
    if (current.option === "extra-index-url") pushAll(extra, current.values);
    if (current.option === "find-links") pushAll(extra, current.values.filter((v) => !isPublicFindLinks(v)).map(findLinksLabel));
    current = null;
  };
  for (const line of content.split(/\r?\n/)) {
    // Comment lines, and a `#` or `;` comment after whitespace.
    if (/^\s*[#;]/.test(line)) continue;
    const raw = line.replace(/\s+[#;].*$/, "");
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(raw);
    if (header) {
      flush();
      section = header[1].trim().toLowerCase();
      continue;
    }
    if (/^\s/.test(raw)) {
      // A continuation line: more of the value of the key above it.
      if (current && raw.trim()) pushAll(current.values, raw.trim().split(/\s+/));
      continue;
    }
    flush();
    if (section !== "global" && section !== "install") continue;
    const kv = /^([\w.-]+)\s*[=:]\s*(.*)$/.exec(raw.trim());
    if (!kv) continue;
    current = { option: resolvePipOption(kv[1]), values: kv[2].split(/\s+/).filter(Boolean) };
  }
  flush();
  return { index, extra };
}

/** The environment that decides the rules: a change to any of them re-reads them. */
const RULE_ENV = ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE", "FOURDA_PRIVATE_PACKAGES", "FOURDA_PUBLIC_MIRRORS", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOPROXY", "GOENV", "HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "VIRTUAL_ENV", "ProgramData", "PROGRAMDATA", "ALLUSERSPROFILE", "PREFIX", "CARGO_HOME", "UV_CONFIG_FILE", "UV_NO_CONFIG", "UV_DEFAULT_INDEX", "UV_INDEX_URL", "UV_INDEX", "UV_EXTRA_INDEX_URL", "UV_FIND_LINKS", "UV_NO_INDEX"];
/** Variables read by prefix, any case: npm's `npm_config_*`, yarn's `YARN_*` and pip's `PIP_*`. */
const RULE_ENV_PREFIX = /^(?:npm_config_|yarn_|pip_)/i;

/**
 * A setting read from a file inside a directory applies to that directory and below (`scope`); one
 * from the user's or the system's configuration, or the environment, applies everywhere (null).
 */
interface ScopedSetting extends PrivateSetting {
  scope: string | null;
}

/** Whether `dir` is `scope` or below it (any directory when `scope` is null). */
function within(dir: string, scope: string | null): boolean {
  if (scope === null) return true;
  const rel = path.relative(scope, dir);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** The first setting that applies to `dir` (null: only the user's, the system's, the environment's). */
function settingFor(list: readonly ScopedSetting[], dir: string | null): PrivateSetting | null {
  const hit = list.find((s) => (dir === null ? s.scope === null : within(path.resolve(dir), s.scope)));
  return hit ? { url: hit.url, from: hit.from } : null;
}

/** The environment the rules depend on, as one string. */
const envKeyOf = (env: NodeJS.ProcessEnv): string =>
  [
    ...RULE_ENV.map((k) => `${k}=${env[k] ?? ""}`),
    ...Object.keys(env)
      .filter((k) => RULE_ENV_PREFIX.test(k))
      .sort()
      .map((k) => `${k}=${env[k] ?? ""}`),
  ].join("\n");

/** `dir` and each directory above it, nearest first (at most 32 levels). */
export function ancestorsOf(dir: string): string[] {
  const out: string[] = [];
  for (let d = dir, i = 0; i < 32; i++) {
    out.push(d);
    const up = path.dirname(d);
    if (up === d) break;
    d = up;
  }
  return out;
}

/** The rules for one project: what its files, the user's files and the environment say is private. */
export class PrivatePackageRules {
  private readonly npmScopes = new Map<string, string>();
  private readonly goPatterns: Array<{ key: string; value: string; from: string }> = [];
  private readonly listed: Array<{ ecosystem: string | null; pattern: string; re: NameMatcher; rePypi: NameMatcher; reCrates: NameMatcher }> = [];
  /** FOURDA_PUBLIC_MIRRORS: hosts the user declares mirror only the public registries; their packages are checked. */
  readonly publicMirrors: ReadonlySet<string>;
  /**
   * pip's index from PIP_INDEX_URL or a pip config file, when it is not pypi.org: every package a
   * requirements file installs comes from it, so they are private, as for a lockfile's index.
   */
  readonly pipIndex: PrivateSetting | null = null;
  /**
   * pip's extra indexes (PIP_EXTRA_INDEX_URL, config) that are not public. pip takes a package from
   * whichever index has the newest release, so any name it installs may come from one: every
   * package a requirements file installs is private, as for `--index-url` (blind audit round 4).
   */
  readonly pipExtra: string[] = [];
  /** The first such extra index and where it is set, for the reason line. */
  readonly pipExtraFrom: PrivateSetting | null = null;
  /**
   * Indexes uv, Poetry, PDM or pipenv consult for any name that are not public: a `[[tool.uv.index]]`
   * that is the default or not `explicit`, `[tool.uv] index-url` / `extra-index-url`, `uv.toml` (the
   * project's, the user's, the system's), UV_DEFAULT_INDEX / UV_INDEX_URL / UV_INDEX /
   * UV_EXTRA_INDEX_URL, uv's `find-links` / `no-index` (uv.toml, `[tool.uv]`, `[tool.uv.pip]`,
   * UV_FIND_LINKS, UV_NO_INDEX; pre-publish round 10, W12), a Poetry source that is not `explicit`, a PDM source (R7, 2), a Pipfile
   * `[[source]]` (R8). Each applies under the directory its file is in (pythonIndexFor).
   */
  private readonly pythonIndexes: ScopedSetting[] = [];
  /**
   * Default npm registries that are not public: `registry=` in any `.npmrc` npm reads (the
   * project's and those above it, the user's, the global one), `npm_config_registry`, yarn's
   * `npmRegistryServer` (or YARN_NPM_REGISTRY_SERVER), bun's `[install] registry`. Each applies
   * under the directory its file is in (npmRegistryFor).
   */
  private readonly npmDefaults: ScopedSetting[] = [];
  /** GOPROXY naming a proxy that is not public (the environment, else the `go env -w` file). */
  readonly goProxy: PrivateSetting | null = null;
  /** Cargo configuration files (`.cargo/config.toml` at every level, CARGO_HOME's), each with the directory it applies under. */
  private readonly cargoConfigs: Array<{ file: string; content: string; scope: string | null }> = [];
  private readonly cargoMirrors = new Map<string, PrivateSetting | null>();
  /** Crates a Cargo configuration `[patch.*]` takes from git or another registry, by normalised name. */
  private readonly cargoPatched = new Map<string, string>();
  /** Packages a Pipfile with a source that is not public declares, PEP 503-normalised, with why. */
  private readonly pipfileNames = new Map<string, string>();
  /**
   * Rule files that are there and could not be read (readRuleFile), each with the ecosystem whose
   * rules it holds and the directory it applies under. Such a file may map any name of that
   * ecosystem to a private registry, so none under it is shown public (ecosystemWide).
   */
  private readonly unreadable: Array<{ ecosystem: string; file: string; reason: string; scope: string | null }> = [];
  /** Every file the rules were read from (present or not), with its signature then. */
  private readonly inputs: Map<string, FileSignature>;
  private readonly envKey: string;

  /**
   * `memberDirs`: directories below the project the tree walk found a registry configuration in
   * (`.npmrc`, `.yarnrc.yml`, `bunfig.toml`). Their private scopes apply to the whole project: a
   * server started at a monorepo root sent `@acme/ui`, which `services/api/.npmrc` maps to a
   * private registry and no lockfile records (blind audit round 4). A member's file can only add
   * private names.
   */
  constructor(
    private readonly dirs: string[],
    private readonly env: NodeJS.ProcessEnv = process.env,
    private readonly memberDirs: string[] = [],
  ) {
    const home = env.HOME || env.USERPROFILE || os.homedir();
    const mirrors = publicMirrorHosts(env);
    this.publicMirrors = mirrors;
    const isMirror = (url: string) => declaredMirror(url, mirrors);
    // Each directory and every one above it: npm applies a workspace root's `.npmrc` to every member,
    // and a server started in `packages/app` sent `@acme/vault-core` that `../../.npmrc` made private
    // (blind audit round 3, B2). Reading more files can only add private names. A file in a directory
    // applies to that directory and below (ScopedSetting): a `.cargo/config.toml` or PDM source in one
    // project of a tree made every crate and PyPI package of its siblings private (R8, nit).
    const withParents = [...new Set(dirs.flatMap((d) => ancestorsOf(path.resolve(d))))];
    const scopeDirs = [...new Set([...withParents, ...memberDirs.map((d) => path.resolve(d))])];
    const npmEnv = npmEnvConfig(env);
    type Scoped = { file: string; scope: string | null };
    const inDirs = (name: string): Scoped[] => scopeDirs.map((d) => ({ file: path.resolve(d, name), scope: d }));
    const global = (files: Array<string | null>): Scoped[] => files.filter((f): f is string => Boolean(f)).map((f) => ({ file: path.resolve(f), scope: null }));
    // The user's `.npmrc` (`npm_config_userconfig` in any case) and the global one (R7, 5).
    const npmrcs = [...inDirs(".npmrc"), ...global([npmEnv.userconfig || (home ? path.join(home, ".npmrc") : null), ...npmGlobalConfigFiles(env)])];
    // yarn reads its rc file (YARN_RC_FILENAME) in the project and above, and in the home directory.
    const yarnName = yarnRcFilename(env);
    const yarnrcs = [...inDirs(yarnName), ...global([home ? path.join(home, yarnName) : null])];
    // bun reads the project's bunfig.toml and the user's ($XDG_CONFIG_HOME/.bunfig.toml, ~/.bunfig.toml).
    const xdg = env.XDG_CONFIG_HOME || null;
    const bunfigs = [...inDirs("bunfig.toml"), ...global([xdg ? path.join(xdg, ".bunfig.toml") : null, home ? path.join(home, ".bunfig.toml") : null])];
    // pnpm v10+ reads `registry` and `registries` from pnpm-workspace.yaml (pnpmWorkspaceRegistries).
    const pnpmWorkspaces = inDirs("pnpm-workspace.yaml");
    const goFile = goEnvPath(env);
    const pipFiles = pipConfigFiles(env);
    // uv finds `uv.toml` and `pyproject.toml` in the project and the directories above it; pipenv the Pipfile.
    const uvFiles = [...withParents.map((d) => ({ file: path.join(d, "uv.toml"), scope: d })), ...global(uvConfigFiles(env))];
    const pyprojects = withParents.map((d) => ({ file: path.join(d, "pyproject.toml"), scope: d }));
    const pipfiles = inDirs("Pipfile");
    const cargoHome = env.CARGO_HOME?.trim() || (home ? path.join(home, ".cargo") : null);
    const cargoGlobal = new Set(cargoHome ? [path.resolve(cargoHome, "config.toml"), path.resolve(cargoHome, "config")] : []);
    const cargoFiles = cargoConfigFiles(dirs, env, ancestorsOf).map((file) => ({ file, scope: cargoGlobal.has(file) ? null : path.dirname(path.dirname(file)) }));
    // Signatures first: a write that lands while a file is read still reads as a change.
    this.inputs = signatureMap([...[...npmrcs, ...yarnrcs, ...bunfigs, ...pnpmWorkspaces, ...uvFiles, ...pyprojects, ...pipfiles, ...cargoFiles].map((f) => f.file), ...(goFile ? [goFile] : []), ...pipFiles]);
    this.envKey = envKeyOf(env);
    // A file's text, "" when nothing is there. One that is there and could not be read is recorded:
    // its ecosystem fails closed under `scope`, it is never an empty file.
    const read = (file: string, ecosystem: string, scope: string | null): string => {
      const got = readRuleFile(file);
      if (got.state === "unreadable" && !this.unreadable.some((u) => u.file === file && u.ecosystem === ecosystem)) this.unreadable.push({ ecosystem, file, reason: got.reason, scope });
      return got.state === "read" ? got.text : "";
    };

    // pip. Later files win in pip, but which one wins can depend on a file this server cannot see
    // the same way pip does: any index-url that is not public makes the requirements private.
    let pipIndex: PrivateSetting | null = null;
    const extra: PrivateSetting[] = [];
    const noteIndex = (url: string, from: string) => {
      if (!pipIndex || !isPublicPypiIndex(url)) pipIndex = { url, from };
    };
    for (const file of pipFiles) {
      const conf = pipConfigIndexes(read(file, "PyPI", null));
      if (conf.index) noteIndex(conf.index, file);
      pushAll(extra, conf.extra.map((url) => ({ url, from: file })));
    }
    // PIP_INDEX_URL, PIP_EXTRA_INDEX_URL, PIP_FIND_LINKS, and the prefixes pip's options accept (R8, B4).
    const pipEnv = pipEnvIndexes(env);
    for (const setting of pipEnv.index) noteIndex(setting.url.trim(), setting.from);
    pushAll(extra, pipEnv.extra);
    const chosen = pipIndex as PrivateSetting | null;
    this.pipIndex = chosen && !isPublicPypiIndex(chosen.url) && !isMirror(chosen.url) ? { url: sourceLabel(chosen.url), from: chosen.from } : null;
    const extraPrivate = extra.filter((e) => !isPublicExtraPypiIndex(e.url) && !isMirror(e.url));
    this.pipExtra = [...new Set(extraPrivate.map((e) => sourceLabel(e.url)))];
    this.pipExtraFrom = extraPrivate.length > 0 ? { url: sourceLabel(extraPrivate[0].url), from: extraPrivate[0].from } : null;

    // uv, Poetry, PDM, pipenv.
    const python: ScopedSetting[] = uvEnvIndexes(env).map((s) => ({ ...s, scope: null }));
    for (const { file, scope } of uvFiles) {
      const text = read(file, "PyPI", scope);
      pushAll(python, pythonIndexConfig(text, "uv.toml").map((url) => ({ url, from: file, scope })));
      // find-links and no-index, under pip's find-links policy, the setting named in the reason (pre-publish round 10, W12).
      pushAll(python, uvFindLinksConfig(text, "uv.toml").map(({ url, setting }) => ({ url, from: `${setting}, ${file}`, scope })));
    }
    for (const { file, scope } of pyprojects) {
      const text = read(file, "PyPI", scope);
      pushAll(python, pythonIndexConfig(text, "pyproject").map((url) => ({ url, from: file, scope })));
      pushAll(python, uvFindLinksConfig(text, "pyproject").map(({ url, setting }) => ({ url, from: `${setting}, ${file}`, scope })));
    }
    for (const { file, scope } of pipfiles) {
      const pipfile = pipfilePrivate(read(file, "PyPI", scope));
      const index = pipfile.indexes.find((url) => !isMirror(url));
      if (!index) continue;
      python.push({ url: index, from: file, scope });
      // Its packages are private wherever they are named: no lockfile or tree group may list them.
      for (const name of pipfile.names) if (!this.pipfileNames.has(pep503(name))) this.pipfileNames.set(pep503(name), `${file} installs it from ${sourceLabel(index)} (a Pipfile [[source]]), not pypi.org; ${PUBLIC_MIRRORS_HINT}`);
    }
    // The no-index label is not a URL: kept as it is, and no mirror can declare it public.
    pushAll(this.pythonIndexes, python.filter((p) => !isMirror(p.url)).map((p) => ({ ...p, url: p.url === UV_NO_INDEX_LABEL ? p.url : sourceLabel(p.url) })));

    // npm, yarn, bun.
    const npmDefaults: ScopedSetting[] = [];
    for (const { scope, from } of npmEnv.scopes) if (!this.npmScopes.has(scope)) this.npmScopes.set(scope, from);
    if (npmEnv.registry) npmDefaults.push({ ...npmEnv.registry, scope: null });
    const seen = new Set<string>();
    for (const { file, scope } of npmrcs) {
      if (seen.has(file)) continue;
      seen.add(file);
      const rc = npmrcRead(read(file, "npm", scope));
      for (const s of rc.scopes) if (!this.npmScopes.has(s)) this.npmScopes.set(s, file);
      if (rc.defaultRegistry && !isPublicNpmRegistry(rc.defaultRegistry)) npmDefaults.push({ url: rc.defaultRegistry, from: file, scope });
    }
    for (const { file, scope } of yarnrcs) {
      if (seen.has(file)) continue;
      seen.add(file);
      const text = read(file, "npm", scope);
      for (const s of yarnrcPrivateScopes(text)) if (!this.npmScopes.has(s)) this.npmScopes.set(s, file);
      const server = yarnrcRegistry(text);
      if (server && !isPublicNpmRegistry(server)) npmDefaults.push({ url: server, from: file, scope });
    }
    const yarnEnv = yarnEnvConfig(env, (text) => parseFlow(text).value);
    for (const { scope, from } of yarnEnv.scopes) if (!this.npmScopes.has(scope)) this.npmScopes.set(scope, from);
    if (yarnEnv.registry) npmDefaults.push({ ...yarnEnv.registry, scope: null });
    for (const { file, scope } of bunfigs) {
      if (seen.has(file)) continue;
      seen.add(file);
      const bunfig = bunfigRegistries(read(file, "npm", scope));
      for (const s of bunfig.scopes) if (!this.npmScopes.has(s)) this.npmScopes.set(s, file);
      if (bunfig.registry && !isPublicNpmRegistry(bunfig.registry)) npmDefaults.push({ url: bunfig.registry, from: file, scope });
    }
    for (const { file, scope } of pnpmWorkspaces) {
      if (seen.has(file)) continue;
      seen.add(file);
      const workspace = pnpmWorkspaceRegistries(read(file, "npm", scope));
      for (const s of workspace.scopes) if (!this.npmScopes.has(s)) this.npmScopes.set(s, file);
      if (workspace.registry && !isPublicNpmRegistry(workspace.registry)) npmDefaults.push({ url: workspace.registry, from: file, scope });
      // A registry setting this reader cannot follow fails closed: pnpm may fetch any name from a
      // registry it names, so npm under this folder is registry-private (pre-publish round 10, W10).
      if (workspace.unread) npmDefaults.push({ url: workspace.unread.url ?? UNREAD_REGISTRY, from: `${file}, a registry setting this server cannot read; write it as plain registry/registries URLs`, scope });
    }
    pushAll(this.npmDefaults, npmDefaults.filter((d) => (d.url === UNREAD_REGISTRY || hostOf(d.url) !== null) && !isMirror(d.url)).map((d) => ({ ...d, url: d.url === UNREAD_REGISTRY ? d.url : sourceLabel(d.url) })));

    // Go.
    const fromFile = goEnvPairs(goFile ? read(goFile, "Go", null) : "");
    for (const key of ["GOPRIVATE", "GONOPROXY", "GONOSUMDB"]) {
      // As go does: an empty variable is unset, and the `go env -w` value applies.
      const fromEnv = env[key]?.trim() ? env[key] : undefined;
      const value = fromEnv ?? fromFile[key];
      if (value && value.trim()) this.goPatterns.push({ key, value, from: fromEnv !== undefined ? "the environment" : "go env" });
    }
    const proxyFromEnv = env.GOPROXY?.trim() ? env.GOPROXY : undefined;
    const proxy = goProxyPrivate(proxyFromEnv ?? fromFile.GOPROXY, mirrors);
    this.goProxy = proxy ? { url: sourceLabel(proxy), from: proxyFromEnv !== undefined ? "GOPROXY" : `GOPROXY in ${goFile}` } : null;

    // Cargo.
    pushAll(this.cargoConfigs, cargoFiles.map(({ file, scope }) => ({ file, scope, content: read(file, "crates.io", scope) })));
    // `[patch]` names one crate: private wherever it is named. The source replacement is per directory (cargoMirrorFor).
    const cargo = cargoConfigPrivate(this.cargoConfigs);
    for (const p of cargo.patched) {
      const key = normName("crates.io", p.name);
      if (!this.cargoPatched.has(key)) this.cargoPatched.set(key, `${p.file} patches it from ${p.registry}, not crates.io`);
    }

    for (const raw of (env.FOURDA_PRIVATE_PACKAGES ?? "").split(/[,\s]+/)) {
      const entry = raw.trim();
      if (!entry) continue;
      const m = /^(npm|crates\.io|cargo|pypi|go):(.+)$/i.exec(entry);
      const ecosystem = m ? ECOSYSTEM_PREFIXES[m[1].toLowerCase()] : null;
      const pattern = m ? m[2] : entry;
      this.listed.push({ ecosystem, pattern, re: listGlob(pattern), rePypi: listGlob(pattern, pep503), reCrates: listGlob(pattern, (s) => normName("crates.io", s)) });
    }
  }

  /** True when a file the rules came from, or the environment behind them, has changed since. */
  stale(env: NodeJS.ProcessEnv = this.env): boolean {
    return envKeyOf(env) !== this.envKey || anySignatureChanged(this.inputs);
  }

  /**
   * What the rules say, as one string: two readings that say the same thing are the same rules,
   * whatever happened to the files' times. (A rewrite of an unchanged `.npmrc` must not throw
   * away a scan: refreshPrivateRules compares this.)
   */
  fingerprint(): string {
    return JSON.stringify([
      [...this.npmScopes.keys()].sort(),
      this.goPatterns.map((g) => `${g.key}=${g.value}`).sort(),
      this.listed.map((l) => `${l.ecosystem ?? "*"}:${l.pattern}`).sort(),
      [...this.publicMirrors].sort(),
      this.pipIndex?.url ?? "",
      [...this.pipExtra].sort(),
      this.pythonIndexes.map((s) => `${s.scope ?? "*"}|${s.url}`),
      this.npmDefaults.map((s) => `${s.scope ?? "*"}|${s.url}`),
      this.goProxy?.url ?? "",
      this.cargoConfigs.filter((c) => c.content).map((c) => `${c.scope ?? "*"}|${c.content}`),
      [...this.cargoPatched.keys()].sort(),
      [...this.pipfileNames.keys()].sort(),
      this.unreadable.map((u) => `${u.ecosystem}|${u.scope ?? "*"}|${u.file}|${u.reason}`),
    ]);
  }

  /** The same rules read again (after stale()). */
  reread(env: NodeJS.ProcessEnv = process.env): PrivatePackageRules {
    return new PrivatePackageRules(this.dirs, env, this.memberDirs);
  }

  /**
   * Whether a private-registry rule names this package: a FOURDA_PRIVATE_PACKAGES pattern, an npm
   * scope mapped to a private registry, a Go GOPRIVATE / GONOPROXY / GONOSUMDB pattern, or a
   * Pipfile [[source]] index (the rules 6.5.0 had). A Cargo `[patch]` (local code or another
   * source) is not one. Decided from the rules themselves, never from reason text: a reason quotes
   * repository text (a spec, a folder name) that can spell any rule's wording (round 3 of the hook
   * review, item 2).
   */
  registryRuleCovers(ecosystem: string, name: string): boolean {
    for (const l of this.listed) {
      if (l.ecosystem !== null && l.ecosystem !== ecosystem) continue;
      const hit = ecosystem === "PyPI" ? l.rePypi.test(pep503(name)) : ecosystem === "crates.io" ? l.reCrates.test(normName("crates.io", name)) : l.re.test(name);
      if (hit) return true;
    }
    if (ecosystem === "npm" && name.startsWith("@")) {
      const scope = name.slice(0, name.indexOf("/") > 0 ? name.indexOf("/") : undefined).toLowerCase();
      if (this.npmScopes.has(scope)) return true;
    }
    if (ecosystem === "Go" && this.goPatterns.some((g) => goPrivateMatch(g.value, name))) return true;
    return ecosystem === "PyPI" && this.pipfileNames.has(pep503(name));
  }

  /** Why this name is private, or null when nothing says it is. */
  reasonFor(ecosystem: string, name: string): string | null {
    for (const l of this.listed) {
      if (l.ecosystem !== null && l.ecosystem !== ecosystem) continue;
      const hit =
        ecosystem === "PyPI" ? l.rePypi.test(pep503(name)) : ecosystem === "crates.io" ? l.reCrates.test(normName("crates.io", name)) : l.re.test(name);
      if (hit) return `FOURDA_PRIVATE_PACKAGES lists ${l.ecosystem ? `${l.ecosystem}:` : ""}${l.pattern}`;
    }
    if (ecosystem === "npm" && name.startsWith("@")) {
      const scope = name.slice(0, name.indexOf("/") > 0 ? name.indexOf("/") : undefined).toLowerCase();
      const file = this.npmScopes.get(scope);
      if (file) return `${scope} is mapped to a private registry in ${file}`;
    }
    if (ecosystem === "Go") {
      for (const g of this.goPatterns) {
        const hit = goPrivateMatch(g.value, name);
        if (hit) return `${g.key} (${g.from}) matches ${hit}`;
      }
    }
    if (ecosystem === "crates.io" && this.cargoPatched.size > 0) return this.cargoPatched.get(normName("crates.io", name)) ?? null;
    if (ecosystem === "PyPI" && this.pipfileNames.size > 0) return this.pipfileNames.get(pep503(name)) ?? null;
    return null;
  }

  /** The default npm registry that is not public and applies to `dir` (null: the user's, global or environment setting only). */
  npmRegistryFor(dir: string | null): PrivateSetting | null {
    return settingFor(this.npmDefaults, dir);
  }

  /** The index uv, Poetry, PDM or pipenv consults for any name that is not public and applies to `dir`. */
  pythonIndexFor(dir: string | null): PrivateSetting | null {
    return settingFor(this.pythonIndexes, dir);
  }

  /**
   * The registry the Cargo configuration that applies to `dir` replaces crates.io with, when it is
   * not crates.io: the `.cargo/config.toml` files in `dir` and above (nearest first), then CARGO_HOME's.
   */
  cargoMirrorFor(dir: string | null): PrivateSetting | null {
    const key = dir === null ? "*" : path.resolve(dir);
    if (this.cargoMirrors.has(key)) return this.cargoMirrors.get(key) ?? null;
    const files = this.cargoConfigs
      .filter((c) => (dir === null ? c.scope === null : within(key, c.scope)))
      .sort((a, b) => (b.scope?.length ?? -1) - (a.scope?.length ?? -1));
    const mirror = cargoConfigPrivate(files).mirror;
    const result = mirror && !declaredMirror(mirror.url, this.publicMirrors) ? mirror : null;
    this.cargoMirrors.set(key, result);
    return result;
  }

  /**
   * Why every package of `ecosystem` this project installs is private, or null: a default registry,
   * index or proxy (or one added beside the public one) that is not public and that the package
   * manager consults for any name (R7: one policy for npm, PyPI, Go and Cargo). `dir` is the directory
   * whose configuration applies (a group's own directory and above, the user's and the environment's;
   * null: only the latter). For PyPI the settings are not judged when `indexRecorded`: uv.lock,
   * poetry.lock and Pipfile.lock record each package's index. pdm.lock records none, and a
   * `[[tool.pdm.source]]` with a pdm.lock sent every private name (R8, B4).
   */
  /**
   * Whether a configured registry, index or proxy that is not public serves every name of
   * `ecosystem` for `dir` (ecosystemWide's settings, not its "rule file could not be read" case):
   * an npm registry, GOPROXY, a Cargo source replacement, a pip index or extra index, uv's, Poetry's,
   * PDM's or pipenv's index. A private-registry rule as 6.5.0 had it (round 3 of the hook review, item 2).
   */
  registryConfigured(ecosystem: string, dir: string | null): boolean {
    if (ecosystem === "npm") return this.npmRegistryFor(dir) !== null;
    if (ecosystem === "Go") return Boolean(this.goProxy);
    if (ecosystem === "crates.io") return this.cargoMirrorFor(dir) !== null;
    if (ecosystem === "PyPI") return Boolean(this.pipIndex || this.pipExtraFrom || this.pythonIndexFor(dir));
    return false;
  }

  ecosystemWide(ecosystem: string, dir: string | null, indexRecorded: boolean): string | null {
    const hint = PUBLIC_MIRRORS_HINT;
    const npm = ecosystem === "npm" ? this.npmRegistryFor(dir) : null;
    if (npm) return `npm installs it from ${npm.url} (${npm.from}), not the public registry; ${hint}`;
    if (ecosystem === "Go" && this.goProxy) return `go downloads it through ${this.goProxy.url} (${this.goProxy.from}), not the public proxy; ${hint}`;
    const cargo = ecosystem === "crates.io" ? this.cargoMirrorFor(dir) : null;
    if (cargo) return `cargo replaces crates.io with ${cargo.url} (${cargo.from}); ${hint}`;
    if (ecosystem === "PyPI" && !indexRecorded) {
      // The setting and the escape are named: under a private pip index a public `requests` is not
      // looked up either, and the answer said neither why nor how to have it checked (pre-publish round 10, W4).
      if (this.pipIndex) return `pip installs it from ${this.pipIndex.url} (index-url, ${this.pipIndex.from}), not pypi.org; ${hint}`;
      if (this.pipExtraFrom) return `pip may install it from ${this.pipExtraFrom.url} (an extra index or find-links location, ${this.pipExtraFrom.from}), not pypi.org; ${hint}`;
      const python = this.pythonIndexFor(dir);
      if (python) return `uv, Poetry, PDM or pipenv may install it from ${python.url} (${python.from}), not pypi.org; ${hint}`;
    }
    // A rule file that is there and could not be read may make any name of its ecosystem private.
    // Not for PyPI when every package's index is recorded: the lockfile itself shows where each comes from.
    if (ecosystem !== "PyPI" || !indexRecorded) {
      const key = dir === null ? null : path.resolve(dir);
      const unread = this.unreadable.find((u) => u.ecosystem === ecosystem && (key === null ? u.scope === null : within(key, u.scope)));
      if (unread) return unreadRuleReason(unread.file, unread.reason, ecosystem);
    }
    return null;
  }

  /** The notice for pip extra indexes that are not public (configuration or requirements files), or null. */
  static pipExtraNotice(indexes: string[]): string | null {
    const unique = [...new Set(indexes)];
    if (unique.length === 0) return null;
    return `pip also installs from ${unique.join(", ")} (an extra index). pip may take any package from it, so the packages pip installs here were treated as private: never sent, and not checked. A lockfile that records each package's index (uv.lock, poetry.lock, Pipfile.lock) lets the public ones be checked.`;
  }

  /**
   * When the default npm registry is not a public one (Artifactory, Verdaccio, GitHub Packages): any
   * package may be published only there, so every npm package of the project is private, as for a
   * pip `--index-url` (R7: one policy for every ecosystem). Until 6.3.0 the host was read as a
   * mirror and unscoped names were sent (review of #64, S5). Said in every coverage note and
   * dependency_check answer that concerns npm.
   */
  npmRegistryNotice(dirs: ReadonlyArray<string | null>): string | null {
    const registry = dirs.map((d) => this.npmRegistryFor(d)).find(Boolean);
    if (!registry) return null;
    const host = hostOf(registry.url) ?? registry.url;
    if (registry.url === UNREAD_REGISTRY) return `Your npm registry could not be read (${registry.from}), so it may not be the public registry. The npm packages of this project were treated as private: never sent, and not checked. If it only mirrors registry.npmjs.org, write its URL plainly and set FOURDA_PUBLIC_MIRRORS to its host to check them.`;
    return `Your npm registry is ${host} (${registry.from}), not the public registry. Any package may be published only there, so the npm packages of this project were treated as private: never sent, and not checked. If ${host} only mirrors registry.npmjs.org, set FOURDA_PUBLIC_MIRRORS=${host} to check them.`;
  }

  /** Which file maps `scope` (`@acme`) to a private registry, or null. */
  privateScopeFile(scope: string): string | null {
    return this.npmScopes.get(scope.toLowerCase()) ?? null;
  }

  /** Whether any rule exists (a project with none skips the per-name checks). */
  get empty(): boolean {
    return this.npmScopes.size === 0 && this.goPatterns.length === 0 && this.listed.length === 0 && this.cargoPatched.size === 0 && this.pipfileNames.size === 0;
  }
}

/**
 * npm lockfiles: packages installed from a host other than the public registry, a public mirror
 * of it, or the default `registry=` an `.npmrc` names (read as a mirror, as for the scopes). The
 * lockfile's own `resolved` / `tarball` location, as Cargo.lock `source` and uv `registry` are
 * used: `package-lock.json` / `npm-shrinkwrap.json` `resolved`, yarn v1 `resolved`, pnpm `tarball`.
 * Git, codeload and file locations are left to the readers, which report them as not checkable.
 */
export function npmLockPrivateSources(dir: string, mirrorHosts: ReadonlySet<string>): PrivateIndexEntry[] {
  return runSteps(npmLockPrivateSourcesSteps(dir, mirrorHosts));
}

/** npmLockPrivateSources, pausing every STEP_MASK + 1 yarn.lock or pnpm-lock.yaml lines (runStepsYielding; pre-publish round 10, W11). */
export function* npmLockPrivateSourcesSteps(dir: string, mirrorHosts: ReadonlySet<string>): Steps<PrivateIndexEntry[]> {
  const out: PrivateIndexEntry[] = [];
  const privateLocation = (location: string): boolean => {
    if (!/^https?:\/\//i.test(location)) return false;
    const host = hostOf(location);
    return !!host && !isPublicNpmHost(host) && !mirrorHosts.has(host) && !CODE_HOSTS.test(host);
  };
  const take = (file: string, name: string, version: string | null, location: string) => {
    if (privateLocation(location)) out.push({ name, version, registry: sourceLabel(location), file });
  };
  // A lockfile that is not valid JSON makes every name of the ecosystem here unknown (unreadEntry),
  // with one exception: a merge conflict whose every block is closed holds both sides whole, so the
  // locations in its text are all of them. Then only a location that is not public (or a value that
  // cannot be read) makes the names unknown; none means the file names no private source.
  const notJson = (file: string, text: string, values: RegExp, keys: RegExp | null) => {
    if (wholeMergeConflict(text)) {
      const found = [...text.matchAll(values)].map((m) => jsonString(m[1]));
      const complete = keys === null || [...text.matchAll(keys)].length === found.length;
      if (complete && !found.some((value) => value === null || privateLocation(value))) return;
      // Its text names a source that is not public: the reason is that source, not the file being unread.
      if (complete && found.some((value) => value !== null && privateLocation(value))) {
        out.push({ ...unreadEntry(file, NOT_JSON), privateSeen: true });
        return;
      }
    }
    out.push(unreadEntry(file, NOT_JSON));
  };
  // A lockfile's text, null when nothing is there. One that is there and could not be read is said
  // (unreadEntry): what it installs from is not known, and that is never "nothing private".
  const textOf = (file: string): string | null => {
    const got = readRuleFile(file);
    if (got.state === "unreadable") out.push(unreadEntry(file, got.reason));
    return got.state === "read" && got.text.trim() !== "" ? got.text : null;
  };
  for (const lock of ["package-lock.json", "npm-shrinkwrap.json"]) {
    const file = path.join(dir, lock);
    // The lockfile reader's own parse of this file as it is now (rememberNpmLockLocations): the
    // locations it kept, so the file is not read and parsed a second time (audit 2026-11-25, F-M1).
    const kept = recallNpmLockLocations(file);
    if (kept) {
      for (let i = 0; i < kept.length; i++) {
        const [name, version, location] = kept[i];
        take(file, name, version, location);
        if ((i & STEP_MASK) === STEP_MASK) yield;
      }
      continue;
    }
    const text = textOf(file);
    if (text === null) continue;
    let doc: NpmLockDoc;
    try {
      doc = JSON.parse(text) as NpmLockDoc;
    } catch {
      notJson(file, text, RESOLVED_VALUE, RESOLVED_KEY);
      continue;
    }
    yield;
    try {
      yield* npmLockLocationsSteps(doc, (name, version, location) => take(file, name, version, location));
    } catch {
      notJson(file, text, RESOLVED_VALUE, RESOLVED_KEY);
    }
  }
  const yarn = path.join(dir, "yarn.lock");
  const yarnText = textOf(yarn);
  if (yarnText !== null && !(yield* yarnLockSources(yarnText, (name, version, location) => take(yarn, name, version, location)))) out.push(unreadEntry(yarn, LINE_TOO_LONG));
  // bun.lock (JSONC): `packages` values are `["name@version", "<registry or tarball URL>", {...}, "sha"]`;
  // the URL is "" for the default registry (blind audit round 4: `@acme/ui` from a private one was sent).
  const bunFile = path.join(dir, "bun.lock");
  const bunText = textOf(bunFile);
  if (bunText !== null) {
    try {
      const doc = JSON.parse(stripTrailingCommas(bunText)) as { packages?: Record<string, unknown> };
      for (const value of Object.values(doc.packages ?? {})) {
        if (!Array.isArray(value) || typeof value[0] !== "string" || typeof value[1] !== "string") continue;
        const spec = value[0];
        const at = spec.lastIndexOf("@");
        if (at <= 0) continue;
        take(bunFile, spec.slice(0, at), spec.slice(at + 1) || null, value[1]);
      }
    } catch {
      notJson(bunFile, bunText, QUOTED_STRING, null);
    }
  }
  const pnpm = path.join(dir, "pnpm-lock.yaml");
  const pnpmText = textOf(pnpm);
  if (pnpmText !== null && !(yield* pnpmLockSources(pnpmText, (name, version, location) => take(pnpm, name, version, location)))) out.push(unreadEntry(pnpm, LINE_TOO_LONG));
  return out;
}

type NpmLockDoc = {
  packages?: Record<string, { name?: string; version?: string; resolved?: string }>;
  dependencies?: Record<string, { version?: string; resolved?: string; dependencies?: unknown }>;
};

/**
 * Every location a parsed package-lock.json / npm-shrinkwrap.json names an install from, with the
 * package and version: `resolved` of each `packages` entry (v2, v3), else of each v1 `dependencies`
 * entry, nested ones included (v1 writes a tarball dependency's URL as its version: that URL is
 * where it is installed from, any version of the name). Pauses every STEP_MASK + 1 entries. Throws
 * on a document of the wrong shape, as the private-source pass always has (it is then not JSON to it).
 */
export function* npmLockLocationsSteps(doc: unknown, visit: (name: string, version: string | null, location: string) => void): Steps<void> {
  const lock = doc as NpmLockDoc;
  let n = 0;
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    const at = key.lastIndexOf("node_modules/");
    const name = entry.name ?? (at >= 0 ? key.slice(at + "node_modules/".length) : "");
    if (name && typeof entry.resolved === "string") visit(name, entry.version ?? null, entry.resolved);
    if ((++n & STEP_MASK) === 0) yield;
  }
  if (lock.packages) return;
  function* walk(deps: NpmLockDoc["dependencies"]): Steps<void> {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      if (typeof entry?.resolved === "string") visit(name, entry.version ?? null, entry.resolved);
      else if (typeof entry?.version === "string" && /^https?:\/\//i.test(entry.version)) visit(name, null, entry.version);
      if ((++n & STEP_MASK) === 0) yield;
      yield* walk(entry?.dependencies as NpmLockDoc["dependencies"]);
    }
  }
  yield* walk(lock.dependencies);
}

/** A location that is private for some set of public mirrors: http(s), on a host that is neither the public registry nor a code host. */
function npmLocationMaybePrivate(location: string): boolean {
  if (!/^https?:\/\//i.test(location)) return false;
  const host = hostOf(location);
  return !!host && !isPublicNpmHost(host) && !CODE_HOSTS.test(host);
}

/**
 * The locations the lockfile reader kept from its own parse of a package-lock.json, by file, with
 * the stat signature the file had when it was read (taken before the read: a file changed during it
 * does not match afterwards, and is read again). Only locations that can be private under some
 * mirror set are kept (none, for a project installed from the public registry), so this costs no
 * memory the answer itself does not hold.
 */
const npmLockLocationMemo = new Map<string, { signature: FileSignature; locations: Array<[string, string | null, string]> }>();
const NPM_LOCATION_MEMO_FILES = 512;
/**
 * The most locations kept for one file. A lockfile that installs more from hosts that may be
 * private (a company registry for everything) is not kept, and the pass reads it again, pausing as
 * it goes: kept for 20 such files of 185,000 entries, the locations would outweigh the parse they save.
 */
const MAX_KEPT_LOCATIONS = 20_000;

/** Steps for the npm lockfile reader: keep what the private-source pass needs from `doc`, read from `file` at `signature`. */
export function* rememberNpmLockLocationsSteps(file: string, signature: FileSignature, doc: unknown): Steps<void> {
  const key = path.resolve(file);
  npmLockLocationMemo.delete(key);
  const locations: Array<[string, string | null, string]> = [];
  let tooMany = false;
  try {
    yield* npmLockLocationsSteps(doc, (name, version, location) => {
      if (tooMany || !npmLocationMaybePrivate(location)) return;
      if (locations.length >= MAX_KEPT_LOCATIONS) {
        tooMany = true;
        locations.length = 0;
      } else locations.push([name, version, location]);
    });
  } catch {
    // A shape the pass reads as not JSON: nothing is kept, so it reads the file itself and says so.
    return;
  }
  if (tooMany) return;
  npmLockLocationMemo.set(key, { signature, locations });
  if (npmLockLocationMemo.size > NPM_LOCATION_MEMO_FILES) npmLockLocationMemo.delete(npmLockLocationMemo.keys().next().value as string);
}

/** The locations kept for `file` as it is now, taken: the next pass over it (a rule change) reads the file. */
function recallNpmLockLocations(file: string): Array<[string, string | null, string]> | null {
  const key = path.resolve(file);
  const kept = npmLockLocationMemo.get(key);
  if (!kept) return null;
  npmLockLocationMemo.delete(key);
  return kept.signature === fileSignature(file) ? kept.locations : null;
}

/** Tests only: forget the kept locations. */
export function _resetNpmLockLocations(): void {
  npmLockLocationMemo.clear();
}

const NOT_JSON = "is not valid JSON";
/** A `"resolved": "<location>"` value in package-lock.json text (the only field the JSON read takes a location from). */
const RESOLVED_VALUE = /"resolved"\s*:\s*"((?:[^"\\\r\n]|\\.)*)"/g;
/** Every `"resolved"` key: one whose value RESOLVED_VALUE cannot read leaves the locations incomplete. */
const RESOLVED_KEY = /"resolved"/g;
/** Every quoted string on one line, in bun.lock text (its `packages` values carry the registry or tarball URL). */
const QUOTED_STRING = /"((?:[^"\\\r\n]|\\.)*)"/g;

/** A JSON string's body (`https:\/\/x`) as the string it stands for, or null when it is not one. */
function jsonString(body: string): string | null {
  try {
    return JSON.parse(`"${body}"`) as string;
  } catch {
    return null;
  }
}

/** Whether `text` is a merge conflict whose every block is closed: each side is there, whole. */
function wholeMergeConflict(text: string): boolean {
  const count = (marker: RegExp) => [...text.matchAll(marker)].length;
  const open = count(/^<{7}(?=[ \t\r\n]|$)/gm);
  return open > 0 && count(/^={7}\r?$/gm) === open && count(/^>{7}(?=[ \t\r\n]|$)/gm) === open;
}
const LINE_TOO_LONG = `has a line longer than ${MAX_LOCKFILE_LINE.toLocaleString("en-US")} characters inside an entry, which was not read`;

const isBlank = (code: number) => code === 32 || code === 9;

/** How many spaces and tabs `line` starts with. */
function leadingBlanks(line: string): number {
  let i = 0;
  while (i < line.length && isBlank(line.charCodeAt(i))) i++;
  return i;
}

/** A bare npm package name, scoped or not (at most 214 characters, as the registry allows). */
const isPackageName = (name: string): boolean => name.length > 0 && name.length <= 214 && /^(?:@[^\s/@]+\/)?[^\s/@]+$/.test(name);

/** The package a yarn.lock block header names: `"@scope/name@^1.0.0", ...:` is `@scope/name`. Null for a comment or anything else. */
function yarnHeaderName(line: string): string | null {
  const start = line.charCodeAt(0) === 34 ? 1 : 0;
  const stop = (c: string) => c === "@" || c === '"' || c === "," || c === " " || c === "\t";
  let i = start;
  if (line[i] === "@") {
    i++;
    while (i < line.length && line[i] !== "/" && !stop(line[i])) i++;
    if (line[i] !== "/" || i === start + 1) return null;
    i++;
  }
  const from = i;
  while (i < line.length && !stop(line[i])) i++;
  return i > from && line[i] === "@" ? line.slice(start, i) : null;
}

/** The package an npm alias header installs (`"alias@npm:real@^1.0.0":` is `real`), or null. */
function yarnAliasTarget(line: string, name: string): string | null {
  const from = (line.charCodeAt(0) === 34 ? 1 : 0) + name.length;
  if (!line.startsWith("@npm:", from)) return null;
  const rest = line.slice(from + "@npm:".length, from + "@npm:".length + 216);
  const at = rest.indexOf("@", rest.startsWith("@") ? 1 : 0);
  return at > 0 && isPackageName(rest.slice(0, at)) ? rest.slice(0, at) : null;
}

/** The value of `key value` or `key: value` on a trimmed yarn.lock line, unquoted; null when the line is another key. */
function yarnField(text: string, key: string): string | null {
  if (!text.startsWith(key)) return null;
  let i = key.length;
  if (text[i] === ":") i++;
  if (i >= text.length || !isBlank(text.charCodeAt(i))) return null;
  const value = text.slice(i).trim();
  return value.length >= 2 && value[0] === '"' && value.indexOf('"', 1) > 0 ? value.slice(1, value.indexOf('"', 1)) : value;
}

/**
 * yarn.lock (v1 and berry), line by line: each block's package with every location it installs from
 * (v1 `resolved "<url>"`; berry `resolution: "name@<url>"`, or a registry entry whose tarball came
 * from elsewhere, `name@npm:1.0.0::__archiveUrl=https%3A%2F%2Fhost%2F...`). Nothing here matches
 * across a line break, and a line over MAX_LOCKFILE_LINE is not examined, so blank lines and long
 * lines cost their length once. False when a line inside a block that was being read is too long,
 * or a block's header is: that block's location is then not known.
 */
function* yarnLockSources(text: string, onSource: (name: string, version: string | null, location: string) => void): Steps<boolean> {
  let complete = true;
  let step = 0;
  // The block's package, and the package behind an npm alias (v1: in the header's own spec; berry:
  // in `resolution:`), which is the name the lockfile reader installs it under.
  let name: string | null = null;
  let names = new Set<string>();
  let version: string | null = null;
  let locations: string[] = [];
  const flush = () => {
    for (const n of names) for (const location of locations) onSource(n, version, location);
    name = null;
    names = new Set();
    version = null;
    locations = [];
  };
  for (const line of textLines(text)) {
    if ((++step & STEP_MASK) === 0) yield;
    const indent = leadingBlanks(line);
    if (indent === line.length) continue;
    if (line.length > MAX_LOCKFILE_LINE) {
      // A header too long to read opens a block whose package is not known: its locations are
      // not read, so the file is not fully read.
      if (indent === 0) {
        flush();
        complete = false;
      } else if (name) complete = false;
      continue;
    }
    if (indent === 0) {
      flush();
      name = yarnHeaderName(line);
      if (name) {
        names.add(name);
        const alias = yarnAliasTarget(line, name);
        if (alias) names.add(alias);
      }
      continue;
    }
    if (!name) continue;
    const field = line.slice(indent);
    if (version === null) {
      const v = yarnField(field, "version");
      if (v !== null) {
        version = v.split(/\s/)[0] || null;
        continue;
      }
    }
    const resolved = yarnField(field, "resolved");
    if (resolved !== null) {
      locations.push(resolved);
      continue;
    }
    const resolution = yarnField(field, "resolution");
    if (resolution === null) continue;
    const at = resolution.indexOf("@", resolution.startsWith("@") ? 1 : 0);
    const target = at > 0 ? resolution.slice(at + 1) : "";
    if (at > 0 && isPackageName(resolution.slice(0, at))) names.add(resolution.slice(0, at));
    if (/^https?:\/\//i.test(target)) locations.push(target);
    const archiveAt = target.indexOf("__archiveUrl=");
    if (archiveAt >= 0) {
      const raw = target.slice(archiveAt + "__archiveUrl=".length).split(/[&#\s]/)[0];
      try {
        locations.push(decodeURIComponent(raw));
      } catch {
        // a malformed escape names no host
      }
    }
  }
  flush();
  return complete;
}

/** The package (and version, when the key pins one) a pnpm `packages:` key names, or null. */
function pnpmKeyPackage(rawKey: string): { name: string; version: string | null } | null {
  let key = rawKey.trim();
  // The opening quote of a key whose end was not read (a long key is read for its start only).
  if ((key[0] === "'" || key[0] === '"') && (key.length < 2 || key[key.length - 1] !== key[0])) key = key.slice(1);
  const parsed = parsePnpmKey(key);
  if (parsed) return { name: parsed[0], version: parsed[1] };
  // A key that pins no registry version (`ms@https://host/x.tgz`, `name@file:...`): the name before
  // the `@`. A key with no such name (a bare URL or path) names its package in its own fields.
  if (key[0] === "'" || key[0] === '"') key = key.slice(1);
  if (key.startsWith("/")) key = key.slice(1);
  const at = key.indexOf("@", key.startsWith("@") ? 1 : 0);
  const name = at > 0 ? key.slice(0, at) : "";
  return isPackageName(name) ? { name, version: null } : null;
}

/** The scalar after `key:` on a trimmed YAML line, unquoted; null when the line is another key or has no value. */
function pnpmScalar(text: string, key: string): string | null {
  if (!text.startsWith(key) || text[key.length] !== ":") return null;
  const value = text.slice(key.length + 1).trim();
  const bare = value.length >= 2 && (value[0] === "'" || value[0] === '"') && value[value.length - 1] === value[0] ? value.slice(1, -1) : value;
  return bare === "" ? null : bare;
}

/** Every `tarball: <url>` on a line (a flow mapping may hold it anywhere), unquoted. */
function pnpmTarballs(line: string): string[] {
  const out: string[] = [];
  for (let at = line.indexOf("tarball:"); at >= 0; at = line.indexOf("tarball:", at + 1)) {
    let i = at + "tarball:".length;
    while (i < line.length && isBlank(line.charCodeAt(i))) i++;
    if (line[i] === "'" || line[i] === '"') i++;
    let j = i;
    while (j < line.length && !"'\",} \t".includes(line[j])) j++;
    if (j > i) out.push(line.slice(i, j));
  }
  return out;
}

/**
 * pnpm-lock.yaml (v5 to v9), line by line: each entry's package with the `tarball:` locations
 * written INSIDE that entry. An entry starts at every key two columns deep, whether or not the key
 * names a package: a key that is a URL (`ms@https://pkg.pr.new/...:`) takes its name from the part
 * before the `@` or from its own `name:` field (as the lockfile reader does), and its tarball never
 * belongs to the entry above it. A key line is read for its name only (the first MAX_LOCKFILE_LINE
 * characters), so its length costs nothing more; a longer line inside an entry is not examined and
 * the answer is false: that entry's location is then not known.
 */
function* pnpmLockSources(text: string, onSource: (name: string, version: string | null, location: string) => void): Steps<boolean> {
  let complete = true;
  let step = 0;
  let entry: { key: { name: string; version: string | null } | null; name: string | null; version: string | null; tarballs: string[] } | null = null;
  const flush = () => {
    if (entry && entry.tarballs.length > 0) {
      const name = entry.name && isPackageName(entry.name) ? entry.name : (entry.key?.name ?? null);
      if (name) for (const tarball of entry.tarballs) onSource(name, entry.version ?? entry.key?.version ?? null, tarball);
    }
    entry = null;
  };
  for (const line of textLines(text)) {
    if ((++step & STEP_MASK) === 0) yield;
    const indent = leadingBlanks(line);
    if (indent === line.length) continue;
    if (indent === 0) {
      flush();
      continue;
    }
    if (indent <= 2) {
      flush();
      const long = line.length > MAX_LOCKFILE_LINE;
      const head = long ? line.slice(indent, MAX_LOCKFILE_LINE) : line.slice(indent).trimEnd();
      // A long key is read for its name; anything after the key on that line was not examined.
      if (long && !line.trimEnd().endsWith(":")) complete = false;
      // `key:` alone, or `key: {...}` on one line; a URL in the key has `://`, never `: `.
      const inline = long ? -1 : head.indexOf(": ");
      const key = inline >= 0 ? head.slice(0, inline) : head.endsWith(":") ? head.slice(0, -1) : head;
      entry = { key: pnpmKeyPackage(key), name: null, version: null, tarballs: inline >= 0 ? pnpmTarballs(head.slice(inline)) : [] };
      continue;
    }
    if (!entry) continue;
    if (line.length > MAX_LOCKFILE_LINE) {
      complete = false;
      continue;
    }
    const field = line.slice(indent);
    if (indent === 4) {
      const name = pnpmScalar(field, "name");
      if (name !== null) entry.name = name;
      const version = pnpmScalar(field, "version");
      if (version !== null) entry.version = exactVersion(version);
    }
    if (field.includes("tarball:")) pushAll(entry.tarballs, pnpmTarballs(field));
  }
  flush();
  return complete;
}

/**
 * Cargo.toml: dependencies a manifest takes from somewhere other than crates.io: another registry
 * (`registry = "acme"`, `registry-index = "..."`) or git (`git = "https://..."`, as Cargo.lock
 * records every git source as private), in any dependency table (`[dependencies]`, dev, build,
 * `[target.<cfg>.dependencies]`, `[workspace.dependencies]`, the `[dependencies.<name>]` form) and
 * in `[patch.<source>]`. With no Cargo.lock the exact pin `omega-ledger = { version = "=1.2.0",
 * registry = "acme" }` was sent to OSV.dev and crates.io (blind audit round 4); a `git =` one too (R7, 4).
 * A `path =` dependency is local code, never a crates.io release: its name is private too (R8).
 */
export function cargoManifestPrivate(content: string): Array<{ name: string; registry: string; path?: string }> {
  const out: Array<{ name: string; registry: string; path?: string }> = [];
  /** The `path =` of a dependency that is local code (git wins, as fromElsewhere has it). */
  const localPath = (git: string | null, local: string | null) => (!git && local ? { path: local } : {});
  const isDepTable = (name: string) => /(?:^|\.)(?:dev-|build-)?dependencies$/.test(name) || /^patch\.(?:[^.]+|.+:\/\/.+)$/.test(name);
  const fromElsewhere = (registry: string | null, git: string | null, local: string | null = null): string | null => {
    if (git) return git;
    if (local) return `the local path ${local}`;
    return registry && registry !== "crates-io" && !isPublicCratesSource(registry) ? registry : null;
  };
  let table = "";
  let single: { key: string; pkg: string | null; registry: string | null; git: string | null; local: string | null } | null = null;
  const dottedEntries = new Map<string, { key: string; pkg: string | null; registry: string | null; git: string | null; local: string | null }>();
  const flush = () => {
    const where = single ? fromElsewhere(single.registry, single.git, single.local) : null;
    // A `package =` rename installs under its key: both names are the project's (privacy review 2026-11-24).
    if (single && where) for (const name of new Set([single.key, single.pkg ?? single.key])) out.push({ name, registry: where, ...localPath(single.git, single.local) });
    single = null;
  };
  for (const line of tomlLines(content)) {
    const header = tomlHeader(line);
    if (header) {
      flush();
      table = header.name;
      const sub = /^(.*(?:^|\.)(?:dev-|build-)?dependencies|patch\.(?:[^.]+|.+:\/\/.+))\.([^.]+)$/.exec(table);
      if (sub && !header.array) single = { key: sub[2], pkg: null, registry: null, git: null, local: null };
      continue;
    }
    // `"name".path = "..."`: a quoted crate name with a dotted key (tomlKeyValue reads no dot after a quote).
    const quotedDotted = /^("[^"]+"|'[^']+')\s*\.\s*([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(line);
    const kv = quotedDotted ? { key: `${quotedDotted[1]}.${quotedDotted[2]}`, value: quotedDotted[3].trim() } : tomlKeyValue(line);
    if (!kv) continue;
    if (single) {
      if (kv.key === "registry" || kv.key === "registry-index") single.registry = tomlString(kv.value);
      if (kv.key === "git") single.git = tomlString(kv.value);
      if (kv.key === "path") single.local = tomlString(kv.value);
      if (kv.key === "package") single.pkg = tomlString(kv.value);
      continue;
    }
    if (!isDepTable(table)) continue;
    // Dotted keys are the inline table spelled over lines: `name.path = "..."`, `name.git = "..."`,
    // `name.registry = "..."`, `name.package = "real"` (re-check 2026-11-24: `x.workspace = true`
    // was read as a crate named `x.workspace`, and `x.path` was not read at all).
    const dotted = /^("[^"]+"|'[^']+'|[A-Za-z0-9_-]+)\s*\.\s*([A-Za-z0-9_-]+)$/.exec(kv.key);
    if (dotted) {
      const name = dotted[1].replace(/^["']|["']$/g, "");
      const k = `${table}\0${name}`;
      const d = dottedEntries.get(k) ?? { key: name, pkg: null, registry: null, git: null, local: null };
      const v = tomlString(kv.value);
      if (dotted[2] === "registry" || dotted[2] === "registry-index") d.registry = v;
      if (dotted[2] === "git") d.git = v;
      if (dotted[2] === "path") d.local = v;
      if (dotted[2] === "package") d.pkg = v;
      dottedEntries.set(k, d);
      continue;
    }
    if (!kv.value.startsWith("{")) continue;
    const where = fromElsewhere(inlineKey(kv.value, "registry") ?? inlineKey(kv.value, "registry-index"), inlineKey(kv.value, "git"), inlineKey(kv.value, "path"));
    if (where) for (const name of new Set([kv.key, inlineKey(kv.value, "package") ?? kv.key])) out.push({ name, registry: where, ...localPath(inlineKey(kv.value, "git"), inlineKey(kv.value, "path")) });
  }
  flush();
  for (const d of dottedEntries.values()) {
    single = d;
    flush();
  }
  return out;
}

/**
 * pyproject.toml: packages a manifest takes from somewhere other than pypi.org.
 * - uv: `[tool.uv.sources] name = { index = "acme" }` (or a list of such), where `acme` is a
 *   `[[tool.uv.index]]` whose URL is not pypi.org, or is not declared at all;
 * - Poetry: `name = { version = ..., source = "acme" }` in a dependency table, where `acme` is a
 *   `[[tool.poetry.source]]` whose URL is not pypi.org (or is not declared);
 * - a direct source: uv `{ git = ... }` / `{ url = ... }` / `{ path = ... }`, the same in Poetry,
 *   and a PEP 508 `name @ <location>` in any dependency list, whose location is not public (R7, 3).
 * With no lockfile, `omega-quant==2.0.0` and `omega-risk = "1.4.0"` were sent to OSV.dev and PyPI
 * (blind audit round 4). Returns each such name with the index or location it names.
 */
export function pyprojectManifestPrivate(content: string): Array<{ name: string; registry: string; local?: true }> {
  const indexes = new Map<string, string>();
  const wanted: Array<{ name: string; index: string; kind: "uv" | "poetry" }> = [];
  const direct: Array<{ name: string; registry: string; local?: true }> = [];
  let table = "";
  let block: { kind: "uv" | "poetry"; name: string | null; url: string | null } | null = null;
  const endBlock = () => {
    if (block?.name) indexes.set(`${block.kind}\0${block.name}`, block.url ?? "");
    block = null;
  };
  const isPoetryDeps = (name: string) => /^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/.test(name);
  /** A `{ git = ..., url = ..., path = ... }` source: private unless its location is public. */
  const directSource = (name: string, table: string) => {
    // `{ workspace = true }`: a uv workspace member, local code (re-check 2026-11-24: sent to pypi.org).
    if (/(?:^|[{,\s])workspace\s*=\s*true\b/.test(table)) {
      direct.push({ name, registry: "a uv workspace member (local code)", local: true });
      return;
    }
    const location = inlineKey(table, "git") ?? inlineKey(table, "url") ?? inlineKey(table, "path") ?? inlineKey(table, "file");
    if (!location) return;
    const local = inlineKey(table, "path") !== null || inlineKey(table, "file") !== null;
    const git = inlineKey(table, "git") !== null;
    // A path or a git checkout is not a registry release (local): withheld, and not called private.
    if (local || git) direct.push({ name, registry: local ? `the local path ${location}` : `git (${sourceLabel(location.replace(/^git\+/i, ""))})`, local: true });
    else if (privateDirectReference(location)) direct.push({ name, registry: sourceLabel(location.replace(/^git\+/i, "")) });
  };
  for (const line of tomlLines(content)) {
    const header = tomlHeader(line);
    if (header) {
      endBlock();
      table = header.name;
      if (header.array && table === "tool.uv.index") block = { kind: "uv", name: null, url: null };
      if (header.array && table === "tool.poetry.source") block = { kind: "poetry", name: null, url: null };
      continue;
    }
    const kv = tomlKeyValue(line);
    if (!kv) continue;
    if (block) {
      if (kv.key === "name") block.name = tomlString(kv.value);
      if (kv.key === "url") block.url = tomlString(kv.value);
      continue;
    }
    if (table === "tool.uv.sources") {
      for (const m of kv.value.matchAll(/\bindex\s*=\s*("(?:[^"\\]|\\.)*"|'[^']*')/g)) {
        const index = tomlString(m[1]);
        if (index) wanted.push({ name: kv.key, index, kind: "uv" });
      }
      for (const m of kv.value.matchAll(/\{[^{}]*\}/g)) directSource(kv.key, m[0]);
    } else if (/^tool\.uv\.sources\.[^.]+$/.test(table)) {
      const name = table.slice("tool.uv.sources.".length);
      if (kv.key === "index") {
        const index = tomlString(kv.value);
        if (index) wanted.push({ name, index, kind: "uv" });
      } else if (["git", "url", "path", "workspace"].includes(kv.key)) directSource(name, `{ ${kv.key} = ${kv.value} }`);
    } else if (isPoetryDeps(table) && kv.value.startsWith("{")) {
      const source = inlineKey(kv.value, "source");
      if (source) wanted.push({ name: kv.key, index: source, kind: "poetry" });
      directSource(kv.key, kv.value);
    }
  }
  endBlock();
  const out: Array<{ name: string; registry: string }> = [];
  for (const w of wanted) {
    const url = indexes.get(`${w.kind}\0${w.index}`);
    // An index or source the file does not declare is still not pypi.org as far as anything here knows.
    if (url && isPublicPypiIndex(url)) continue;
    out.push({ name: w.name, registry: url ? sourceLabel(url) : `the "${w.index}" ${w.kind === "uv" ? "index" : "source"}` });
  }
  for (const ref of pep508DirectReferences(content)) {
    if (privateDirectReference(ref.location)) out.push({ name: ref.name, registry: /^file:/i.test(ref.location) ? "a local file" : sourceLabel(ref.location.replace(/^git\+/i, "")) });
  }
  return [...out, ...direct];
}

/**
 * What a group's manifest (no lockfile needed) takes from a private source: Cargo.toml (and every
 * workspace member's: `crates/billing/Cargo.toml` with `registry = "acme"` was never read, R7 4),
 * pyproject.toml.
 */
export function manifestPrivateSources(dir: string, ecosystem: string): PrivateIndexEntry[] {
  // A manifest that is there and could not be read is said (unreadEntry), never "no private source".
  const unread: PrivateIndexEntry[] = [];
  const noteUnread = (file: string, reason: string) => {
    if (!unread.some((u) => u.file === file)) unread.push(unreadEntry(file, reason));
  };
  const textOf = (file: string): string => {
    const got = readRuleFile(file);
    if (got.state === "unreadable") noteUnread(file, got.reason);
    return got.state === "read" ? got.text : "";
  };
  // `path`: where local code is, relative to the manifest (`at`).
  const read = (file: string, text: string, parse: (content: string) => Array<{ name: string; registry: string; local?: true; path?: string }>): PrivateIndexEntry[] => {
    if (!text) return [];
    try {
      return parse(text).map((p) => ({
        name: p.name,
        version: null,
        registry: p.registry,
        file,
        ...(p.local ? { local: true as const } : {}),
        ...(p.local && p.path !== undefined ? { at: path.resolve(path.dirname(file), p.path) } : {}),
      }));
    } catch {
      noteUnread(file, "could not be parsed");
      return [];
    }
  };
  if (ecosystem === "crates.io") {
    const cargo = (text: string) =>
      cargoManifestPrivate(text).map((p) => ({
        name: p.name,
        ...(p.path !== undefined ? { local: true as const, path: p.path } : {}),
        registry: p.path !== undefined ? p.registry : /^[a-z+]*https?:\/\//i.test(p.registry) || /^(?:ssh|git):/i.test(p.registry) ? sourceLabel(p.registry) : `the "${p.registry}" registry`,
      }));
    // The workspace's own crates (the root package and every member) are local code too (R8).
    const ownName = (text: string) => {
      const name = cargoPackageName(text);
      return name ? [{ name, registry: "a local workspace crate (not a crates.io release)", local: true as const, path: "." }] : [];
    };
    const root = path.join(dir, "Cargo.toml");
    const rootText = textOf(root);
    let members: string[] = [];
    try {
      members = cargoWorkspaceManifests(dir, rootText);
    } catch {
      members = [];
    }
    const found = [[root, rootText] as const, ...members.map((file) => [file, textOf(file)] as const)].flatMap(([file, text]) => [...read(file, text, cargo), ...read(file, text, ownName)]);
    // A member of a workspace whose root is above it, with or without a Cargo.lock: the root's path,
    // git and private-registry crates (`{ workspace = true }` inherits them) and every member crate are
    // this project's own (review 2026-11-24: started in a member, an inherited path crate went to
    // index.crates.io). Cargo's root is the nearest directory above with a [workspace] table.
    const workspaceTable = /^\s*\[workspace\]/m;
    if (rootText && !workspaceTable.test(rootText)) {
      for (const ancestor of workspaceSearchDirs(path.resolve(dir))) {
        const file = path.join(ancestor, "Cargo.toml");
        const got = fs.existsSync(file) ? readRuleFile(file) : null;
        if (got?.state !== "read" || !workspaceTable.test(got.text)) continue;
        let listed: string[] = [];
        try {
          listed = cargoWorkspaceManifests(ancestor, got.text);
        } catch {
          listed = [];
        }
        const mine = path.resolve(root).toLowerCase();
        if (listed.some((f) => path.resolve(f).toLowerCase() === mine)) pushAll(found, manifestPrivateSources(ancestor, ecosystem));
        break;
      }
    }
    return [...found, ...unread];
  }
  if (ecosystem === "PyPI") {
    const file = path.join(dir, "pyproject.toml");
    // The project's own name (`[project].name`, `[tool.poetry].name`) is local code, as a Cargo
    // workspace's crates are (re-check 2026-11-24: asked about directly, it was sent to pypi.org).
    const ownProject = (text: string) => {
      const name = /^name\s*=\s*["']([^"']+)["']/m.exec(tomlTable(text, "project") ?? tomlTable(text, "tool.poetry") ?? "")?.[1];
      return name ? [{ name, registry: "this project's own package (pyproject.toml)", local: true as const, path: "." }] : [];
    };
    const text = textOf(file);
    return [...read(file, text, pyprojectManifestPrivate), ...read(file, text, ownProject), ...unread];
  }
  return [];
}

/** A Cargo.toml's `[package] name`, or null. */
function cargoPackageName(content: string): string | null {
  let table = "";
  for (const line of tomlLines(content)) {
    const header = tomlHeader(line);
    if (header) {
      table = header.name;
      continue;
    }
    const kv = tomlKeyValue(line);
    if (kv && table === "package" && kv.key === "name") return tomlString(kv.value);
  }
  return null;
}

/**
 * Local packages a uv.lock or poetry.lock in `dir` names with their directory: uv `source = {
 * editable | directory | virtual | path = "<dir>" }`, Poetry `[package.source] type = "directory"`.
 * Each with `at`, so one inside the project is recognised as the project's own package (a uv
 * workspace member, the project itself). The readers already hold every local package as private;
 * a lockfile that cannot be read here only leaves them so.
 */
export function pythonLocalPackages(dir: string): PrivateIndexEntry[] {
  const out: PrivateIndexEntry[] = [];
  for (const lock of ["uv.lock", "poetry.lock"]) {
    const file = path.join(dir, lock);
    const got = readRuleFile(file);
    if (got.state !== "read") continue;
    let pkg: { name: string | null; version: string | null; dir: string | null; directory: boolean; url: string | null } | null = null;
    let table = "";
    const flush = () => {
      const at = pkg?.dir ?? (pkg?.directory ? pkg.url : null);
      if (pkg?.name && at !== null && at !== undefined) out.push({ name: pkg.name, version: pkg.version, registry: `local code (${at})`, file, local: true, at: path.resolve(dir, at) });
      pkg = null;
    };
    for (const raw of textLines(got.text)) {
      const line = raw.trim();
      if (line.startsWith("[")) {
        if (line === "[[package]]") {
          flush();
          pkg = { name: null, version: null, dir: null, directory: false, url: null };
        }
        table = line;
        continue;
      }
      if (!pkg) continue;
      const kv = /^([A-Za-z-]+)\s*=\s*(.*)$/.exec(line);
      if (!kv) continue;
      const str = /^"([^"]*)"/.exec(kv[2])?.[1] ?? null;
      if (table === "[[package]]") {
        if (kv[1] === "name") pkg.name = str;
        else if (kv[1] === "version") pkg.version = str;
        else if (kv[1] === "source") pkg.dir = /^\{\s*(?:editable|directory|virtual|path)\s*=\s*"([^"]*)"/.exec(kv[2])?.[1] ?? pkg.dir;
      } else if (table === "[package.source]") {
        if (kv[1] === "type") pkg.directory = str === "directory";
        else if (kv[1] === "url") pkg.url = str;
      }
    }
    flush();
  }
  return out;
}

/** Whether `dir` is `root` or below it. */
export function insideDir(root: string, dir: string): boolean {
  const rel = path.relative(path.resolve(root), path.resolve(dir));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

const GO_MODULE = /^module\s+"?([^\s"]+)"?/m;

/** A go.work's `use` directories, and the modules its `replace` points at a directory (with that directory). */
function goWorkDirectives(content: string): { uses: string[]; replaced: Array<{ module: string; dir: string }> } {
  const uses: string[] = [];
  const replaced: Array<{ module: string; dir: string }> = [];
  const unquote = (s: string) => s.replace(/^["`]|["`]$/g, "");
  let block: "use" | "replace" | null = null;
  for (const raw of textLines(content)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (!line) continue;
    if (block && line === ")") {
      block = null;
      continue;
    }
    const opener = /^(use|replace)\s*\($/.exec(line);
    if (opener) {
      block = opener[1] as "use" | "replace";
      continue;
    }
    const single = /^(use|replace)\s+(.+)$/.exec(line);
    const kind = single ? single[1] : block;
    const rest = single ? single[2] : line;
    if (kind === "use") uses.push(unquote(rest.trim()));
    else if (kind === "replace") {
      const [left, right] = rest.split("=>").map((s) => s.trim().split(/\s+/).map(unquote));
      // `=> ./dir` (one word that is a path) is local code; `=> other/module v1.2.3` is not.
      if (left?.[0] && right?.length === 1 && /^(?:\.{1,2}(?:[\\/]|$)|[\\/]|[A-Za-z]:[\\/])/.test(right[0])) replaced.push({ module: left[0], dir: right[0] });
    }
  }
  return { uses, replaced };
}

/**
 * The modules of the go.work that governs `dir`: the first one from `dir` up to `root`, as the go
 * command looks for one (none with GOWORK=off). Each `use` directory inside `root` with the module
 * its go.mod names, and each module its `replace` points at a directory inside `root`. The go
 * command builds every one from the workspace whatever version a go.mod requires: local code, never
 * sent, and the project's own package. Nothing outside `root` is read. A go.work that is there and
 * cannot be read is said (unreadEntry).
 */
export function goWorkModules(dir: string, root: string, env: NodeJS.ProcessEnv = process.env): PrivateIndexEntry[] {
  if ((env.GOWORK ?? "").trim() === "off" || !insideDir(root, dir)) return [];
  let file: string | null = null;
  let got: ReturnType<typeof readRuleFile> = { state: "absent" };
  for (let d = path.resolve(dir); insideDir(root, d); d = path.dirname(d)) {
    got = readRuleFile(path.join(d, "go.work"));
    if (got.state !== "absent") {
      file = path.join(d, "go.work");
      break;
    }
    if (path.dirname(d) === d) break;
  }
  if (file === null) return [];
  if (got.state === "unreadable") return [unreadEntry(file, got.reason)];
  if (got.state !== "read") return [];
  const base = path.dirname(file);
  const out: PrivateIndexEntry[] = [];
  const add = (name: string, at: string) => out.push({ name, version: null, registry: "local code (a go.work workspace module)", file, local: true, at, workspace: true });
  const { uses, replaced } = goWorkDirectives(got.text);
  for (const use of uses) {
    const at = path.resolve(base, use);
    if (!insideDir(root, at)) continue;
    const mod = readRuleFile(path.join(at, "go.mod"));
    const module = mod.state === "read" ? GO_MODULE.exec(mod.text)?.[1] : undefined;
    if (module) add(module, at);
  }
  for (const { module, dir: target } of replaced) {
    const at = path.resolve(base, target);
    if (insideDir(root, at)) add(module, at);
  }
  return out;
}

/**
 * Why a group's lockfile shows a private DEFAULT registry, or null: every package it installs comes
 * from one host that is not public, and no rule that names packages (a scope mapped to that host, a
 * per-package index or registry in the manifest) explains it. Then the package manager fetched names
 * from there with no visible configuration (an Artifactory set in a CI environment, a deleted
 * `.npmrc`), and a name not installed yet would come from there too (pre-publish round 10, W4).
 * `entries`: the group's lockfile entries from a private source (mirrors already removed), and the
 * entry of any file of the group that could not be read (PrivateIndexEntry.unread), which alone is a reason;
 * `installed`: the names the lockfile installs; `explained(name)`: a name rule covers it.
 */
export function lockfileRegistryWide(
  ecosystem: string,
  entries: readonly PrivateIndexEntry[],
  installed: readonly string[],
  explained: (name: string) => boolean,
): string | null {
  // A lockfile or manifest of the group that is there and could not be read: what the group
  // installs from is not known, whatever the files that were read list.
  const unread = entries.find((p) => p.unread !== undefined);
  if (unread) return unreadRuleReason(unread.file, unread.unread ?? "could not be read", ecosystem);
  // A registry location: git, a local path or file names one package, never a default registry.
  const registries = entries.filter((p) => !p.local && !p.wide && !/^(?:git\+|git:|ssh:)|\.git(?:[#?/]|$)/i.test(p.registry));
  const hostOfEntry = (p: PrivateIndexEntry) => hostOf(p.registry.replace(/^[a-z]+\+/i, ""));
  const hosts = new Set(registries.map(hostOfEntry));
  if (registries.length === 0 || hosts.size !== 1 || hosts.has(null)) return null;
  const local = new Set(entries.filter((p) => p.local).map((p) => normName(ecosystem, p.name)));
  const fromHost = new Set(registries.map((p) => normName(ecosystem, p.name)));
  const names = installed.filter((n) => !local.has(normName(ecosystem, n)));
  if (names.length === 0 || !names.every((n) => fromHost.has(normName(ecosystem, n)))) return null;
  if (names.every(explained)) return null;
  const host = [...hosts][0] as string;
  return `${registries[0].file} installs every ${ecosystem} package from ${host}, not the public registry, so a package not installed yet would come from there too; ${PUBLIC_MIRRORS_HINT}`;
}

/**
 * Why a lockfile or manifest entry from a private source is private. A registry or index location
 * (not git, not local code) names the FOURDA_PUBLIC_MIRRORS escape: a mirror of the public registry
 * declared there is checked again, and the answer never said so (pre-publish round 10, W4).
 */
export function lockEntryReason(entry: PrivateIndexEntry): string {
  if (entry.unknownSource) return `${entry.file}: ${entry.name} is ${entry.registry}, so where it comes from is not known and it was not looked up`;
  // An `npm:<x>` npm and Yarn read differently: neither reading was looked up (it may be a registry release).
  if (entry.registry.startsWith(AMBIGUOUS_SPEC_START)) return `${entry.file} declares it with ${entry.registry}`;
  // Local code, a workspace member, git or an alias key: not a private package, and not looked up.
  if (entry.local || /^(?:git\b|git\+|git:|ssh:)|\.git(?:[#?/@]|$)/i.test(entry.registry)) return `${entry.file} installs it from ${entry.registry}: ${NOT_REGISTRY_MARK}, so it was not looked up`;
  const base = `${entry.file} installs it from ${entry.registry}, not the public registry`;
  const registry = !entry.local && hostOf(entry.registry.replace(/^[a-z]+\+/i, "")) !== null && !/^(?:git\+|git:|ssh:)|\.git(?:[#?/]|$)/i.test(entry.registry);
  return registry ? `${base}; ${PUBLIC_MIRRORS_HINT}` : base;
}

/** The reason for a requirements file's `--index-url`, extra index or find-links location that is not public. */
export function requirementsWideReason(file: string, setting: string, registry: string): string {
  return `${file} sets ${setting} ${registry}: pip may install any package of it from there, not pypi.org; ${PUBLIC_MIRRORS_HINT}`;
}

/**
 * Why no name of `ecosystem` under a rule file that is there and could not be read is treated as
 * public: the file may map any of them to a private registry, index or source, and what it says is
 * not known. `reason` completes "<file> <reason>" (readRuleFile).
 */
export function unreadRuleReason(file: string, reason: string, ecosystem: string): string {
  return `${file} ${reason}: it may name a private registry or source for any ${ecosystem} package here, so none is treated as public`;
}

/**
 * What a scan says about the dependencies it did not send: those withheld only because a lockfile
 * or manifest could not be read are said as that (the file is unreadable, where they come from is
 * not known), never called private; the rest as privateLine says them.
 */
export function withheldLine(excluded: { count: number; dependencies: ReadonlyArray<{ name: string; unreadable_file?: string }>; unreadable?: { count: number; names: string[]; files: string[] } }): string {
  const unread = excluded.unreadable;
  if (!unread || unread.count <= 0) return privateLine(excluded.count, excluded.dependencies.map((d) => d.name));
  const n = unread.count;
  const one = n === 1;
  const files = `${unread.files.slice(0, 3).join(", ")}${unread.files.length > 3 ? ", ..." : ""}`;
  const kind = unread.files.every((f) => LOCKFILE_NAME.test(f)) ? "lockfile" : "file";
  const plural = unread.files.length > 1;
  const listed = `${unread.names.join(", ")}${n > unread.names.length ? ", ..." : ""}`;
  const line =
    `NOT CHECKED (unreadable ${kind}): ${files} could not be read, so where ${one ? "1 dependency" : `${n.toLocaleString("en-US")} dependencies`} (${listed}) ${one ? "is" : "are"} installed from is not known. ` +
    `${one ? "It was" : "They were"} withheld as possibly private, never sent to OSV.dev or a registry, so nothing is known about ${one ? "its" : "their"} advisories: this is not a clean result. ` +
    `Repair or regenerate the ${kind}${plural ? "s" : ""} (reinstall), then scan again. See coverage.unreadable_lockfiles.`;
  const rest = excluded.count - n;
  if (rest <= 0) return line;
  return `${line} ${privateLine(rest, excluded.dependencies.filter((d) => !d.unreadable_file).map((d) => d.name))}`;
}

/** "lockfile" for a lockfile's path, else "file" (a manifest or a rule file). */
export function unreadFileKind(file: string): "lockfile" | "file" {
  return LOCKFILE_NAME.test(file) ? "lockfile" : "file";
}

/** A lockfile's name at the end of a path (not a manifest's, such as package.json or Cargo.toml). */
const LOCKFILE_NAME = /(?:^|[\\/])(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|deno\.lock|Cargo\.lock|poetry\.lock|uv\.lock|pdm\.lock|Pipfile\.lock|go\.sum|Gemfile\.lock|gems\.locked|composer\.lock)$/;

/** The sentence a private item or coverage line says. */
export function privateLine(count: number, names: string[]): string {
  const listed = `${names.slice(0, 5).join(", ")}${names.length > 5 ? ", ..." : ""}`;
  return `NOT CHECKED (private): ${count.toLocaleString("en-US")} dependenc${count === 1 ? "y is" : "ies are"} private (${listed}) and ${count === 1 ? "was" : "were"} never sent to OSV.dev or a registry, so nothing is known about ${count === 1 ? "its" : "their"} advisories: this is not a clean result for ${count === 1 ? "it" : "them"}. See coverage.private_dependency_list for why each is private.`;
}
