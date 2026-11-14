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
 * plus an explicit list, FOURDA_PRIVATE_PACKAGES: comma- or space-separated globs, `*` matching
 * anything (`/` included), each optionally prefixed with its ecosystem (`npm:@acme/*`,
 * `crates.io:acme-*`, `PyPI:acme-*`, `Go:github.com/acme/*`; unprefixed applies to all).
 *
 * A private name is never sent and is reported as "not checked (private)", never as clean.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { anySignatureChanged, signatureMap, type FileSignature } from "./file-signature.js";

/** A dependency left out of every lookup because its name is private, and why. */
export interface PrivateDependency {
  ecosystem: string;
  name: string;
  version: string | null;
  /** In this server's words: which file or setting says it is private. */
  why: string;
}

/** A lockfile entry installed from a registry that is not the public one (or from git). */
export interface PrivateIndexEntry {
  name: string;
  version: string | null;
  /** The registry, index or git URL the lockfile names. */
  registry: string;
  /** Absolute path of the lockfile. */
  file: string;
}

const PUBLIC_NPM_HOSTS = new Set(["registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com", "registry.npmmirror.com"]);
const PUBLIC_PYPI_HOSTS = new Set(["pypi.org", "pypi.python.org", "files.pythonhosted.org", "test.pypi.org"]);
const PUBLIC_CRATES_SOURCES = new Set(["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"]);

const hostOf = (url: string): string | null => {
  try {
    return new URL(url.trim().replace(/^["']|["']$/g, "")).hostname.toLowerCase();
  } catch {
    return null;
  }
};

/** Whether an npm registry URL is the public registry (or a public mirror of it). */
export function isPublicNpmRegistry(url: string): boolean {
  const host = hostOf(url);
  return host !== null && PUBLIC_NPM_HOSTS.has(host);
}

/** Whether a Python index URL is pypi.org. */
export function isPublicPypiIndex(url: string): boolean {
  const host = hostOf(url);
  return host !== null && PUBLIC_PYPI_HOSTS.has(host);
}

/** Whether a Cargo.lock `source` is crates.io. */
export function isPublicCratesSource(source: string): boolean {
  const bare = (s: string) => s.trim().replace(/\/+$/, "").toLowerCase();
  return [...PUBLIC_CRATES_SOURCES].some((s) => bare(s) === bare(source));
}

/**
 * A registry, index or git URL as it may be shown: no credentials, no query, no fragment
 * (a lockfile URL can carry a token: `https://user:token@npm.acme.dev/`).
 */
export function sourceLabel(source: string): string {
  const m = /^([a-z]+\+)?(.*)$/i.exec(source.trim());
  const prefix = m?.[1] ?? "";
  try {
    const u = new URL(m?.[2] ?? source);
    return `${prefix}${u.protocol}//${u.host}${u.pathname}`.replace(/\/+$/, "");
  } catch {
    return prefix ? `${prefix}(unreadable URL)` : "(unreadable URL)";
  }
}

/** Scopes one `.npmrc` maps to a non-public registry (`@acme:registry=...`). */
export function npmrcPrivateScopes(content: string): string[] {
  return npmrcRead(content).scopes;
}

/** One `.npmrc`: the scopes it maps to a non-public registry, and its own default `registry=` host (a mirror). */
function npmrcRead(content: string): { scopes: string[]; defaultHost: string | null } {
  const scopes: string[] = [];
  let defaultHost: string | null = null;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const m = /^(@[^:\s=]+):registry\s*=\s*(.+)$/i.exec(line);
    if (m && !isPublicNpmRegistry(m[2])) scopes.push(m[1].toLowerCase());
    const d = /^registry\s*=\s*(.+)$/i.exec(line);
    if (d) defaultHost = hostOf(d[1]);
  }
  return { scopes, defaultHost };
}

// ---------------------------------------------------------------------------------------------
// .yarnrc.yml: a small YAML reader (block mappings at any indentation, flow mappings, quoted and
// plain scalars, comments). No YAML library is a dependency; this is the subset yarnrc files use.
// ---------------------------------------------------------------------------------------------

type YamlValue = string | YamlMap | YamlValue[];
interface YamlMap {
  [key: string]: YamlValue;
}

function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
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

/** The mappings of a YAML document (the subset above). */
export function parseYamlSubset(content: string): YamlMap {
  const root: YamlMap = {};
  const stack: Array<{ indent: number; map: YamlMap }> = [{ indent: -1, map: root }];
  const lines = content.split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    const line = stripComment(lines[n]);
    if (!line.trim() || line.trim().startsWith("-")) continue;
    const indent = line.length - line.trimStart().length;
    const m = /^\s*("(?:[^"\\]|\\.)*"|'[^']*'|[^:]+?)\s*:(?:\s+(.*)|\s*)$/.exec(line);
    if (!m) continue;
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    const parent = stack[stack.length - 1].map;
    const key = unquote(m[1]);
    let rest = (m[2] ?? "").trim();
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

/** The `go env -w` file: GOENV, else the user config directory's `go/env`; null when off. */
function goEnvPath(env: NodeJS.ProcessEnv): string | null {
  if (env.GOENV === "off") return null;
  return env.GOENV || defaultGoEnvFile(env);
}

/** KEY=VALUE pairs of a `go env -w` file. */
function goEnvFile(file: string | null): Record<string, string> {
  if (!file) return {};
  const out: Record<string, string> = {};
  for (const line of safeRead(file).split(/\r?\n/)) {
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

/** Go's path.Match for one path element: `*` and `?` never cross `/`, `[...]` classes. */
function elementMatch(pattern: string, value: string): boolean {
  const re = pattern.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]");
  try {
    return new RegExp(`^${re}$`).test(value);
  } catch {
    return false;
  }
}

/** Go's module.MatchPrefixPatterns: a glob list matched against the leading elements of a module path. */
export function goPrivateMatch(patterns: string, modulePath: string): string | null {
  const parts = modulePath.split("/");
  for (const raw of patterns.split(",")) {
    const pattern = raw.trim().replace(/\/+$/, "");
    if (!pattern) continue;
    const elements = pattern.split("/");
    if (elements.length > parts.length) continue;
    if (elements.every((e, i) => elementMatch(e, parts[i]))) return pattern;
  }
  return null;
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
function listGlob(pattern: string, normalise: (s: string) => string = (s) => s): RegExp | null {
  const scope = /^@[^/*]+$/.test(pattern);
  const body = normalise(pattern)
    .split("*")
    .map((part) => part.replace(/[.+^${}()|[\]\\?]/g, "\\$&"))
    .join(".*");
  try {
    return new RegExp(`^${body}${scope ? "(?:/.*)?" : ""}$`, "i");
  } catch {
    return null;
  }
}

const ECOSYSTEM_PREFIXES: Record<string, string> = { npm: "npm", "crates.io": "crates.io", cargo: "crates.io", pypi: "PyPI", go: "Go" };
/**
 * pip's own configuration files, in the order pip reads them (later wins): the user file, then
 * PIP_CONFIG_FILE. Site-wide and virtualenv files are not read.
 */
function pipConfigFiles(env: NodeJS.ProcessEnv): string[] {
  // pip's own switch: PIP_CONFIG_FILE=os.devnull loads no configuration file at all.
  if (env.PIP_CONFIG_FILE === "os.devnull") return [];
  const home = env.HOME || env.USERPROFILE || os.homedir();
  const files: string[] = [];
  if (process.platform === "win32") {
    if (env.APPDATA) files.push(path.join(env.APPDATA, "pip", "pip.ini"));
  } else {
    if (home) files.push(path.join(home, ".pip", "pip.conf"));
    if (process.platform === "darwin" && home) files.push(path.join(home, "Library", "Application Support", "pip", "pip.conf"));
    const config = env.XDG_CONFIG_HOME || (home ? path.join(home, ".config") : null);
    if (config) files.push(path.join(config, "pip", "pip.conf"));
  }
  if (env.PIP_CONFIG_FILE && env.PIP_CONFIG_FILE !== "os.devnull") files.push(env.PIP_CONFIG_FILE);
  return files;
}

/** `index-url` and `extra-index-url` from a pip config file's [global] and [install] sections. */
export function pipConfigIndexes(content: string): { index: string | null; extra: string[] } {
  let section = "";
  let index: string | null = null;
  const extra: string[] = [];
  let continuing: "extra" | null = null;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/[#;].*$/, "");
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      section = header[1].trim().toLowerCase();
      continuing = null;
      continue;
    }
    if (section !== "global" && section !== "install") continue;
    const kv = /^([\w-]+)\s*[=:]\s*(.*)$/.exec(line.trim());
    if (kv && /^\S/.test(line)) {
      const key = kv[1].toLowerCase().replaceAll("_", "-");
      const values = kv[2].split(/\s+/).filter(Boolean);
      if (key === "index-url" && values[0]) index = values[0];
      if (key === "extra-index-url") extra.push(...values);
      continuing = key === "extra-index-url" ? "extra" : null;
    } else if (continuing === "extra" && line.trim()) {
      extra.push(...line.trim().split(/\s+/));
    }
  }
  return { index, extra };
}

/** The environment that decides the rules: a change to any of them re-reads them. */
const RULE_ENV = ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE", "FOURDA_PRIVATE_PACKAGES", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOENV", "NPM_CONFIG_USERCONFIG", "npm_config_userconfig", "HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME"];

/** The rules for one project: what its files, the user's files and the environment say is private. */
/** `dir` and each directory above it, nearest first (at most 32 levels). */
function ancestorsOf(dir: string): string[] {
  const out: string[] = [];
  for (let d = dir, i = 0; i < 32; i++) {
    out.push(d);
    const up = path.dirname(d);
    if (up === d) break;
    d = up;
  }
  return out;
}

export class PrivatePackageRules {
  private readonly npmScopes = new Map<string, string>();
  private readonly goPatterns: Array<{ key: string; value: string; from: string }> = [];
  private readonly listed: Array<{ ecosystem: string | null; pattern: string; re: RegExp; rePypi: RegExp | null; reCrates: RegExp | null }> = [];
  /** Hosts an `.npmrc` names as its default `registry=`: a mirror of the public registry, so not private. */
  readonly npmMirrorHosts = new Set<string>();
  /**
   * pip's index from PIP_INDEX_URL or a pip config file, when it is not pypi.org: every package a
   * requirements file installs comes from it, so they are private, as for a lockfile's index.
   */
  readonly pipIndex: { url: string; from: string } | null = null;
  /** pip's extra indexes (PIP_EXTRA_INDEX_URL, config) that are not public: names are still read as public, and said. */
  readonly pipExtra: string[] = [];
  /** Every file the rules were read from (present or not), with its signature then. */
  private readonly inputs: Map<string, FileSignature>;
  private readonly envKey: string;

  constructor(
    private readonly dirs: string[],
    private readonly env: NodeJS.ProcessEnv = process.env,
  ) {
    const home = env.HOME || env.USERPROFILE || os.homedir();
    // Each directory and every one above it: npm applies a workspace root's `.npmrc` to every member,
    // and a server started in `packages/app` sent `@acme/vault-core` that `../../.npmrc` made private
    // (blind audit round 3, B2). Reading more files can only add private names.
    const withParents = [...new Set(dirs.flatMap((d) => ancestorsOf(path.resolve(d))))];
    const npmrcs = [
      ...withParents.map((d) => path.join(d, ".npmrc")),
      env.NPM_CONFIG_USERCONFIG || env.npm_config_userconfig || (home ? path.join(home, ".npmrc") : null),
    ].filter((f): f is string => Boolean(f));
    const yarnrcs = withParents.map((d) => path.resolve(d, ".yarnrc.yml"));
    const goFile = goEnvPath(env);
    const pipFiles = pipConfigFiles(env);
    // Signatures first: a write that lands while a file is read still reads as a change.
    this.inputs = signatureMap([...npmrcs.map((f) => path.resolve(f)), ...yarnrcs, ...(goFile ? [goFile] : []), ...pipFiles]);
    let pipIndex: { url: string; from: string } | null = null;
    const extra: string[] = [];
    for (const file of pipFiles) {
      const read = pipConfigIndexes(safeRead(file));
      if (read.index) pipIndex = { url: read.index, from: file };
      extra.push(...read.extra);
    }
    if (env.PIP_INDEX_URL?.trim()) pipIndex = { url: env.PIP_INDEX_URL.trim(), from: "PIP_INDEX_URL" };
    extra.push(...(env.PIP_EXTRA_INDEX_URL ?? "").split(/\s+/).filter(Boolean));
    this.pipIndex = pipIndex && !isPublicPypiIndex(pipIndex.url) ? { url: sourceLabel(pipIndex.url), from: pipIndex.from } : null;
    this.pipExtra = [...new Set(extra.filter((u) => !isPublicPypiIndex(u)).map(sourceLabel))];
    this.envKey = RULE_ENV.map((k) => `${k}=${env[k] ?? ""}`).join("\n");
    // A parent directory's file adds private scopes only: its default `registry=` (a public mirror,
    // which makes a lockfile host public) is taken from the project's own files and the user's.
    const ownNpmrcs = new Set([...dirs.map((d) => path.resolve(d, ".npmrc")), ...npmrcs.slice(withParents.length).map((f) => path.resolve(f))]);
    for (const file of new Set(npmrcs.map((f) => path.resolve(f)))) {
      const read = npmrcRead(safeRead(file));
      for (const scope of read.scopes) if (!this.npmScopes.has(scope)) this.npmScopes.set(scope, file);
      if (read.defaultHost && ownNpmrcs.has(file)) this.npmMirrorHosts.add(read.defaultHost);
    }
    for (const file of new Set(yarnrcs)) {
      for (const scope of yarnrcPrivateScopes(safeRead(file))) if (!this.npmScopes.has(scope)) this.npmScopes.set(scope, file);
    }
    const fromFile = goEnvFile(goFile);
    for (const key of ["GOPRIVATE", "GONOPROXY", "GONOSUMDB"]) {
      // As go does: an empty variable is unset, and the `go env -w` value applies.
      const fromEnv = env[key]?.trim() ? env[key] : undefined;
      const value = fromEnv ?? fromFile[key];
      if (value && value.trim()) this.goPatterns.push({ key, value, from: fromEnv !== undefined ? "the environment" : "go env" });
    }
    for (const raw of (env.FOURDA_PRIVATE_PACKAGES ?? "").split(/[,\s]+/)) {
      const entry = raw.trim();
      if (!entry) continue;
      const m = /^(npm|crates\.io|cargo|pypi|go):(.+)$/i.exec(entry);
      const ecosystem = m ? ECOSYSTEM_PREFIXES[m[1].toLowerCase()] : null;
      const pattern = m ? m[2] : entry;
      const re = listGlob(pattern);
      if (re) this.listed.push({ ecosystem, pattern, re, rePypi: listGlob(pattern, pep503), reCrates: listGlob(pattern, (s) => normName("crates.io", s)) });
    }
  }

  /** True when a file the rules came from, or the environment behind them, has changed since. */
  stale(env: NodeJS.ProcessEnv = this.env): boolean {
    return RULE_ENV.map((k) => `${k}=${env[k] ?? ""}`).join("\n") !== this.envKey || anySignatureChanged(this.inputs);
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
      [...this.npmMirrorHosts].sort(),
      this.pipIndex?.url ?? "",
      [...this.pipExtra].sort(),
    ]);
  }

  /** The same rules read again (after stale()). */
  reread(env: NodeJS.ProcessEnv = process.env): PrivatePackageRules {
    return new PrivatePackageRules(this.dirs, env);
  }

  /** Why this name is private, or null when nothing says it is. */
  reasonFor(ecosystem: string, name: string): string | null {
    for (const l of this.listed) {
      if (l.ecosystem !== null && l.ecosystem !== ecosystem) continue;
      const hit =
        ecosystem === "PyPI"
          ? Boolean(l.rePypi?.test(pep503(name)))
          : ecosystem === "crates.io"
            ? Boolean(l.reCrates?.test(normName("crates.io", name)))
            : l.re.test(name);
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
    return null;
  }

  /**
   * When an `.npmrc` sets a default `registry=` that is not a public one (Artifactory, Verdaccio,
   * GitHub Packages): that host is read as a mirror, so unscoped names are still looked up on the
   * public registry, and one published only there would be sent by name. Said once, in every
   * coverage note and dependency_check answer that concerns npm (review of #64, S5 decision).
   */
  /** The notice for pip extra indexes that are not public (configuration or requirements files), or null. */
  static pipExtraNotice(indexes: string[]): string | null {
    const unique = [...new Set(indexes)];
    if (unique.length === 0) return null;
    return `pip also installs from ${unique.join(", ")} (an extra index). Packages published only there are looked up on pypi.org by name; list them in FOURDA_PRIVATE_PACKAGES, or install them through --index-url, to keep them private.`;
  }

  npmRegistryNotice(): string | null {
    const hosts = [...this.npmMirrorHosts].filter((h) => !PUBLIC_NPM_HOSTS.has(h));
    if (hosts.length === 0) return null;
    return `Your npm registry is ${hosts.join(", ")}. Unscoped packages published only there are looked up on the public registry by name; list them in FOURDA_PRIVATE_PACKAGES (or use a scope) to keep them private.`;
  }

  /** Whether any rule exists (a project with none skips the per-name checks). */
  get empty(): boolean {
    return this.npmScopes.size === 0 && this.goPatterns.length === 0 && this.listed.length === 0;
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
  const out: PrivateIndexEntry[] = [];
  const take = (file: string, name: string, version: string | null, location: string) => {
    if (!/^https?:\/\//i.test(location)) return;
    const host = hostOf(location);
    if (!host || PUBLIC_NPM_HOSTS.has(host) || mirrorHosts.has(host) || CODE_HOSTS.test(host)) return;
    out.push({ name, version, registry: sourceLabel(location), file });
  };
  for (const lock of ["package-lock.json", "npm-shrinkwrap.json"]) {
    const file = path.join(dir, lock);
    const text = safeRead(file, LOCK_READ_CAP);
    if (!text) continue;
    try {
      const doc = JSON.parse(text) as { packages?: Record<string, { name?: string; version?: string; resolved?: string }>; dependencies?: Record<string, { version?: string; resolved?: string }> };
      for (const [key, entry] of Object.entries(doc.packages ?? {})) {
        const at = key.lastIndexOf("node_modules/");
        const name = entry.name ?? (at >= 0 ? key.slice(at + "node_modules/".length) : "");
        if (name && typeof entry.resolved === "string") take(file, name, entry.version ?? null, entry.resolved);
      }
      const walk = (deps: Record<string, { version?: string; resolved?: string; dependencies?: unknown }> | undefined) => {
        for (const [name, entry] of Object.entries(deps ?? {})) {
          if (typeof entry?.resolved === "string") take(file, name, entry.version ?? null, entry.resolved);
          walk(entry?.dependencies as typeof deps);
        }
      };
      if (!doc.packages) walk(doc.dependencies);
    } catch {
      // unreadable: the readers report it
    }
  }
  const yarn = path.join(dir, "yarn.lock");
  const yarnText = safeRead(yarn, LOCK_READ_CAP);
  for (const block of yarnText.split(/\r?\n(?=\S)/)) {
    const head = /^"?((?:@[^@/"\s]+\/)?[^@"\s,]+)@/.exec(block);
    const resolved = /^\s+resolved\s+"([^"]+)"/m.exec(block)?.[1];
    const version = /^\s+version\s+"([^"]+)"/m.exec(block)?.[1] ?? null;
    if (head && resolved) take(yarn, head[1], version, resolved);
  }
  const pnpm = path.join(dir, "pnpm-lock.yaml");
  const pnpmText = safeRead(pnpm, LOCK_READ_CAP);
  let current: { name: string; version: string | null } | null = null;
  for (const line of pnpmText.split(/\r?\n/)) {
    const key = /^ {2}['"]?\/?((?:@[^@/'"\s]+\/)?[^@/'"\s(]+)[@/]([^:('"\s]+)[^:]*['"]?:\s*$/.exec(line);
    if (key) {
      current = { name: key[1], version: key[2] };
      continue;
    }
    const tarball = /tarball:\s*['"]?([^'",}\s]+)/.exec(line)?.[1];
    if (tarball && current) take(pnpm, current.name, current.version, tarball);
  }
  return out;
}

/** Code hosts: an archive from one is a git or URL dependency, which the readers report as not checkable. */
const CODE_HOSTS = /^(?:github\.com|codeload\.github\.com|api\.github\.com|raw\.githubusercontent\.com|gitlab\.com|bitbucket\.org)$/i;
/** Lockfiles are bounded by the readers (bounded-read.ts); this pass reads at most this much. */
const LOCK_READ_CAP = 64 * 1024 * 1024;

function safeRead(file: string, cap = 1024 * 1024): string {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > cap) return "";
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

/** The sentence a private item or coverage line says. */
export function privateLine(count: number, names: string[]): string {
  const listed = `${names.slice(0, 5).join(", ")}${names.length > 5 ? ", ..." : ""}`;
  return `NOT CHECKED (private): ${count.toLocaleString("en-US")} dependenc${count === 1 ? "y is" : "ies are"} private (${listed}) and ${count === 1 ? "was" : "were"} never sent to OSV.dev or a registry, so nothing is known about ${count === 1 ? "its" : "their"} advisories: this is not a clean result for ${count === 1 ? "it" : "them"}. See coverage.private_dependency_list for why each is private.`;
}
