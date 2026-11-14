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
import { anySignatureChanged, signatureMap, type FileSignature } from "./file-signature.js";
import { pushAll } from "../array-utils.js";
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
  uvEnvIndexes,
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
}

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
}

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
    const pattern = raw.trim().replace(/\/+$/, "");
    if (!pattern) continue;
    const elements = pattern.toLowerCase().split("/");
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
const RULE_ENV = ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE", "FOURDA_PRIVATE_PACKAGES", "FOURDA_PUBLIC_MIRRORS", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOPROXY", "GOENV", "HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "VIRTUAL_ENV", "ProgramData", "PROGRAMDATA", "ALLUSERSPROFILE", "PREFIX", "CARGO_HOME", "UV_CONFIG_FILE", "UV_NO_CONFIG", "UV_DEFAULT_INDEX", "UV_INDEX_URL", "UV_INDEX", "UV_EXTRA_INDEX_URL"];
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
  private readonly listed: Array<{ ecosystem: string | null; pattern: string; re: RegExp; rePypi: RegExp | null; reCrates: RegExp | null }> = [];
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
   * UV_EXTRA_INDEX_URL, a Poetry source that is not `explicit`, a PDM source (R7, 2), a Pipfile
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
    this.inputs = signatureMap([...[...npmrcs, ...yarnrcs, ...bunfigs, ...uvFiles, ...pyprojects, ...pipfiles, ...cargoFiles].map((f) => f.file), ...(goFile ? [goFile] : []), ...pipFiles]);
    this.envKey = envKeyOf(env);

    // pip. Later files win in pip, but which one wins can depend on a file this server cannot see
    // the same way pip does: any index-url that is not public makes the requirements private.
    let pipIndex: PrivateSetting | null = null;
    const extra: PrivateSetting[] = [];
    const noteIndex = (url: string, from: string) => {
      if (!pipIndex || !isPublicPypiIndex(url)) pipIndex = { url, from };
    };
    for (const file of pipFiles) {
      const read = pipConfigIndexes(safeRead(file));
      if (read.index) noteIndex(read.index, file);
      pushAll(extra, read.extra.map((url) => ({ url, from: file })));
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
    for (const { file, scope } of uvFiles) pushAll(python, pythonIndexConfig(safeRead(file), "uv.toml").map((url) => ({ url, from: file, scope })));
    for (const { file, scope } of pyprojects) pushAll(python, pythonIndexConfig(safeRead(file), "pyproject").map((url) => ({ url, from: file, scope })));
    for (const { file, scope } of pipfiles) {
      const read = pipfilePrivate(safeRead(file));
      const index = read.indexes.find((url) => !isMirror(url));
      if (!index) continue;
      python.push({ url: index, from: file, scope });
      // Its packages are private wherever they are named: no lockfile or tree group may list them.
      for (const name of read.names) if (!this.pipfileNames.has(pep503(name))) this.pipfileNames.set(pep503(name), `${file} installs it from ${sourceLabel(index)} (a Pipfile source), not pypi.org`);
    }
    pushAll(this.pythonIndexes, python.filter((p) => !isMirror(p.url)).map((p) => ({ ...p, url: sourceLabel(p.url) })));

    // npm, yarn, bun.
    const npmDefaults: ScopedSetting[] = [];
    for (const { scope, from } of npmEnv.scopes) if (!this.npmScopes.has(scope)) this.npmScopes.set(scope, from);
    if (npmEnv.registry) npmDefaults.push({ ...npmEnv.registry, scope: null });
    const seen = new Set<string>();
    for (const { file, scope } of npmrcs) {
      if (seen.has(file)) continue;
      seen.add(file);
      const read = npmrcRead(safeRead(file));
      for (const s of read.scopes) if (!this.npmScopes.has(s)) this.npmScopes.set(s, file);
      if (read.defaultRegistry && !isPublicNpmRegistry(read.defaultRegistry)) npmDefaults.push({ url: read.defaultRegistry, from: file, scope });
    }
    for (const { file, scope } of yarnrcs) {
      if (seen.has(file)) continue;
      seen.add(file);
      const text = safeRead(file);
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
      const read = bunfigRegistries(safeRead(file));
      for (const s of read.scopes) if (!this.npmScopes.has(s)) this.npmScopes.set(s, file);
      if (read.registry && !isPublicNpmRegistry(read.registry)) npmDefaults.push({ url: read.registry, from: file, scope });
    }
    pushAll(this.npmDefaults, npmDefaults.filter((d) => hostOf(d.url) !== null && !isMirror(d.url)).map((d) => ({ ...d, url: sourceLabel(d.url) })));

    // Go.
    const fromFile = goEnvFile(goFile);
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
    pushAll(this.cargoConfigs, cargoFiles.map(({ file, scope }) => ({ file, scope, content: safeRead(file) })));
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
      const re = listGlob(pattern);
      if (re) this.listed.push({ ecosystem, pattern, re, rePypi: listGlob(pattern, pep503), reCrates: listGlob(pattern, (s) => normName("crates.io", s)) });
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
    ]);
  }

  /** The same rules read again (after stale()). */
  reread(env: NodeJS.ProcessEnv = process.env): PrivatePackageRules {
    return new PrivatePackageRules(this.dirs, env, this.memberDirs);
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
  ecosystemWide(ecosystem: string, dir: string | null, indexRecorded: boolean): string | null {
    const hint = "set FOURDA_PUBLIC_MIRRORS to its host if it only mirrors the public registry";
    const npm = ecosystem === "npm" ? this.npmRegistryFor(dir) : null;
    if (npm) return `npm installs it from ${npm.url} (${npm.from}), not the public registry; ${hint}`;
    if (ecosystem === "Go" && this.goProxy) return `go downloads it through ${this.goProxy.url} (${this.goProxy.from}), not the public proxy; ${hint}`;
    const cargo = ecosystem === "crates.io" ? this.cargoMirrorFor(dir) : null;
    if (cargo) return `cargo replaces crates.io with ${cargo.url} (${cargo.from}); ${hint}`;
    if (ecosystem === "PyPI" && !indexRecorded) {
      if (this.pipIndex) return `pip installs it from ${this.pipIndex.url} (${this.pipIndex.from}), not pypi.org`;
      if (this.pipExtraFrom) return `pip may install it from ${this.pipExtraFrom.url} (an extra index, ${this.pipExtraFrom.from}), not pypi.org`;
      const python = this.pythonIndexFor(dir);
      if (python) return `uv, Poetry, PDM or pipenv may install it from ${python.url} (${python.from}), not pypi.org; ${hint}`;
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
  const out: PrivateIndexEntry[] = [];
  const take = (file: string, name: string, version: string | null, location: string) => {
    if (!/^https?:\/\//i.test(location)) return;
    const host = hostOf(location);
    if (!host || isPublicNpmHost(host) || mirrorHosts.has(host) || CODE_HOSTS.test(host)) return;
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
    if (!head) continue;
    // yarn v1: `resolved "https://..."`; berry: `version: 1.0.0`.
    const version = /^\s+version:?\s+"?([^"\s]+)"?/m.exec(block)?.[1] ?? null;
    const resolved = /^\s+resolved\s+"([^"]+)"/m.exec(block)?.[1];
    if (resolved) take(yarn, head[1], version, resolved);
    // yarn berry: `resolution: "name@https://host/x.tgz"`, or a registry entry whose tarball came from
    // elsewhere (`name@npm:1.0.0::__archiveUrl=https%3A%2F%2Fhost%2F...`).
    const resolution = /^\s+resolution:\s+"?([^"\r\n]+?)"?\s*$/m.exec(block)?.[1];
    if (resolution) {
      const at = resolution.indexOf("@", resolution.startsWith("@") ? 1 : 0);
      const target = at > 0 ? resolution.slice(at + 1) : "";
      if (/^https?:\/\//i.test(target)) take(yarn, head[1], version, target);
      const archive = /__archiveUrl=([^&#\s]+)/.exec(target)?.[1];
      if (archive) {
        try {
          take(yarn, head[1], version, decodeURIComponent(archive));
        } catch {
          // a malformed escape names no host
        }
      }
    }
  }
  // bun.lock (JSONC): `packages` values are `["name@version", "<registry or tarball URL>", {...}, "sha"]`;
  // the URL is "" for the default registry (blind audit round 4: `@acme/ui` from a private one was sent).
  const bunFile = path.join(dir, "bun.lock");
  const bunText = safeRead(bunFile, LOCK_READ_CAP);
  if (bunText) {
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
      // unreadable: the readers report it
    }
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

/**
 * Cargo.toml: dependencies a manifest takes from somewhere other than crates.io: another registry
 * (`registry = "acme"`, `registry-index = "..."`) or git (`git = "https://..."`, as Cargo.lock
 * records every git source as private), in any dependency table (`[dependencies]`, dev, build,
 * `[target.<cfg>.dependencies]`, `[workspace.dependencies]`, the `[dependencies.<name>]` form) and
 * in `[patch.<source>]`. With no Cargo.lock the exact pin `omega-ledger = { version = "=1.2.0",
 * registry = "acme" }` was sent to OSV.dev and crates.io (blind audit round 4); a `git =` one too (R7, 4).
 * A `path =` dependency is local code, never a crates.io release: its name is private too (R8).
 */
export function cargoManifestPrivate(content: string): Array<{ name: string; registry: string }> {
  const out: Array<{ name: string; registry: string }> = [];
  const isDepTable = (name: string) => /(?:^|\.)(?:dev-|build-)?dependencies$/.test(name) || /^patch\.(?:[^.]+|.+:\/\/.+)$/.test(name);
  const fromElsewhere = (registry: string | null, git: string | null, local: string | null = null): string | null => {
    if (git) return git;
    if (local) return `the local path ${local}`;
    return registry && registry !== "crates-io" && !isPublicCratesSource(registry) ? registry : null;
  };
  let table = "";
  let single: { key: string; pkg: string | null; registry: string | null; git: string | null; local: string | null } | null = null;
  const flush = () => {
    const where = single ? fromElsewhere(single.registry, single.git, single.local) : null;
    if (single && where) out.push({ name: single.pkg ?? single.key, registry: where });
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
    const kv = tomlKeyValue(line);
    if (!kv) continue;
    if (single) {
      if (kv.key === "registry" || kv.key === "registry-index") single.registry = tomlString(kv.value);
      if (kv.key === "git") single.git = tomlString(kv.value);
      if (kv.key === "path") single.local = tomlString(kv.value);
      if (kv.key === "package") single.pkg = tomlString(kv.value);
      continue;
    }
    if (!isDepTable(table) || !kv.value.startsWith("{")) continue;
    const where = fromElsewhere(inlineKey(kv.value, "registry") ?? inlineKey(kv.value, "registry-index"), inlineKey(kv.value, "git"), inlineKey(kv.value, "path"));
    if (where) out.push({ name: inlineKey(kv.value, "package") ?? kv.key, registry: where });
  }
  flush();
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
export function pyprojectManifestPrivate(content: string): Array<{ name: string; registry: string }> {
  const indexes = new Map<string, string>();
  const wanted: Array<{ name: string; index: string; kind: "uv" | "poetry" }> = [];
  const direct: Array<{ name: string; registry: string }> = [];
  let table = "";
  let block: { kind: "uv" | "poetry"; name: string | null; url: string | null } | null = null;
  const endBlock = () => {
    if (block?.name) indexes.set(`${block.kind}\0${block.name}`, block.url ?? "");
    block = null;
  };
  const isPoetryDeps = (name: string) => /^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/.test(name);
  /** A `{ git = ..., url = ..., path = ... }` source: private unless its location is public. */
  const directSource = (name: string, table: string) => {
    const location = inlineKey(table, "git") ?? inlineKey(table, "url") ?? inlineKey(table, "path") ?? inlineKey(table, "file");
    if (!location) return;
    const local = inlineKey(table, "path") !== null || inlineKey(table, "file") !== null;
    if (local || privateDirectReference(location)) direct.push({ name, registry: local ? `the local path ${location}` : sourceLabel(location.replace(/^git\+/i, "")) });
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
      } else if (["git", "url", "path"].includes(kv.key)) directSource(name, `{ ${kv.key} = ${kv.value} }`);
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
  const read = (file: string, parse: (content: string) => Array<{ name: string; registry: string; local?: true }>): PrivateIndexEntry[] => {
    const text = safeRead(file);
    if (!text) return [];
    try {
      return parse(text).map((p) => ({ name: p.name, version: null, registry: p.registry, file, ...(p.local ? { local: true as const } : {}) }));
    } catch {
      return [];
    }
  };
  if (ecosystem === "crates.io") {
    const cargo = (text: string) =>
      cargoManifestPrivate(text).map((p) => ({
        name: p.name,
        ...(p.registry.startsWith("the local path ") ? { local: true as const } : {}),
        registry: p.registry.startsWith("the local path ") ? p.registry : /^[a-z+]*https?:\/\//i.test(p.registry) || /^(?:ssh|git):/i.test(p.registry) ? sourceLabel(p.registry) : `the "${p.registry}" registry`,
      }));
    // The workspace's own crates (the root package and every member) are local code too (R8).
    const ownName = (text: string) => {
      const name = cargoPackageName(text);
      return name ? [{ name, registry: "a local workspace crate (not a crates.io release)", local: true as const }] : [];
    };
    const root = path.join(dir, "Cargo.toml");
    let members: string[] = [];
    try {
      members = cargoWorkspaceManifests(dir, safeRead(root));
    } catch {
      members = [];
    }
    return [root, ...members].flatMap((file) => [...read(file, cargo), ...read(file, ownName)]);
  }
  if (ecosystem === "PyPI") return read(path.join(dir, "pyproject.toml"), pyprojectManifestPrivate);
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
