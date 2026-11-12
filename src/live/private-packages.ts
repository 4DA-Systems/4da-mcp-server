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

/** `@scope` -> the file that maps it to a private registry, from one `.npmrc`. */
export function npmrcPrivateScopes(content: string): string[] {
  const out: string[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const m = /^(@[^:\s=]+):registry\s*=\s*(.+)$/i.exec(line);
    if (m && !isPublicNpmRegistry(m[2])) out.push(m[1].toLowerCase());
  }
  return out;
}

/** Scopes a `.yarnrc.yml` maps to a registry server other than the public one (`npmScopes.<scope>.npmRegistryServer`). */
export function yarnrcPrivateScopes(content: string): string[] {
  const out: string[] = [];
  const lines = content.split(/\r?\n/);
  let inScopes = false;
  let scope: string | null = null;
  for (const raw of lines) {
    if (/^\S/.test(raw)) {
      inScopes = /^npmScopes\s*:/.test(raw);
      scope = null;
      continue;
    }
    if (!inScopes) continue;
    const scopeLine = /^ {2}["']?@?([^"':\s]+)["']?\s*:\s*$/.exec(raw);
    if (scopeLine) {
      scope = `@${scopeLine[1].toLowerCase()}`;
      continue;
    }
    const server = /^\s{4,}npmRegistryServer\s*:\s*(.+)$/.exec(raw);
    if (scope && server && !isPublicNpmRegistry(server[1])) out.push(scope);
  }
  return out;
}

/** KEY=VALUE pairs of a `go env -w` file. */
function goEnvFile(env: NodeJS.ProcessEnv): Record<string, string> {
  const file = env.GOENV && env.GOENV !== "off" ? env.GOENV : env.GOENV === "off" ? null : defaultGoEnvFile(env);
  if (!file) return {};
  try {
    const out: Record<string, string> = {};
    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
      if (m) out[m[1]] = m[2].trim();
    }
    return out;
  } catch {
    return {};
  }
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

/** A FOURDA_PRIVATE_PACKAGES entry: `*` matches anything, `/` included. */
function listGlob(pattern: string): RegExp | null {
  try {
    return new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\?]/g, "\\$&").replace(/\*/g, ".*")}$`, "i");
  } catch {
    return null;
  }
}

const ECOSYSTEM_PREFIXES: Record<string, string> = { npm: "npm", "crates.io": "crates.io", cargo: "crates.io", pypi: "PyPI", go: "Go" };

/** The rules for one project: what its files, the user's files and the environment say is private. */
export class PrivatePackageRules {
  private readonly npmScopes = new Map<string, string>();
  private readonly goPatterns: Array<{ key: string; value: string; from: string }> = [];
  private readonly listed: Array<{ ecosystem: string | null; pattern: string; re: RegExp }> = [];

  constructor(dirs: string[], env: NodeJS.ProcessEnv = process.env) {
    const home = env.HOME || env.USERPROFILE || os.homedir();
    const npmrcs = [
      ...dirs.map((d) => path.join(d, ".npmrc")),
      env.NPM_CONFIG_USERCONFIG || env.npm_config_userconfig || (home ? path.join(home, ".npmrc") : null),
    ].filter((f): f is string => Boolean(f));
    for (const file of new Set(npmrcs.map((f) => path.resolve(f)))) {
      for (const scope of npmrcPrivateScopes(safeRead(file))) if (!this.npmScopes.has(scope)) this.npmScopes.set(scope, file);
    }
    for (const file of new Set(dirs.map((d) => path.resolve(d, ".yarnrc.yml")))) {
      for (const scope of yarnrcPrivateScopes(safeRead(file))) if (!this.npmScopes.has(scope)) this.npmScopes.set(scope, file);
    }
    const goFile = goEnvFile(env);
    for (const key of ["GOPRIVATE", "GONOPROXY", "GONOSUMDB"]) {
      const fromEnv = env[key];
      const value = fromEnv !== undefined ? fromEnv : goFile[key];
      if (value && value.trim()) this.goPatterns.push({ key, value, from: fromEnv !== undefined ? "the environment" : "go env" });
    }
    for (const raw of (env.FOURDA_PRIVATE_PACKAGES ?? "").split(/[,\s]+/)) {
      const entry = raw.trim();
      if (!entry) continue;
      const m = /^(npm|crates\.io|cargo|pypi|go):(.+)$/i.exec(entry);
      const ecosystem = m ? ECOSYSTEM_PREFIXES[m[1].toLowerCase()] : null;
      const pattern = m ? m[2] : entry;
      const re = listGlob(pattern);
      if (re) this.listed.push({ ecosystem, pattern, re });
    }
  }

  /** Why this name is private, or null when nothing says it is. */
  reasonFor(ecosystem: string, name: string): string | null {
    for (const l of this.listed) {
      if ((l.ecosystem === null || l.ecosystem === ecosystem) && l.re.test(name)) return `FOURDA_PRIVATE_PACKAGES lists ${l.ecosystem ? `${l.ecosystem}:` : ""}${l.pattern}`;
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

  /** Whether any rule exists (a project with none skips the per-name checks). */
  get empty(): boolean {
    return this.npmScopes.size === 0 && this.goPatterns.length === 0 && this.listed.length === 0;
  }
}

function safeRead(file: string): string {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > 1024 * 1024) return "";
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
