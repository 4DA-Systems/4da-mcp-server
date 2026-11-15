// SPDX-License-Identifier: Apache-2.0
/**
 * Registry and index configuration the private-name rules read beyond the lockfiles
 * (private-packages.ts): what makes EVERY package of an ecosystem private for a project (a default
 * registry, index or proxy that is not public), and which single packages come from a private place
 * (a direct URL, a git or path source, a Cargo patch). Pre-publish audit of 5d709ff (R7): each layout
 * below sent a private name to OSV.dev, a public registry or HN.
 *
 * The policy is one for every ecosystem: a registry, index, proxy or mirror that is not public, and
 * that the package manager consults for any name, makes the project's packages of that ecosystem
 * private: never sent, reported as not checked. A server that only mirrors the public registry is
 * declared with FOURDA_PUBLIC_MIRRORS (hosts), and its packages are checked again.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { pushAll } from "../array-utils.js";
import {
  CODE_HOSTS,
  hostOf,
  inlineBool,
  inlineKey,
  isPublicCratesSource,
  isPublicExtraPypiIndex,
  isPublicGoProxy,
  isPublicNpmRegistry,
  isPublicPypiIndex,
  sourceLabel,
  tomlHeader,
  tomlKeyValue,
  tomlLines,
  tomlString,
  tomlStrings,
} from "./private-hosts.js";

/** A registry, index or proxy that is not public, and the file or variable that names it. */
export interface PrivateSetting {
  url: string;
  from: string;
}

/** A file read whole, or "" (missing, not a file, larger than `cap`). */
export function readSmall(file: string, cap = 1024 * 1024): string {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > cap) return "";
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

/** FOURDA_PUBLIC_MIRRORS: hosts (or URLs) the user declares mirror only the public registries. */
export function publicMirrorHosts(env: NodeJS.ProcessEnv): Set<string> {
  const out = new Set<string>();
  for (const raw of (env.FOURDA_PUBLIC_MIRRORS ?? "").split(/[,\s]+/)) {
    const entry = raw.trim();
    if (!entry) continue;
    const host = /:\/\//.test(entry) ? hostOf(entry) : entry.toLowerCase().replace(/[:/].*$/, "");
    if (host) out.add(host);
  }
  return out;
}

/** Whether `url` is on a host FOURDA_PUBLIC_MIRRORS declares a public mirror. */
export const declaredMirror = (url: string, mirrors: ReadonlySet<string>): boolean => {
  const host = hostOf(url);
  return host !== null && mirrors.has(host);
};

/** Environment variables whose names match, any case (npm and yarn read theirs case-insensitively). */
function envMatching(env: NodeJS.ProcessEnv, re: RegExp): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const [key, value] of Object.entries(env)) if (value !== undefined && re.test(key)) out.push([key, value]);
  return out;
}

// ---------------------------------------------------------------------------------------------
// npm and yarn
// ---------------------------------------------------------------------------------------------

/**
 * npm's settings from the environment, as npm reads them: `npm_config_<key>` in any case, `_` in a
 * key read as `-`. `npm_config_@acme:registry=https://npm.acme.dev/` maps the scope (R7, 5).
 */
export function npmEnvConfig(env: NodeJS.ProcessEnv): {
  userconfig: string | null;
  globalconfig: string | null;
  prefix: string | null;
  registry: PrivateSetting | null;
  scopes: Array<{ scope: string; from: string }>;
} {
  let userconfig: string | null = null;
  let globalconfig: string | null = null;
  let prefix: string | null = null;
  let registry: PrivateSetting | null = null;
  const scopes: Array<{ scope: string; from: string }> = [];
  for (const [key, value] of envMatching(env, /^npm_config_/i)) {
    const raw = key.slice("npm_config_".length);
    const name = raw.toLowerCase();
    const dashed = name.replace(/(?!^)_/g, "-");
    if (!value.trim()) continue;
    if (dashed === "userconfig") userconfig = value.trim();
    else if (dashed === "globalconfig") globalconfig = value.trim();
    else if (dashed === "prefix") prefix = value.trim();
    else if (dashed === "registry") {
      if (!isPublicNpmRegistry(value)) registry = { url: value.trim(), from: key };
    } else {
      const m = /^(@[^:]+):registry$/.exec(name);
      if (m && !isPublicNpmRegistry(value)) {
        for (const scope of new Set([m[1], m[1].replace(/_/g, "-")])) scopes.push({ scope, from: key });
      }
    }
  }
  if (!prefix && env.PREFIX?.trim()) prefix = env.PREFIX.trim();
  return { userconfig, globalconfig, prefix, registry, scopes };
}

/**
 * npm's global configuration file: `npm_config_globalconfig`, else `<prefix>/etc/npmrc`, the prefix
 * being `npm_config_prefix` / PREFIX, else every default npm uses on this platform (Windows: the
 * `%APPDATA%\npm` an installed npm sets, and node's own directory; elsewhere node's parent).
 */
export function npmGlobalConfigFiles(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform, execPath = process.execPath): string[] {
  const conf = npmEnvConfig(env);
  if (conf.globalconfig) return [conf.globalconfig];
  const p = platform === "win32" ? path.win32 : path.posix;
  if (conf.prefix) return [p.join(conf.prefix, "etc", "npmrc")];
  const prefixes = platform === "win32" ? [...(env.APPDATA ? [p.join(env.APPDATA, "npm")] : []), p.dirname(execPath)] : [p.dirname(p.dirname(execPath))];
  return [...new Set(prefixes.map((prefix) => p.join(prefix, "etc", "npmrc")))];
}

/** The rc file name yarn reads (`YARN_RC_FILENAME`, default `.yarnrc.yml`). */
export function yarnRcFilename(env: NodeJS.ProcessEnv): string {
  const set = envMatching(env, /^yarn_rc_filename$/i)[0]?.[1]?.trim();
  return set && !/[\\/]/.test(set) ? set : ".yarnrc.yml";
}

/** A `.yarnrc.yml`'s top-level `npmRegistryServer` (yarn's default registry), or null. */
export function yarnrcRegistry(content: string): string | null {
  for (const raw of content.split(/\r?\n/)) {
    const m = /^npmRegistryServer\s*:\s*(.+?)\s*(?:#.*)?$/.exec(raw);
    if (m) return m[1].replace(/^["']|["']$/g, "");
  }
  return null;
}

/** yarn's settings from the environment: `YARN_NPM_REGISTRY_SERVER`, and `YARN_NPM_SCOPES` as YAML flow or JSON. */
export function yarnEnvConfig(env: NodeJS.ProcessEnv, parseFlowMap: (text: string) => unknown): { registry: PrivateSetting | null; scopes: Array<{ scope: string; from: string }> } {
  let registry: PrivateSetting | null = null;
  const scopes: Array<{ scope: string; from: string }> = [];
  for (const [key, value] of envMatching(env, /^yarn_npm_registry_server$/i)) {
    if (value.trim() && !isPublicNpmRegistry(value)) registry = { url: value.trim(), from: key };
  }
  for (const [key, value] of envMatching(env, /^yarn_npm_scopes$/i)) {
    const parsed = parseFlowMap(value.trim()) as Record<string, unknown> | null;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue;
    for (const [scope, conf] of Object.entries(parsed)) {
      const server = conf && typeof conf === "object" ? (conf as Record<string, unknown>).npmRegistryServer : undefined;
      if (typeof server === "string" && server && !isPublicNpmRegistry(server)) scopes.push({ scope: `@${scope.replace(/^@/, "").toLowerCase()}`, from: key });
    }
  }
  return { registry, scopes };
}

// ---------------------------------------------------------------------------------------------
// pip's options
// ---------------------------------------------------------------------------------------------

/**
 * The long options pip reads in a requirements file (pip/_internal/req/req_file.py: SUPPORTED_OPTIONS
 * and SUPPORTED_OPTIONS_REQ). optparse accepts any unambiguous prefix of one: `--index` is
 * `--index-url`, `--extra-index` is `--extra-index-url`, `--find` is `--find-links`. Only the full
 * spellings were read, and `--index https://pypi.acme.dev/simple` sent every pin to OSV.dev (R8, B4).
 */
const PIP_LONG_OPTIONS = [
  "index-url", "extra-index-url", "no-index", "constraint", "requirement", "editable", "find-links",
  "no-binary", "only-binary", "prefer-binary", "require-hashes", "pre", "trusted-host", "use-feature",
  "global-option", "config-settings", "hash",
];
/** Long options whose value is the next token when not given with `=`. */
const PIP_VALUE_OPTIONS = new Set(["index-url", "extra-index-url", "constraint", "requirement", "editable", "find-links", "no-binary", "only-binary", "trusted-host", "use-feature", "global-option", "config-settings", "hash"]);
/** Short options and the long option each is. */
const PIP_SHORT_OPTIONS: Record<string, string> = { i: "index-url", f: "find-links", r: "requirement", c: "constraint", e: "editable" };

/** The pip long option `name` names (exactly, or as optparse's unambiguous prefix), or null. */
export function resolvePipOption(name: string): string | null {
  const key = name.toLowerCase().replaceAll("_", "-");
  if (!key) return null;
  if (PIP_LONG_OPTIONS.includes(key)) return key;
  const hits = PIP_LONG_OPTIONS.filter((o) => o.startsWith(key));
  return hits.length === 1 ? hits[0] : null;
}

/**
 * The options on one logical requirements line, as pip's optparse reads them: `--name value`,
 * `--name=value`, an unambiguous prefix of a long option, `-x value` and the attached `-xvalue`
 * (`-ihttps://...`, `-f./wheels`, `-rbase.txt`). Quotes around a value are dropped.
 */
export function pipLineOptions(line: string): Array<{ option: string; value: string | null }> {
  const tokens = line.replace(/(^|\s)#.*$/, "").trim().split(/\s+/).filter(Boolean);
  const out: Array<{ option: string; value: string | null }> = [];
  const clean = (v: string | undefined) => (v === undefined ? null : v.replace(/^["']|["']$/g, "") || null);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith("--")) {
      const eq = t.indexOf("=");
      const option = resolvePipOption(eq >= 0 ? t.slice(2, eq) : t.slice(2));
      if (!option) continue;
      if (!PIP_VALUE_OPTIONS.has(option)) out.push({ option, value: null });
      else out.push({ option, value: clean(eq >= 0 ? t.slice(eq + 1) : tokens[++i]) });
    } else if (/^-[A-Za-z]/.test(t)) {
      const option = PIP_SHORT_OPTIONS[t[1]];
      if (!option) continue;
      const attached = t.slice(2).replace(/^=/, "");
      out.push({ option, value: clean(attached || tokens[++i]) });
    }
  }
  return out;
}

/**
 * Whether a `--find-links` location is public: pypi.org's files or a well-known public wheel index.
 * A local directory or any other host serves packages pip may take instead of pypi.org's, so it is
 * judged like a private extra index (R8, B4).
 */
export const isPublicFindLinks = (location: string): boolean => /^https?:\/\//i.test(location.trim()) && isPublicExtraPypiIndex(location.trim());

/**
 * pip's index settings from the environment: `PIP_<OPTION>` for index-url, extra-index-url and
 * find-links, any case, the option named as pip spells it or by an unambiguous prefix
 * (PIP_INDEX_URL, PIP_INDEX, PIP_EXTRA_INDEX, PIP_FIND_LINKS). Values are whitespace-separated lists.
 */
export function pipEnvIndexes(env: NodeJS.ProcessEnv): { index: PrivateSetting[]; extra: PrivateSetting[] } {
  const index: PrivateSetting[] = [];
  const extra: PrivateSetting[] = [];
  for (const [key, value] of envMatching(env, /^pip_/i)) {
    const option = resolvePipOption(key.slice(4));
    const values = value.split(/\s+/).filter(Boolean);
    if (option === "index-url" && values[0]) index.push({ url: values[0], from: key });
    else if (option === "extra-index-url") pushAll(extra, values.map((url) => ({ url, from: key })));
    else if (option === "find-links") pushAll(extra, values.filter((v) => !isPublicFindLinks(v)).map((v) => ({ url: findLinksLabel(v), from: key })));
  }
  return { index, extra };
}

/** A find-links location as an index URL: a URL as it is, a local directory as `file:` (never public). */
export const findLinksLabel = (location: string): string => (/^[a-z][a-z0-9+.-]*:\/\//i.test(location.trim()) ? location.trim() : `file:///${location.trim().replace(/\\/g, "/").replace(/^\/+/, "")}`);

// ---------------------------------------------------------------------------------------------
// Pipfile (pipenv)
// ---------------------------------------------------------------------------------------------

/**
 * A Pipfile's `[[source]]` indexes that are not public, and the packages it declares. pipenv resolves
 * every package against its sources (the first is the default), so a source that is not public makes
 * each package the Pipfile declares private, except one pinned to a public source by `index = "..."`.
 * A Pipfile with a private source and no Pipfile.lock sent its packages to OSV.dev and pypi.org (R8, B4).
 */
export function pipfilePrivate(content: string): { indexes: string[]; names: string[] } {
  const sources: Array<{ name: string | null; url: string | null }> = [];
  const declared: Array<{ name: string; index: string | null }> = [];
  let table = "";
  let block: { name: string | null; url: string | null } | null = null;
  for (const line of tomlLines(content)) {
    const header = tomlHeader(line);
    if (header) {
      if (block) sources.push(block);
      block = header.array && header.name === "source" ? { name: null, url: null } : null;
      table = header.name;
      continue;
    }
    const kv = tomlKeyValue(line);
    if (!kv) continue;
    if (block) {
      if (kv.key === "name") block.name = tomlString(kv.value);
      if (kv.key === "url") block.url = tomlString(kv.value);
      continue;
    }
    // [packages], [dev-packages] and pipenv's other package categories.
    if (table !== "requires" && table !== "pipenv" && table !== "scripts" && table !== "source") {
      declared.push({ name: kv.key, index: kv.value.startsWith("{") ? inlineKey(kv.value, "index") : null });
    }
  }
  if (block) sources.push(block);
  const indexes = sources.filter((s, i) => s.url && !(i === 0 ? isPublicPypiIndex(s.url) : isPublicExtraPypiIndex(s.url))).map((s) => s.url as string);
  if (indexes.length === 0) return { indexes, names: [] };
  const publicSource = new Set(sources.filter((s) => s.name && s.url && isPublicPypiIndex(s.url)).map((s) => s.name as string));
  return { indexes, names: declared.filter((d) => !(d.index && publicSource.has(d.index))).map((d) => d.name) };
}

// ---------------------------------------------------------------------------------------------
// Python: uv, Poetry, PDM
// ---------------------------------------------------------------------------------------------

/**
 * uv's user- and system-level configuration files, every one any uv on any platform reads, plus
 * UV_CONFIG_FILE. UV_NO_CONFIG (uv's own switch) skips the discovered ones.
 */
export function uvConfigFiles(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): string[] {
  const files: string[] = [];
  if (env.UV_CONFIG_FILE?.trim()) files.push(env.UV_CONFIG_FILE.trim());
  if (env.UV_NO_CONFIG && env.UV_NO_CONFIG !== "0" && env.UV_NO_CONFIG.toLowerCase() !== "false") return files;
  const win = platform === "win32";
  const p = win ? path.win32 : path.posix;
  const home = (win ? env.USERPROFILE || env.HOME : env.HOME || env.USERPROFILE) || os.homedir();
  if (env.XDG_CONFIG_HOME) files.push(p.join(env.XDG_CONFIG_HOME, "uv", "uv.toml"));
  if (home) files.push(p.join(home, ".config", "uv", "uv.toml"));
  if (win && env.APPDATA) files.push(p.join(env.APPDATA, "uv", "uv.toml"));
  for (const dir of (env.XDG_CONFIG_DIRS || (win ? "" : "/etc/xdg")).split(win ? ";" : ":").filter(Boolean)) files.push(p.join(dir, "uv", "uv.toml"));
  if (!win) files.push("/etc/uv/uv.toml");
  if (win) files.push(p.join(env.ProgramData || env.PROGRAMDATA || env.ALLUSERSPROFILE || "C:\\ProgramData", "uv", "uv.toml"));
  return [...new Set(files)];
}

/** Every index a uv setting lists: `UV_INDEX="acme=https://x https://y"`. */
const uvIndexList = (value: string): string[] =>
  value
    .split(/\s+/)
    .filter(Boolean)
    .map((entry) => entry.replace(/^[A-Za-z0-9_.-]+=(?=[a-z][a-z0-9+.-]*:)/i, ""));

/**
 * Every index uv, Poetry or PDM would consult for ANY name that is not public: a default or
 * replacing index that is not pypi.org, or an added one that is neither pypi.org nor a public wheel
 * index. An index or source marked `explicit` serves only the packages pinned to it
 * (pyprojectManifestPrivate reads those). `prefix` is `tool.uv.` in pyproject.toml, `` in uv.toml.
 */
export function pythonIndexConfig(content: string, kind: "pyproject" | "uv.toml" | "Pipfile"): string[] {
  if (kind === "Pipfile") return pipfilePrivate(content).indexes;
  const uv = kind === "pyproject" ? "tool.uv" : "";
  const at = (name: string) => (uv ? (name ? `${uv}.${name}` : uv) : name);
  let table = "";
  let block: { kind: "uv" | "poetry" | "pdm"; url: string | null; explicit: boolean; isDefault: boolean } | null = null;
  const found: string[] = [];
  const judge = (url: string, replaces: boolean) => {
    if (replaces ? !isPublicPypiIndex(url) : !isPublicExtraPypiIndex(url)) found.push(url);
  };
  const endBlock = () => {
    if (block?.url && !block.explicit) judge(block.url, block.isDefault);
    block = null;
  };
  for (const line of tomlLines(content)) {
    const header = tomlHeader(line);
    if (header) {
      endBlock();
      table = header.name;
      if (header.array && table === at("index")) block = { kind: "uv", url: null, explicit: false, isDefault: false };
      if (kind === "pyproject" && header.array && table === "tool.poetry.source") block = { kind: "poetry", url: null, explicit: false, isDefault: true };
      if (kind === "pyproject" && header.array && table === "tool.pdm.source") block = { kind: "pdm", url: null, explicit: false, isDefault: true };
      continue;
    }
    const kv = tomlKeyValue(line);
    if (!kv) continue;
    if (block) {
      const key = kv.key.toLowerCase();
      if (key === "url") block.url = tomlString(kv.value);
      if (block.kind === "uv" && key === "explicit") block.explicit = kv.value.startsWith("true");
      if (block.kind === "uv" && key === "default") block.isDefault = kv.value.startsWith("true");
      // Poetry: `priority = "explicit"` serves pinned packages only; primary, default, supplemental,
      // secondary (and the legacy `default = true` / `secondary = true`) are consulted for any name.
      if (block.kind === "poetry" && key === "priority") block.explicit = tomlString(kv.value) === "explicit";
      // A supplemental or secondary source is added beside pypi.org: the public wheel indexes are allowed there.
      if (block.kind === "poetry" && (key === "priority" ? /^(?:supplemental|secondary)$/.test(tomlString(kv.value) ?? "") : key === "secondary" && kv.value.startsWith("true"))) block.isDefault = false;
      continue;
    }
    // [tool.uv] / uv.toml top level, and their `pip` table: index-url replaces, extra-index-url adds.
    if (table === at("") || table === at("pip")) {
      const key = kv.key.toLowerCase();
      if (key === "index-url") for (const url of tomlStrings(kv.value)) judge(url, true);
      if (key === "extra-index-url") for (const url of tomlStrings(kv.value)) judge(url, false);
      // `index = [{ url = "...", default = true }]` written inline.
      if (key === "index") {
        for (const m of kv.value.matchAll(/\{[^{}]*\}/g)) {
          const url = inlineKey(m[0], "url");
          if (url && !inlineBool(m[0], "explicit")) judge(url, Boolean(inlineBool(m[0], "default")));
        }
      }
    }
  }
  endBlock();
  return found;
}

/** uv's index variables that are not public: UV_DEFAULT_INDEX and UV_INDEX_URL replace pypi.org, UV_INDEX and UV_EXTRA_INDEX_URL add indexes. */
export function uvEnvIndexes(env: NodeJS.ProcessEnv): PrivateSetting[] {
  const out: PrivateSetting[] = [];
  for (const key of ["UV_DEFAULT_INDEX", "UV_INDEX_URL"]) {
    const url = env[key]?.trim();
    if (url && !isPublicPypiIndex(url)) out.push({ url, from: key });
  }
  for (const key of ["UV_INDEX", "UV_EXTRA_INDEX_URL"]) {
    for (const url of uvIndexList(env[key] ?? "")) if (!isPublicExtraPypiIndex(url)) out.push({ url, from: key });
  }
  return out;
}

/** A direct reference's location is public: pypi.org, a public wheel index, or a public code host. */
function publicLocation(location: string): boolean {
  const url = location.replace(/^git\+/i, "");
  if (/^file:/i.test(url)) return false;
  const host = hostOf(url) ?? /^(?:[\w.-]+@)?([^/:\s]+):/.exec(url)?.[1]?.toLowerCase() ?? null;
  if (!host) return false;
  return isPublicExtraPypiIndex(`https://${host}/`) || CODE_HOSTS.test(host);
}

/**
 * A PEP 508 direct reference or a URL requirement whose location is not public (R7, 3):
 * `name @ https://pkgs.acme.dev/x.whl`, `name @ git+https://git.acme.dev/x`, `name @ file:///...`.
 * The name is installed from there, never from pypi.org: sending it reveals the private package.
 */
export function privateDirectReference(location: string): boolean {
  return !publicLocation(location.trim());
}

/** `name @ location` in any string of a pyproject.toml (PEP 621 dependencies, optional ones, groups). */
export function pep508DirectReferences(content: string): Array<{ name: string; location: string }> {
  const out: Array<{ name: string; location: string }> = [];
  for (const s of tomlStrings(content)) {
    const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@\s*((?:git\+)?[a-z][a-z0-9+.-]*:\S+)/i.exec(s);
    if (m) out.push({ name: m[1], location: m[2] });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------------------------

/** GOPROXY's first proxy that is not public (`https://athens.acme.dev,direct`), or null. */
export function goProxyPrivate(value: string | undefined, mirrors: ReadonlySet<string>): string | null {
  for (const entry of (value ?? "").split(/[,|]/)) {
    const url = entry.trim();
    if (!url || url === "direct" || url === "off") continue;
    if (!isPublicGoProxy(url) && !declaredMirror(url, mirrors)) return url;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// Cargo
// ---------------------------------------------------------------------------------------------

/** A Cargo glob element (`*`, `?`) against a directory name. */
const globElement = (pattern: string, name: string) => new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`).test(name);

/** Directories under `root` a workspace `members` glob names (`crates/*`, `tools/cli`, `**` at most 4 deep). */
function expandMemberGlob(root: string, pattern: string): string[] {
  let current = [root];
  const parts = pattern.replace(/\\/g, "/").split("/").filter((p) => p && p !== ".");
  for (const part of parts) {
    const next: string[] = [];
    for (const dir of current) {
      if (part === "..") continue;
      if (part === "**") {
        const walk = (d: string, depth: number) => {
          next.push(d);
          if (depth >= 4) return;
          for (const e of listDirs(d)) walk(path.join(d, e), depth + 1);
        };
        walk(dir, 0);
      } else if (/[*?]/.test(part)) {
        for (const e of listDirs(dir)) if (globElement(part, e)) next.push(path.join(dir, e));
      } else next.push(path.join(dir, part));
    }
    current = next.slice(0, 2000);
  }
  return current;
}

function listDirs(dir: string): string[] {
  try {
    return fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !e.name.startsWith(".") && e.name !== "target" && e.name !== "node_modules")
      .map((e) => e.name);
  } catch {
    return [];
  }
}

/** The member manifests a workspace root Cargo.toml lists (`[workspace] members`, minus `exclude`). */
export function cargoWorkspaceManifests(dir: string, rootContent: string): string[] {
  let table = "";
  const members: string[] = [];
  const exclude: string[] = [];
  for (const line of tomlLines(rootContent)) {
    const header = tomlHeader(line);
    if (header) {
      table = header.name;
      continue;
    }
    const kv = tomlKeyValue(line);
    if (!kv || table !== "workspace") continue;
    if (kv.key === "members") pushAll(members, tomlStrings(kv.value));
    if (kv.key === "exclude") pushAll(exclude, tomlStrings(kv.value));
  }
  const root = path.resolve(dir);
  const excluded = (d: string) => {
    const rel = path.relative(root, d).replace(/\\/g, "/");
    return exclude.some((e) => {
      const ex = e.replace(/\\/g, "/").replace(/\/+$/, "");
      return rel === ex || rel.startsWith(`${ex}/`) || (/[*?]/.test(ex) && rel.split("/").length === ex.split("/").length && rel.split("/").every((seg, i) => globElement(ex.split("/")[i], seg)));
    });
  };
  const out: string[] = [];
  for (const pattern of members) {
    for (const d of expandMemberGlob(root, pattern)) {
      const rel = path.relative(root, d);
      if (rel.startsWith("..") || path.isAbsolute(rel) || excluded(d)) continue;
      const manifest = path.join(d, "Cargo.toml");
      if (manifest !== path.join(root, "Cargo.toml") && fs.existsSync(manifest)) out.push(manifest);
    }
  }
  return [...new Set(out)].slice(0, 500);
}

/** Cargo's configuration files for a directory: `.cargo/config.toml` (and `config`) there and above, then CARGO_HOME's. */
export function cargoConfigFiles(dirs: string[], env: NodeJS.ProcessEnv, ancestorsOf: (dir: string) => string[]): string[] {
  const home = env.HOME || env.USERPROFILE || os.homedir();
  const cargoHome = env.CARGO_HOME?.trim() || (home ? path.join(home, ".cargo") : null);
  const files: string[] = [];
  for (const dir of new Set(dirs.flatMap((d) => ancestorsOf(path.resolve(d))))) files.push(path.join(dir, ".cargo", "config.toml"), path.join(dir, ".cargo", "config"));
  if (cargoHome) files.push(path.join(cargoHome, "config.toml"), path.join(cargoHome, "config"));
  return [...new Set(files.map((f) => path.resolve(f)))];
}

/**
 * What Cargo configuration files say, together: the registry crates.io is replaced by
 * (`[source.crates-io] replace-with = "acme"`, `[source.acme] registry = "https://..."` or a
 * `[registries.acme] index`) when it is not crates.io, and the crates a `[patch.*]` table takes
 * from git or another registry. A vendored directory or local registry is a copy of crates.io.
 */
export function cargoConfigPrivate(files: Array<{ file: string; content: string }>): { mirror: PrivateSetting | null; patched: Array<{ name: string; registry: string; file: string }> } {
  const sources = new Map<string, { registry: string | null; replaceWith: string | null; file: string }>();
  const registries = new Map<string, string>();
  const patched: Array<{ name: string; registry: string; file: string }> = [];
  for (const { file, content } of files) {
    let table = "";
    let single: { name: string; git: string | null; registry: string | null } | null = null;
    const flush = () => {
      if (single?.git || (single?.registry && single.registry !== "crates-io")) patched.push({ name: single.name, registry: single.git ? sourceLabel(single.git) : `the "${single.registry}" registry`, file });
      single = null;
    };
    for (const line of tomlLines(content)) {
      const header = tomlHeader(line);
      if (header) {
        flush();
        table = header.name;
        const sub = /^patch\.(?:[^.]+|.+:\/\/.+)\.([^.]+)$/.exec(table);
        if (sub) single = { name: sub[1], git: null, registry: null };
        continue;
      }
      const kv = tomlKeyValue(line);
      if (!kv) continue;
      if (single) {
        if (kv.key === "git") single.git = tomlString(kv.value);
        if (kv.key === "registry" || kv.key === "registry-index") single.registry = tomlString(kv.value);
        continue;
      }
      const source = /^source\.(.+)$/.exec(table)?.[1];
      if (source) {
        const entry = sources.get(source) ?? { registry: null, replaceWith: null, file };
        if (kv.key === "registry") entry.registry = tomlString(kv.value);
        if (kv.key === "replace-with") entry.replaceWith = tomlString(kv.value);
        if (!sources.has(source)) sources.set(source, entry);
        continue;
      }
      const reg = /^registries\.(.+)$/.exec(table)?.[1];
      if (reg && kv.key === "index") {
        const url = tomlString(kv.value);
        if (url && !registries.has(reg)) registries.set(reg, url);
        continue;
      }
      if (table === "registries" && kv.value.startsWith("{")) {
        const url = inlineKey(kv.value, "index");
        if (url && !registries.has(kv.key)) registries.set(kv.key, url);
        continue;
      }
      if (table === "source" && kv.value.startsWith("{")) {
        const entry = { registry: inlineKey(kv.value, "registry"), replaceWith: inlineKey(kv.value, "replace-with"), file };
        if (!sources.has(kv.key)) sources.set(kv.key, entry);
        continue;
      }
      if (/^patch\.(?:[^.]+|.+:\/\/.+)$/.test(table) && kv.value.startsWith("{")) {
        const git = inlineKey(kv.value, "git");
        const registry = inlineKey(kv.value, "registry") ?? inlineKey(kv.value, "registry-index");
        if (git || (registry && registry !== "crates-io")) patched.push({ name: inlineKey(kv.value, "package") ?? kv.key, registry: git ? sourceLabel(git) : `the "${registry}" registry`, file });
      }
    }
    flush();
  }
  let mirror: PrivateSetting | null = null;
  const replaced = sources.get("crates-io");
  let target = replaced?.replaceWith ?? null;
  for (let hop = 0; target && hop < 8 && !mirror; hop++) {
    const src = sources.get(target);
    const url = src?.registry ?? registries.get(target) ?? null;
    if (url) {
      const full = /^[a-z]+\+/i.test(url) ? url : `registry+${url}`;
      if (!isPublicCratesSource(full) && !isPublicCratesSource(url) && !/index\.crates\.io|github\.com\/rust-lang\/crates\.io-index/i.test(url)) mirror = { url: sourceLabel(url), from: replaced?.file ?? "Cargo configuration" };
      break;
    }
    if (!src) break;
    // A vendored directory or local registry: crates.io's own crates, copied.
    target = src.replaceWith;
  }
  return { mirror, patched };
}
