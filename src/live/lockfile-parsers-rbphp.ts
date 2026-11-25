// SPDX-License-Identifier: Apache-2.0
/**
 * Ruby (Gemfile.lock -> RubyGems) and PHP (composer.lock -> Packagist).
 *
 * Until 6.2.5 neither was read: a Rails or Symfony project came back "No
 * manifest files found... run from your project root", which reads as the
 * user's mistake rather than an ecosystem this server did not cover (audit
 * A2, 2026-10-12). Both readers mirror the desktop app's
 * (src-tauri/src/ace/lockfile/ruby.rs; ProjectScanner::parse_composer_lock),
 * and the conformance corpus scores them against the same truth
 * (rb-js-rails-6.0, php-js-symfony-demo).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { emptySource, found, InstanceSet, partialRead, unreadableReason, type LockfileProblem, type VersionSource } from "./lockfile-types.js";
import { sourceLabel, type PrivateIndexEntry } from "./private-packages.js";
import { readTextFile } from "./text-file.js";

/** The public RubyGems hosts a `GEM` section's `remote:` may name. */
const PUBLIC_GEM_HOSTS = new Set(["rubygems.org", "index.rubygems.org", "gems.rubygems.org", "api.rubygems.org"]);
/** Where public Packagist packages are served from: Packagist itself and the public code hosts its dists point at. */
const PUBLIC_COMPOSER_HOSTS = new Set(["repo.packagist.org", "packagist.org", "api.github.com", "github.com", "codeload.github.com", "gitlab.com", "bitbucket.org", "api.bitbucket.org"]);

const hostOf = (url: unknown): string | null => {
  if (typeof url !== "string") return null;
  try {
    return new URL(url).hostname.toLowerCase().replace(/\.+$/, "");
  } catch {
    return null;
  }
};

/** Lines longer than this are not lockfile syntax; skipping them keeps every pattern below linear. */
const MAX_LINE = 4096;

/**
 * Gemfile.lock: the `specs:` of each `GEM` section (registry gems). A GIT section's gems are git
 * checkouts, not RubyGems releases: never sent, listed as not checkable (`uncheckable`). A PATH
 * section's are local code (the project's own gemspec, a vendored engine): neither. A platform
 * suffix (`nokogiri (1.10.4-x86_64-linux)`) is not part of the version: RubyGems prereleases use
 * `.pre`, never `-`.
 *
 * Also what the file names: every gem it holds a spec for in any section (`specs`), and the gems
 * those specs depend on that have no spec of their own (`dangling`): Bundler writes a spec for
 * every gem a spec depends on, `bundler` itself excepted, so one missing is a damaged file.
 */
export function readGemfileLock(content: string): {
  instances: InstanceSet;
  versions: Map<string, string>;
  direct: string[];
  /**
   * Gems from a `GEM` section any of whose `remote:` lines is not rubygems.org: private (review of
   * #64, X2). Which remote of a section served which gem is not recorded, so a section with a
   * private remote is private as a whole, whatever order its remotes are in (audit 2026-11-25, F3).
   */
  privateIndex: Array<{ name: string; version: string; registry: string }>;
  /** GIT gems: not registry releases (F5). */
  uncheckable: Array<{ name: string; version: string; kind: "git" }>;
  /** Every gem name the file holds a spec for, in any section, lower-cased. */
  specs: Set<string>;
  /** Gems a spec depends on that have no spec anywhere in the file (F4). */
  dangling: string[];
} {
  const instances = new InstanceSet();
  const versions = new Map<string, string>();
  const direct: string[] = [];
  const privateIndex: Array<{ name: string; version: string; registry: string }> = [];
  const uncheckable: Array<{ name: string; version: string; kind: "git" }> = [];
  const specs = new Set<string>();
  const required = new Set<string>();
  let section = "";
  let inSpecs = false;
  /** The current GEM section's gems and its first private remote (null: every remote is rubygems.org, or it names none). */
  let gemSection: { gems: Array<{ name: string; version: string }>; privateRemote: string | null } | null = null;
  const closeGemSection = () => {
    if (gemSection?.privateRemote) for (const g of gemSection.gems) privateIndex.push({ ...g, registry: gemSection.privateRemote });
    gemSection = null;
  };
  for (const raw of content.split(/\r?\n/)) {
    if (raw.length > MAX_LINE || raw.trim() === "") continue;
    if (!raw.startsWith(" ")) {
      closeGemSection();
      section = raw.trimEnd();
      inSpecs = false;
      if (section === "GEM") gemSection = { gems: [], privateRemote: null };
      continue;
    }
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (gemSection && indent === 2 && line.startsWith("remote:")) {
      // Bundler writes one GEM section per source, and older Bundlers several remotes in one: any
      // remote that is not rubygems.org (`remote: https://gems.acme.dev/`) is a private gem server.
      const remote = line.slice("remote:".length).trim();
      const host = hostOf(remote);
      if (!(host && PUBLIC_GEM_HOSTS.has(host)) && gemSection.privateRemote === null) gemSection.privateRemote = sourceLabel(remote);
      continue;
    }
    if (section === "DEPENDENCIES" && indent === 2) {
      const name = /^([^\s!(]+)/.exec(line)?.[1];
      if (name) direct.push(name);
      continue;
    }
    if (line === "specs:" && indent === 2) {
      inSpecs = true;
      continue;
    }
    if (indent === 2) {
      inSpecs = false;
      continue;
    }
    if (!inSpecs || (section !== "GEM" && section !== "GIT" && section !== "PATH")) continue;
    if (indent === 6) {
      // A dependency of the spec above: `    loofah (2.12.0)` then `      nokogiri (>= 1.5.9)`.
      const dep = /^([^\s(]+)/.exec(line)?.[1];
      if (dep && dep !== "bundler") required.add(dep.toLowerCase());
      continue;
    }
    if (indent !== 4) continue;
    const open = line.indexOf(" (");
    if (open <= 0 || !line.endsWith(")")) continue;
    const name = line.slice(0, open);
    const version = line.slice(open + 2, -1).split("-")[0].trim();
    if (!name || name.includes(" ") || !version) continue;
    specs.add(name.toLowerCase());
    if (section === "GIT") {
      if (!uncheckable.some((u) => u.name === name)) uncheckable.push({ name, version, kind: "git" });
      continue;
    }
    if (section !== "GEM") continue;
    instances.add(name, version);
    if (!versions.has(name)) versions.set(name, version);
    gemSection?.gems.push({ name, version });
  }
  closeGemSection();
  const dangling = [...required].filter((n) => !specs.has(n)).sort();
  return { instances, versions, direct, privateIndex, uncheckable, specs, dangling };
}

/** A gem name: what `gem '<name>'` must hold to be compared (no interpolation, no spaces). */
const GEM_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** Blocks whose gems Bundler always records, whatever the platform or group: their gems are compared. */
const RECORDED_BLOCKS = new Set(["group", "groups", "platforms", "platform", "source", "git", "path", "github", "gitlab", "bitbucket"]);
/** A Gemfile larger than this is not compared (it is no Gemfile). */
const MAX_GEMFILE_BYTES = 1024 * 1024;

/** A Ruby line with string contents emptied and its comment dropped, so keywords are only found in code. */
function rubyCode(line: string): string {
  let out = "";
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) {
        quote = null;
        out += c;
      }
      continue;
    }
    if (c === "#") break;
    if (c === '"' || c === "'") quote = c;
    out += c;
  }
  return out.trim();
}

/**
 * The gems a Gemfile (or gems.rb) declares that Bundler always records in the lockfile's
 * DEPENDENCIES, or why the file could not be followed. Not a Ruby parser: it reads `gem '<name>'`
 * statements at the start of a line, at the top level or inside the blocks Bundler records whatever
 * the platform (`group`, `platforms`, `source`, `git`, `path`). A gem behind a condition (`if` /
 * `unless`, a modifier, `case`, `install_if`, `env`, a loop) may legitimately be left out of the
 * lockfile, so it is not compared; neither is a name built at run time, nor what `gemspec` or
 * `eval_gemfile` brings in. More `end`s than blocks, or a block never closed, is a file this does
 * not follow: null names, and the reason.
 */
export function gemfileDeclared(content: string): { names: string[] } | { error: string } {
  if (content.length > MAX_GEMFILE_BYTES) return { error: "it is larger than any Gemfile this server compares" };
  const names: string[] = [];
  /** Open blocks: true when Bundler records the gems inside whatever happens at run time. */
  const blocks: boolean[] = [];
  /** How many of the open blocks are conditional: a count, so a deep nest costs nothing per gem. */
  let conditional = 0;
  let inComment = false;
  for (const raw of content.split(/\r?\n/)) {
    if (raw.length > MAX_LINE) continue;
    if (inComment) {
      if (/^=end\b/.test(raw)) inComment = false;
      continue;
    }
    if (/^=begin\b/.test(raw)) {
      inComment = true;
      continue;
    }
    const code = rubyCode(raw);
    if (code === "") continue;
    if (/^end\b/.test(code)) {
      if (blocks.length === 0) return { error: "it has an `end` with no block open, so its structure could not be followed" };
      if (blocks.pop() === false) conditional--;
      continue;
    }
    if (/^(?:else|elsif|when|in|rescue|ensure)\b/.test(code)) continue;
    const opensKeyword = /^(?:if|unless|case|while|until|for|begin|def|class|module)\b/.test(code) && !/\bend\s*$/.test(code);
    // No two adjacent `\s*` in either pattern: a long run of spaces costs one pass, never its square (`code` is trimmed).
    const opensDo = /\bdo(?:\s*\|[^|]*\|)?$/.test(code);
    const gem = /^gem(?:\s+|\s*\(\s*)(['"])([^'"]*)\1/.exec(raw.trim());
    if (gem && GEM_NAME.test(gem[2]) && !/\b(?:if|unless)\b/.test(code) && conditional === 0) names.push(gem[2]);
    const opened = opensKeyword ? false : opensDo ? RECORDED_BLOCKS.has(/^([a-z_]+)/.exec(code)?.[1] ?? "") : null;
    if (opened !== null) {
      blocks.push(opened);
      if (!opened) conditional++;
    }
  }
  if (blocks.length > 0) return { error: "a block in it is never closed, so its structure could not be followed" };
  return { names: [...new Set(names)] };
}

/** "x", "x and y", "x, y, z and 2 more": a few names of a list, as every lockfile reason words them. */
function someNames(names: string[]): string {
  if (names.length <= 3) return names.length <= 1 ? (names[0] ?? "") : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  return `${names.slice(0, 3).join(", ")} and ${names.length - 3} more`;
}

/**
 * The problem of a lockfile that has no entry for what the manifest beside it declares (audit
 * 2026-11-25, F1; npm and uv said it already): PARTIAL, behind the manifest. `damage`, when the
 * file is also damaged inside, makes it damage (the cut wording) rather than only out of date.
 */
export function manifestAheadProblem(lockPath: string, manifest: string, missing: string[], damage: { reason: string; missing: number } | null = null): LockfileProblem {
  const behind = manifestAheadText(manifest, missing);
  if (damage) return partialRead(lockPath, `${damage.reason}; also, ${behind}`, damage.missing + missing.length);
  return partialRead(lockPath, behind, missing.length, true);
}

/** "Gemfile declares x and y, but this lockfile has no entry for them: it is older than Gemfile, or truncated". */
export function manifestAheadText(manifest: string, missing: string[]): string {
  const them = missing.length === 1 ? "it" : "them";
  return `${manifest} declares ${someNames(missing)}, but this lockfile has no entry for ${them}: it is older than ${manifest}, or truncated`;
}

/** A lockfile read whole and not compared with its manifest, because the manifest could not be read or followed: said, never damage. */
export function notComparedProblem(lockPath: string, manifest: string, why: string): LockfileProblem {
  return {
    file: lockPath,
    notCrossChecked: true,
    error: `it was not compared with ${manifest} (${why}), so a dependency ${manifest} declares that this lockfile has no entry for would not be noticed`,
  };
}

/** A lockfile's damage from entries it depends on and holds no entry for (F4), worded as uv.lock's. */
export function danglingDamage(dangling: string[], entry: string): { reason: string; missing: number } | null {
  if (dangling.length === 0) return null;
  const one = dangling.length === 1;
  return { reason: `it is truncated or damaged: ${dangling.length} package${one ? "" : "s"} named as ${one ? "a dependency has" : "dependencies have"} no ${entry} (${someNames(dangling)})`, missing: dangling.length };
}

interface ComposerPackage {
  name?: unknown;
  version?: unknown;
  dist?: { type?: unknown; url?: unknown };
  source?: { type?: unknown; url?: unknown };
  "notification-url"?: unknown;
}

/** A repository a composer.json declares, as the lockfile's package URLs can be matched against it. */
interface ComposerRepository {
  /** Lowercased URL with no trailing `.git` or `/`. */
  url: string;
  host: string | null;
  type: string;
}

const normaliseRepoUrl = (url: string) => url.trim().toLowerCase().replace(/\.git$/, "").replace(/\/+$/, "");

/** composer.json `repositories` that are not Packagist (an array or an object of entries; `packagist.org: false` entries skipped). */
export function composerRepositories(manifest: Record<string, unknown> | null): ComposerRepository[] {
  const raw = manifest?.repositories;
  const entries = Array.isArray(raw) ? raw : raw && typeof raw === "object" ? Object.values(raw) : [];
  const out: ComposerRepository[] = [];
  for (const e of entries as Array<{ type?: unknown; url?: unknown }>) {
    if (!e || typeof e !== "object" || typeof e.url !== "string") continue;
    const host = hostOf(e.url);
    if (host && (host === "repo.packagist.org" || host === "packagist.org")) continue;
    out.push({ url: normaliseRepoUrl(e.url), host, type: typeof e.type === "string" ? e.type : "composer" });
  }
  return out;
}

/**
 * Why a composer.lock package is private, or null (review of #64, X2): its dist or source is on a
 * host other than Packagist and the public code hosts (a Satis or Private Packagist server), or it
 * comes from a repository composer.json declares that is not Packagist (a `vcs` repository, even
 * one on GitHub, a `path` or `artifact` one, or a `composer` server).
 */
function composerPrivate(entry: ComposerPackage, repos: ComposerRepository[]): string | null {
  const urls = [entry.dist?.url, entry.source?.url, entry["notification-url"]].filter((u): u is string => typeof u === "string" && u.length > 0);
  for (const url of urls) {
    const n = normaliseRepoUrl(url);
    const host = hostOf(url);
    const repo = repos.find((r) => n === r.url || n.startsWith(`${r.url}/`) || (r.type !== "vcs" && r.type !== "git" && r.host !== null && r.host === host));
    if (repo) return sourceLabel(repo.url);
    if (host === null) {
      // A relative dist URL: a `path` or `artifact` repository, local code.
      if (entry.dist?.type === "path" || entry.dist?.type === "zip") return `local ${String(entry.dist?.type)} repository`;
      continue;
    }
    if (!PUBLIC_COMPOSER_HOSTS.has(host)) return sourceLabel(url);
  }
  return null;
}

/** A Composer platform requirement (`php`, `ext-json`, `lib-icu`, `composer-plugin-api`): not a package, never locked. */
const isComposerPlatform = (name: string) => !name.includes("/");

/** The names in an object's keys (`require`, `provide`, `replace`), lower-cased as Composer stores them; none when it is no object. */
const composerKeys = (value: unknown): string[] =>
  value && typeof value === "object" && !Array.isArray(value) ? Object.keys(value).map((k) => k.toLowerCase()) : [];

/**
 * composer.lock: `packages` (runtime) and `packages-dev` (dev). A leading `v`
 * is dropped (`v5.4.0` is release 5.4.0 on Packagist and in OSV). A branch
 * checkout (`dev-main`) names no version: it is not checked, and is listed as
 * not checkable (audit 2026-11-25, F5), unless it is a metapackage (no code of
 * its own: roave/security-advisories) or local code (a `path` dist). A
 * numbered branch alias (`3.0.x-dev`) is kept, as osv-scanner and the desktop
 * app keep it.
 *
 * Also what the file names: every package it holds and every name one of them provides or
 * replaces (`names`, lower-cased), and the packages an entry requires that none of them is
 * (`dangling`, F4): Composer locks every package an entry requires.
 */
export function readComposerLock(
  lock: { packages?: unknown; "packages-dev"?: unknown },
  repos: ComposerRepository[] = [],
): {
  instances: InstanceSet;
  versions: Map<string, string>;
  privateIndex: Array<{ name: string; version: string; registry: string }>;
  uncheckable: Array<{ name: string; version: string; kind: "git" | "url" }>;
  names: Set<string>;
  dangling: string[];
} {
  const instances = new InstanceSet();
  const versions = new Map<string, string>();
  const privateIndex: Array<{ name: string; version: string; registry: string }> = [];
  const uncheckable: Array<{ name: string; version: string; kind: "git" | "url" }> = [];
  const names = new Set<string>();
  const required = new Set<string>();
  for (const [key, dev] of [["packages", false], ["packages-dev", true]] as const) {
    const list = lock[key];
    if (!Array.isArray(list)) continue;
    for (const entry of list as Array<ComposerPackage & { type?: unknown; require?: unknown; provide?: unknown; replace?: unknown }>) {
      if (typeof entry?.name !== "string" || !entry.name) continue;
      names.add(entry.name.toLowerCase());
      for (const n of [...composerKeys(entry.provide), ...composerKeys(entry.replace)]) names.add(n);
      for (const n of composerKeys(entry.require)) if (!isComposerPlatform(n)) required.add(n);
      if (typeof entry.version !== "string") continue;
      const version = entry.version.replace(/^v(?=\d)/, "");
      if (!/^\d/.test(version)) {
        // A branch checkout: no release of that name, so nothing to ask OSV.dev about (F5).
        // A `path` dist is the project's own local code, and a metapackage installs no code: neither is listed.
        if (entry.type !== "metapackage" && entry.dist?.type !== "path" && version) {
          uncheckable.push({ name: entry.name, version: entry.version, kind: entry.source?.type === "git" ? "git" : "url" });
        }
        continue;
      }
      instances.add(entry.name, version, dev);
      if (!versions.has(entry.name)) versions.set(entry.name, version);
      const registry = composerPrivate(entry, repos);
      if (registry) privateIndex.push({ name: entry.name, version, registry });
    }
  }
  const dangling = [...required].filter((n) => !names.has(n)).sort();
  return { instances, versions, privateIndex, uncheckable, names, dangling };
}

/**
 * The packages a composer.json requires that its composer.lock holds no entry for (F1): `require`,
 * and `require-dev` unless the lock holds no dev package at all (written with `--no-dev`). Platform
 * requirements, and names composer.json itself provides or replaces, are never locked.
 */
function composerManifestAhead(manifest: Record<string, unknown>, lock: Record<string, unknown>, names: Set<string>): string[] {
  const own = new Set([...composerKeys(manifest.provide), ...composerKeys(manifest.replace)]);
  const devLocked = Array.isArray(lock["packages-dev"]) && lock["packages-dev"].length > 0;
  const wanted = [...composerKeys(manifest.require), ...(devLocked ? composerKeys(manifest["require-dev"]) : [])];
  return [...new Set(wanted.filter((n) => !isComposerPlatform(n) && !own.has(n) && !names.has(n)))];
}

/**
 * Why a Gemfile.lock is not the whole file Bundler wrote, or null. Bundler writes the gems
 * first and a `DEPENDENCIES` section after them, for a project with no gems too: a file with
 * none stops before its end, and what it lists may not be every gem.
 */
export function gemfileLockDamage(content: string): string | null {
  return /^DEPENDENCIES[ \t]*\r?$/m.test(content) ? null : "it is truncated: it has no DEPENDENCIES section, which Bundler writes after the gems";
}

/**
 * The lockfile Bundler reads in a directory: `gems.locked` when the Gemfile is `gems.rb` (Bundler
 * prefers that pair), else `Gemfile.lock`, else a `gems.locked` on its own. Same format either way.
 */
export function gemLockfile(cwd: string): string | null {
  const gemfileLock = path.join(cwd, "Gemfile.lock");
  const gemsLocked = path.join(cwd, "gems.locked");
  if (fs.existsSync(gemsLocked) && (fs.existsSync(path.join(cwd, "gems.rb")) || !fs.existsSync(gemfileLock))) return gemsLocked;
  return fs.existsSync(gemfileLock) ? gemfileLock : null;
}

export function resolveRuby(cwd: string): VersionSource {
  const lockPath = gemLockfile(cwd);
  if (lockPath === null) return emptySource();
  let content: string;
  try {
    content = readTextFile(lockPath);
  } catch (error) {
    return { ...emptySource(), problems: [{ file: lockPath, error: unreadableReason(error) }] };
  }
  const read = readGemfileLock(content);
  const cut = gemfileLockDamage(content);
  const problems: LockfileProblem[] = [];
  // gems.rb's pair was read: a Gemfile.lock left beside it is not what Bundler installs, and is said.
  const passedOver = path.join(cwd, "Gemfile.lock");
  if (lockPath !== passedOver && fs.existsSync(passedOver)) {
    problems.push({ file: passedOver, conflict: true, error: "gems.locked was read instead: with a gems.rb present Bundler uses gems.rb and gems.locked, so this file is not what gets installed" });
  }
  // A spec's dependency with no spec of its own: the file is damaged inside (F4).
  const inner = danglingDamage(read.dangling, "spec");
  const damage = cut && inner ? { reason: `${cut}; ${inner.reason.replace(/^it is truncated or damaged: /, "")}`, missing: inner.missing } : cut ? { reason: cut, missing: 0 } : inner;
  // The Gemfile beside it, against what the file records (F1): DEPENDENCIES and every spec.
  const manifestName = path.basename(lockPath) === "gems.locked" ? "gems.rb" : "Gemfile";
  const manifest = readManifest(path.join(cwd, manifestName));
  let ahead: string[] = [];
  if (manifest.state === "read") {
    const declared = gemfileDeclared(manifest.text);
    const recorded = new Set([...read.specs, ...read.direct.map((n) => n.toLowerCase())]);
    if ("error" in declared) problems.push(notComparedProblem(lockPath, manifestName, declared.error));
    else ahead = declared.names.filter((n) => !recorded.has(n.toLowerCase()));
  } else if (manifest.state === "unreadable") problems.push(notComparedProblem(lockPath, manifestName, manifest.reason));
  const uncheckable = read.uncheckable.map((u) => ({ ...u, file: lockPath }));
  if (read.instances.size === 0) {
    // Nothing was read and the file says why: named, never taken for a project with no gems.
    const why = [damage?.reason, ahead.length > 0 ? manifestAheadText(manifestName, ahead) : null].filter(Boolean).join("; ");
    if (why) problems.push({ file: lockPath, error: `${why}; no gem could be read from it` });
    const extra = { ...(problems.length > 0 ? { problems } : {}), ...(uncheckable.length > 0 ? { uncheckable } : {}) };
    return { ...emptySource(), ...extra };
  }
  if (ahead.length > 0) problems.push(manifestAheadProblem(lockPath, manifestName, ahead, damage));
  else if (damage) problems.push(partialRead(lockPath, damage.reason, damage.missing));
  const privateIndex: PrivateIndexEntry[] = read.privateIndex.map((p) => ({ ...p, file: lockPath }));
  return found(read.versions, read.instances, lockPath, "lockfile", {
    direct: { deps: read.direct, devDeps: [] },
    ...(privateIndex.length > 0 ? { privateIndex } : {}),
    ...(uncheckable.length > 0 ? { uncheckable } : {}),
    ...(problems.length > 0 ? { problems } : {}),
  });
}

/** A manifest beside a lockfile: read, absent, or there and not readable (said, never taken for absent). */
function readManifest(file: string): { state: "read"; text: string } | { state: "absent" } | { state: "unreadable"; reason: string } {
  if (!fs.existsSync(file)) return { state: "absent" };
  try {
    return { state: "read", text: readTextFile(file) };
  } catch (error) {
    return { state: "unreadable", reason: unreadableReason(error).replace(/^could not be read/, "it could not be read") };
  }
}

export function resolvePhp(cwd: string): VersionSource {
  const lockPath = path.join(cwd, "composer.lock");
  if (!fs.existsSync(lockPath)) return emptySource();
  // Unreadable or not JSON throws here: resolveVersionSource names the file with the reason.
  const lock = JSON.parse(readTextFile(lockPath)) as unknown;
  // Composer writes both lists, empty or not: JSON with neither is some other file.
  const isLock = typeof lock === "object" && lock !== null && !Array.isArray(lock) && ("packages" in lock || "packages-dev" in lock);
  if (!isLock) {
    return { ...emptySource(), problems: [{ file: lockPath, error: "it is valid JSON but not a composer.lock: it has no `packages` or `packages-dev` list" }] };
  }
  const manifest = composerManifestRead(cwd);
  const read = readComposerLock(lock as Record<string, unknown>, composerRepositories(manifest.state === "read" ? manifest.json : null));
  const problems: LockfileProblem[] = [];
  // composer.json against what the lock holds (F1); an entry's requirement with no entry (F4).
  const ahead = manifest.state === "read" ? composerManifestAhead(manifest.json, lock as Record<string, unknown>, read.names) : [];
  if (manifest.state === "unreadable") problems.push(notComparedProblem(lockPath, "composer.json", manifest.reason));
  // The root package provides or replaces some names itself (symfony-demo replaces symfony/polyfill-php70,
  // which its locked packages require): without composer.json read, which ones is not known, so no
  // requirement is called dangling.
  const own = manifest.state === "read" ? new Set([...composerKeys(manifest.json.provide), ...composerKeys(manifest.json.replace), ...(typeof manifest.json.name === "string" ? [manifest.json.name.toLowerCase()] : [])]) : null;
  const damage = own ? danglingDamage(read.dangling.filter((n) => !own.has(n)), "entry") : null;
  const uncheckable = read.uncheckable.map((u) => ({ ...u, file: lockPath }));
  if (read.instances.size === 0) {
    // composer.json requires packages and the lock holds none of them: nothing it pins was read.
    const why = [damage?.reason, ahead.length > 0 ? manifestAheadText("composer.json", ahead) : null].filter(Boolean).join("; ");
    if (why) problems.push({ file: lockPath, error: `${why}; no package could be read from it` });
    return { ...emptySource(), ...(problems.length > 0 ? { problems } : {}), ...(uncheckable.length > 0 ? { uncheckable } : {}) };
  }
  if (ahead.length > 0) problems.push(manifestAheadProblem(lockPath, "composer.json", ahead, damage));
  else if (damage) problems.push(partialRead(lockPath, damage.reason, damage.missing));
  const privateIndex: PrivateIndexEntry[] = read.privateIndex.map((p) => ({ ...p, file: lockPath }));
  return found(read.versions, read.instances, lockPath, "lockfile", {
    direct: composerDirect(cwd),
    ...(privateIndex.length > 0 ? { privateIndex } : {}),
    ...(uncheckable.length > 0 ? { uncheckable } : {}),
    ...(problems.length > 0 ? { problems } : {}),
  });
}

/** composer.json beside a composer.lock: read as a JSON object, absent, or there and not usable (said). */
function composerManifestRead(cwd: string): { state: "read"; json: Record<string, unknown> } | { state: "absent" } | { state: "unreadable"; reason: string } {
  const got = readManifest(path.join(cwd, "composer.json"));
  if (got.state !== "read") return got;
  try {
    const json = JSON.parse(got.text) as unknown;
    if (json && typeof json === "object" && !Array.isArray(json)) return { state: "read", json: json as Record<string, unknown> };
    return { state: "unreadable", reason: "it is not a JSON object" };
  } catch (error) {
    return { state: "unreadable", reason: `it is not valid JSON: ${error instanceof Error ? error.message.slice(0, 120) : String(error).slice(0, 120)}` };
  }
}

/** composer.json `require` / `require-dev` package names (platform requirements such as `php` and `ext-*` left out). */
function composerDirect(cwd: string): { deps: string[]; devDeps: string[] } {
  try {
    const manifest = JSON.parse(readTextFile(path.join(cwd, "composer.json"))) as Record<string, unknown>;
    const names = (field: string) =>
      Object.keys((manifest[field] as Record<string, unknown> | undefined) ?? {}).filter((n) => n.includes("/"));
    return { deps: names("require"), devDeps: names("require-dev") };
  } catch {
    return { deps: [], devDeps: [] };
  }
}
