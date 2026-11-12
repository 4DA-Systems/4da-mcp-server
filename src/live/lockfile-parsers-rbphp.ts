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
import { emptySource, found, InstanceSet, type VersionSource } from "./lockfile-types.js";
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
 * Gemfile.lock: the `specs:` of each `GEM` section (registry gems). GIT and
 * PATH sections are local or git sources, not RubyGems releases, and are
 * skipped. A platform suffix (`nokogiri (1.10.4-x86_64-linux)`) is not part
 * of the version: RubyGems prereleases use `.pre`, never `-`.
 */
export function readGemfileLock(content: string): {
  instances: InstanceSet;
  versions: Map<string, string>;
  direct: string[];
  /** Gems from a `GEM` section whose `remote:` is not rubygems.org: private (review of #64, X2). */
  privateIndex: Array<{ name: string; version: string; registry: string }>;
} {
  const instances = new InstanceSet();
  const versions = new Map<string, string>();
  const direct: string[] = [];
  const privateIndex: Array<{ name: string; version: string; registry: string }> = [];
  let section = "";
  let inSpecs = false;
  /** The current GEM section's private remote, or null when it is rubygems.org (or names none). */
  let privateRemote: string | null = null;
  for (const raw of content.split(/\r?\n/)) {
    if (raw.length > MAX_LINE || raw.trim() === "") continue;
    if (!raw.startsWith(" ")) {
      section = raw.trimEnd();
      inSpecs = false;
      privateRemote = null;
      continue;
    }
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (section === "GEM" && indent === 2 && line.startsWith("remote:")) {
      // Bundler writes one GEM section per source; a second one (`remote: https://gems.acme.dev/`) is a private gem server.
      const remote = line.slice("remote:".length).trim();
      const host = hostOf(remote);
      privateRemote = host && PUBLIC_GEM_HOSTS.has(host) ? null : sourceLabel(remote);
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
    if (!inSpecs || indent !== 4 || section !== "GEM") continue;
    const open = line.indexOf(" (");
    if (open <= 0 || !line.endsWith(")")) continue;
    const name = line.slice(0, open);
    const version = line.slice(open + 2, -1).split("-")[0].trim();
    if (!name || name.includes(" ") || !version) continue;
    instances.add(name, version);
    if (!versions.has(name)) versions.set(name, version);
    if (privateRemote) privateIndex.push({ name, version, registry: privateRemote });
  }
  return { instances, versions, direct, privateIndex };
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

/**
 * composer.lock: `packages` (runtime) and `packages-dev` (dev). A leading `v`
 * is dropped (`v5.4.0` is release 5.4.0 on Packagist and in OSV). A branch
 * checkout (`dev-main`) names no version and is skipped; a numbered branch
 * alias (`3.0.x-dev`) is kept, as osv-scanner and the desktop app keep it.
 */
export function readComposerLock(
  lock: { packages?: unknown; "packages-dev"?: unknown },
  repos: ComposerRepository[] = [],
): { instances: InstanceSet; versions: Map<string, string>; privateIndex: Array<{ name: string; version: string; registry: string }> } {
  const instances = new InstanceSet();
  const versions = new Map<string, string>();
  const privateIndex: Array<{ name: string; version: string; registry: string }> = [];
  for (const [key, dev] of [["packages", false], ["packages-dev", true]] as const) {
    const list = lock[key];
    if (!Array.isArray(list)) continue;
    for (const entry of list as ComposerPackage[]) {
      if (typeof entry?.name !== "string" || typeof entry.version !== "string") continue;
      const version = entry.version.replace(/^v(?=\d)/, "");
      if (!entry.name || !/^\d/.test(version)) continue;
      instances.add(entry.name, version, dev);
      if (!versions.has(entry.name)) versions.set(entry.name, version);
      const registry = composerPrivate(entry, repos);
      if (registry) privateIndex.push({ name: entry.name, version, registry });
    }
  }
  return { instances, versions, privateIndex };
}

export function resolveRuby(cwd: string): VersionSource {
  const lockPath = path.join(cwd, "Gemfile.lock");
  if (!fs.existsSync(lockPath)) return emptySource();
  const read = readGemfileLock(readTextFile(lockPath));
  if (read.instances.size === 0) return emptySource();
  const privateIndex: PrivateIndexEntry[] = read.privateIndex.map((p) => ({ ...p, file: lockPath }));
  return found(read.versions, read.instances, lockPath, "lockfile", { direct: { deps: read.direct, devDeps: [] }, ...(privateIndex.length > 0 ? { privateIndex } : {}) });
}

export function resolvePhp(cwd: string): VersionSource {
  const lockPath = path.join(cwd, "composer.lock");
  if (!fs.existsSync(lockPath)) return emptySource();
  const read = readComposerLock(JSON.parse(readTextFile(lockPath)) as Record<string, unknown>, composerRepositories(composerManifest(cwd)));
  if (read.instances.size === 0) return emptySource();
  const privateIndex: PrivateIndexEntry[] = read.privateIndex.map((p) => ({ ...p, file: lockPath }));
  return found(read.versions, read.instances, lockPath, "lockfile", { direct: composerDirect(cwd), ...(privateIndex.length > 0 ? { privateIndex } : {}) });
}

function composerManifest(cwd: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readTextFile(path.join(cwd, "composer.json"))) as Record<string, unknown>;
  } catch {
    return null;
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
