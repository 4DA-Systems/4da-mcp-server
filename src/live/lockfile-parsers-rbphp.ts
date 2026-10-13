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

/** Lines longer than this are not lockfile syntax; skipping them keeps every pattern below linear. */
const MAX_LINE = 4096;

/**
 * Gemfile.lock: the `specs:` of each `GEM` section (registry gems). GIT and
 * PATH sections are local or git sources, not RubyGems releases, and are
 * skipped. A platform suffix (`nokogiri (1.10.4-x86_64-linux)`) is not part
 * of the version: RubyGems prereleases use `.pre`, never `-`.
 */
export function readGemfileLock(content: string): { instances: InstanceSet; versions: Map<string, string>; direct: string[] } {
  const instances = new InstanceSet();
  const versions = new Map<string, string>();
  const direct: string[] = [];
  let section = "";
  let inSpecs = false;
  for (const raw of content.split(/\r?\n/)) {
    if (raw.length > MAX_LINE || raw.trim() === "") continue;
    if (!raw.startsWith(" ")) {
      section = raw.trimEnd();
      inSpecs = false;
      continue;
    }
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
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
  }
  return { instances, versions, direct };
}

interface ComposerPackage {
  name?: unknown;
  version?: unknown;
}

/**
 * composer.lock: `packages` (runtime) and `packages-dev` (dev). A leading `v`
 * is dropped (`v5.4.0` is release 5.4.0 on Packagist and in OSV). A branch
 * checkout (`dev-main`) names no version and is skipped; a numbered branch
 * alias (`3.0.x-dev`) is kept, as osv-scanner and the desktop app keep it.
 */
export function readComposerLock(lock: { packages?: unknown; "packages-dev"?: unknown }): { instances: InstanceSet; versions: Map<string, string> } {
  const instances = new InstanceSet();
  const versions = new Map<string, string>();
  for (const [key, dev] of [["packages", false], ["packages-dev", true]] as const) {
    const list = lock[key];
    if (!Array.isArray(list)) continue;
    for (const entry of list as ComposerPackage[]) {
      if (typeof entry?.name !== "string" || typeof entry.version !== "string") continue;
      const version = entry.version.replace(/^v(?=\d)/, "");
      if (!entry.name || !/^\d/.test(version)) continue;
      instances.add(entry.name, version, dev);
      if (!versions.has(entry.name)) versions.set(entry.name, version);
    }
  }
  return { instances, versions };
}

export function resolveRuby(cwd: string): VersionSource {
  const lockPath = path.join(cwd, "Gemfile.lock");
  if (!fs.existsSync(lockPath)) return emptySource();
  const read = readGemfileLock(fs.readFileSync(lockPath, "utf-8"));
  if (read.instances.size === 0) return emptySource();
  return found(read.versions, read.instances, lockPath, "lockfile", { direct: { deps: read.direct, devDeps: [] } });
}

export function resolvePhp(cwd: string): VersionSource {
  const lockPath = path.join(cwd, "composer.lock");
  if (!fs.existsSync(lockPath)) return emptySource();
  const read = readComposerLock(JSON.parse(fs.readFileSync(lockPath, "utf-8")) as Record<string, unknown>);
  if (read.instances.size === 0) return emptySource();
  return found(read.versions, read.instances, lockPath, "lockfile", { direct: composerDirect(cwd) });
}

/** composer.json `require` / `require-dev` package names (platform requirements such as `php` and `ext-*` left out). */
function composerDirect(cwd: string): { deps: string[]; devDeps: string[] } {
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(cwd, "composer.json"), "utf-8")) as Record<string, unknown>;
    const names = (field: string) =>
      Object.keys((manifest[field] as Record<string, unknown> | undefined) ?? {}).filter((n) => n.includes("/"));
    return { deps: names("require"), devDeps: names("require-dev") };
  } catch {
    return { deps: [], devDeps: [] };
  }
}
