// SPDX-License-Identifier: Apache-2.0
/**
 * The shape every lockfile reader returns, shared by lockfile-parsers.ts,
 * lockfile-parsers-pygo.ts and js-lockfile-readers.ts.
 */

import type { PrivateIndexEntry } from "./private-packages.js";

/** One installed copy of a package. `dev` is undefined when the lockfile does not say. */
export interface PackageInstance {
  name: string;
  version: string;
  dev?: boolean;
}

/** Versions read from one directory, and the file they came from. */
export interface VersionSource {
  /** The version a direct dependency of this name resolves to. */
  versions: Map<string, string>;
  /** Every installed copy, deduplicated by name@version. */
  instances: PackageInstance[];
  /** Absolute path of the file the versions were read from, or null when none exists. */
  source: string | null;
  /**
   * `lockfile` = exact versions; `manifest` = exact pins from a requirements
   * file; `declared_ranges` = a manifest with no lockfile (package.json,
   * Cargo.toml): its versions are the floors of declared ranges, not installs.
   */
  kind: SourceKind | null;
  /** Every further file read for this ecosystem in this directory (Python reads several). */
  extraSources?: string[];
  /** declared_ranges: the declared requirement per name ("^1.2.0"), for names whose version is only a floor. */
  ranges?: Map<string, string>;
  /**
   * The direct dependencies the lockfile itself names (Gemfile.lock
   * DEPENDENCIES, composer.json require / require-dev), for ecosystems whose
   * manifest the project scanner does not read.
   */
  direct?: { deps: string[]; devDeps: string[] };
  /** Lockfiles present here that could not be read, and why: never a silent "no lockfile". */
  problems?: LockfileProblem[];
  /**
   * Dependencies the lockfile installs from git, a URL or a local archive.
   * They are not registry releases, so the registry package's advisories do
   * not describe them: never sent to OSV under that name, always listed.
   */
  uncheckable?: UncheckableDependency[];
  /**
   * Packages the lockfile installs from a registry or index that is not the public one (Cargo
   * `source = "registry+https://..."` other than crates.io, or git; a uv / poetry / Pipfile index
   * other than pypi.org): private, never sent anywhere (private-packages.ts).
   */
  privateIndex?: PrivateIndexEntry[];
  /**
   * npm aliases the lockfile installs at the top level: the name the manifest
   * declares (`my-lodash`) to the registry package it is (`lodash`).
   */
  aliases?: Map<string, string>;
  /**
   * PyPI: requirement names with no exact version anywhere in this directory
   * (`pydantic>=2.0.0`, a bare `requests`), by the file that lists them.
   * There is no installed version to ask about, so they are not checked.
   */
  unpinned?: UnpinnedRequirements[];
}

/** A dependency that is not a registry release (see VersionSource.uncheckable). */
export interface UncheckableDependency {
  name: string;
  /** The version its own manifest states, when the lockfile records one. It is not a registry release of that version. */
  version: string | null;
  kind: "git" | "url" | "file";
  /** Absolute path of the lockfile or requirements file that names it. */
  file: string;
}

/** Requirements with no pinned version, per file (see VersionSource.unpinned). */
export interface UnpinnedRequirements {
  /** Absolute path. */
  file: string;
  names: string[];
}

/** A lockfile that exists but could not be read, or not all of it, or that disagrees with the one that was read. */
export interface LockfileProblem {
  /** Absolute path. */
  file: string;
  /** Why, in words ("merge-conflict markers", "invalid JSON: ..."). */
  error: string;
  /**
   * Set when the file WAS read except for this many entries (a yarn.lock line
   * past the length cap): a partial read, not an unreadable file.
   */
  skipped?: number;
  /**
   * Set when the file was read but not to its end: truncated or damaged. How
   * many entries were lost is not known (`skipped`, when set, is a lower bound).
   */
  partial?: true;
  /**
   * Set when nothing is wrong with reading: another lockfile in the same
   * directory was read instead, and this one pins a different set (or could
   * not be compared). One of the two is stale; the scan cannot tell which.
   */
  conflict?: true;
  /** Set for a requirements include refused because it points outside the project (B-11): a policy, not damage. */
  refused?: true;
  /** The ecosystem whose resolution reported it (stamped by resolveVersionSource), for ecosystem_filter. */
  ecosystem?: string;
}

export type SourceKind = "lockfile" | "manifest" | "declared_ranges";

export function emptySource(): VersionSource {
  return { versions: new Map(), instances: [], source: null, kind: null };
}

/**
 * Collects instances deduplicated by name@version. A copy seen as runtime
 * anywhere stays runtime; dev is only claimed when every sighting says dev,
 * and unknown when any sighting does not say.
 */
export class InstanceSet {
  private byKey = new Map<string, PackageInstance>();

  add(name: string, version: string, dev?: boolean): void {
    const key = `${name}\0${version}`;
    const existing = this.byKey.get(key);
    if (!existing) {
      this.byKey.set(key, dev === undefined ? { name, version } : { name, version, dev });
      return;
    }
    if (existing.dev === undefined || dev === undefined) delete existing.dev;
    else existing.dev = existing.dev && dev;
  }

  get size(): number {
    return this.byKey.size;
  }

  toArray(): PackageInstance[] {
    return [...this.byKey.values()];
  }
}

export function found(
  versions: Map<string, string>,
  instances: InstanceSet | PackageInstance[],
  source: string,
  kind: SourceKind,
  extra: Pick<VersionSource, "extraSources" | "ranges" | "direct" | "uncheckable" | "aliases" | "unpinned" | "problems" | "privateIndex"> = {},
): VersionSource {
  return {
    versions,
    instances: Array.isArray(instances) ? instances : instances.toArray(),
    source,
    kind,
    ...extra,
  };
}
