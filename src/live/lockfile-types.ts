// SPDX-License-Identifier: Apache-2.0
/**
 * The shape every lockfile reader returns, shared by lockfile-parsers.ts,
 * lockfile-parsers-pygo.ts and js-lockfile-readers.ts.
 */

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
  extra: Pick<VersionSource, "extraSources" | "ranges"> = {},
): VersionSource {
  return {
    versions,
    instances: Array.isArray(instances) ? instances : instances.toArray(),
    source,
    kind,
    ...extra,
  };
}
