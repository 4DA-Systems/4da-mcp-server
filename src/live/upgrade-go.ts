// SPDX-License-Identifier: Apache-2.0
/**
 * Go modules for `upgrade_impact`, from the module proxy (proxy.golang.org):
 * `/@v/list` for the tagged versions, `/@v/<version>.info` for a release's
 * time and VCS origin, and `/@v/<version>.zip` as the archive a changelog is
 * read from (the zip holds the module's files under `<module>@<version>/`).
 *
 * Major versions 2 and up are DIFFERENT modules: `github.com/jackc/pgx/v5`
 * is not a newer release of `github.com/jackc/pgx/v4`, and the proxy lists
 * each path's own versions only. `goMajorPath` gives the path a major lives
 * at, so an upgrade across majors is read from the target module and the
 * report can say that every import path changes.
 *
 * `.info` carries `Origin` (VCS URL, the tag's ref, the module's subdirectory
 * in a multi-module repository) for versions the proxy fetched recently.
 * That, not a guess from the import path, names the GitHub repository and tag
 * for the opt-in release-notes fallback: `go.uber.org/zap` lives at
 * github.com/uber-go/zap, and aws-sdk-go-v2's `service/s3` tags its releases
 * `service/s3/v1.50.0`.
 */

import type { PublishedVersion, RegistryIndex, UpgradeNet } from "./upgrade-sources.js";

const GO_PROXY = "https://proxy.golang.org";
const GO_TIMEOUT_MS = 15_000;
/** `.info` reads per call: one per release crossed, newest first, then dates are left null. */
const MAX_INFO_READS = 40;

/** A module path: a dotted host, then path elements (case kept; the proxy escapes capitals). */
export const GO_MODULE = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:\/[A-Za-z0-9._~+-]+)+$|^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/;

/** Proxy escaping: each capital letter becomes `!` + lowercase. */
export function escapeGoPath(path: string): string {
  return path.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

export interface GoInfo {
  Version?: string;
  Time?: string;
  Origin?: { VCS?: string; URL?: string; Subdir?: string; Ref?: string };
}

/** The major version a module path carries: `/v5` -> 5, `gopkg.in/yaml.v3` -> 3, none -> null (0 or 1). */
export function goPathMajor(path: string): number | null {
  const m = /\/v(\d+)$/.exec(path) ?? (/^gopkg\.in\//.test(path) ? /\.v(\d+)$/.exec(path) : null);
  return m ? Number(m[1]) : null;
}

/** The module path without its major suffix. */
export function goBasePath(path: string): string {
  if (/^gopkg\.in\//.test(path)) return path.replace(/\.v\d+$/, "");
  return path.replace(/\/v\d+$/, "");
}

/** The path major `major` lives at: none for 0 and 1, `/vN` (or gopkg.in's `.vN`) from 2. */
export function goMajorPath(path: string, major: number): string {
  const base = goBasePath(path);
  if (/^gopkg\.in\//.test(path)) return `${base}.v${major}`;
  return major >= 2 ? `${base}/v${major}` : base;
}

export function goVersionMajor(version: string): number | null {
  const m = /^v?(\d+)\./.exec(version.trim());
  return m ? Number(m[1]) : null;
}

/** GitHub repository from a module path: `github.com/<owner>/<repo>/...`. */
export function githubRepoOfGoPath(path: string): string | null {
  const m = /^github\.com\/([\w.-]+)\/([\w.-]+)/.exec(path);
  return m ? `https://github.com/${m[1]}/${m[2]}` : null;
}

export async function goInfo(net: UpgradeNet, module: string, version: string): Promise<GoInfo | null> {
  const res = await net.fetch(`${GO_PROXY}/${escapeGoPath(module)}/@v/${escapeGoPath(version)}.info`, {}, GO_TIMEOUT_MS);
  if (!res.ok) return null;
  try {
    return (await res.json()) as GoInfo;
  } catch {
    return null;
  }
}

export async function loadGoIndex(net: UpgradeNet, module: string): Promise<RegistryIndex | null> {
  const base = `${GO_PROXY}/${escapeGoPath(module)}/@v/list`;
  const res = await net.fetch(base, {}, GO_TIMEOUT_MS);
  // The proxy answers 404 and 410 for a path it cannot resolve.
  if (res.status === 404 || res.status === 410) return null;
  if (!res.ok) throw new Error(`Go module proxy HTTP ${res.status} for ${module}`);
  const listed = (await res.text())
    .split("\n")
    .map((v) => v.trim())
    .filter((v) => /^v\d+\.\d+\.\d+/.test(v));
  let versions: PublishedVersion[] = listed.map((version) => ({ version, published: null }));
  if (versions.length === 0) {
    // An untagged module: the proxy's @latest is a pseudo-version.
    const latest = await net.fetch(`${GO_PROXY}/${escapeGoPath(module)}/@latest`, {}, GO_TIMEOUT_MS);
    if (!latest.ok) return null;
    const info = (await latest.json()) as GoInfo;
    if (!info.Version) return null;
    versions = [{ version: info.Version, published: info.Time ?? null }];
  }
  return { name: module, ecosystem: "Go", versions, repository: githubRepoOfGoPath(module) };
}

/**
 * Publish times for the versions an upgrade crosses (newest first, at most
 * MAX_INFO_READS), and the target's VCS origin. Missing `.info` leaves a null date.
 */
export async function enrichGoVersions(
  net: UpgradeNet,
  module: string,
  versions: PublishedVersion[],
  target: PublishedVersion | null,
  budget = MAX_INFO_READS,
): Promise<{ origin: GoInfo["Origin"] | null }> {
  const rest = [...versions].reverse().filter((v) => v !== target && !v.published);
  const wanted = (target ? [target, ...rest] : rest).slice(0, budget);
  let origin: GoInfo["Origin"] | null = null;
  await Promise.all(
    wanted.map(async (v) => {
      const info = await goInfo(net, module, v.version).catch(() => null);
      if (info?.Time && !v.published) v.published = info.Time;
      if (v === target && info?.Origin) origin = info.Origin;
    }),
  );
  return { origin };
}

/**
 * The tag prefix a module's releases carry: `service/s3` for
 * `refs/tags/service/s3/v1.50.0`, "" for a module at the repository root.
 * From the proxy's recorded ref when there is one; otherwise from a
 * github.com path (the elements after owner/repo, minus a `/vN` suffix,
 * which a major-version subdirectory does not put in its tags).
 */
export function goTagPrefix(module: string, version: string, origin: GoInfo["Origin"] | null): string {
  const ref = origin?.Ref?.replace(/^refs\/tags\//, "");
  if (ref && ref.endsWith(version)) return ref.slice(0, ref.length - version.length).replace(/\/$/, "");
  if (origin?.Subdir !== undefined) return origin.Subdir.replace(/(?:^|\/)v\d+$/, "");
  const m = /^github\.com\/[\w.-]+\/[\w.-]+\/(.+)$/.exec(goBasePath(module));
  return m ? m[1] : "";
}

/** The proxy's zip of one module version. */
export function goZipUrl(module: string, version: string): string {
  return `${GO_PROXY}/${escapeGoPath(module)}/@v/${escapeGoPath(version)}.zip`;
}
