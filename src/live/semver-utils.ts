// SPDX-License-Identifier: Apache-2.0

import type { SemverDistance } from "./types.js";

export function parseSemver(version: string): [number, number, number] | null {
  const match = version.replace(/^v/, "").match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return [parseInt(match[1]), parseInt(match[2]), parseInt(match[3])];
}

/**
 * How far `current` is behind `latest`. `label` is the kind of bump, by the
 * caret rules npm and Cargo apply: below 1.0 a minor bump is breaking (^0.8.6
 * does not admit 0.9.0) and below 0.1 a patch bump is too (^0.0.3 is =0.0.3),
 * so both are labelled "major", the same as upgrade_impact and dependency_check.
 * Until 6.0.2 sqlx 0.8 -> 0.9 and reqwest 0.12 -> 0.13 were labelled "minor".
 * The numeric fields stay literal (0.8.6 -> 0.9.0 is major 0, minor 1).
 */
export function computeSemverDistance(current: string, latest: string): SemverDistance | null {
  const c = parseSemver(current);
  const l = parseSemver(latest);
  if (!c || !l) return null;

  const major = l[0] - c[0];
  const minor = major === 0 ? l[1] - c[1] : 0;
  const patch = major === 0 && minor === 0 ? l[2] - c[2] : 0;

  let label: SemverDistance["label"] = "up-to-date";
  if (major > 0) label = "major";
  else if (minor > 0) label = c[0] === 0 ? "major" : "minor";
  else if (patch > 0) label = c[0] === 0 && c[1] === 0 ? "major" : "patch";

  return { major: Math.max(0, major), minor: Math.max(0, minor), patch: Math.max(0, patch), label };
}

export function isPreRelease(version: string): boolean {
  return /[-+]/.test(version.replace(/^v/, "").replace(/^\d+\.\d+\.\d+/, "").slice(0, 1));
}

/**
 * Compare two versions by MAJOR.MINOR.PATCH. Returns 1 if a > b, -1 if a < b,
 * 0 if equal or either is unparseable. Prerelease/build suffixes are ignored
 * (sufficient for choosing the highest fix version among advisories).
 */
export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) {
    if (pa[i] > pb[i]) return 1;
    if (pa[i] < pb[i]) return -1;
  }
  return 0;
}

/** Highest version (by MAJOR.MINOR.PATCH) from a list, or null if empty. */
export function maxSemver(versions: string[]): string | null {
  if (versions.length === 0) return null;
  return versions.reduce((max, v) => (compareSemver(v, max) > 0 ? v : max), versions[0]);
}

/**
 * Highest NON-prerelease version by semver from a list.
 *
 * Registries list versions in publish order, and maintenance releases for an
 * older line land AFTER newer lines (React published 19.0.8 after 19.2.x; rsa
 * published 0.9.10 after 0.10.0-rc.*). Taking the "last stable entry" therefore
 * reported an older line as the latest stable — which surfaced as a bogus
 * stable version in dependency_health and a literal DOWNGRADE recommendation
 * in upgrade_planner. Order-independent max fixes the class.
 */
export function maxStableSemver(versions: string[]): string | null {
  const stable = versions.filter((v) => parseSemver(v) !== null && !isPreRelease(v));
  return maxSemver(stable);
}
