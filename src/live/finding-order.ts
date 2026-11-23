// SPDX-License-Identifier: Apache-2.0
/**
 * One order for scan findings that does not depend on where an answer came from.
 *
 * A scan merges answers read from the cache with answers fetched in the call, and which ones
 * were cached changes from call to call. Everything built from the merged list (which record
 * represents an alias group, the order a detailed page is cut from) must come out the same for
 * the same scan state, so findings are put in this order first: ecosystem, package, installed
 * version (by the ecosystem's ordering), the directories that lock the copy, the lockfile
 * version of an install-drift row, then the advisory id.
 */

import { compareVersions, isComparable } from "./version-compare.js";
import type { VulnerabilityEntry } from "./types.js";

type Identity = Pick<VulnerabilityEntry, "ecosystem" | "package" | "currentVersion" | "vulnId" | "sourceDirs" | "installDriftOf">;

/** Code-unit order: the same in every locale. */
function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Names ignoring case (crates.io, Go, npm, PyPI), then by code unit: total, and the same in every locale. */
export function compareNames(a: string, b: string): number {
  return byCodeUnit(a.toLowerCase(), b.toLowerCase()) || byCodeUnit(a, b);
}

/**
 * Versions the ecosystem can read first, in its order (equal ones by their text); unreadable
 * ones after, by their text. A total order, so a sort that uses it has one result.
 */
export function compareVersionText(a: string, b: string, ecosystem: string): number {
  const readA = isComparable(a, ecosystem);
  const readB = isComparable(b, ecosystem);
  if (readA !== readB) return readA ? -1 : 1;
  return (readA ? compareVersions(a, b, ecosystem) : 0) || byCodeUnit(a, b);
}

function dirsKey(v: Identity): string {
  return [...(v.sourceDirs ?? [])].sort(byCodeUnit).join("\n");
}

/** The identity order of two findings; 0 only for the same advisory on the same copy. */
export function compareFindingIdentity(a: Identity, b: Identity): number {
  return (
    compareNames(a.ecosystem, b.ecosystem) ||
    compareNames(a.package, b.package) ||
    compareVersionText(a.currentVersion, b.currentVersion, a.ecosystem) ||
    byCodeUnit(dirsKey(a), dirsKey(b)) ||
    byCodeUnit(a.installDriftOf ?? "", b.installDriftOf ?? "") ||
    byCodeUnit(a.vulnId, b.vulnId)
  );
}

/** A copy of `entries` in identity order. */
export function inFindingOrder<T extends Identity>(entries: readonly T[]): T[] {
  return [...entries].sort(compareFindingIdentity);
}
