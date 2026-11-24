// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check: what one pass works on (an item as validated, as resolved to one version, and
 * as answered), the keys it files them under, and the small helpers every stage of a pass shares
 * (dependency-check.ts checkPass).
 */

import type { CheckEcosystem } from "../live/release-metadata.js";
import type { CheckItem, Signal, Verdict } from "./dependency-check-signals.js";
import { describeReading, type RangeCheck, type Target } from "./dependency-check-versions.js";
import type { NpmWhy, Resolution } from "./dependency-check-resolution.js";

export const ECOSYSTEMS: readonly CheckEcosystem[] = ["npm", "crates.io", "PyPI", "Go"];

/** The installed version, when it is not the version being judged: never named to a registry (PyPI per-release documents). */
export function installedNotJudged(item: { from?: string | null; to: string }): string | null {
  return item.from && item.from !== item.to ? item.from : null;
}

export interface ItemResult {
  ecosystem: string;
  package: string;
  /** crates.io: the spelling asked, when the crate is published under another (`serde-json` is serde_json). */
  package_requested?: string;
  /** Every release what was asked can install, each judged, when that is more than one (dependency-check-resolution.ts). */
  resolution?: Resolution;
  from: string | null;
  to: string;
  /** "latest" or the constraint, when the caller asked for one and `to` is what it resolved to. */
  to_requested?: string;
  /** How `to` was read: an exact version, a range (in the ecosystem's own syntax), or "latest". */
  to_read_as?: string;
  verdict: Verdict;
  reason: string;
  signals: Signal[];
  range_check?: RangeCheck;
  /** crates.io: `to` needs a newer Rust than the project's rust-version (a caveat; the verdict is unchanged). */
  needs_newer_rust?: { needs: string; declared: string; manifest: string };
  /** Unmaintained-package notices on `to`: reported, never part of the verdict (audit L3). */
  maintenance_notices?: string[];
  /**
   * "private": the package name is private and was never looked up (live/private-packages.ts).
   * "module_path": a Go module path the go command does not accept as written (live/go-path.ts).
   * "input": the item was refused as written (its reason says why); the call's other items are answered.
   */
  not_checked?: "private" | "module_path" | "time_budget" | "input";
  /**
   * not_checked "private" because this lockfile (or manifest) could not be read: where the package
   * would be installed from is not known, so it was withheld. Repairing the file is the remedy.
   */
  unreadable_file?: string;
  /** not_checked "module_path": the path the module declares, or the one the spelling most likely means. */
  canonical_module_path?: string;
  /** Unknown because this server's own request limit held a registry read back: seconds until asking again can read it. */
  retry_after_seconds?: number;
}

/** A validated request item. */
export interface Requested {
  ecosystem: CheckEcosystem;
  package: string;
  /** crates.io: the spelling asked, once `package` is the crate's published spelling (round 10, W2). */
  asked?: string;
  /** What the caller passed as `to`, trimmed. */
  raw: string;
  target: Target;
  from?: string;
}

/** A request item with its `to` resolved to one version (or left unresolved with the reason). */
export interface Resolved extends CheckItem {
  requested?: string;
  /** How `to` was read (describeReading). */
  readAs?: string;
  rangeCheck?: RangeCheck;
  /** Set when no single version could be chosen; the item is then blocked with this text. */
  unresolved?: string;
  /**
   * Advisories OSV.dev's batch query named for `to` or `from` that the package's advisory list
   * (/v1/query) did not hold: the list is incomplete, so no release is named safe from it.
   * `misread`: advisories the list holds whose ranges do not show a release affected that the
   * batch query names them for; the list's ranges cannot name a safe release either.
   */
  listGap?: ListGap;
  /**
   * OSV.dev's batch query gave no current answer, so the package's advisory list (/v1/query) could
   * not be held against it: no release is named safe from the list (blind audit round 5).
   */
  batchUnread?: string;
  /** `to` is the release the constraint resolves to (resolvedRelease), not a pick among its safe releases. */
  resolvesRange?: boolean;
  /** crates.io: the spelling asked, when `package` is the published one. */
  asked?: string;
  /** npm: `to` is npm's pick (npmPick) and Yarn or pnpm can install `highest`, which is judged too (round 10, W2). */
  npmAlso?: { highest: string; why: NpmWhy };
}

export interface ListGap {
  ids: string[];
  versions: string[];
  misread?: string[];
}

/** Before resolution: an exact `to` as is, anything else shown as the caller wrote it. */
export function provisional(r: Requested): Resolved {
  const to = r.target.kind === "exact" ? r.target.version : r.raw;
  return { ecosystem: r.ecosystem, package: r.package, to, readAs: describeReading(r.ecosystem, r.raw, r.target), ...(r.from ? { from: r.from } : {}), ...(r.asked ? { asked: r.asked } : {}) };
}

/** Let timers and other calls run between CPU-bound steps. */
export function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/** A package name as its registry compares it: PEP 503 for PyPI; `-`/`_` and case folded for crates.io (round 10, W2). */
const keyName = (eco: string, name: string) =>
  eco === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : eco === "crates.io" ? name.toLowerCase().replace(/_/g, "-") : name;
export const instanceKey = (eco: string, name: string, version: string) => `${eco}\0${keyName(eco, name)}\0${version}`;
export const lookupKey = (item: { ecosystem: string; package: string }) => `${item.ecosystem}\0${keyName(item.ecosystem, item.package)}`;
export const head = (item: Resolved) => ({
  ecosystem: item.ecosystem,
  package: item.package,
  ...(item.asked ? { package_requested: item.asked } : {}),
  from: item.from ?? null,
  to: item.to,
  ...(item.requested ? { to_requested: item.requested } : {}),
  ...(item.readAs ? { to_read_as: item.readAs } : {}),
});
