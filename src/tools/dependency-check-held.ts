// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check and what an npm release holds (audit 6.2.5 D-4).
 *
 * `{to: "4.20.0"}` for express said proceed, and `{to: "4.x"}` named 4.20.0 the smallest safe
 * release: no advisory of express affects it, but it exact-pins qs 6.11.0, cookie 0.6.0,
 * body-parser 1.20.3 and path-to-regexp 0.1.10, all affected, and installing it installs them.
 * An agent wrote it from that answer. Here the releases a check judges (an exact `to`, a
 * constraint's pick and the smallest and newest safe releases in range) are judged with their held
 * dependencies too (held-dependencies.ts): an affected one makes `to` review or avoid by the same
 * severity rule as its own advisories, and keeps the release out of the safe ones.
 *
 * Fail closed: when the registry or OSV cannot answer, `to` is `unknown` (never proceed) and the
 * safe releases stay as its own advisories decide them, with the reason in the signal.
 */

import { heldAdvisories, HELD_CANDIDATES, type AdvisoryQuery, type HeldCheck } from "../live/held-dependencies.js";
import type { FixPathSources } from "../live/fix-paths.js";

/** Time a dependency_check call may spend judging held dependencies, in all. */
const HELD_CHECK_BUDGET_MS = 10_000;
/** The newest safe releases a range check lists (RangeCheck.safe_versions), judged as well. */
const NEWEST_LISTED = 8;

export const HELD_RANGE_NOTE =
  "releases that exact-pin or narrowly range a dependency with a known advisory (installing them installs it), or whose such dependencies could not be checked, are not counted safe";

export class HeldJudge {
  private readonly checks = new Map<string, HeldCheck>();
  /** Per package: every release's held specs, or null when the registry could not be read. */
  private readonly specs = new Map<string, Record<string, Record<string, string>> | null>();
  private readonly deadline = Date.now() + HELD_CHECK_BUDGET_MS;

  constructor(
    private readonly sources: FixPathSources | null,
    private readonly query: AdvisoryQuery,
  ) {}

  /** Judge these releases (those not judged yet), in one advisory lookup. */
  async judge(requests: Array<{ pkg: string; versions: string[] }>): Promise<void> {
    if (!this.sources) return;
    const sources = this.sources;
    for (const pkg of new Set(requests.map((r) => r.pkg))) {
      if (this.specs.has(pkg)) continue;
      const facts = Date.now() < this.deadline ? await sources.releaseFacts("npm", pkg).catch(() => null) : null;
      this.specs.set(pkg, facts?.heldSpecs ?? null);
    }
    const releases: Array<{ key: string; specs: Record<string, string> }> = [];
    for (const { pkg, versions } of requests) {
      const all = this.specs.get(pkg);
      for (const v of new Set(versions)) {
        const key = `${pkg}@${v}`;
        if (this.checks.has(key) || releases.some((r) => r.key === key)) continue;
        if (all === null || all === undefined) this.checks.set(key, { status: "unchecked", reason: "the npm registry could not be read" });
        else if (!all[v]) this.checks.set(key, { status: "checked", affected: [] });
        else releases.push({ key, specs: all[v] });
      }
    }
    if (releases.length === 0) return;
    for (const [key, check] of await heldAdvisories(sources, this.query, releases, this.deadline)) this.checks.set(key, check);
  }

  at(pkg: string, version: string): HeldCheck | undefined {
    return this.checks.get(`${pkg}@${version}`);
  }

  affected(pkg: string, version: string): boolean {
    const c = this.at(pkg, version);
    return c?.status === "checked" && c.affected.length > 0;
  }

  /**
   * checkRange's held filter for one package, or undefined when nothing about it could be judged
   * (registry or OSV down): the safe releases then stay as its own advisories decide, and `to`
   * says unknown instead.
   */
  rangeFilter(pkg: string): { unsafe: (version: string) => boolean; note: string } | undefined {
    const all = this.specs.get(pkg);
    if (!all) return undefined;
    const judged = [...this.checks.entries()].filter(([k]) => k.startsWith(`${pkg}@`) && all[k.slice(pkg.length + 1)]);
    if (judged.length > 0 && judged.every(([, c]) => c.status === "unchecked")) return undefined;
    return {
      unsafe: (v) => {
        const c = this.at(pkg, v);
        // A release that holds something and was not judged is not called safe.
        if (!c) return Boolean(all[v]);
        return c.status === "unchecked" || c.affected.length > 0;
      },
      note: HELD_RANGE_NOTE,
    };
  }
}

/** The releases of a safe list worth judging: the smallest (above `from`) and the newest few. */
export function heldRangeCandidates(ownSafe: string[], above: (v: string) => boolean): string[] {
  return [...new Set([...ownSafe.filter(above).slice(0, HELD_CANDIDATES), ...ownSafe.slice(-NEWEST_LISTED)])];
}
