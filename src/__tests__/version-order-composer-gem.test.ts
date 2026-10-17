// SPDX-License-Identifier: Apache-2.0
/**
 * Packagist (Composer) and RubyGems (Gem::Version) ordering (readiness audit
 * H2, 2026-10-16). OSV's ranges for both use two-part bounds (`introduced:
 * "6.4"`, `introduced: "3.0"`), which MAJOR.MINOR.PATCH read as "equal" to
 * every version. Two consequences:
 * - fix targets jumped majors: symfony/process 5.1.0 was sent to 8.0.5 (5.4.51
 *   clears both advisories), rack 2.0.6 to 3.2.6 (2.2.23 is clean);
 * - the dangerous direction: a two-part `fixed` bound made a version inside
 *   the window look clean.
 * The fixture is every OSV record for rack and symfony/process (pinned
 * 2026-10-16); the expected targets were checked against OSV's own
 * /v1/query at the exact version (0 advisories at 5.4.51 and at 2.2.23).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { compareVersions, isComparable, isComposerOrGemPrerelease } from "../live/version-compare.js";
import { advisoryAffects, advisoryRanges, smallestCleanVersion, type AdvisoryRanges } from "../live/osv-ranges.js";
import { extractFixedVersion } from "../live/osv-scanner.js";
import type { OsvVulnerability } from "../live/types.js";

type Events = Array<Record<string, string>>;
const fixture = JSON.parse(
  fs.readFileSync(path.join(import.meta.dirname, "fixtures", "version-order", "osv-rack-symfony-process.json"), "utf8"),
) as Record<string, Array<{ id: string; ranges: Events[] }>>;

function records(ecosystem: string, name: string): OsvVulnerability[] {
  return fixture[name].map(
    (r) =>
      ({
        id: r.id,
        affected: [{ package: { ecosystem, name }, ranges: r.ranges.map((events) => ({ type: "ECOSYSTEM", events })) }],
      }) as unknown as OsvVulnerability,
  );
}

/** The scan's target: each affecting advisory's own fix, then the smallest version clean against every record. */
function target(ecosystem: string, name: string, installed: string) {
  const recs = records(ecosystem, name);
  const advisories = recs.map((r) => advisoryRanges(r, name, ecosystem)).filter((a): a is AdvisoryRanges => a !== null);
  const fixes = recs
    .filter((r, i) => advisoryAffects(advisories[i], installed, ecosystem))
    .map((r) => extractFixedVersion(r.affected, name, ecosystem, installed))
    .filter((f): f is string => f !== null);
  return smallestCleanVersion({ ecosystem, fixes, advisories, published: null });
}

const span = (introduced: string, end: { fixed?: string; lastAffected?: string }): AdvisoryRanges => ({
  id: "T",
  spans: [{ introduced, fixed: end.fixed ?? null, lastAffected: end.lastAffected ?? null }],
  versions: [],
});

describe("Packagist ordering (Composer)", () => {
  it.each([
    ["5.4.51", "6.4", -1],
    ["7.0.0", "6.4", 1],
    ["6.4", "6.4.0", 0],
    ["6.4", "6.4.0.0", 0],
    ["v5.4.51", "5.4.51", 0],
    ["1.0.0.1", "1.0.0", 1],
    ["5.4.0-RC1", "5.4.0", -1],
    ["5.4.0-beta2", "5.4.0-RC1", -1],
    ["5.4.0-alpha1", "5.4.0-beta1", -1],
    ["5.4.0-dev", "5.4.0-alpha1", -1],
    ["5.4.0-beta2", "5.4.0-beta10", -1],
    ["5.4.0-patch1", "5.4.0", 1],
    ["2.0.0", "10.0", -1],
  ] as const)("%s vs %s = %d", (a, b, want) => {
    expect(compareVersions(a, b, "Packagist")).toBe(want);
    expect(compareVersions(b, a, "Packagist")).toBe(-want || 0);
  });

  it("reads two-part and v-prefixed bounds; a branch name stays unreadable", () => {
    expect(isComparable("6.4", "Packagist")).toBe(true);
    expect(isComparable("v3.0.3", "Packagist")).toBe(true);
    expect(isComparable("dev-main", "Packagist")).toBe(false);
    expect(isComparable("3.0.x-dev", "Packagist")).toBe(false);
  });

  it("knows Composer's prereleases", () => {
    expect(isComposerOrGemPrerelease("5.4.0-RC1", "Packagist")).toBe(true);
    expect(isComposerOrGemPrerelease("5.4.0", "Packagist")).toBe(false);
    expect(isComposerOrGemPrerelease("5.4.0-patch1", "Packagist")).toBe(false);
  });
});

describe("RubyGems ordering (Gem::Version)", () => {
  it.each([
    ["2.2.23", "3.0", -1],
    ["3.1.0", "3.0", 1],
    ["3.0", "3.0.0", 0],
    ["1.10.4.1", "1.10.4", 1],
    ["3.0.0.beta1", "3.0.0", -1],
    ["3.0.0.rc1", "3.0.0.beta1", 1],
    ["3.0.0.rc1", "3.0.0.rc2", -1],
    ["6.1.0-pre", "6.1.0", -1],
    ["1.0.a", "1.0", -1],
    ["2.0.0", "10.0", -1],
  ] as const)("%s vs %s = %d", (a, b, want) => {
    expect(compareVersions(a, b, "RubyGems")).toBe(want);
    expect(compareVersions(b, a, "RubyGems")).toBe(-want || 0);
  });

  it("reads two-part bounds and knows letter segments are prereleases", () => {
    expect(isComparable("3.0", "RubyGems")).toBe(true);
    expect(isComposerOrGemPrerelease("3.0.0.beta1", "RubyGems")).toBe(true);
    expect(isComposerOrGemPrerelease("3.0.0", "RubyGems")).toBe(false);
  });
});

describe("a two-part bound never decides the wrong way (the dangerous direction)", () => {
  it.each(["Packagist", "RubyGems"])("%s: inside [0, 6.4) is affected, 6.4.0 is not", (eco) => {
    const a = span("0", { fixed: "6.4" });
    expect(advisoryAffects(a, "6.3.9", eco)).toBe(true);
    expect(advisoryAffects(a, "5.0.0", eco)).toBe(true);
    expect(advisoryAffects(a, "6.4.0", eco)).toBe(false);
    expect(advisoryAffects(a, "6.4.1", eco)).toBe(false);
  });

  it.each(["Packagist", "RubyGems"])("%s: last_affected 6.4 is inclusive of 6.4.0", (eco) => {
    const a = span("6.0", { lastAffected: "6.4" });
    expect(advisoryAffects(a, "6.4.0", eco)).toBe(true);
    expect(advisoryAffects(a, "6.0.0", eco)).toBe(true);
    expect(advisoryAffects(a, "6.4.1", eco)).toBe(false);
    expect(advisoryAffects(a, "5.9.9", eco)).toBe(false);
  });

  it.each(["Packagist", "RubyGems"])("%s: a version below a two-part introduced is outside the window", (eco) => {
    const a = span("6.4", { fixed: "6.4.33" });
    expect(advisoryAffects(a, "5.4.51", eco)).toBe(false);
    expect(advisoryAffects(a, "6.4.0", eco)).toBe(true);
    expect(advisoryAffects(a, "6.4.32", eco)).toBe(true);
  });
});

describe("same-line fix targets (OSV records pinned 2026-10-16)", () => {
  it("symfony/process 5.1.0 -> 5.4.51, clear of both advisories", () => {
    const t = target("Packagist", "symfony/process", "5.1.0");
    expect(t?.target).toBe("5.4.51");
    expect(t?.stillAffectedBy).toEqual([]);
  });

  it("rack 2.0.6 -> 2.2.23, clear of every advisory", () => {
    const t = target("RubyGems", "rack", "2.0.6");
    expect(t?.target).toBe("2.2.23");
    expect(t?.stillAffectedBy).toEqual([]);
  });
});

/**
 * Review of 6.2.5 H2 (2026-10-18). GHSA-r39x-jcww-82v6 opens its windows at
 * two-part bounds (`introduced: "8.0"`) and lists the line's prereleases
 * (v8.0.0-BETA1, v8.0.0-RC1) as affected. A record with the list is judged
 * by it (OSV schema: in `versions` OR in a range); one without must still be
 * right, so a Packagist lower bound with no stability opens at that
 * release's dev stability, as Composer reads `>=8.0` (`>= 8.0.0.0-dev`,
 * checked with composer/semver 3.4.3). Record pinned 2026-10-18.
 */
describe("Packagist prereleases inside a two-part window (GHSA-r39x-jcww-82v6)", () => {
  const record = JSON.parse(
    fs.readFileSync(path.join(import.meta.dirname, "fixtures", "version-order", "osv-GHSA-r39x-jcww-82v6.json"), "utf8"),
  ) as OsvVulnerability;
  const withList = advisoryRanges(record, "symfony/process", "Packagist")!;
  const rangesOnly = { ...withList, versions: [] };

  it.each(["v8.0.0-RC1", "8.0.0-RC1", "8.0.0-BETA1", "v6.4.0-BETA1", "6.4.0-RC1", "7.4.0-RC1", "8.0.0", "6.4.32"])("%s is affected, with and without the versions list", (v) => {
    expect(advisoryAffects(withList, v, "Packagist")).toBe(true);
    expect(advisoryAffects(rangesOnly, v, "Packagist")).toBe(true);
  });

  it.each(["8.0.5", "6.4.33", "6.3.9-RC1", "5.4.51"])("%s is not", (v) => {
    expect(advisoryAffects(withList, v, "Packagist")).toBe(false);
    expect(advisoryAffects(rangesOnly, v, "Packagist")).toBe(false);
  });

  it("a prerelease of the fix release stays affected (the safe reading of `fixed`)", () => {
    expect(advisoryAffects(rangesOnly, "8.0.5-RC1", "Packagist")).toBe(true);
  });

  it("the pinned advisory source reports it too", async () => {
    const { PinnedRecordsSource } = await import("../live/pinned-advisories.js");
    const source = new PinnedRecordsSource([record]);
    expect(source.affecting("Packagist", "symfony/process", "8.0.0-RC1")).toEqual(["GHSA-r39x-jcww-82v6"]);
    const bare = { ...record, affected: record.affected!.map((a) => ({ ...a, versions: [] })) } as OsvVulnerability;
    expect(new PinnedRecordsSource([bare]).affecting("Packagist", "symfony/process", "6.4.0-BETA1")).toEqual(["GHSA-r39x-jcww-82v6"]);
  });
});

describe("Composer's grammar and tag order (composer/semver 3.4.3)", () => {
  it.each([
    ["1.0.0-beta", "1.0.0-beta0", -1],
    ["1.0.0-beta0", "1.0.0-beta1", -1],
    ["1.0.0-RC", "1.0.0-RC1", -1],
    ["1.0.0-alpha1.2", "1.0.0-alpha1.10", -1],
    ["1.0.0-beta-2", "1.0.0-beta2", 0],
  ] as const)("%s vs %s = %d", (a, b, want) => {
    expect(compareVersions(a, b, "Packagist")).toBe(want);
    expect(compareVersions(b, a, "Packagist")).toBe(-want || 0);
  });

  it("refuses what Composer refuses: five numeric parts, `_` before a tag number", () => {
    expect(isComparable("1.2.3.4.5", "Packagist")).toBe(false);
    expect(isComparable("1.0.0-beta_1", "Packagist")).toBe(false);
    expect(isComparable("1.0.0_beta1", "Packagist")).toBe(true);
  });
});