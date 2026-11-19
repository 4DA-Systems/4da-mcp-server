// SPDX-License-Identifier: Apache-2.0
/**
 * PEP 440's exclusive comparisons and local labels, as pip (pypa/packaging) reads them:
 *
 * - `>V` does not admit a post-release of V, nor a local version of V, unless V is itself a
 *   post-release: `>2023.3` leaves out 2023.3.post1.
 * - `<V` does not admit a pre-release of V unless V is itself a pre-release: `<2.0` leaves out
 *   2.0rc1 and 2.0.dev1.
 * - `==V` with a local label is exact: `==1.0+abc` does not admit 1.0. Without one the candidate's
 *   label is ignored: `==1.0` admits 1.0+abc.
 *
 * `>2023.3,<2023.4` on pytz named 2023.3.post1 as the safe release in range; pip admits nothing.
 */

import { describe, expect, it } from "vitest";
import type { PackageReleaseIndex, ReleaseRecord } from "../live/release-metadata.js";
import { checkRange, parseTarget, pep440SpecAdmits, rangeAdmits } from "../tools/dependency-check-versions.js";

const admits = (spec: string, cases: Record<string, boolean>) => {
  for (const [version, expected] of Object.entries(cases)) expect(pep440SpecAdmits(spec, version), `${spec} admits ${version}`).toBe(expected);
};

describe("PEP 440 `>V`", () => {
  it("leaves out post-releases and local versions of V", () => {
    admits(">1.7", { "1.7": false, "1.7.0": false, "1.7.post1": false, "1.7.0.post3": false, "1.7+abc": false, "1.7.1": true, "1.8.post1": true, "1.8+abc": true, "1.7.1.dev1": true });
    admits(">2023.3", { "2023.3": false, "2023.3.post1": false, "2023.4": true });
  });

  it("admits later post-releases when V is itself a post-release", () => {
    admits(">1.7.post2", { "1.7": false, "1.7.post1": false, "1.7.post2": false, "1.7.0.post3": true, "1.7.1": true });
  });

  it("`>=V` still admits them", () => {
    admits(">=1.7", { "1.7": true, "1.7.post1": true, "1.7+abc": true, "1.6.9": false });
  });
});

describe("PEP 440 `<V`", () => {
  it("leaves out pre-releases of V", () => {
    admits("<2.0", { "2.0": false, "2.0rc1": false, "2.0a1": false, "2.0.0b2": false, "2.0.dev1": false, "1.9": true, "1.9.9rc1": true, "1.9.post1": true });
  });

  it("admits earlier pre-releases when V is itself a pre-release", () => {
    admits("<2.0rc2", { "2.0rc1": true, "2.0b1": true, "2.0.dev1": true, "2.0rc2": false, "2.0": false });
    admits("<2.0.dev3", { "2.0.dev2": true, "2.0.dev3": false });
  });

  it("`<=V` is unchanged", () => {
    admits("<=2.0", { "2.0": true, "2.0rc1": true, "2.0+abc": true, "2.0.post1": false });
  });
});

describe("PEP 440 `==V` and `!=V` with local labels", () => {
  it("a local label in the specifier is exact", () => {
    admits("==1.0+abc", { "1.0": false, "1.0+abc": true, "1.0+ABC": true, "1.0.0+abc": true, "1.0+abc.1": false, "1.0+xyz": false });
    admits("!=1.0+abc", { "1.0": true, "1.0+abc": false, "1.0+xyz": true });
  });

  it("without one, the candidate's label is ignored", () => {
    admits("==1.0", { "1.0": true, "1.0.0": true, "1.0+abc": true, "1.0.post1": false });
    admits("!=1.0", { "1.0": false, "1.0+abc": false, "1.1": true });
    admits("==3.1.6", { "3.1.6+ubuntu.1": true });
  });
});

describe("in dependency_check's range reading", () => {
  const rec = (version: string): ReleaseRecord => ({ version, publishedAt: "2025-01-01T00:00:00Z", trust: "unknown", trustEvidence: "", installScripts: null, deprecated: null, withdrawn: null, dependencies: null }) as unknown as ReleaseRecord;
  const index = (versions: string[]): PackageReleaseIndex => ({ ecosystem: "PyPI", name: "pytz", createdAt: null, releases: Object.fromEntries(versions.map((v) => [v, rec(v)])) });

  it("`>2023.3,<2023.4` on pytz admits no release, so none is named safe in it", () => {
    expect(parseTarget("PyPI", ">2023.3,<2023.4")).toEqual({ kind: "range", range: ">2023.3,<2023.4" });
    for (const v of ["2023.3", "2023.3.post1", "2023.4"]) expect(rangeAdmits("PyPI", ">2023.3,<2023.4", v), v).toBe(false);
    const rc = checkRange({ ecosystem: "PyPI", index: index(["2022.7.1", "2023.3", "2023.3.post1", "2023.4"]), range: ">2023.3,<2023.4", basis: "requested", advisories: [] });
    expect(rc).toMatchObject({ releases_in_range: 0, smallest_safe_in_range: null, newest_safe_in_range: null, safe_versions: [] });
  });

  it("`<2.0` offers no 2.0 pre-release, even to a caller who allows pre-releases", () => {
    const rc = checkRange({ ecosystem: "PyPI", index: index(["2.0rc1", "2.0.dev1"]), range: "<2.0", basis: "requested", advisories: [], allowPrerelease: true });
    expect(rc).toMatchObject({ releases_in_range: 0, newest_safe_in_range: null });
    expect(rc.prereleases_not_offered).toBeUndefined();
  });

  it("`>=2023.3,<2023.4` still admits the post-release", () => {
    const rc = checkRange({ ecosystem: "PyPI", index: index(["2023.3", "2023.3.post1", "2023.4"]), range: ">=2023.3,<2023.4", basis: "requested", advisories: [] });
    expect(rc).toMatchObject({ releases_in_range: 2, smallest_safe_in_range: "2023.3", newest_safe_in_range: "2023.3.post1" });
  });
});
