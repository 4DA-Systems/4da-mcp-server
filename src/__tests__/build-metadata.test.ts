// SPDX-License-Identifier: Apache-2.0
/**
 * B-12 (audit 2026-10-12): `+build` metadata is not a prerelease. Semver
 * ignores build metadata for precedence and only a `-` suffix marks a
 * prerelease, so toml_edit's `0.25.17+spec-1.1.0` is its latest stable
 * release. It was read as a prerelease and dependency_health / upgrade_planner
 * named 0.23.9 (the last release without metadata) as the latest stable.
 */
import { describe, expect, it } from "vitest";
import { isPreRelease, maxStableSemver } from "../live/semver-utils.js";
import { isPrerelease } from "../live/upgrade-sources.js";
import { isPrereleaseVersion } from "../live/osv-ranges.js";

const TOML_EDIT = ["0.22.27", "0.23.0", "0.23.9", "0.23.10+spec-1.0.0", "0.24.0+spec-1.1.0", "0.25.16+spec-1.1.0", "0.25.17+spec-1.1.0", "0.26.0-alpha.1+spec-1.1.0"];

describe("build metadata is not a prerelease", () => {
  it("latest stable of a toml_edit-like list is 0.25.17+spec-1.1.0", () => {
    expect(maxStableSemver(TOML_EDIT)).toBe("0.25.17+spec-1.1.0");
  });

  it("`+meta` is stable; `-pre+meta` is a prerelease", () => {
    expect(isPreRelease("1.2.3+meta")).toBe(false);
    expect(isPreRelease("v1.2.3+incompatible")).toBe(false);
    expect(isPreRelease("1.2.3-rc.1+meta")).toBe(true);
    expect(isPreRelease("1.2.3-rc.1")).toBe(true);
    expect(isPreRelease("1.2.3")).toBe(false);
  });

  it("PEP 440 spellings after MAJOR.MINOR.PATCH: pre and dev releases are prereleases, post and local are not", () => {
    expect(isPreRelease("2.0.0rc1")).toBe(true);
    expect(isPreRelease("2.0.0a1")).toBe(true);
    expect(isPreRelease("2.0.0b2")).toBe(true);
    expect(isPreRelease("2.0.0.dev3")).toBe(true);
    expect(isPreRelease("2.0.0.post1")).toBe(false);
    expect(isPreRelease("2.0.0+local.1")).toBe(false);
  });

  it("the ecosystem predicates agree", () => {
    expect(isPrerelease("0.25.17+spec-1.1.0", "crates.io")).toBe(false);
    expect(isPrerelease("0.26.0-alpha.1+spec-1.1.0", "crates.io")).toBe(true);
    expect(isPrereleaseVersion("0.25.17+spec-1.1.0", "crates.io")).toBe(false);
    expect(isPrereleaseVersion("1.0+abc.5", "PyPI")).toBe(false);
  });
});
