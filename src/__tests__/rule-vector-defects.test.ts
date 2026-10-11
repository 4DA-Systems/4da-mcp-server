// SPDX-License-Identifier: Apache-2.0
/**
 * Regressions for the defects the shared rule vectors (4DA
 * src-tauri/tests/conformance/vectors/) found in this engine, pinned here
 * without the corpus so every CI job runs them. Vector ids in the names.
 */

import { describe, expect, it } from "vitest";
import { compareVersions } from "../live/version-compare.js";
import { pep440SpecAdmits } from "../tools/dependency-check-versions.js";
import { leavesCaret, refreshRule, type ParentRequirement } from "../live/refresh-rule.js";

describe("PEP 440 local labels order (vo-013..vo-015)", () => {
  it.each([
    ["1.0", "1.0+abc.5", -1],
    ["1.0+abc.5", "1.0+abc.7", -1],
    ["1.0+abc.7", "1.0+5", -1],
    ["1.0+abc", "1.0+abc.1", -1],
    ["1.0+ABC.5", "1.0+abc.5", 0],
    ["1.0+abc.5", "1.0.post1", -1],
    ["1.0+5", "1.0", 1],
  ])("%s vs %s = %i", (a, b, want) => {
    expect(compareVersions(a, b, "PyPI")).toBe(want);
  });

  it("a specifier without a local label still ignores the candidate's (==3.1.6 admits 3.1.6+local)", () => {
    expect(pep440SpecAdmits("==3.1.6", "3.1.6+ubuntu.1")).toBe(true);
  });
});

const npm = (parent: string, text: string | null): ParentRequirement => ({ parent, text, dialect: "npm" });
const cargo = (parent: string, text: string | null): ParentRequirement => ({ parent, text, dialect: "cargo" });

describe("refreshRule: the AD-055 ¶1 refresh-or-parent rule", () => {
  it("any requirement that excludes the target decides, even beside an unreadable one (rv-048)", () => {
    expect(refreshRule("1.2.3", "1.3.0", [npm("a", "git+https://github.com/o/r.git#v1.2.3"), npm("b", "~1.2.0")])).toEqual({
      verdict: "parent_must_move",
      inferred: false,
      via: ["b"],
    });
  });

  it("every requirement admitting the target is a read refresh (rv-001, rv-051)", () => {
    expect(refreshRule("1.2.5", "1.2.6", [npm("mkdirp", "^1.2.5"), npm("rc", "^1.2.0")])).toEqual({ verdict: "refresh", inferred: false, via: [] });
  });

  it("an exact pin among caret ranges blocks, and is named (rv-017: js-yaml 3.13.1 under mocha)", () => {
    const reqs = [npm("cosmiconfig", "^3.13.1"), npm("eslint", "^3.13.0"), npm("mocha", "3.13.1"), npm("svgo", "^3.13.1")];
    expect(refreshRule("3.13.1", "3.15.2", reqs)).toEqual({ verdict: "parent_must_move", inferred: false, via: ["mocha"] });
  });

  it("an npm alias is read by its range (rv-047)", () => {
    expect(refreshRule("4.2.0", "4.2.3", [npm("cliui", "npm:string-width@^4.2.0")])).toEqual({ verdict: "refresh", inferred: false, via: [] });
  });

  it("Cargo: a bare version is a caret; `=` pins (rv-052, rv-053)", () => {
    expect(refreshRule("0.8.0", "0.8.11", [cargo("tokio", "0.8")]).verdict).toBe("refresh");
    expect(refreshRule("0.8.0", "0.8.11", [cargo("tokio", "=0.8.0")])).toEqual({ verdict: "parent_must_move", inferred: false, via: ["tokio"] });
  });

  it("nothing readable falls back to semver compatibility, marked inferred (rv-002, rv-012, rv-049, rv-050)", () => {
    expect(refreshRule("1.2.5", "1.2.6", [])).toEqual({ verdict: "refresh", inferred: true, via: [] });
    expect(refreshRule("8.5.1", "9.0.0", [])).toEqual({ verdict: "parent_must_move", inferred: true, via: [] });
    expect(refreshRule("1.2.3", "1.2.4", [npm("p", "github:o/r#v1")])).toEqual({ verdict: "refresh", inferred: true, via: [] });
    expect(refreshRule("1.2.3", "2.0.0", [npm("p", "file:../local")])).toEqual({ verdict: "parent_must_move", inferred: true, via: [] });
  });

  it("a requirement that could not be read at all counts as unreadable, not as admitting", () => {
    expect(refreshRule("1.2.5", "1.2.6", [npm("a", "^1.2.0"), npm("b", null)])).toEqual({ verdict: "refresh", inferred: true, via: [] });
  });

  it("unreadable versions give no verdict (rv-065)", () => {
    expect(refreshRule("not-a-version", "1.0.0", [])).toEqual({ verdict: "unknown", inferred: true, via: [] });
  });

  it.each([
    ["1.2.5", "1.3.0", false],
    ["1.2.5", "2.0.0", true],
    ["0.8.0", "0.8.11", false],
    ["0.8.0", "0.9.0", true],
    ["0.0.3", "0.0.4", true],
    ["0.0.3", "0.1.0", true],
    ["v1.2.0", "v1.4.0", false],
  ])("the caret fallback: %s -> %s leaves it: %s (rv-060..rv-064)", (installed, target, leaves) => {
    expect(leavesCaret(installed, target)).toBe(leaves);
  });
});
