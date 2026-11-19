// SPDX-License-Identifier: Apache-2.0
/**
 * Patterns that come from a repository's own files are matched in bounded time.
 *
 * A Cargo `members` entry of many `*` used to be turned into a regular expression
 * (`.*.*.*...`), which backtracks exponentially against a directory name that does not match:
 * eleven stars took 46 seconds, and the first tool call of a session reads the manifest. These
 * tests assert results. Under the old code the long patterns below do not return within the
 * test timeout, which is how a regression shows.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { hasWildcard, wildcardMatch } from "../live/glob-match.js";
import { cargoWorkspaceManifests, expandMemberGlob } from "../live/private-configs.js";
import { expandMember } from "../tools/upgrade-impact-features.js";

const made: string[] = [];
function tree(files: string[]): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "a1119-glob-"));
  made.push(root);
  for (const f of files) {
    fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true });
    fs.writeFileSync(path.join(root, f), "[package]\nname = \"x\"\nversion = \"0.1.0\"\n");
  }
  return root;
}
afterEach(() => {
  for (const d of made.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

/** The matcher the code used before, kept here as the reference for ordinary patterns. */
const reference = (pattern: string, name: string) => new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`).test(name);

describe("wildcardMatch", () => {
  it("agrees with the regular-expression reading on ordinary patterns", () => {
    const patterns = ["*", "?", "", "a", "a*", "*a", "*a*", "a?c", "crate-*", "*-sys", "a*b*c", "??", "*?*", "a.b", "a+b", "[x]", "a**b", "x*y?z*"];
    const names = ["", "a", "ab", "abc", "crate-core", "crate-", "openssl-sys", "aXbYc", "a.b", "axb", "a+b", "[x]", "x", "xyzz", "x1y2z3", "ac"];
    for (const p of patterns) for (const n of names) expect(wildcardMatch(p, n), `${JSON.stringify(p)} vs ${JSON.stringify(n)}`).toBe(reference(p, n));
  });

  it("answers for a pattern of many stars against a name that does not match", () => {
    const name = `${"a".repeat(200)}!`;
    expect(wildcardMatch(`${"*a".repeat(40)}*b`, name)).toBe(false);
    expect(wildcardMatch("*".repeat(5000), name)).toBe(true);
    expect(wildcardMatch(`${"a*".repeat(100)}!`, name)).toBe(true);
    expect(wildcardMatch(`${"?".repeat(201)}`, name)).toBe(true);
    expect(wildcardMatch(`${"?".repeat(202)}`, name)).toBe(false);
  });

  it("hasWildcard sees `*` and `?` only", () => {
    expect(hasWildcard("crates/*")).toBe(true);
    expect(hasWildcard("tools/cl?")).toBe(true);
    expect(hasWildcard("tools/[cli]")).toBe(false);
  });
});

describe("Cargo workspace members", () => {
  it("still expands the ordinary shapes", () => {
    const root = tree(["Cargo.toml", "crates/core/Cargo.toml", "crates/cli/Cargo.toml", "tools/gen/Cargo.toml", "crates/old/Cargo.toml", "deep/a/b/Cargo.toml"]);
    const rel = (files: string[]) => files.map((f) => path.relative(root, f).split(path.sep).join("/")).sort();
    expect(rel(cargoWorkspaceManifests(root, '[workspace]\nmembers = ["crates/*", "tools/gen"]\nexclude = ["crates/old"]\n'))).toEqual(["crates/cli/Cargo.toml", "crates/core/Cargo.toml", "tools/gen/Cargo.toml"]);
    expect(rel(cargoWorkspaceManifests(root, '[workspace]\nmembers = ["crates/c*"]\n'))).toEqual(["crates/cli/Cargo.toml", "crates/core/Cargo.toml"]);
    expect(rel(cargoWorkspaceManifests(root, '[workspace]\nmembers = ["**"]\n'))).toEqual(["crates/cli/Cargo.toml", "crates/core/Cargo.toml", "crates/old/Cargo.toml", "deep/a/b/Cargo.toml", "tools/gen/Cargo.toml"]);
  });

  it("a member pattern of many stars beside a long directory name returns", () => {
    const long = `${"a".repeat(120)}-not-a-match`;
    const root = tree(["Cargo.toml", `${long}/Cargo.toml`, "crates/core/Cargo.toml"]);
    const stars = `${"*a".repeat(30)}*b`;
    expect(cargoWorkspaceManifests(root, `[workspace]\nmembers = ["${stars}", "crates/*"]\nexclude = ["${stars}"]\n`).map((f) => path.basename(path.dirname(f)))).toEqual(["core"]);
    expect(expandMemberGlob(root, stars)).toEqual([]);
    expect(expandMember(root, stars)).toEqual([]);
  });

  it("a pattern of many `**` does not walk the tree once per `**`", () => {
    const root = tree(["Cargo.toml", "a/b/c/Cargo.toml", "a/d/Cargo.toml"]);
    const once = expandMemberGlob(root, "**").sort();
    expect(expandMemberGlob(root, Array.from({ length: 200 }, () => "**").join("/")).sort()).toEqual(once);
  });
});
