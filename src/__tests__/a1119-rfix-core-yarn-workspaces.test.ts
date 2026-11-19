// SPDX-License-Identifier: Apache-2.0
/**
 * yarn classic writes no entry for a workspace member. Members named by a
 * brace pattern (`packages/{a,b}`) are members; and when the member list
 * cannot be established whole, a declared name with no entry is not taken
 * for damage, because it may be a member.
 */
import { afterEach, describe, expect, it } from "vitest";
import { expandWorkspaces } from "../live/js-manifests.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { removeProject, tempProject } from "./helpers/a1119-readers.js";

const YARN = `# yarn lockfile v1\n\n\nms@2.1.3:\n  version "2.1.3"\n  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz"\n`;

describe("yarn classic workspaces", () => {
  const dirs: string[] = [];
  const project = (files: Record<string, string>) => {
    const dir = tempProject(files);
    dirs.push(dir);
    return dir;
  };
  afterEach(() => dirs.splice(0).forEach(removeProject));
  const member = (name: string) => JSON.stringify({ name, version: "1.0.0" });

  it("expands brace sets", () => {
    const dir = project({ "packages/a/package.json": member("ws-a"), "packages/b/package.json": member("ws-b"), "packages/c/package.json": member("ws-c"), "tools/x/package.json": member("x") });
    expect(expandWorkspaces(dir, ["packages/{a,b}"])).toEqual({ dirs: ["packages/a", "packages/b"], complete: true });
    expect(expandWorkspaces(dir, ["{packages,tools}/*"])).toEqual({ dirs: ["packages/a", "packages/b", "packages/c", "tools/x"], complete: true });
    expect(expandWorkspaces(dir, ["packages/{a,{b,c}}", "!packages/c"])).toEqual({ dirs: ["packages/a", "packages/b"], complete: true });
  });

  it("a dependency on a member named by a brace pattern is not a missing entry", () => {
    const dir = project({
      "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/{a,b}"], dependencies: { ms: "2.1.3", "ws-b": "^1.0.0" } }),
      "packages/a/package.json": member("ws-a"),
      "packages/b/package.json": member("ws-b"),
      "yarn.lock": YARN,
    });
    expect(resolveVersionSource(dir, "npm").problems ?? []).toEqual([]);
  });

  it("an unreadable member package.json: names that may be members are not called missing", () => {
    const dir = project({
      "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"], dependencies: { ms: "2.1.3", "ws-b": "^1.0.0" } }),
      "packages/a/package.json": member("ws-a"),
      "packages/b/package.json": "{ not json",
      "yarn.lock": YARN,
    });
    // Not damage: the one note says the lockfile was not cross-checked, and why (a1119-advice2-uncrossed.test.ts).
    const problems = resolveVersionSource(dir, "npm").problems ?? [];
    expect(problems).toEqual([expect.objectContaining({ notCrossChecked: true })]);
    expect(problems[0].partial).toBeUndefined();
  });

  it("with the member list whole, a declared name no member has is still a missing entry", () => {
    const dir = project({
      "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"], dependencies: { ms: "2.1.3", "ws-b": "^1.0.0" } }),
      "packages/a/package.json": member("ws-a"),
      "yarn.lock": YARN,
    });
    expect((resolveVersionSource(dir, "npm").problems ?? [])[0]?.error).toMatch(/package\.json declares ws-b \(dependencies\)/);
  });
});
