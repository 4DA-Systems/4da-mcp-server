// SPDX-License-Identifier: Apache-2.0
/**
 * A start folder with no manifest is read as the project above it only inside a git repository, and
 * never above that repository's root. Check of round 2 (2026-11-24, real2/b-nogit): with no `.git`
 * above, a server started in an empty `newapp/` beside `sibling/` read the parent as the project, so
 * the first call scanned the parent's dependencies (2,979 ms against 112 ms) and the parent was
 * recorded as the project. Without a repository nothing above the start folder is read, as in 6.5.0.
 */

import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { nearestProjectAbove } from "../project-tree.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

describe("nearestProjectAbove", () => {
  it("no repository: no climb (b-nogit)", () => {
    h.write("package.json", JSON.stringify({ name: "parent", dependencies: { ms: "2.1.3" } }));
    h.write("sibling/package.json", JSON.stringify({ name: "sibling" }));
    h.write("newapp/.keep", "");
    expect(nearestProjectAbove(path.join(h.dir, "newapp"))).toBeNull();
  });

  it("inside a repository: the project folder above, never above the repository root", () => {
    h.write("repo/.git/HEAD", "ref: refs/heads/main\n");
    h.write("repo/app/package.json", JSON.stringify({ name: "app" }));
    h.write("repo/app/src/lib/index.js", "export {};\n");
    h.write("package.json", JSON.stringify({ name: "outside" }));
    h.write("repo/notes/todo.md", "x\n");
    expect(nearestProjectAbove(path.join(h.dir, "repo", "app", "src", "lib"))).toBe(path.join(h.dir, "repo", "app"));
    // The repository's root is not a project, and what is above it is never read.
    expect(nearestProjectAbove(path.join(h.dir, "repo", "notes"))).toBeNull();
    expect(nearestProjectAbove(path.join(h.dir, "repo"))).toBeNull();
  });
});
