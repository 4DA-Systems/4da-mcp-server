// SPDX-License-Identifier: Apache-2.0
/**
 * Names withheld because a project takes them from a path, git, a URL, its workspace or an alias are
 * scoped (re-check of 0d30b40, 2026-11-24, cases b3-remember, b7-catedit): 7068665 remembered them
 * for the whole process and every project, so
 * - a removed alias key and a catalog entry changed from `link:` to `^2.1.3` stayed "private";
 * - a project that declares the same name as a registry range without a lockfile could not check it;
 * - public names (lodash or @types/react as alias keys, requests from git) were uncheckable everywhere;
 * - the answer called them "a private package" and pointed at private-registry tooling.
 * The rule now (private-guard.ts nonRegistryElsewhere): a name some scanned project takes from a
 * non-registry source is withheld in another project while that project still declares it so,
 * unless the project being asked about declares it as a registry dependency; alias keys stay inside
 * their own project; the answer says why, in words that do not call it private.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { resetPrivateGuard } from "../live/private-guard.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  resetPrivateGuard();
  h = createHarness();
  h.NPM = {
    ms: { latest: "2.1.3", versions: { "2.1.3": {} } },
    lodash: { latest: "4.17.21", versions: { "4.17.21": {} } },
    "types-react": { latest: "19.0.0", versions: { "19.0.0": {} } },
    "@types/react": { latest: "19.0.0", versions: { "19.0.0": {} } },
  };
  h.PYPI = { requests: { "2.32.3": {} } };
  h.write(".git/HEAD", "ref: refs/heads/main\n");
});
afterEach(() => {
  h.dispose();
  resetPrivateGuard();
});

function liveIn(dir: string): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}
function rewrite(file: string, body: string) {
  h.write(file, body);
  const later = new Date(Date.now() + 5000);
  fs.utimesSync(path.join(h.dir, file), later, later);
}
async function check(live: LiveIntelligence, ecosystem: string, pkg: string) {
  const r = (await executeDependencyCheck(null, { items: [{ ecosystem, package: pkg, to: "1.0.1" }] }, live)) as { results: Array<{ verdict: string; not_checked?: string; reason: string }> };
  return r.results[0];
}

describe("withheld only while the project still declares it so", () => {
  it("an alias key removed from package.json is checked again", async () => {
    h.write("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", dependencies: { lodash: "npm:ms@2.1.3" } }));
    const live = liveIn(path.join(h.dir, "a"));
    expect((await check(live, "npm", "lodash")).not_checked).toBe("private");
    rewrite("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    live.refreshIfLockfilesChanged();
    expect((await check(live, "npm", "lodash")).not_checked).toBeUndefined();
  });

  it("a catalog entry changed from link: to a range is checked again, in a second project too", async () => {
    h.write("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", dependencies: { ms: "catalog:" } }));
    h.write("a/pnpm-workspace.yaml", "catalog:\n  ms: link:../ms\n");
    h.write("b/package.json", JSON.stringify({ name: "b", version: "1.0.0", dependencies: { lodash: "4.17.21" } }));
    const a = liveIn(path.join(h.dir, "a"));
    await executeDependencyHealth(null, {}, a);
    expect((await check(liveIn(path.join(h.dir, "b")), "npm", "ms")).not_checked).toBe("private");
    rewrite("a/pnpm-workspace.yaml", "catalog:\n  ms: ^2.1.3\n");
    a.refreshIfLockfilesChanged();
    expect((await check(a, "npm", "ms")).not_checked).toBeUndefined();
    expect((await check(liveIn(path.join(h.dir, "b")), "npm", "ms")).not_checked).toBeUndefined();
  });
});

describe("another project that declares the name from a registry asks about it", () => {
  it("a declared range with no lockfile is enough", async () => {
    h.write("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", dependencies: { lodash: "file:../vendor/lodash" } }));
    h.write("b/package.json", JSON.stringify({ name: "b", version: "1.0.0", dependencies: { lodash: "^4.17.0" } }));
    await executeDependencyHealth(null, {}, liveIn(path.join(h.dir, "a")));
    expect((await check(liveIn(path.join(h.dir, "b")), "npm", "lodash")).not_checked).toBeUndefined();
  });
});

describe("alias keys stay inside their project", () => {
  it("@types/react and lodash as alias keys in one project are checked in another", async () => {
    h.write("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", dependencies: { "@types/react": "npm:types-react@19.0.0", lodash: "npm:ms@2.1.3" } }));
    h.write("b/package.json", JSON.stringify({ name: "b", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    await executeDependencyHealth(null, {}, liveIn(path.join(h.dir, "a")));
    const b = liveIn(path.join(h.dir, "b"));
    expect((await check(b, "npm", "@types/react")).not_checked).toBeUndefined();
    expect((await check(b, "npm", "lodash")).not_checked).toBeUndefined();
  });
});

describe("the answer says why, and never calls the name a private package", () => {
  it("a name another project takes from git", async () => {
    h.write("a/requirements.txt", "idna==3.7\nrequests @ git+https://github.com/psf/requests@v2.31.0\n");
    h.write("b/package.json", JSON.stringify({ name: "b", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    await executeDependencyHealth(null, {}, liveIn(path.join(h.dir, "a")));
    const r = await check(liveIn(path.join(h.dir, "b")), "PyPI", "requests");
    expect(r.not_checked).toBe("private");
    expect(r.reason).toMatch(/^NOT CHECKED \(not a registry release\)/);
    expect(r.reason).toContain(path.join(h.dir, "a"));
    expect(r.reason).not.toMatch(/private package|private registry/);
  });

  it("inside the project, an alias key and a path dependency", async () => {
    h.write("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", dependencies: { "acme-key": "npm:ms@2.1.3", "acme-dir": "file:../acme-dir" } }));
    const live = liveIn(path.join(h.dir, "a"));
    for (const pkg of ["acme-key", "acme-dir"]) {
      const r = await check(live, "npm", pkg);
      expect(r.reason).toMatch(/^NOT CHECKED \(not a registry release\)/);
      expect(r.reason).not.toMatch(/private package|private registry/);
    }
  });
});
