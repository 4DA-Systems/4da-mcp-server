// SPDX-License-Identifier: Apache-2.0
/**
 * A yarn.lock's local parent edges are read from the package.json files, so its cached parent
 * index is current only while those are unchanged as well as the lockfile: a manifest edited
 * without touching yarn.lock rebuilds the edges, and no step names a parent it no longer declares.
 * Keyed on the manifests' content, so the outcome does not depend on timestamp granularity.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { clearLockfileParentCache, lockfileParentReads, readLockfileParents } from "../live/lockfile-parents.js";
import { removeProject, tempProject } from "./helpers/a1119-readers.js";

const LOCK =
  '# yarn lockfile v1\n\n\nminimist@0.0.8:\n  version "0.0.8"\n  resolved "https://registry.yarnpkg.com/minimist/-/minimist-0.0.8.tgz"\n  integrity sha512-AAAA\n\nmkdirp@0.5.1:\n  version "0.5.1"\n  resolved "https://registry.yarnpkg.com/mkdirp/-/mkdirp-0.5.1.tgz"\n  integrity sha512-AAAA\n  dependencies:\n    minimist "0.0.8"\n';

describe("yarn local parent edges follow the manifests", () => {
  let dir: string;
  afterEach(() => removeProject(dir));

  const localParents = (name: string, version: string) =>
    (readLockfileParents(path.join(dir, "yarn.lock"), name, version)?.edges ?? []).filter((e) => e.local).map((e) => `${e.dir} ${e.section}`);

  it("a root manifest changed without touching yarn.lock rebuilds the edges", () => {
    clearLockfileParentCache();
    dir = tempProject({ "package.json": JSON.stringify({ name: "app", dependencies: { mkdirp: "0.5.1" } }), "yarn.lock": LOCK });
    expect(localParents("mkdirp", "0.5.1")).toEqual([". dependencies"]);
    // Same length on purpose: only the content says it changed.
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", dependencies: { mkdirx: "0.5.1" } }));
    expect(localParents("mkdirp", "0.5.1")).toEqual([]);
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", devDependencies: { mkdirp: "0.5.1" } }));
    expect(localParents("mkdirp", "0.5.1")).toEqual([". devDependencies"]);
  });

  it("a workspace member's manifest too, and an unchanged one is not re-read", () => {
    clearLockfileParentCache();
    dir = tempProject({
      "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }),
      "packages/api/package.json": JSON.stringify({ name: "api", dependencies: { mkdirp: "0.5.1" } }),
      "yarn.lock": LOCK,
    });
    expect(localParents("mkdirp", "0.5.1")).toEqual(["packages/api dependencies"]);
    const reads = lockfileParentReads();
    expect(localParents("mkdirp", "0.5.1")).toEqual(["packages/api dependencies"]);
    expect(lockfileParentReads()).toBe(reads);
    fs.writeFileSync(path.join(dir, "packages", "api", "package.json"), JSON.stringify({ name: "api", dependencies: { mkdirq: "0.5.1" } }));
    expect(localParents("mkdirp", "0.5.1")).toEqual([]);
  });
});
