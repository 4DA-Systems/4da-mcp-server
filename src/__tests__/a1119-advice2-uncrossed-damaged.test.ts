// SPDX-License-Identifier: Apache-2.0
/**
 * A lockfile can be damaged AND not cross-checked against its manifests: both notes reach the
 * answer. The project's problems were kept one per file, so the NOT CROSS-CHECKED note was
 * dropped whenever the same yarn.lock already carried a PARTIAL one.
 */

import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { removeProject, scanProject, stubOsv, tempProject } from "./helpers/a1119-readers.js";

/** ms names a dependency (debug) no entry installs: the file stops early. */
const YARN = `# yarn lockfile v1\n\n\nms@2.1.3:\n  version "2.1.3"\n  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz"\n  integrity sha512-AAAA\n  dependencies:\n    debug "^4.3.4"\n`;
const FILES = {
  "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"], dependencies: { ms: "2.1.3", "ws-b": "^1.0.0" } }),
  "packages/a/package.json": JSON.stringify({ name: "ws-a", version: "1.0.0" }),
  "packages/b/package.json": "{ not json",
  "yarn.lock": YARN,
};

describe("a damaged lockfile that was also not cross-checked", () => {
  let dir: string;
  let priorOffline: string | undefined;
  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = tempProject(FILES);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    removeProject(dir);
  });

  it("carries both notes, each once", async () => {
    const live = new LiveIntelligence(new Database(":memory:"));
    const { entries, discovery } = scanProjectTree(dir);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    const problems = live.getLockfileProblems();
    expect(problems.filter((p) => p.partial)).toHaveLength(1);
    expect(problems.filter((p) => p.notCrossChecked)).toHaveLength(1);

    stubOsv([]);
    const scan = await scanProject(dir);
    expect(scan.coverage.note).toMatch(/PARTIAL: 1 lockfile was NOT read to the end: yarn\.lock/);
    expect(scan.coverage.note).toMatch(/NOT CROSS-CHECKED: 1 lockfile was not cross-checked against the manifests that declare its dependencies: yarn\.lock/);
    expect(scan.coverage.partial_lockfiles).toHaveLength(1);
    expect(scan.coverage.not_cross_checked_lockfiles).toHaveLength(1);
  });
});
