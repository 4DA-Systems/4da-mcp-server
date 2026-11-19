// SPDX-License-Identifier: Apache-2.0
/**
 * Settles whether yarn.lock's lack of local parent edges (it names no manifest as a parent) keeps
 * upgrade_planner from reaching the declared dependency above a transitive copy. The same project
 * (root declares mkdirp 0.5.1, which pins minimist 0.0.8) is planned from a package-lock.json and
 * from a yarn.lock (classic and berry): the step should name mkdirp as the parent to move in all three.
 * Today it does for npm only (the yarn cases are marked as known failures below).
 */

import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { npmAdvisory, removeProject, stubOsv, tempProject, type NpmDoc } from "./helpers/a1119-readers.js";

const MINIMIST = npmAdvisory("GHSA-xvch-5gv4-984h", "minimist", "1.2.6", "CRITICAL");
const DOCS: Record<string, NpmDoc> = {
  minimist: { latest: "1.2.8", versions: { "0.0.8": {}, "1.2.6": {}, "1.2.8": {} } },
  mkdirp: { latest: "0.5.6", versions: { "0.5.1": { dependencies: { minimist: "0.0.8" } }, "0.5.6": { dependencies: { minimist: "^1.2.6" } } } },
};
const ROOT = JSON.stringify({ name: "app", version: "1.0.0", dependencies: { mkdirp: "0.5.1" } });

const LOCKS: Record<string, Record<string, string>> = {
  npm: {
    "package-lock.json": JSON.stringify({
      name: "app",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "app", version: "1.0.0", dependencies: { mkdirp: "0.5.1" } },
        "node_modules/mkdirp": { version: "0.5.1", resolved: "https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.1.tgz", integrity: "sha512-AAAA", dependencies: { minimist: "0.0.8" } },
        "node_modules/minimist": { version: "0.0.8", resolved: "https://registry.npmjs.org/minimist/-/minimist-0.0.8.tgz", integrity: "sha512-AAAA" },
      },
    }),
  },
  "yarn classic": {
    "yarn.lock":
      '# yarn lockfile v1\n\n\nminimist@0.0.8:\n  version "0.0.8"\n  resolved "https://registry.yarnpkg.com/minimist/-/minimist-0.0.8.tgz"\n  integrity sha512-AAAA\n\nmkdirp@0.5.1:\n  version "0.5.1"\n  resolved "https://registry.yarnpkg.com/mkdirp/-/mkdirp-0.5.1.tgz"\n  integrity sha512-AAAA\n  dependencies:\n    minimist "0.0.8"\n',
  },
  "yarn berry": {
    "yarn.lock": [
      "__metadata:",
      "  version: 8",
      "  cacheKey: 10c0",
      "",
      '"app@workspace:.":',
      "  version: 0.0.0-use.local",
      '  resolution: "app@workspace:."',
      "  dependencies:",
      '    mkdirp: "npm:0.5.1"',
      "  languageName: unknown",
      "  linkType: soft",
      "",
      '"minimist@npm:0.0.8":',
      "  version: 0.0.8",
      '  resolution: "minimist@npm:0.0.8"',
      "  checksum: 10c0/00",
      "  languageName: node",
      "  linkType: hard",
      "",
      '"mkdirp@npm:0.5.1":',
      "  version: 0.5.1",
      '  resolution: "mkdirp@npm:0.5.1"',
      "  dependencies:",
      '    minimist: "npm:0.0.8"',
      "  checksum: 10c0/00",
      "  languageName: node",
      "  linkType: hard",
      "",
    ].join("\n"),
  },
};

describe("a transitive copy under a declared dependency, per lockfile", () => {
  let dirs: string[];
  let priorOffline: string | undefined;
  beforeEach(() => {
    dirs = [];
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    dirs.forEach(removeProject);
  });

  for (const [kind, lock] of Object.entries(LOCKS)) {
    // Settled 2026-11-19: real for yarn. With no local edge the planner cannot see that the root declares
    // mkdirp ("the lockfile names no parent of mkdirp 0.5.1"), so the step is upgrade_parent_unverified with
    // no command. Fail-closed, but weaker than npm's. `it.fails` until yarn.lock gets local edges.
    (kind === "npm" ? it : it.fails)(`${kind}: the step names mkdirp, the declared parent, as what to upgrade`, async () => {
      stubOsv([MINIMIST], DOCS);
      const dir = tempProject({ "package.json": ROOT, ...lock });
      dirs.push(dir);
      const live = new LiveIntelligence(new Database(":memory:"));
      const { entries, discovery } = scanProjectTree(dir);
      live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
      const plan = (await executeUpgradePlanner(null as never, { project_path: dir } as never, live)) as Record<string, any>;
      const row = plan.recommendations.find((r: { package: string }) => r.package === "minimist");
      expect(row).toMatchObject({ scope: "transitive", action: "upgrade_parent" });
      expect(JSON.stringify(row.parentUpgrades)).toMatch(/"name":"mkdirp"/);
    });
  }
});
