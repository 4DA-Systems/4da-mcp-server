// SPDX-License-Identifier: Apache-2.0
/**
 * yarn.lock names no manifest as a parent, so its local parent edges come from the package.json
 * files (the project's and each workspace member's), claimed only where the lockfile keys that
 * declared descriptor to the copy. With them a transitive fix in a Yarn project names the declared
 * parent to upgrade, with its command, as from a package-lock.json. The same project (root declares
 * mkdirp 0.5.1, which pins minimist 0.0.8) is planned from npm, yarn classic and berry lockfiles.
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
    it(`${kind}: the step names mkdirp, the declared parent, as what to upgrade`, async () => {
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
      expect(row.parentUpgrades[0].levers[0].commands).toEqual([{ dir: ".", command: COMMANDS[kind] }]);
    });
  }

  const planRow = async (files: Record<string, string>, docs: Record<string, NpmDoc> = DOCS) => {
    stubOsv([MINIMIST], docs);
    const dir = tempProject(files);
    dirs.push(dir);
    const live = new LiveIntelligence(new Database(":memory:"));
    const { entries, discovery } = scanProjectTree(dir);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    const plan = (await executeUpgradePlanner(null as never, { project_path: dir } as never, live)) as Record<string, any>;
    return plan.recommendations.find((r: { package: string }) => r.package === "minimist");
  };
  const classicBlock = (keys: string, version: string, deps: Record<string, string> = {}) =>
    `${keys}:
  version "${version}"
  resolved "https://registry.yarnpkg.com/x/-/x-${version}.tgz"
  integrity sha512-AAAA
${Object.keys(deps).length > 0 ? `  dependencies:
${Object.entries(deps).map(([d, r]) => `    ${d} "${r}"
`).join("")}` : ""}
`;

  it("two declared parents share one entry under two specifiers: each is named, with its command", async () => {
    const docs: Record<string, NpmDoc> = { ...DOCS, optimist: { latest: "0.6.2", versions: { "0.6.1": { dependencies: { minimist: "~0.0.8" } }, "0.6.2": { dependencies: { minimist: "^1.2.6" } } } } };
    const row = await planRow(
      {
        "package.json": JSON.stringify({ name: "app", dependencies: { mkdirp: "0.5.1", optimist: "0.6.1" } }),
        "yarn.lock": `# yarn lockfile v1


${classicBlock("minimist@0.0.8, minimist@~0.0.8", "0.0.8")}${classicBlock("mkdirp@0.5.1", "0.5.1", { minimist: "0.0.8" })}${classicBlock("optimist@0.6.1", "0.6.1", { minimist: "~0.0.8" })}`,
      },
      docs,
    );
    expect(row).toMatchObject({ action: "upgrade_parent" });
    const names = row.parentUpgrades.map((u: { parent: string }) => u.parent).sort();
    expect(names).toEqual(["mkdirp", "optimist"]);
    const commands = row.parentUpgrades.flatMap((u: { levers: Array<{ commands?: Array<{ command: string }> }> }) => u.levers.flatMap((l) => (l.commands ?? []).map((c) => c.command))).sort();
    expect(commands).toEqual(["yarn upgrade mkdirp@0.5.6", "yarn upgrade optimist@0.6.2"]);
  });

  it("a damaged lockfile (the parent's specifier keys no entry): stays unverified, no parent is guessed", async () => {
    const row = await planRow({
      "package.json": ROOT,
      "yarn.lock": `# yarn lockfile v1


${classicBlock("minimist@0.0.8", "0.0.8")}${classicBlock("mkdirp@0.5.1", "0.5.1", { minimist: "^0.0.8" })}`,
    });
    expect(row.action).not.toBe("upgrade_parent");
    expect(JSON.stringify(row)).not.toMatch(/"command"/);
  });

  it("a workspace member as the declaring parent: the lever is named, run in that member", async () => {
    const row = await planRow({
      "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }),
      "packages/api/package.json": JSON.stringify({ name: "api", version: "1.0.0", dependencies: { mkdirp: "0.5.1" } }),
      "yarn.lock": LOCKS["yarn classic"]["yarn.lock"],
    });
    expect(row).toMatchObject({ scope: "transitive", action: "upgrade_parent" });
    expect(row.parentUpgrades[0].levers[0].commands).toEqual([{ dir: "packages/api", command: "yarn workspace api add mkdirp@0.5.6" }]);
  });
});

const COMMANDS: Record<string, string> = { npm: "npm install mkdirp@0.5.6 --save-exact", "yarn classic": "yarn upgrade mkdirp@0.5.6", "yarn berry": "yarn up mkdirp@0.5.6" };
