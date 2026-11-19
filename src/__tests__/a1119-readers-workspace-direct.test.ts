// SPDX-License-Identifier: Apache-2.0
/**
 * A dependency a workspace member declares, or one the root declares in
 * optionalDependencies or peerDependencies, is a direct dependency of the
 * project: graded and labelled as one (a transitive-only copy has its critical
 * advisories capped at high), described in the section that declares it, and
 * moved where it is declared.
 *
 * pnpm10-workspace-direct is a lockfile pnpm 10 wrote; the others are inline,
 * in the formats npm, Yarn and Bun write.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { bunParents, pnpmParents } from "../live/lockfile-parents.js";
import { resolveGroup } from "../live/resolution.js";
import { scanCurrentProject } from "../project-scanner.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { fixtureProject, npmAdvisory, removeProject, scanProject, stubOsv, tempProject, type NpmDoc } from "./helpers/a1119-readers.js";

const MINIMIST = npmAdvisory("GHSA-xvch-5gv4-984h", "minimist", "0.2.4", "CRITICAL");
const MINIMIST_DOC: NpmDoc = { latest: "1.2.8", versions: { "0.0.8": {}, "0.2.4": {}, "1.2.8": {} } };

/** The audit set of the project in `dir`, as `name@version` -> scope and "direct". */
function auditScopes(dir: string): Record<string, string> {
  const npm = scanCurrentProject(dir).depsByEcosystem.npm ?? { deps: [], devDeps: [] };
  const { audit } = resolveGroup({ dir, language: "npm", deps: npm.deps, devDeps: npm.devDeps, targets: {} });
  return Object.fromEntries(audit.map((d) => [`${d.name}@${d.version}`, `${!d.devScopeKnown ? "unknown" : d.isDev ? "dev" : "runtime"}${d.isDirect ? " direct" : ""}`]));
}

function liveFor(dir: string): LiveIntelligence {
  const live = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return live;
}

/** upgrade_planner for `dir`, on `live` (a layer of its own by default). */
async function plan(dir: string, extra: Record<string, unknown> = {}, live = liveFor(dir)): Promise<Record<string, any>> {
  return (await executeUpgradePlanner(null as never, { project_path: dir, ...extra } as never, live)) as Record<string, any>;
}

const PNPM_MEMBER_DEV = {
  "package.json": JSON.stringify({ private: true }),
  "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n",
  "packages/api/package.json": JSON.stringify({ name: "api", private: true, devDependencies: { minimist: "0.0.8" } }),
  "pnpm-lock.yaml": [
    "lockfileVersion: '9.0'",
    "",
    "settings:",
    "  autoInstallPeers: true",
    "  excludeLinksFromLockfile: false",
    "",
    "importers:",
    "",
    "  .: {}",
    "",
    "  packages/api:",
    "    devDependencies:",
    "      minimist:",
    "        specifier: 0.0.8",
    "        version: 0.0.8",
    "",
    "packages:",
    "",
    "  minimist@0.0.8:",
    "    resolution: {integrity: sha512-AAAA}",
    "",
    "snapshots:",
    "",
    "  minimist@0.0.8: {}",
    "",
  ].join("\n"),
};

const npmLock = (packages: Record<string, unknown>) => JSON.stringify({ name: "root", lockfileVersion: 3, requires: true, packages });
const tgz = (name: string, version: string) => ({ version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: "sha512-AAAA" });

describe("a dependency any manifest of the project declares is direct", () => {
  let dirs: string[];
  let priorOffline: string | undefined;
  const project = (dir: string) => {
    dirs.push(dir);
    return dir;
  };

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

  it("pnpm 10: a workspace member's dependency is direct, at the advisory's own severity", async () => {
    const dir = project(fixtureProject("pnpm10-workspace-direct"));
    expect(auditScopes(dir)).toEqual({ "minimist@0.0.8": "runtime direct" });
    stubOsv([MINIMIST]);
    const answer = await scanProject(dir);
    expect(answer.vulnerabilities[0]).toMatchObject({ package: "minimist", is_direct: true, is_dev: false, severity: "critical", advisory_severity: "critical" });
  });

  it("npm: a workspace member's dependency and the root's optional and peer dependencies are direct", () => {
    const manifest = { name: "root", private: true, workspaces: ["packages/*"], optionalDependencies: { wordwrap: "0.0.3" }, peerDependencies: { ms: "2.0.0" } };
    const dir = project(
      tempProject({
        "package.json": JSON.stringify(manifest),
        "packages/api/package.json": JSON.stringify({ name: "api", version: "1.0.0", dependencies: { minimist: "0.0.8" } }),
        "package-lock.json": npmLock({
          "": manifest,
          "node_modules/api": { resolved: "packages/api", link: true },
          "node_modules/minimist": tgz("minimist", "0.0.8"),
          "node_modules/ms": { ...tgz("ms", "2.0.0"), peer: true },
          "node_modules/wordwrap": { ...tgz("wordwrap", "0.0.3"), optional: true },
          "packages/api": { name: "api", version: "1.0.0", dependencies: { minimist: "0.0.8" } },
        }),
      }),
    );
    expect(auditScopes(dir)).toEqual({ "minimist@0.0.8": "runtime direct", "ms@2.0.0": "runtime direct", "wordwrap@0.0.3": "runtime direct" });
  });

  it("only the copy a declaration resolves to is direct: another version of the name stays transitive", () => {
    const root = { name: "root", private: true, workspaces: ["packages/*"], dependencies: { minimist: "^1.2.8", mkdirp: "0.5.1" } };
    const dir = project(
      tempProject({
        "package.json": JSON.stringify(root),
        "packages/api/package.json": JSON.stringify({ name: "api", version: "1.0.0", dependencies: { minimist: "0.0.8" } }),
        "package-lock.json": npmLock({
          "": root,
          "node_modules/api": { resolved: "packages/api", link: true },
          "node_modules/minimist": tgz("minimist", "1.2.8"),
          "node_modules/mkdirp": { ...tgz("mkdirp", "0.5.1"), dependencies: { minimist: "0.0.10" } },
          "node_modules/mkdirp/node_modules/minimist": tgz("minimist", "0.0.10"),
          "packages/api": { name: "api", version: "1.0.0", dependencies: { minimist: "0.0.8" } },
          "packages/api/node_modules/minimist": tgz("minimist", "0.0.8"),
        }),
      }),
    );
    expect(auditScopes(dir)).toEqual({
      "minimist@1.2.8": "runtime direct",
      "mkdirp@0.5.1": "runtime direct",
      "minimist@0.0.10": "runtime",
      "minimist@0.0.8": "runtime direct",
    });
  });

  it("yarn classic and berry: a workspace member's dependency is direct", () => {
    const member = JSON.stringify({ name: "api", version: "1.0.0", dependencies: { minimist: "0.0.8" } });
    const classic = project(
      tempProject({
        "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }),
        "packages/api/package.json": member,
        "yarn.lock":
          '# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\nminimist@0.0.8:\n  version "0.0.8"\n  resolved "https://registry.yarnpkg.com/minimist/-/minimist-0.0.8.tgz#857fcabfc3397d2625b8228262e86aa7a011b05d"\n  integrity sha512-AAAA\n',
      }),
    );
    expect(auditScopes(classic)).toEqual({ "minimist@0.0.8": "runtime direct" });
    const berry = project(
      tempProject({
        "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }),
        "packages/api/package.json": member,
        "yarn.lock": [
          "# This file is generated by running \"yarn install\" inside your project.",
          "# Manual changes might be lost - proceed with caution!",
          "",
          "__metadata:",
          "  version: 8",
          "  cacheKey: 10c0",
          "",
          '"api@workspace:packages/api":',
          "  version: 0.0.0-use.local",
          '  resolution: "api@workspace:packages/api"',
          "  dependencies:",
          '    minimist: "npm:0.0.8"',
          "  languageName: unknown",
          "  linkType: soft",
          "",
          '"minimist@npm:0.0.8":',
          "  version: 0.0.8",
          '  resolution: "minimist@npm:0.0.8"',
          "  checksum: 10c0/0123456789abcdef",
          "  languageName: node",
          "  linkType: hard",
          "",
          '"root@workspace:.":',
          "  version: 0.0.0-use.local",
          '  resolution: "root@workspace:."',
          "  languageName: unknown",
          "  linkType: soft",
          "",
        ].join("\n"),
      }),
    );
    expect(auditScopes(berry)).toEqual({ "minimist@0.0.8": "runtime direct" });
  });

  it("bun: a workspace member's dependency is direct, and its parent edge names the member and the section", () => {
    const lock = {
      lockfileVersion: 1,
      workspaces: { "": { name: "root" }, "packages/api": { name: "api", devDependencies: { minimist: "0.0.8" } } },
      packages: { api: ["api@workspace:packages/api"], minimist: ["minimist@0.0.8", "", {}, "sha512-AAAA=="] },
    };
    const dir = project(
      tempProject({
        "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }),
        "packages/api/package.json": JSON.stringify({ name: "api", version: "1.0.0", devDependencies: { minimist: "0.0.8" } }),
        "bun.lock": JSON.stringify(lock, null, 2),
      }),
    );
    expect(auditScopes(dir)).toEqual({ "minimist@0.0.8": "dev direct" });
    expect(bunParents(lock as never, "minimist", "0.0.8")).toEqual([expect.objectContaining({ local: true, dir: "packages/api", section: "devDependencies", range: "0.0.8" })]);
  });

  it("pnpm: a member's devDependency is dev-only and direct, and its parent edge names its own section", () => {
    const dir = project(tempProject(PNPM_MEMBER_DEV));
    expect(auditScopes(dir)).toEqual({ "minimist@0.0.8": "dev direct" });
    expect(pnpmParents(PNPM_MEMBER_DEV["pnpm-lock.yaml"], "minimist", "0.0.8")).toEqual([
      expect.objectContaining({ local: true, dir: "packages/api", section: "devDependencies", range: "0.0.8" }),
    ]);
  });

  it("the plan and the scan move a member's dependency in that member's directory, in the section it is declared in", async () => {
    stubOsv([MINIMIST], { minimist: MINIMIST_DOC });
    const dir = project(tempProject(PNPM_MEMBER_DEV));
    const row = (await plan(dir)).recommendations.find((r: { package: string }) => r.package === "minimist");
    expect(row).toMatchObject({ scope: "direct", action: "upgrade_direct", currentVersion: "0.0.8", targetVersion: "0.2.4", isDev: true });
    expect(row.upgradeCommands).toEqual([expect.objectContaining({ dir: "packages/api", command: expect.stringContaining("minimist@0.2.4") })]);
    const reasons = row.reasons.join(" ");
    expect(reasons).toMatch(/Declared by workspace member packages\/api\/package\.json \(devDependencies "0\.0\.8"\)/);
    expect(reasons).not.toMatch(/\(dependencies "0\.0\.8"\)|not declared in your manifest/);

    const scan = await scanProject(dir);
    expect(scan.vulnerabilities[0]).toMatchObject({ is_direct: true, is_dev: true, severity: "high", advisory_severity: "critical" });
    expect(scan.fix_targets["minimist@0.0.8"]).toMatchObject({ target: "0.2.4", action: "upgrade_direct", commands: [expect.objectContaining({ dir: "packages/api" })] });
  });

  it("include_dev:false over a scan that read dev copies counts a member's vulnerable devDependency as a devDependency", async () => {
    stubOsv([MINIMIST], { minimist: MINIMIST_DOC });
    const dir = project(tempProject(PNPM_MEMBER_DEV));
    const live = liveFor(dir);
    expect((await plan(dir, {}, live)).recommendations.map((r: { package: string }) => r.package)).toEqual(["minimist"]);
    const answer = await plan(dir, { include_dev: false }, live);
    expect(answer.recommendations).toEqual([]);
    expect(answer.summary).toMatch(/include_dev: false left out 1 vulnerable devDependency \(/);
    expect(answer.summary).not.toMatch(/transitive cop/);
  });
});
