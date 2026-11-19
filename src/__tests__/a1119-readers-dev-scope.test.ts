// SPDX-License-Identifier: Apache-2.0
/**
 * A package is dev-only only when no runtime root reaches it: not a
 * `dependencies`, `optionalDependencies` or `peerDependencies` entry of the
 * project or of a workspace member, and nothing those install. A copy any
 * runtime path reaches is runtime, whatever else lists it; a copy whose scope
 * cannot be established is unknown, which every tool treats as runtime.
 *
 * npm-devdirect, pnpm8-peer-variants, pnpm10-devdirect and bun-peer-vuln are
 * lockfiles the package managers wrote; the yarn ones are in the format yarn
 * writes.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { readBunLock } from "../live/bun-lockfile.js";
import { readPnpmLock } from "../live/js-lockfile-readers.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { InstanceSet } from "../live/lockfile-types.js";
import { resolveGroup } from "../live/resolution.js";
import { scanCurrentProject } from "../project-scanner.js";
import { fixtureProject, npmAdvisory, removeProject, scanProject, stubOsv, tempProject, vulnerableCopies } from "./helpers/a1119-readers.js";

const MINIMIST = npmAdvisory("GHSA-xvch-5gv4-984h", "minimist", "0.2.4", "CRITICAL");
const WS = npmAdvisory("GHSA-6fc8-4gx4-v693", "ws", "7.4.6", "MODERATE", "7.0.0");
const AJV = npmAdvisory("GHSA-v88g-cgmw-v5xw", "ajv", "6.12.3", "MODERATE");

/** The audit set of the project in `dir`, as `name@version` -> [scope, direct?]. */
function auditScopes(dir: string): Record<string, string> {
  const scan = scanCurrentProject(dir);
  const npm = scan.depsByEcosystem.npm ?? { deps: [], devDeps: [] };
  const { audit } = resolveGroup({ dir, language: "npm", deps: npm.deps, devDeps: npm.devDeps, targets: {} });
  return Object.fromEntries(
    audit.map((d) => [`${d.name}@${d.version}`, `${!d.devScopeKnown ? "unknown" : d.isDev ? "dev" : "runtime"}${d.isDirect ? " direct" : ""}`]),
  );
}

/** What a lockfile reader says of each copy: true (dev-only), false (runtime) or "unknown". */
function lockScopes(dir: string): Record<string, boolean | "unknown"> {
  return Object.fromEntries(resolveVersionSource(dir, "npm").instances.map((i) => [`${i.name}@${i.version}`, i.dev ?? "unknown"]));
}

describe("dev-only is only what no runtime root reaches", () => {
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

  describe("npm: a devDependency a runtime dependency also needs", () => {
    it("is graded runtime, because the lockfile does not mark the copy dev", () => {
      const scopes = auditScopes(project(fixtureProject("npm-devdirect")));
      expect(scopes).toEqual({
        "optimist@0.6.1": "runtime direct",
        "minimist@0.0.8": "runtime direct",
        "wordwrap@0.0.3": "runtime",
      });
    });

    it("is still scanned with include_dev:false, at the advisory's own severity", async () => {
      stubOsv([MINIMIST]);
      const dir = project(fixtureProject("npm-devdirect"));
      const answer = await scanProject(dir, { include_dev: false });
      expect(vulnerableCopies(answer)).toEqual(["minimist@0.0.8"]);
      expect(answer.vulnerabilities[0]).toMatchObject({ is_dev: false, is_direct: true, severity: "critical", advisory_severity: "critical" });
    });

    it("a devDependency the lockfile marks dev stays dev-only and is left out by include_dev:false", async () => {
      stubOsv([MINIMIST]);
      const lock = {
        name: "x",
        lockfileVersion: 3,
        packages: {
          "": { name: "x", dependencies: { wordwrap: "0.0.3" }, devDependencies: { minimist: "0.0.8" } },
          "node_modules/minimist": { version: "0.0.8", dev: true },
          "node_modules/wordwrap": { version: "0.0.3" },
        },
      };
      const dir = project(tempProject({
        "package.json": JSON.stringify({ name: "x", dependencies: { wordwrap: "0.0.3" }, devDependencies: { minimist: "0.0.8" } }),
        "package-lock.json": JSON.stringify(lock),
      }));
      expect(auditScopes(dir)).toEqual({ "wordwrap@0.0.3": "runtime direct", "minimist@0.0.8": "dev direct" });
      const answer = await scanProject(dir, { include_dev: false });
      expect(vulnerableCopies(answer)).toEqual([]);
      expect((await scanProject(dir)).vulnerabilities[0]).toMatchObject({ package: "minimist", is_dev: true, severity: "high", advisory_severity: "critical" });
    });
  });

  describe("pnpm lockfile 5/6: one package keyed under two peer sets", () => {
    const entry = (key: string, dev: string | null) => `  ${key}:\n    resolution: {integrity: sha512-AAAA}\n${dev === null ? "" : `    dev: ${dev}\n`}\n`;
    const scopeOf = (entries: string): boolean | "unknown" => {
      const instances = new InstanceSet();
      readPnpmLock(`lockfileVersion: '6.0'\n\npackages:\n\n${entries}`, new Map(), instances);
      const ws = instances.toArray().find((i) => i.name === "ws");
      return ws?.dev ?? "unknown";
    };
    const A = "/ws@7.4.5(utf-8-validate@5.0.10)";
    const B = "/ws@7.4.5(utf-8-validate@5.0.9)";

    it("is runtime when any of its entries is runtime, in either order", () => {
      expect(scopeOf(entry(A, "false") + entry(B, "true"))).toBe(false);
      expect(scopeOf(entry(A, "true") + entry(B, "false"))).toBe(false);
    });

    it("is runtime when an entry has no dev field (used by runtime and dev alike)", () => {
      expect(scopeOf(entry(A, null) + entry(B, "true"))).toBe(false);
      expect(scopeOf(entry(A, "true") + entry(B, null))).toBe(false);
      expect(scopeOf(entry(A, null))).toBe(false);
    });

    it("is dev-only when every entry is dev", () => {
      expect(scopeOf(entry(A, "true") + entry(B, "true"))).toBe(true);
    });

    it("grades the real workspace: ws 7.4.5 is a runtime dependency of packages/api", () => {
      const dir = project(fixtureProject("pnpm8-peer-variants"));
      expect(lockScopes(dir)).toEqual({
        "node-gyp-build@4.8.4": false,
        "utf-8-validate@5.0.10": false,
        "utf-8-validate@5.0.9": true,
        "ws@7.4.5": false,
      });
      const scopes = auditScopes(dir);
      expect(scopes["ws@7.4.5"]).toMatch(/^runtime/);
      expect(scopes["utf-8-validate@5.0.9"]).toMatch(/^dev/);
    });

    it("scans ws with include_dev:false", async () => {
      stubOsv([WS]);
      const answer = await scanProject(project(fixtureProject("pnpm8-peer-variants")), { include_dev: false });
      expect(vulnerableCopies(answer)).toEqual(["ws@7.4.5"]);
      expect(answer.vulnerabilities[0]).toMatchObject({ is_dev: false, dev_scope_known: true });
    });
  });

  describe("pnpm lockfile 9: scope comes from the dependency graph", () => {
    it("a devDependency a runtime dependency also needs is runtime", () => {
      const dir = project(fixtureProject("pnpm10-devdirect"));
      expect(lockScopes(dir)).toEqual({ "minimist@0.0.8": false, "optimist@0.6.1": false, "wordwrap@0.0.3": false });
      expect(auditScopes(dir)).toEqual({
        "optimist@0.6.1": "runtime direct",
        "minimist@0.0.8": "runtime direct",
        "wordwrap@0.0.3": "runtime",
      });
    });

    it("is scanned with include_dev:false", async () => {
      stubOsv([MINIMIST]);
      const answer = await scanProject(project(fixtureProject("pnpm10-devdirect")), { include_dev: false });
      expect(vulnerableCopies(answer)).toEqual(["minimist@0.0.8"]);
    });

    it("what only a devDependency reaches is dev-only, peer-suffixed snapshots included", () => {
      const lock = [
        "lockfileVersion: '9.0'",
        "",
        "importers:",
        "",
        "  .:",
        "    dependencies:",
        "      wordwrap:",
        "        specifier: 0.0.3",
        "        version: 0.0.3",
        "    devDependencies:",
        "      ws:",
        "        specifier: 7.4.5",
        "        version: 7.4.5(utf-8-validate@5.0.9)",
        "",
        "packages:",
        "",
        "  node-gyp-build@4.8.4:",
        "    resolution: {integrity: sha512-AAAA}",
        "",
        "  utf-8-validate@5.0.9:",
        "    resolution: {integrity: sha512-AAAA}",
        "",
        "  wordwrap@0.0.3:",
        "    resolution: {integrity: sha512-AAAA}",
        "",
        "  ws@7.4.5:",
        "    resolution: {integrity: sha512-AAAA}",
        "    peerDependencies:",
        "      utf-8-validate: ^5.0.2",
        "",
        "snapshots:",
        "",
        "  node-gyp-build@4.8.4: {}",
        "",
        "  utf-8-validate@5.0.9:",
        "    dependencies:",
        "      node-gyp-build: 4.8.4",
        "",
        "  wordwrap@0.0.3: {}",
        "",
        "  ws@7.4.5(utf-8-validate@5.0.9):",
        "    optionalDependencies:",
        "      utf-8-validate: 5.0.9",
        "",
      ].join("\n");
      const dir = project(tempProject({
        "package.json": JSON.stringify({ name: "x", dependencies: { wordwrap: "0.0.3" }, devDependencies: { ws: "7.4.5" } }),
        "pnpm-lock.yaml": lock,
      }));
      expect(lockScopes(dir)).toEqual({
        "wordwrap@0.0.3": false,
        "ws@7.4.5": true,
        "utf-8-validate@5.0.9": true,
        "node-gyp-build@4.8.4": true,
      });
    });

    it("claims no dev-only copy when a snapshot names a dependency the lockfile does not hold", () => {
      const lock = [
        "lockfileVersion: '9.0'",
        "",
        "importers:",
        "",
        "  .:",
        "    dependencies:",
        "      optimist:",
        "        specifier: 0.6.1",
        "        version: 0.6.1",
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
        "  optimist@0.6.1:",
        "    resolution: {integrity: sha512-AAAA}",
        "",
        "snapshots:",
        "",
        "  minimist@0.0.8: {}",
        "",
        "  optimist@0.6.1:",
        "    dependencies:",
        "      wordwrap: 0.0.3",
        "",
      ].join("\n");
      const dir = project(tempProject({
        "package.json": JSON.stringify({ name: "x", dependencies: { optimist: "0.6.1" }, devDependencies: { minimist: "0.0.8" } }),
        "pnpm-lock.yaml": lock,
      }));
      expect(lockScopes(dir)["minimist@0.0.8"]).toBe("unknown");
      expect(auditScopes(dir)["minimist@0.0.8"]).toBe("unknown direct");
    });
  });

  describe("bun: a peer dependency of a runtime package is installed with it", () => {
    it("grades ajv, and what ajv needs, runtime", () => {
      const dir = project(fixtureProject("bun-peer-vuln"));
      const instances = new InstanceSet();
      readBunLock(fs.readFileSync(path.join(dir, "bun.lock"), "utf-8"), new Map(), instances);
      const scope = Object.fromEntries(instances.toArray().map((i) => [i.name, i.dev]));
      expect(scope).toMatchObject({
        "ajv-keywords": false,
        ajv: false,
        "fast-deep-equal": false,
        "fast-json-stable-stringify": false,
        "json-schema-traverse": false,
        "uri-js": false,
        punycode: false,
        table: true,
        lodash: true,
        "slice-ansi": true,
      });
    });

    it("scans ajv with include_dev:false", async () => {
      stubOsv([AJV]);
      const answer = await scanProject(project(fixtureProject("bun-peer-vuln")), { include_dev: false });
      expect(vulnerableCopies(answer)).toEqual(["ajv@6.12.2"]);
      expect(answer.vulnerabilities[0]).toMatchObject({ is_dev: false, dev_scope_known: true });
    });

    it("a workspace member's dependencies and the project's peerDependencies are runtime roots", () => {
      const lock = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "fx", "devDependencies": { "mkdirp": "0.5.1", }, "peerDependencies": { "wordwrap": "0.0.3", }, },
    "packages/a": { "name": "ws-a", "dependencies": { "ms": "2.0.0", }, },
  },
  "packages": {
    "minimist": ["minimist@0.0.8", "", {}, "sha512-AAAA=="],
    "mkdirp": ["mkdirp@0.5.1", "", { "dependencies": { "minimist": "0.0.8" } }, "sha512-AAAA=="],
    "ms": ["ms@2.1.3", "", {}, "sha512-AAAA=="],
    "wordwrap": ["wordwrap@0.0.3", "", {}, "sha512-AAAA=="],
    "ws-a": ["ws-a@workspace:packages/a"],
    "ws-a/ms": ["ms@2.0.0", "", {}, "sha512-AAAA=="],
  }
}
`;
      const instances = new InstanceSet();
      readBunLock(lock, new Map(), instances);
      expect(Object.fromEntries(instances.toArray().map((i) => [`${i.name}@${i.version}`, i.dev ?? "unknown"]))).toEqual({
        "minimist@0.0.8": true,
        "mkdirp@0.5.1": true,
        "ms@2.1.3": "unknown",
        "wordwrap@0.0.3": false,
        "ms@2.0.0": false,
      });
    });
  });

  describe("yarn: scope comes from the dependency graph and package.json", () => {
    const manifest = JSON.stringify({ name: "fx", dependencies: { optimist: "0.6.1" }, devDependencies: { minimist: "~0.0.1", mkdirp: "0.5.1" } });
    const classic = `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


minimist@0.0.8:
  version "0.0.8"
  resolved "https://registry.yarnpkg.com/minimist/-/minimist-0.0.8.tgz#857fcabfc3397d2625b8228262e86aa7a011b05d"
  integrity sha512-AAAA

minimist@~0.0.1:
  version "0.0.10"
  resolved "https://registry.yarnpkg.com/minimist/-/minimist-0.0.10.tgz#de3f98543dbf96082be48ad1a0c7cda836301dcf"
  integrity sha512-AAAA

mkdirp@0.5.1:
  version "0.5.1"
  resolved "https://registry.yarnpkg.com/mkdirp/-/mkdirp-0.5.1.tgz#30057438eac6cf7f8c4767f38648d6697d75c903"
  integrity sha512-AAAA
  dependencies:
    minimist "0.0.8"

optimist@0.6.1:
  version "0.6.1"
  resolved "https://registry.yarnpkg.com/optimist/-/optimist-0.6.1.tgz#da3ea74686fa21a19a111c326e90eb15a0196686"
  integrity sha512-AAAA
  dependencies:
    minimist "~0.0.1"
    wordwrap "~0.0.2"

wordwrap@~0.0.2:
  version "0.0.3"
  resolved "https://registry.yarnpkg.com/wordwrap/-/wordwrap-0.0.3.tgz#a3d5da6cd5c0bc0008d37234bbaf1bed63059107"
  integrity sha512-AAAA
`;
    const berry = `# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"fx@workspace:.":
  version: 0.0.0-use.local
  resolution: "fx@workspace:."
  dependencies:
    minimist: "npm:~0.0.1"
    mkdirp: "npm:0.5.1"
    optimist: "npm:0.6.1"
  languageName: unknown
  linkType: soft

"minimist@npm:0.0.8":
  version: 0.0.8
  resolution: "minimist@npm:0.0.8"
  checksum: 10c0/0123456789abcdef
  languageName: node
  linkType: hard

"minimist@npm:~0.0.1":
  version: 0.0.10
  resolution: "minimist@npm:0.0.10"
  checksum: 10c0/0123456789abcdef
  languageName: node
  linkType: hard

"mkdirp@npm:0.5.1":
  version: 0.5.1
  resolution: "mkdirp@npm:0.5.1"
  dependencies:
    minimist: "npm:0.0.8"
  checksum: 10c0/0123456789abcdef
  languageName: node
  linkType: hard

"optimist@npm:0.6.1":
  version: 0.6.1
  resolution: "optimist@npm:0.6.1"
  dependencies:
    minimist: "npm:~0.0.1"
    wordwrap: "npm:~0.0.2"
  checksum: 10c0/0123456789abcdef
  languageName: node
  linkType: hard

"wordwrap@npm:~0.0.2":
  version: 0.0.3
  resolution: "wordwrap@npm:0.0.3"
  checksum: 10c0/0123456789abcdef
  languageName: node
  linkType: hard
`;
    const expected = {
      "optimist@0.6.1": "runtime direct",
      // A devDependency, and what the runtime dependency optimist installs: runtime.
      "minimist@0.0.10": "runtime direct",
      "wordwrap@0.0.3": "runtime",
      "mkdirp@0.5.1": "dev direct",
      "minimist@0.0.8": "dev",
    };

    it("classic (v1)", () => {
      expect(auditScopes(project(tempProject({ "package.json": manifest, "yarn.lock": classic })))).toEqual(expected);
    });

    it("berry", () => {
      expect(auditScopes(project(tempProject({ "package.json": manifest, "yarn.lock": berry })))).toEqual(expected);
    });

    it("berry, on a lockfile Yarn 4 wrote", () => {
      expect(auditScopes(project(fixtureProject("yarn-berry-multi")))).toEqual({
        "gonzales-pe@4.3.0": "runtime direct",
        "minimist@1.2.8": "runtime direct",
        "mkdirp@0.5.1": "dev direct",
        "minimist@0.0.8": "dev",
      });
    });

    it("berry: a workspace member's dependency is a runtime root, read from the member the lockfile names", () => {
      const lock = berry
        .replace('    optimist: "npm:0.6.1"\n', "")
        .replace('"minimist@npm:0.0.8":', '"fx-api@workspace:packages/api":\n  version: 0.0.0-use.local\n  resolution: "fx-api@workspace:packages/api"\n  dependencies:\n    optimist: "npm:0.6.1"\n  languageName: unknown\n  linkType: soft\n\n"minimist@npm:0.0.8":');
      const dir = project(tempProject({
        "package.json": JSON.stringify({ name: "fx", private: true, workspaces: ["packages/*"], devDependencies: { minimist: "~0.0.1", mkdirp: "0.5.1" } }),
        "packages/api/package.json": JSON.stringify({ name: "fx-api", version: "1.0.0", dependencies: { optimist: "0.6.1" } }),
        "yarn.lock": lock,
      }));
      const scopes = Object.fromEntries(Object.entries(auditScopes(dir)).map(([copy, scope]) => [copy, scope.split(" ")[0]]));
      expect(scopes).toEqual({
        "optimist@0.6.1": "runtime",
        "minimist@0.0.10": "runtime",
        "wordwrap@0.0.3": "runtime",
        "mkdirp@0.5.1": "dev",
        "minimist@0.0.8": "dev",
      });
    });

    it("berry: a member package.json that cannot be read leaves the dev-only claims out", () => {
      const lock = berry.replace('"minimist@npm:0.0.8":', '"fx-api@workspace:packages/api":\n  version: 0.0.0-use.local\n  resolution: "fx-api@workspace:packages/api"\n  languageName: unknown\n  linkType: soft\n\n"minimist@npm:0.0.8":');
      const dir = project(tempProject({ "package.json": manifest, "packages/api/package.json": "{ not json", "yarn.lock": lock }));
      expect(Object.values(lockScopes(dir)).filter((scope) => scope === true)).toEqual([]);
      expect(auditScopes(dir)["mkdirp@0.5.1"]).toBe("unknown direct");
      expect(auditScopes(dir)["optimist@0.6.1"]).toBe("runtime direct");
    });

    it("a workspace member's dependency is a runtime root (classic)", () => {
      const dir = project(tempProject({
        "package.json": JSON.stringify({ name: "fx", private: true, workspaces: ["packages/*"], devDependencies: { minimist: "~0.0.1", mkdirp: "0.5.1" } }),
        "packages/api/package.json": JSON.stringify({ name: "fx-api", version: "1.0.0", dependencies: { optimist: "0.6.1" } }),
        "yarn.lock": classic,
      }));
      const scopes = Object.fromEntries(Object.entries(auditScopes(dir)).map(([copy, scope]) => [copy, scope.split(" ")[0]]));
      expect(scopes).toEqual({
        "optimist@0.6.1": "runtime",
        "minimist@0.0.10": "runtime",
        "wordwrap@0.0.3": "runtime",
        "mkdirp@0.5.1": "dev",
        "minimist@0.0.8": "dev",
      });
    });

    it("with no package.json to name the runtime roots, no copy is called dev-only", () => {
      const dir = project(tempProject({ "yarn.lock": classic }));
      expect(Object.values(lockScopes(dir)).filter((scope) => scope === true)).toEqual([]);
    });

    it("scans the shared copy with include_dev:false and leaves the dev-only one out", async () => {
      stubOsv([MINIMIST]);
      const answer = await scanProject(project(tempProject({ "package.json": manifest, "yarn.lock": classic })), { include_dev: false });
      expect(vulnerableCopies(answer)).toEqual(["minimist@0.0.10"]);
    });
  });
});
