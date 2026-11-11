// SPDX-License-Identifier: Apache-2.0
/**
 * package-lock.json: an alias is the package behind it, and a git or URL
 * dependency is no registry release (audit 2026-11-11, M9 and the git case).
 *
 * `"my-lodash": "npm:lodash@4.17.20"` installs lodash into
 * node_modules/my-lodash. Lockfile v2/v3 write the real `name` on the entry,
 * v1 writes the spec as the entry's version. All three were read under the
 * folder name: OSV was asked about `my-lodash` and the scan said "no known
 * advisories" for a vulnerable lodash. pnpm, yarn and bun already read the
 * real name. And `bignumber.js@2.0.7` resolved from `git+ssh://…` was asked
 * about as npm's `bignumber.js 2.0.7`, which it is not.
 *
 * The fixtures are the shapes `npm install --package-lock-only` writes.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { emptyReadReport, nonRegistrySource, readPnpmLock, readYarnLock } from "../live/js-lockfile-readers.js";
import { readPackageLock, resolveVersionSource } from "../live/lockfile-parsers.js";
import { InstanceSet } from "../live/lockfile-types.js";
import { resolveGroup } from "../live/resolution.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

const registry = (name: string, version: string) => `https://registry.npmjs.org/${name}/-/${name.split("/").pop()}-${version}.tgz`;

const DEPENDENCIES = {
  express5: "npm:express@5.0.0-beta.1",
  "is-number": "7.0.0",
  "minimist-old": "npm:minimist@1.2.5",
  "my-lodash": "npm:lodash@4.17.20",
};

/** lockfileVersion 3 (and the `packages` half of 2). */
const V3 = {
  name: "fx-alias",
  lockfileVersion: 3,
  packages: {
    "": { name: "fx-alias", version: "1.0.0", dependencies: DEPENDENCIES },
    "node_modules/accepts": { version: "1.3.8", resolved: registry("accepts", "1.3.8") },
    "node_modules/express5": { name: "express", version: "5.0.0-beta.1", resolved: registry("express", "5.0.0-beta.1"), dependencies: { accepts: "~1.3.7" } },
    "node_modules/is-number": { version: "7.0.0", resolved: registry("is-number", "7.0.0") },
    "node_modules/minimist-old": { name: "minimist", version: "1.2.5", resolved: registry("minimist", "1.2.5") },
    "node_modules/my-lodash": { name: "lodash", version: "4.17.20", resolved: registry("lodash", "4.17.20") },
  },
};

/** lockfileVersion 1 (and the `dependencies` half of 2): the alias spec is the version. */
const V1_DEPENDENCIES = {
  accepts: { version: "1.3.8", resolved: registry("accepts", "1.3.8") },
  express5: { version: "npm:express@5.0.0-beta.1", resolved: registry("express", "5.0.0-beta.1"), requires: { accepts: "~1.3.7" } },
  "is-number": { version: "7.0.0", resolved: registry("is-number", "7.0.0") },
  "minimist-old": { version: "npm:minimist@1.2.5", resolved: registry("minimist", "1.2.5") },
  "my-lodash": { version: "npm:lodash@4.17.20", resolved: registry("lodash", "4.17.20") },
};
const V1 = { name: "fx-alias", lockfileVersion: 1, requires: true, dependencies: V1_DEPENDENCIES };
const V2 = { ...V3, lockfileVersion: 2, dependencies: V1_DEPENDENCIES };

const EXPECTED = ["accepts@1.3.8", "express@5.0.0-beta.1", "is-number@7.0.0", "lodash@4.17.20", "minimist@1.2.5"];

describe("package-lock.json: an alias is read as the package it installs", () => {
  it.each([
    ["lockfileVersion 1", V1],
    ["lockfileVersion 2", V2],
    ["lockfileVersion 3", V3],
  ])("%s", (_label, lock) => {
    const read = readPackageLock(lock as Parameters<typeof readPackageLock>[0]);
    expect(read.instances.toArray().map((i) => `${i.name}@${i.version}`).sort()).toEqual(EXPECTED);
    // No alias name is ever a package.
    expect(read.instances.toArray().map((i) => i.name)).not.toEqual(expect.arrayContaining(["my-lodash"]));
    expect(Object.fromEntries(read.aliases)).toEqual({ express5: "express", "minimist-old": "minimist", "my-lodash": "lodash" });
    // The version a direct dependency on the real package resolves to.
    expect(read.versions.get("lodash")).toBe("4.17.20");
    expect(read.versions.has("my-lodash")).toBe(false);
  });

  it("an alias beside the package itself: both copies are instances, and the package's own folder is the direct version", () => {
    const read = readPackageLock({
      packages: {
        "": { dependencies: { lodash: "4.17.21", "lodash-old": "npm:lodash@4.17.20" } } as never,
        "node_modules/lodash": { version: "4.17.21", resolved: registry("lodash", "4.17.21") },
        "node_modules/lodash-old": { name: "lodash", version: "4.17.20", resolved: registry("lodash", "4.17.20") },
      },
    });
    expect(read.instances.toArray().map((i) => `${i.name}@${i.version}`).sort()).toEqual(["lodash@4.17.20", "lodash@4.17.21"]);
    expect(read.versions.get("lodash")).toBe("4.17.21");
  });

  it("a `name` that is no package name is ignored: the folder name stands", () => {
    const read = readPackageLock({ packages: { "node_modules/a": { name: "../../etc/passwd", version: "1.0.0" } } });
    expect(read.instances.toArray()).toEqual([{ name: "a", version: "1.0.0", dev: false }]);
  });
});

describe("package-lock.json: git and URL dependencies are not registry releases", () => {
  const lock = {
    name: "fx",
    lockfileVersion: 3,
    packages: {
      "": {
        name: "fx",
        dependencies: {
          "my-lodash": "npm:lodash@4.17.20",
          "min-git": "github:minimistjs/minimist#v1.2.5",
          "local-lib": "file:./lib",
          tarball: "https://example.com/builds/tarball-3.0.0.tgz",
          vendored: "file:vendor/vendored-1.0.0.tgz",
          internal: "^2.0.0",
        },
      },
      lib: { name: "local-lib", version: "1.0.0" },
      "node_modules/local-lib": { resolved: "lib", link: true },
      "node_modules/min-git": { name: "minimist", version: "1.2.5", resolved: "git+ssh://git@github.com/minimistjs/minimist.git#aeb3e27dae0412de5c0494e9563a5f10c82cc7a9" },
      "node_modules/minimist": { version: "1.2.5", resolved: registry("minimist", "1.2.5") },
      "node_modules/my-lodash": { name: "lodash", version: "4.17.20", resolved: registry("lodash", "4.17.20") },
      "node_modules/tarball": { version: "3.0.0", resolved: "https://example.com/builds/tarball-3.0.0.tgz" },
      "node_modules/vendored": { version: "1.0.0", resolved: "file:vendor/vendored-1.0.0.tgz" },
      // A private registry that serves tarballs from a path of its own: asked for by range, so a registry release.
      "node_modules/internal": { version: "2.1.0", resolved: "https://npm.pkg.github.com/download/@acme/internal/2.1.0/0123abcd" },
      "node_modules/codeload": { version: "0.9.0", resolved: "https://codeload.github.com/acme/codeload/tar.gz/0123abcd" },
    },
  };

  it("v3: the git checkout, the URL archive and the local archive are listed, the registry copies are instances, the link is local code", () => {
    const read = readPackageLock(lock as Parameters<typeof readPackageLock>[0]);
    expect(read.instances.toArray().map((i) => `${i.name}@${i.version}`).sort()).toEqual(["internal@2.1.0", "lodash@4.17.20", "minimist@1.2.5"]);
    expect(read.uncheckable.sort((a, b) => a.name.localeCompare(b.name))).toEqual([
      { name: "codeload", version: "0.9.0", kind: "git" },
      { name: "minimist", version: "1.2.5", kind: "git" },
      { name: "tarball", version: "3.0.0", kind: "url" },
      { name: "vendored", version: "1.0.0", kind: "file" },
    ]);
  });

  it("v1: a git or URL location written as the version is listed, not dropped", () => {
    const read = readPackageLock({
      dependencies: {
        "bignumber.js": { version: "git+ssh://git@github.com/acme/bignumber.js.git#aeb3e27", from: "bignumber.js@git+ssh://git@github.com/acme/bignumber.js.git#v2.0.7" } as never,
        short: { version: "github:acme/short#0123abc" },
        lodash: { version: "4.17.20", resolved: registry("lodash", "4.17.20") },
      },
    });
    expect(read.instances.toArray().map((i) => `${i.name}@${i.version}`)).toEqual(["lodash@4.17.20"]);
    expect(read.uncheckable).toEqual([
      { name: "bignumber.js", version: null, kind: "git" },
      { name: "short", version: null, kind: "git" },
    ]);
  });

  it("classifies locations: git, code-host archives, URL archives by what asked for them, local archives and directories", () => {
    expect(nonRegistrySource("git+ssh://git@github.com/a/b.git#abc")).toBe("git");
    expect(nonRegistrySource("github:a/b#v1")).toBe("git");
    expect(nonRegistrySource("https://github.com/a/b.git#commit=abc")).toBe("git");
    expect(nonRegistrySource("https://codeload.github.com/a/b/tar.gz/abc")).toBe("git");
    expect(nonRegistrySource("https://registry.npmjs.org/a/-/a-1.0.0.tgz")).toBeNull();
    expect(nonRegistrySource("https://artifactory.example.com/api/npm/npm/a/-/a-1.0.0.tgz")).toBeNull();
    expect(nonRegistrySource("https://example.com/a.tgz", "https://example.com/a.tgz")).toBe("url");
    expect(nonRegistrySource("https://npm.pkg.github.com/download/@a/b/1.0.0/abc", "^1.0.0")).toBeNull();
    expect(nonRegistrySource("file:vendor/a-1.0.0.tgz")).toBe("file");
    expect(nonRegistrySource("file:../lib")).toBe("local");
    expect(nonRegistrySource("4.17.20")).toBeNull();
  });

  it("yarn.lock (v1 and berry): a git or URL entry is listed, never read as the registry package", () => {
    const v1 = [
      "# yarn lockfile v1",
      "",
      '"bignumber.js@git+ssh://git@github.com/acme/bignumber.js.git#v2.0.7":',
      '  version "2.0.7"',
      '  resolved "git+ssh://git@github.com/acme/bignumber.js.git#aeb3e27dae0412de5c0494e9563a5f10c82cc7a9"',
      "",
      "lodash@4.17.20:",
      '  version "4.17.20"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz#abc"',
      "",
      '"minimist@minimistjs/minimist#v1.2.5":',
      '  version "1.2.5"',
      '  resolved "https://codeload.github.com/minimistjs/minimist/tar.gz/aeb3e27"',
      "",
    ].join("\n");
    const v1Instances = new InstanceSet();
    const v1Report = emptyReadReport();
    readYarnLock(v1, new Map(), v1Instances, undefined, v1Report);
    expect(v1Instances.toArray()).toEqual([{ name: "lodash", version: "4.17.20" }]);
    expect(v1Report.uncheckable).toEqual([
      { name: "bignumber.js", version: "2.0.7", kind: "git" },
      { name: "minimist", version: "1.2.5", kind: "git" },
    ]);

    const berry = [
      "__metadata:",
      "  version: 8",
      "",
      '"bignumber.js@https://github.com/acme/bignumber.js.git#v2.0.7":',
      "  version: 2.0.7",
      '  resolution: "bignumber.js@https://github.com/acme/bignumber.js.git#commit=aeb3e27dae0412de5c0494e9563a5f10c82cc7a9"',
      "",
      '"lodash@npm:4.17.20":',
      "  version: 4.17.20",
      '  resolution: "lodash@npm:4.17.20"',
      "",
    ].join("\n");
    const berryInstances = new InstanceSet();
    const berryReport = emptyReadReport();
    readYarnLock(berry, new Map(), berryInstances, undefined, berryReport);
    expect(berryInstances.toArray()).toEqual([{ name: "lodash", version: "4.17.20" }]);
    expect(berryReport.uncheckable).toEqual([{ name: "bignumber.js", version: "2.0.7", kind: "git" }]);
  });

  it("pnpm-lock.yaml: a git or tarball entry was already left out; now it is listed", () => {
    const lock = [
      "lockfileVersion: '9.0'",
      "",
      "packages:",
      "",
      "  lodash@4.17.20:",
      "    resolution: {integrity: sha512-aaa}",
      "",
      "  minimist@https://codeload.github.com/minimistjs/minimist/tar.gz/aeb3e27:",
      "    resolution: {tarball: https://codeload.github.com/minimistjs/minimist/tar.gz/aeb3e27}",
      "    version: 1.2.5",
      "",
      "snapshots:",
      "",
      "  lodash@4.17.20: {}",
      "",
      "  minimist@https://codeload.github.com/minimistjs/minimist/tar.gz/aeb3e27: {}",
      "",
    ].join("\n");
    const instances = new InstanceSet();
    const report = emptyReadReport();
    readPnpmLock(lock, new Map(), instances, report);
    expect(instances.toArray()).toEqual([{ name: "lodash", version: "4.17.20" }]);
    expect(report.uncheckable).toEqual([{ name: "minimist", version: "1.2.5", kind: "git" }]);
  });
});

describe("the outbound OSV query names the real package", () => {
  let dir: string;
  let priorOffline: string | undefined;
  let asked: string[];

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-alias-"));
    asked = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version?: string }> };
        for (const q of queries) asked.push(`${q.package.name}@${q.version}`);
        return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === "lodash" ? { vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] } : {})) }), { status: 200 });
      }
      if (url.includes("/v1/vulns/")) {
        const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
        return new Response(JSON.stringify({ id, summary: "Command Injection in lodash", database_specific: { severity: "HIGH" } }), { status: 200 });
      }
      throw new TypeError(`fetch failed (${url})`);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it.each([
    ["lockfileVersion 1", V1],
    ["lockfileVersion 2", V2],
    ["lockfileVersion 3", V3],
  ])("%s: lodash 4.17.20 behind `my-lodash` is found, and is a direct dependency", async (_label, lock) => {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "fx-alias", dependencies: DEPENDENCIES }));
    fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify(lock));

    const group = resolveGroup({ dir, language: "npm", deps: Object.keys(DEPENDENCIES), devDeps: [], targets: {} });
    expect(group.resolved.map((d) => `${d.name}@${d.version}`).sort()).toEqual(["express@5.0.0-beta.1", "is-number@7.0.0", "lodash@4.17.20", "minimist@1.2.5"]);

    const result = (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
    expect(asked.sort()).toEqual(EXPECTED);
    expect(asked.join(" ")).not.toMatch(/my-lodash|minimist-old|express5/);
    expect(result.total_vulnerable_packages).toBe(1);
    expect(result.vulnerable_packages[0]).toMatchObject({ package: "lodash", current_version: "4.17.20", is_direct: true });
  });

  it("no lockfile: an alias and a git spec in package.json are the real package and a not-checkable one, never the alias name", async () => {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { "my-lodash": "npm:lodash@4.17.20", "min-git": "github:minimistjs/minimist#v1.2.5", "local-lib": "file:./lib" } }));
    const read = resolveVersionSource(dir, "npm");
    expect(read.instances).toEqual([{ name: "lodash", version: "4.17.20" }]);
    expect(read.uncheckable).toEqual([{ name: "min-git", version: null, kind: "git", file: path.join(dir, "package.json") }]);
    await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, new LiveIntelligence(new Database(":memory:")));
    expect(asked).toEqual(["lodash@4.17.20"]);
  });
});
