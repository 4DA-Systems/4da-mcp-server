// SPDX-License-Identifier: Apache-2.0
/**
 * Blind audit round 4: in a mixed npm + Python + Go project, what_should_i_know tied a version to
 * the wrong package. "Upgrade gin to v1.6.0" was judged as npm `gin` (go.mod requires
 * github.com/gin-gonic/gin), "lodash in package.json to 4.17.20" as a package named `package.json`,
 * and "Set the request timeout to 30" as `timeout@30`. All failed safe (review_needed); now they are right.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { readTaskVersions } from "../tools/briefing-requested-versions.js";
import { detectNewPackages } from "../tools/briefing-new-packages.js";
import { installedGoModule, isManifestFile } from "../tools/briefing-names.js";
import type { ResolvedDependency } from "../live/types.js";

const dep = (name: string, version: string, ecosystem: ResolvedDependency["ecosystem"]) =>
  ({ name, version, ecosystem, isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [] }) as ResolvedDependency;

/** npm has the most dependencies, so a bare name nobody installs is guessed npm. */
const MIXED = [
  dep("react", "18.2.0", "npm"),
  dep("react-dom", "18.2.0", "npm"),
  dep("lodash", "4.17.21", "npm"),
  dep("express", "4.19.2", "npm"),
  dep("requests", "2.32.3", "PyPI"),
  dep("urllib3", "2.2.2", "PyPI"),
  dep("github.com/gin-gonic/gin", "v1.9.1", "Go"),
  dep("github.com/redis/go-redis/v9", "v9.5.1", "Go"),
  dep("gopkg.in/yaml.v3", "v3.0.1", "Go"),
];

describe("a short name is the installed Go module it stands for", () => {
  it.each([
    ["Upgrade gin to v1.6.0", { name: "github.com/gin-gonic/gin", ecosystem: "Go", to: "v1.6.0", from: "v1.9.1" }],
    ["add gin v1.6.0", { name: "github.com/gin-gonic/gin", ecosystem: "Go", to: "v1.6.0", from: "v1.9.1" }],
    ["bump go-redis to v9.6.0", { name: "github.com/redis/go-redis/v9", ecosystem: "Go", to: "v9.6.0", from: "v9.5.1" }],
    ["pin yaml to v3.0.0 in go.mod", { name: "gopkg.in/yaml.v3", ecosystem: "Go", to: "v3.0.0", from: "v3.0.1" }],
  ])("%s", (task, expected) => {
    expect(readTaskVersions(task, MIXED).requested).toEqual([expected]);
  });

  it("an installed dependency of the exact name still wins, and a task that names npm is not read as Go", () => {
    const withNpmGin = [...MIXED, dep("gin", "0.1.0", "npm")];
    expect(readTaskVersions("Upgrade gin to v1.6.0", withNpmGin).requested[0]).toMatchObject({ name: "gin", ecosystem: "npm" });
    expect(readTaskVersions("npm: upgrade gin to 1.6.0", MIXED).requested[0]).toMatchObject({ name: "gin", ecosystem: "npm" });
  });

  it("two installed modules ending the same way are not guessed between", () => {
    const two = [dep("github.com/a/log", "v1.0.0", "Go"), dep("github.com/b/log", "v1.0.0", "Go")];
    expect(installedGoModule("log", two)).toBeNull();
    expect(installedGoModule("gin", MIXED)).toBe("github.com/gin-gonic/gin");
  });

  it('"install gin" with gin in go.mod is not a new npm package', () => {
    expect(detectNewPackages("install gin", MIXED)).toEqual([]);
    expect(detectNewPackages("install gin and left-pad", MIXED)).toEqual([{ name: "left-pad", ecosystem: "npm", alternatives: ["PyPI"] }]);
  });
});

describe("a manifest or lockfile name is never a package", () => {
  it.each([
    ["Update lodash in package.json to 4.17.20", { name: "lodash", ecosystem: "npm", to: "4.17.20", from: "4.17.21" }],
    ["set lodash in package.json to 4.17.20", { name: "lodash", ecosystem: "npm", to: "4.17.20", from: "4.17.21" }],
    ["add left-pad in package.json to 1.3.0", { name: "left-pad", ecosystem: "npm", to: "1.3.0" }],
    ["pin requests inside requirements.txt to 2.31.0", { name: "requests", ecosystem: "PyPI", to: "2.31.0", from: "2.32.3" }],
    ["upgrade gin in services/api/go.mod to v1.10.0", { name: "github.com/gin-gonic/gin", ecosystem: "Go", to: "v1.10.0", from: "v1.9.1" }],
  ])("%s", (task, expected) => {
    const read = readTaskVersions(task, MIXED);
    expect(read.requested).toEqual([expected]);
    expect(read.requested.some((r) => isManifestFile(r.name))).toBe(false);
  });

  it("a manifest named as name@version is unread, not a package", () => {
    expect(readTaskVersions("write package.json@1.2.3", MIXED).requested).toEqual([]);
  });

  it.each(["package.json", "web/package-lock.json", "Cargo.toml", "requirements-dev.txt", "go.mod", "`pnpm-lock.yaml`", "yarn.lock,"])("%s is a manifest", (f) => {
    expect(isManifestFile(f)).toBe(true);
  });
  it.each(["lodash", "json", "toml", "github.com/x/go-mod"])("%s is not a manifest", (f) => {
    expect(isManifestFile(f)).toBe(false);
  });
});

describe("a number in a sentence about settings is not a package version", () => {
  it.each([
    "Set the request timeout to 30",
    "Set the timeout to 1.5",
    "set the port to 8080",
    "Change max connections to 100",
    "use 4 workers",
    "update the retry count to 5",
  ])("%s", (task) => {
    const read = readTaskVersions(task, MIXED);
    expect(read.requested).toEqual([]);
    expect(read.unread).toEqual([]);
  });

  it("an installed package, a quoted name, or a dependency task still reads the number as a version", () => {
    const withTimeout = [...MIXED, dep("timeout", "0.1.0", "npm")];
    expect(readTaskVersions("Set timeout to 0.2.0", withTimeout).requested).toEqual([{ name: "timeout", ecosystem: "npm", to: "0.2.0", from: "0.1.0" }]);
    expect(readTaskVersions("add `timeout` 0.2.0", MIXED).requested[0]).toMatchObject({ name: "timeout", to: "0.2.0" });
    expect(readTaskVersions("upgrade react to 19", MIXED).requested).toEqual([{ name: "react", ecosystem: "npm", to: "19", from: "18.2.0" }]);
    expect(readTaskVersions("add serde_json 1 to Cargo.toml", []).requested).toEqual([{ name: "serde_json", ecosystem: "crates.io", to: "1" }]);
    expect(readTaskVersions("install left-pad 1", MIXED).requested[0]).toMatchObject({ name: "left-pad", to: "1" });
  });
});

describe("a scope and its adjectives are never a package (round-4 privacy review)", () => {
  it.each(["upgrade the @acme scope to 2.0", "bump @acme packages to 2.0.1", "move the @acme org to 3.0"])("%s: no package named after the group word; the version is unread", (task) => {
    const read = readTaskVersions(task, MIXED);
    expect(read.requested).toEqual([]);
    expect(read.unread.length).toBe(1);
  });

  it.each(["install the private @acme scope", "add the internal @acme packages", "install our private packages"])("%s: no new package called `private` or `internal`", (task) => {
    expect(detectNewPackages(task, MIXED)).toEqual([]);
  });

  it("an adjective before a real name still finds the name, and a quoted or explicit one is a name", () => {
    expect(detectNewPackages("install the private left-pad package", MIXED).map((p) => p.name)).toEqual(["left-pad"]);
    expect(readTaskVersions("upgrade the internal lodash to 4.17.20", MIXED).requested[0]).toMatchObject({ name: "lodash", to: "4.17.20" });
    expect(readTaskVersions("npm install private@0.1.0", MIXED).requested[0]).toMatchObject({ name: "private", to: "0.1.0" });
  });
});

describe("what_should_i_know on a setting: nothing about it is sent anywhere (round-4 black-box gate)", () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-task-names-"));
  afterEach(() => vi.unstubAllGlobals());

  /** The briefing over an npm project with express installed; every request it makes, recorded. */
  async function brief(task: string) {
    const sent: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        sent.push(`${url} ${typeof init?.body === "string" ? init.body : ""}`);
        return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: { "content-type": "application/json" } });
      }),
    );
    const deps = { express: "4.19.2" };
    fs.writeFileSync(path.join(scratch, "package.json"), JSON.stringify({ name: "app", dependencies: deps }));
    fs.writeFileSync(
      path.join(scratch, "package-lock.json"),
      JSON.stringify({ name: "app", lockfileVersion: 3, packages: { "": { name: "app", dependencies: deps }, "node_modules/express": { version: "4.19.2" } } }),
    );
    const live = new LiveIntelligence(new Database(":memory:"));
    live.initFromProject(scratch, Object.keys(deps), [], "javascript");
    const db = new FourDADatabase(path.join(scratch, "standalone.db"));
    const prior = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    try {
      return { result: await executeWhatShouldIKnow(db, { task }, live), sent };
    } finally {
      if (prior !== undefined) process.env.FOURDA_OFFLINE = prior;
      db.close();
    }
  }

  it.each(["set back the timeout to 30 seconds", "Set the request timeout to 30"])('"%s" ties no version and sends no `timeout`', async (task) => {
    const { result, sent } = await brief(task);
    expect(result.requested_versions ?? []).toEqual([]);
    expect(sent.filter((s) => /timeout/i.test(s))).toEqual([]);
  });

  it('"set back the timeout and bump express to 5.1.0" ties only express', async () => {
    const { result, sent } = await brief("set back the timeout and bump express to 5.1.0");
    expect((result.requested_versions ?? []).map((r) => [r.name, r.to])).toEqual([["express", "5.1.0"]]);
    expect(sent.filter((s) => /timeout/i.test(s))).toEqual([]);
  });
});
