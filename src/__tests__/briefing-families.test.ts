// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know: package families, "latest" targets and project_path.
 *
 * 2026-10-07 eval: "bump tauri and all tauri plugins to latest" on 4DA's
 * src-tauri matched only `tauri`, missing tauri-build, the tauri-plugin-*
 * crates and @tauri-apps/*, and never said whether the project was already on
 * the latest major.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { FourDADatabase } from "../db.js";
import type { RegistryPackageInfo, ResolvedDependency, VulnerabilityScanResult } from "../live/types.js";
import { detectFamilyBases, detectFamilyPackages, detectTaskPackages, inFamily } from "../tools/briefing-task-scope.js";
import { executeWhatShouldIKnow, type BriefingLiveIntel } from "../tools/what-should-i-know.js";

function dep(name: string, version: string, ecosystem: ResolvedDependency["ecosystem"], isDirect = true): ResolvedDependency {
  return { name, version, ecosystem, isDev: false, isDirect, devScopeKnown: true, target: null, platformActive: true, sourceDirs: ["d:/proj"] };
}

const DEPS: ResolvedDependency[] = [
  dep("tauri", "2.12.1", "crates.io"),
  dep("tauri-build", "2.7.1", "crates.io"),
  dep("tauri-plugin-updater", "2.13.1", "crates.io"),
  dep("tauri-plugin-deep-link", "1.4.0", "crates.io"),
  dep("tauri-utils", "2.9.0", "crates.io", false), // transitive: follows tauri, not bumped by hand
  dep("@tauri-apps/api", "2.11.1", "npm"),
  dep("@tauri-apps/plugin-shell", "2.3.0", "npm"),
  dep("react", "19.2.6", "npm"),
  dep("tokio", "1.50.0", "crates.io"),
];

describe("package families a task names", () => {
  it.each([
    ["bump tauri and all tauri plugins to latest", ["tauri"]],
    ["upgrade tauri and its plugins", ["tauri"]],
    ["bump the @tauri-apps packages", ["@tauri-apps"]],
    ["update tauri-plugin-* crates", ["tauri"]],
    ["update @tauri-apps/* to 2.12", ["@tauri-apps"]],
    ["bump tauri to 2.13", []],
    ["upgrade all dependencies", []],
    ["fix the tests in packages/web", []],
  ])("%s -> %j", (task, bases) => {
    expect(detectFamilyBases(task)).toEqual(bases);
  });

  it("matches prefix and scope families, never the base itself", () => {
    expect(inFamily("tauri-plugin-updater", "tauri")).toBe(true);
    expect(inFamily("tauri-build", "tauri")).toBe(true);
    expect(inFamily("@tauri-apps/api", "tauri")).toBe(true);
    expect(inFamily("@tauri-apps/plugin-shell", "@tauri-apps")).toBe(true);
    expect(inFamily("tauri", "tauri")).toBe(false);
    expect(inFamily("tauritools", "tauri")).toBe(false);
  });

  it("expands to the family's DIRECT dependencies that the project actually has", () => {
    const task = "bump tauri and all tauri plugins to latest";
    const exact = detectTaskPackages(task, [], DEPS);
    expect(exact.map((p) => p.name)).toEqual(["tauri"]);
    const family = detectFamilyPackages(task, [], DEPS, exact);
    expect(family.map((p) => `${p.ecosystem}:${p.name}`)).toEqual([
      "crates.io:tauri-build",
      "crates.io:tauri-plugin-deep-link",
      "crates.io:tauri-plugin-updater",
      "npm:@tauri-apps/api",
      "npm:@tauri-apps/plugin-shell",
    ]);
    expect(family.every((p) => p.family === "tauri")).toBe(true);
    expect(detectFamilyPackages("bump tauri to 2.13", [], DEPS, exact)).toEqual([]);
  });
});

function readyScan(): VulnerabilityScanResult {
  return {
    scannedAt: new Date().toISOString(),
    projectPath: "d:/proj",
    ecosystemsScanned: ["crates.io", "npm"],
    totalScanned: DEPS.length,
    totalVulnerable: 0,
    platformInactiveVulnerable: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    vulnerabilities: [],
    cleanCount: DEPS.length,
    scanDurationMs: 1,
    cached: true,
    offline: false,
  };
}

const LATEST: Record<string, string> = {
  tauri: "2.13.0",
  "tauri-build": "2.8.0",
  "tauri-plugin-updater": "2.14.0",
  "tauri-plugin-deep-link": "2.7.0",
  "@tauri-apps/api": "2.12.1",
  "@tauri-apps/plugin-shell": "2.4.0",
};

function memoryDb(): FourDADatabase {
  const instance = Object.create(FourDADatabase.prototype) as FourDADatabase;
  (instance as unknown as { db: Database.Database }).db = new Database(":memory:");
  return instance;
}

describe("what_should_i_know with families and latest", () => {
  it("briefs every family member and says which are already on the latest major", async () => {
    const requested: string[] = [];
    const live: BriefingLiveIntel = {
      isEnabled: () => true,
      getProjectRoot: () => "d:/proj",
      ensureVulnerabilities: async () => readyScan(),
      getResolvedDeps: () => DEPS,
      fetchRegistryHealth: async (deps) => {
        requested.push(...deps.map((d) => d.name));
        return deps.map(
          (d) =>
            ({
              name: d.name,
              ecosystem: d.ecosystem,
              currentVersion: d.version,
              latestVersion: LATEST[d.name] ?? null,
              latestStableVersion: LATEST[d.name] ?? null,
            }) as RegistryPackageInfo,
        );
      },
    };
    const result = await executeWhatShouldIKnow(memoryDb(), { task: "bump tauri and all tauri plugins to latest" }, live);
    expect(result.task_dependencies.map((d) => d.package)).toEqual([
      "tauri",
      "tauri-build",
      "tauri-plugin-deep-link",
      "tauri-plugin-updater",
      "@tauri-apps/api",
      "@tauri-apps/plugin-shell",
    ]);
    expect(requested).toHaveLength(6);
    const tauri = result.task_dependencies[0];
    expect(tauri.latest).toEqual({ version: "2.13.0", installed_line: "2", latest_line: "2", on_latest_major: true });
    expect(tauri.majors_crossed).toBe(0);
    const deepLink = result.task_dependencies.find((d) => d.package === "tauri-plugin-deep-link")!;
    expect(deepLink.family).toBe("tauri");
    expect(deepLink.latest?.on_latest_major).toBe(false);
    expect(deepLink.majors_crossed).toBe(1);
    expect(result.summary).toContain("already on the latest major: tauri (2.x, latest 2.13.0)");
    expect(result.summary).toContain("behind the latest major: tauri-plugin-deep-link 1.x -> 2.7.0");
    expect(result.delegation_assessment.level).toBe("review_needed");
  });

  it("does not ask the registry when the task does not ask for the latest", async () => {
    let asked = false;
    const live: BriefingLiveIntel = {
      isEnabled: () => true,
      getProjectRoot: () => "d:/proj",
      ensureVulnerabilities: async () => readyScan(),
      getResolvedDeps: () => DEPS,
      fetchRegistryHealth: async () => {
        asked = true;
        return [];
      },
    };
    const result = await executeWhatShouldIKnow(memoryDb(), { task: "bump tauri to 2.13.0" }, live);
    expect(asked).toBe(false);
    expect(result.task_dependencies.map((d) => d.package)).toEqual(["tauri"]);
    expect(result.task_dependencies[0].latest).toBeUndefined();
  });
});

describe("what_should_i_know project_path", () => {
  let dir: string;
  let priorOffline: string | undefined;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    process.env.FOURDA_OFFLINE = "true";
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-wsik-scope-"));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "scoped", dependencies: { "left-pad": "1.3.0" } }));
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: "scoped",
        lockfileVersion: 3,
        packages: {
          "": { name: "scoped", dependencies: { "left-pad": "1.3.0" } },
          "node_modules/left-pad": { version: "1.3.0" },
        },
      }),
    );
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
  });

  it("reads the named project's lockfiles instead of the server's", async () => {
    const server: BriefingLiveIntel = {
      isEnabled: () => false,
      getProjectRoot: () => "d:/proj",
      ensureVulnerabilities: async () => null,
      getResolvedDeps: () => DEPS,
    };
    const here = await executeWhatShouldIKnow(memoryDb(), { task: "bump left-pad" }, server);
    expect(here.task_dependencies).toEqual([]);

    const there = await executeWhatShouldIKnow(memoryDb(), { task: "bump left-pad", project_path: dir }, server);
    expect(there.project_path && path.resolve(there.project_path)).toBe(path.resolve(dir));
    expect(there.task_dependencies.map((d) => `${d.package}@${d.installed.join(",")}`)).toEqual(["left-pad@1.3.0"]);
  });

  it("rejects a project_path that is not a directory", async () => {
    const server: BriefingLiveIntel = { isEnabled: () => false, getProjectRoot: () => "d:/proj", ensureVulnerabilities: async () => null };
    await expect(
      executeWhatShouldIKnow(memoryDb(), { task: "x", project_path: path.join(dir, "missing") }, server),
    ).rejects.toThrow(/not a directory/);
  });
});
