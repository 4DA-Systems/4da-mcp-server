// SPDX-License-Identifier: Apache-2.0
/**
 * Started in a workspace member whose lockfile is in an ancestor that declares it as a member,
 * the server reads the workspace root, reports it as `project_root` and says so. The pnpm member
 * whose root lockfile installs the malware release debug 4.4.2 scored 94/100, "0 vulnerable",
 * and the scan said NO LOCKFILE. An ancestor lockfile whose membership cannot be confirmed is
 * named, not read. With no lockfile read at all, no tool gives a health score, says the plan has
 * vulnerability data, or calls the task safe to delegate, and a declared range is never shown as
 * an installed version: they ask the live layer one question (wasLockfileRead).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { discoveryNote, scanProjectTree, treeResolutionGroups, workspaceNote } from "../project-tree.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { memoryDb } from "./helpers/briefing-stub.js";

const MALWARE = "GHSA-4x49-vf9v-38px";

describe("a1123 discovery: a workspace member, and a project with no lockfile", () => {
  let base: string;
  let priorOffline: string | undefined;
  let asked: string[];

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    base = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-ws-"));
    asked = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version?: string }> };
        for (const q of queries) asked.push(`${q.package.name}@${q.version}`);
        return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === "debug" && q.version === "4.4.2" ? { vulns: [{ id: MALWARE }] } : {})) }), { status: 200 });
      }
      if (url.includes("/v1/vulns/")) {
        return new Response(JSON.stringify({ id: MALWARE, summary: "Malicious code in debug", database_specific: { severity: "CRITICAL" } }), { status: 200 });
      }
      throw new TypeError(`fetch failed (${url})`);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    fs.rmSync(base, { recursive: true, force: true });
  });

  const write = (rel: string, content: string) => {
    fs.mkdirSync(path.dirname(path.join(base, rel)), { recursive: true });
    fs.writeFileSync(path.join(base, rel), content);
  };
  const liveFor = (dir: string) => {
    const live = new LiveIntelligence(new Database(":memory:"));
    const { entries, discovery } = scanProjectTree(dir);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    return live;
  };

  /** The audit's pnpm workspace: packages/app declares debug ^4.4.1, the root lockfile installs 4.4.2. */
  const pnpmWorkspace = () => {
    write("mono/package.json", JSON.stringify({ name: "mono", private: true }));
    write("mono/pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n");
    write("mono/packages/app/package.json", JSON.stringify({ name: "app", version: "1.0.0", dependencies: { debug: "^4.4.1" } }));
    write(
      "mono/pnpm-lock.yaml",
      [
        "lockfileVersion: '9.0'",
        "",
        "importers:",
        "",
        "  .: {}",
        "",
        "  packages/app:",
        "    dependencies:",
        "      debug:",
        "        specifier: ^4.4.1",
        "        version: 4.4.2",
        "",
        "packages:",
        "",
        "  debug@4.4.2:",
        "    resolution: {integrity: sha512-aaa}",
        "",
        "  ms@2.1.3:",
        "    resolution: {integrity: sha512-bbb}",
        "",
        "snapshots:",
        "",
        "  debug@4.4.2:",
        "    dependencies:",
        "      ms: 2.1.3",
        "",
        "  ms@2.1.3: {}",
        "",
      ].join("\n"),
    );
    return { root: path.join(base, "mono"), member: path.join(base, "mono", "packages", "app") };
  };

  it("started in a pnpm member: the workspace root is read, debug 4.4.2 is flagged, and the answer says so", async () => {
    const { root, member } = pnpmWorkspace();
    const { discovery } = scanProjectTree(member);
    expect(discovery.workspace).toEqual({ root, startedIn: member, lockfile: "pnpm-lock.yaml", kind: "pnpm" });
    expect(workspaceNote(discovery)).toMatch(/^Started in packages[\\/]app, a member of the pnpm workspace at .*mono: its dependencies are pinned in that workspace's pnpm-lock\.yaml, so the workspace root was read \(project_root\)\.$/);

    const live = liveFor(member);
    expect(live.getProjectRoot()).toBe(root);
    expect(live.wasLockfileRead()).toBe(true);

    const result = (await executeVulnerabilityScan(null, { project_path: member, force_refresh: true }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
    expect(asked).toContain("debug@4.4.2");
    expect(result.project_root).toBe(root);
    expect(result.total_vulnerable_packages).toBe(1);
    expect(result.vulnerable_packages[0]).toMatchObject({ package: "debug", current_version: "4.4.2" });
    expect(result.workspace_note).toMatch(/^Started in packages[\\/]app, a member of the pnpm workspace/);
    expect(JSON.stringify(result)).not.toMatch(/NO LOCKFILE|npm install --package-lock-only/);

    live.fetchRegistryHealth = async () => [];
    const health = await executeDependencyHealth(null, {}, live);
    expect(health.projectPath).toBe(root);
    expect(health.vulnerableCount).toBe(1);
    expect(health.summary).toMatch(/Started in packages[\\/]app, a member of the pnpm workspace/);
  });

  it("npm, Cargo, uv and go.work members are recognised by what each workspace declares", () => {
    write("npm/package.json", JSON.stringify({ name: "r", workspaces: ["apps/*"] }));
    write("npm/package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": { workspaces: ["apps/*"] }, "apps/web": { name: "web" } } }));
    write("npm/apps/web/package.json", JSON.stringify({ name: "web", dependencies: { ms: "^2" } }));
    write("rs/Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n');
    write("rs/Cargo.lock", 'version = 3\n\n[[package]]\nname = "core"\nversion = "0.1.0"\n');
    write("rs/crates/core/Cargo.toml", '[package]\nname = "core"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1"\n');
    write("py/pyproject.toml", '[project]\nname = "ws"\nversion = "0"\n\n[tool.uv.workspace]\nmembers = ["libs/*"]\n');
    write("py/uv.lock", 'version = 1\n\n[[package]]\nname = "svc-core"\nversion = "0.1.0"\nsource = { editable = "libs/core" }\n');
    write("py/libs/core/pyproject.toml", '[project]\nname = "svc_core"\nversion = "0.1.0"\ndependencies = ["httpx>=0.27"]\n');
    write("go/go.work", "go 1.22\n\nuse (\n\t./svc\n)\n");
    write("go/svc/go.mod", "module example.com/svc\n\ngo 1.22\n\nrequire golang.org/x/net v0.17.0\n");

    const kind = (rel: string) => scanProjectTree(path.join(base, rel)).discovery.workspace;
    expect(kind("npm/apps/web")).toMatchObject({ root: path.join(base, "npm"), lockfile: "package-lock.json", kind: "npm" });
    expect(kind("rs/crates/core")).toMatchObject({ root: path.join(base, "rs"), lockfile: "Cargo.lock", kind: "Cargo" });
    expect(kind("py/libs/core")).toMatchObject({ root: path.join(base, "py"), lockfile: "uv.lock", kind: "uv" });
    expect(kind("go/svc")).toMatchObject({ root: path.join(base, "go"), lockfile: "go.work", kind: "go.work" });
  });

  it("an ancestor lockfile that does not declare this directory as a member is named, not read", async () => {
    write("outer/package.json", JSON.stringify({ name: "outer", dependencies: { ms: "2.1.3" } }));
    write("outer/package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { ms: "2.1.3" } }, "node_modules/ms": { version: "2.1.3" } } }));
    write("outer/tools/cli/package.json", JSON.stringify({ name: "cli", dependencies: { debug: "^4.4.1" } }));
    const dir = path.join(base, "outer", "tools", "cli");
    const { entries, discovery } = scanProjectTree(dir);
    expect(entries.map((e) => e.dir)).toEqual([dir]);
    expect(discovery.workspace).toBeUndefined();
    expect(discovery.ancestorLockfile).toEqual({ path: path.join(base, "outer", "package-lock.json"), kind: "npm" });
    expect(discoveryNote(discovery)).toMatch(/a lockfile above this directory \(.*outer[\\/]package-lock\.json\) was NOT read: this directory could not be confirmed as one of its workspace members/);
    const result = (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
    expect(asked).not.toContain("ms@2.1.3");
    expect(result.coverage.note).toMatch(/was NOT read: this directory could not be confirmed/);
  });

  it("the search never leaves the enclosing git repository", () => {
    const { member } = pnpmWorkspace();
    fs.mkdirSync(path.join(member, ".git"));
    expect(scanProjectTree(member).discovery.workspace).toBeUndefined();
    fs.rmSync(path.join(member, ".git"), { recursive: true });
    // A repository root between the member and the workspace lockfile: the lockfile is outside it.
    fs.mkdirSync(path.join(base, "mono", "packages", ".git"));
    expect(scanProjectTree(member).discovery.workspace).toBeUndefined();
  });

  it("no lockfile read: no health score, no vulnerability data for the plan, no safe_to_delegate, and no floor shown as installed", async () => {
    // One exact pin is checked as declared, so the scan is "ready": vite/packages/vite read safe_to_delegate on 1 of 62.
    write("nolock/package.json", JSON.stringify({ name: "nolock", version: "1.0.0", dependencies: { lodash: "^4.17.20", minimist: "^1.2.5", debug: "^4.4.1", ms: "2.1.3" } }));
    const dir = path.join(base, "nolock");
    const live = liveFor(dir);
    expect(live.wasLockfileRead()).toBe(false);

    live.fetchRegistryHealth = async (deps) =>
      deps.map((d) => ({ name: d.name, ecosystem: d.ecosystem, currentVersion: d.version, latestVersion: "9.0.0", latestStableVersion: "9.0.0", versionsBehind: null, deprecated: false, deprecationMessage: null, lastPublished: null, license: null, weeklyDownloads: null, isDev: d.isDev, fetchError: null, ...(d.declaredRange ? { declaredRange: d.declaredRange } : {}) }));
    const health = await executeDependencyHealth(null, {}, live);
    expect(health.healthScore).toBeNull();
    expect(health.vulnerableCount).toBeNull();
    expect(health.withheldReason).toBe("no_lockfile");
    expect(health.summary).toMatch(/^NOT CHECKED: no lockfile was read for this project/);
    expect(health.summary).not.toMatch(/0 vulnerable|Health: \d/);
    const lodash = health.dependencies.find((d) => d.name === "lodash");
    expect(lodash).toMatchObject({ currentVersion: null, declaredRange: "^4.17.20" });

    const plan = (await executeUpgradePlanner(memoryDb(), {}, live)) as Record<string, any>;
    expect(plan.vulnerabilityDataAvailable).toBe(false);

    const briefing = await executeWhatShouldIKnow(memoryDb(), { task: "upgrade lodash, minimist and debug" }, live);
    expect(briefing.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(briefing.delegation_assessment.reason).toMatch(/no lockfile was read/i);
    for (const d of briefing.task_dependencies) expect(d.installed).toEqual([]);
  });
});
