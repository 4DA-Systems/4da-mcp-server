// SPDX-License-Identifier: Apache-2.0
/**
 * A fix the plan names must be one the user can follow (audit 2026-11-11, M6, M7 and the
 * overrides case from the 4DA app's own verification on 2026-11-10):
 *
 * - a target that does not exist: go.etcd.io/etcd was sent to "v3.4.44", which the Go proxy does
 *   not serve for that module path (Go major 3 is the module go.etcd.io/etcd/v3);
 * - a target its maintainer flagged: lodash.template 4.5.0 was sent to 4.18.0 ("Bad release")
 *   past 4.18.1, because every release of the retired package is deprecated and the rule read
 *   them all as one line-wide notice;
 * - a parent upgrade nobody needs: "tailwindcss 3.4.19 is the smallest tailwindcss release that
 *   brings in sucrase 3.35.1" while the INSTALLED tailwindcss 3.4.18 requires sucrase ^3.35.0,
 *   so `npm update sucrase` fixes it (2 of 9 sampled claims);
 * - an override the project already has: with `"overrides": { "qs": "^6.16.0" }` the plan read
 *   request's own `~6.5.2` and said "add overrides", where `npm update qs` is the fix.
 *
 * Registry and OSV shapes are the real ones (registry.npmjs.org abbreviated documents,
 * proxy.golang.org lists, api.osv.dev records); the version lists are cut down.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { manifestOverride, projectOverride, workspaceYamlOverride } from "../live/overrides.js";
import type { OsvVulnerability } from "../live/types.js";
import { npmExcludedVersions, npmFlaggedReleases } from "../live/withdrawn-releases.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

type Ev = Record<string, string>;
const adv = (id: string, name: string, events: Ev[], ecosystem = "npm", severity = "HIGH"): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity },
  affected: [{ package: { name, ecosystem }, ranges: [{ type: "SEMVER", events }] }],
});
const fixedIn = (v: string): Ev[] => [{ introduced: "0" }, { fixed: v }];

let ADVISORIES: Record<string, OsvVulnerability[]> = {};
type VersionDoc = { deprecated?: string; dependencies?: Record<string, string> };
let NPM: Record<string, { versions: Record<string, VersionDoc>; latest: string }> = {};
/** proxy.golang.org: module path -> the versions its `@v/list` names (with `v`). */
let GO: Record<string, string[]> = {};
/** Every URL asked for, so a test can say what was (not) looked up. */
let REQUESTS: string[] = [];
/** Advisory ids POST /v1/query leaves out of its answer (an incomplete list; blind audit round 5). */
let QUERY_HIDES: string[] = [];

const cmp = (a: string, b: string) => a.replace(/^v/, "").localeCompare(b.replace(/^v/, ""), undefined, { numeric: true });
const affects = (v: OsvVulnerability, version: string) => {
  const fixed = v.affected![0].ranges[0].events.find((e) => e.fixed)?.fixed;
  return fixed ? cmp(version, fixed) < 0 : true;
};

function stubNetwork() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    REQUESTS.push(url);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (ADVISORIES[q.package.name] ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(ADVISORIES).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: (ADVISORIES[q.package.name] ?? []).filter((v) => !QUERY_HIDES.includes(v.id)) });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({}, 404);
      if (npm[2]) {
        // One release by name: the registry answers 404 for a version it does not have.
        const version = doc.versions[decodeURIComponent(npm[2])];
        return version ? json(version) : json({ error: `version not found: ${npm[2]}` }, 404);
      }
      return json({ name, "dist-tags": { latest: doc.latest }, versions: doc.versions });
    }
    const go = /^https:\/\/proxy\.golang\.org\/(.+)\/@v\/(list|v[^/]+\.info)$/.exec(url);
    if (go) {
      const versions = GO[go[1]];
      if (!versions) return new Response("not found", { status: 404 });
      if (go[2] === "list") return new Response(`${versions.join("\n")}\n`, { status: 200 });
      const version = go[2].replace(/\.info$/, "");
      return versions.includes(version) ? json({ Version: version, Time: "2024-01-01T00:00:00Z" }) : new Response(`not found: ${go[1]}@${version}: invalid version: unknown revision ${version}`, { status: 404 });
    }
    return json({}, 404);
  });
}

let dir: string;
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-followable-"));
  ADVISORIES = {};
  QUERY_HIDES = [];
  NPM = {};
  GO = {};
  REQUESTS = [];
  stubNetwork();
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

type LockEntry = { version: string; dev?: boolean; dependencies?: Record<string, string> };
/** A package-lock v3 project: `direct` is declared; `tree` is every installed entry. `manifest` adds package.json fields. */
function project(direct: Record<string, string>, tree: Record<string, LockEntry>, manifest: Record<string, unknown> = {}) {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: direct, ...manifest }));
  const packages: Record<string, unknown> = { "": { name: "x", dependencies: direct } };
  for (const [n, e] of Object.entries(tree)) packages[`node_modules/${n}`] = e;
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
}

async function live() {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

async function plan(params: Record<string, unknown> = {}) {
  const result = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50, ...params }, await live())) as Record<string, any>;
  const step = (name: string) => result.recommendations.find((s: { package: string }) => s.package === name);
  return { result, step };
}

// ---------------------------------------------------------------------------
// A target the registry does not serve
// ---------------------------------------------------------------------------

describe("a fix target must exist for that exact module path (go.etcd.io/etcd, M6)", () => {
  const INSTALLED = "v0.5.0-alpha.5.0.20200910180754-dd1b699fc489";

  function etcdProject() {
    fs.writeFileSync(path.join(dir, "go.mod"), `module example.com/app\n\ngo 1.22\n\nrequire (\n\tgo.etcd.io/etcd ${INSTALLED} // indirect\n)\n`);
    fs.writeFileSync(path.join(dir, "go.sum"), `go.etcd.io/etcd ${INSTALLED} h1:abc=\ngo.etcd.io/etcd ${INSTALLED}/go.mod h1:def=\n`);
    // OSV's records for the import path: fixed versions on the 3.3 and 3.4 lines (GHSA-x35m-3gp4-4fh5 names 3.4.44).
    ADVISORIES["go.etcd.io/etcd"] = [
      adv("GHSA-2xhq-gv6c-p224", "go.etcd.io/etcd", fixedIn("3.4.10"), "Go"),
      adv("GHSA-x35m-3gp4-4fh5", "go.etcd.io/etcd", fixedIn("3.4.44"), "Go"),
    ];
    // What the proxy lists for the module: nothing on 3.4 at all.
    GO["go.etcd.io/etcd"] = ["v0.4.9", "v2.3.8+incompatible", "v3.3.25+incompatible", "v3.3.27+incompatible"];
    // Major 3 is another module, which the proxy does serve.
    GO["go.etcd.io/etcd/v3"] = ["v3.5.0", "v3.5.21", "v3.6.5", "v3.7.0-alpha.0"];
  }

  it("the plan names no release, says the fix is not on this module path, and where it is", async () => {
    etcdProject();
    const { step } = await plan();
    const etcd = step("go.etcd.io/etcd");
    expect(etcd).toMatchObject({ currentVersion: INSTALLED, targetVersion: null, action: "no_fix_available", fixPathChecked: "all_advisories" });
    expect(etcd.withheld).toContain("3.4.44");
    const reasons = etcd.reasons.join(" | ");
    expect(reasons).toMatch(/No installable fix on this module path: /);
    expect(reasons).toMatch(
      /3\.4\.44 is not a version of go\.etcd\.io\/etcd: Go major 3 is a different module, go\.etcd\.io\/etcd\/v3 \(the proxy serves it, v3\.6\.5 its newest release\), and moving to it changes the import path/,
    );
    expect(reasons).not.toMatch(/confirm it is published/);
    expect(JSON.stringify(etcd)).not.toMatch(/go get/);
    // It was asked for by name, at this module path.
    expect(REQUESTS).toContain("https://proxy.golang.org/go.etcd.io/etcd/@v/v3.4.44.info");
  });

  it("vulnerability_scan's fix target and each advisory's own fix say the same", async () => {
    etcdProject();
    const scan = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, await live())) as Record<string, any>;
    const target = scan.fix_targets[`go.etcd.io/etcd@${INSTALLED}`];
    expect(target.target).toBeNull();
    expect(target.note).toMatch(/^No installable fix on this module path: /);
    const row = scan.vulnerabilities.find((v: { vuln_id: string }) => v.vuln_id === "GHSA-x35m-3gp4-4fh5");
    expect(row).toMatchObject({ fixed_version: null, withheld: ["3.4.44"] });
    expect(row.withheld_note).toMatch(/No installable fix for this advisory: 3\.4\.44 is not a version of go\.etcd\.io\/etcd/);
  });

  it("a version the proxy does serve, though its list had not caught up, is the target, confirmed", async () => {
    etcdProject();
    // The list is stale; asked by name, the proxy has v3.4.44+incompatible... here, plainly v3.4.44.
    const fetchList = GO["go.etcd.io/etcd"];
    vi.stubGlobal("fetch", ((original) => async (input: string | URL, init?: RequestInit) => {
      if (String(input) === "https://proxy.golang.org/go.etcd.io/etcd/@v/v3.4.44.info") return new Response(JSON.stringify({ Version: "v3.4.44" }), { status: 200 });
      return original(input, init);
    })(globalThis.fetch as (input: string | URL, init?: RequestInit) => Promise<Response>));
    expect(fetchList).not.toContain("v3.4.44");
    const { step } = await plan();
    const etcd = step("go.etcd.io/etcd");
    expect(etcd.targetVersion).toBe("v3.4.44");
    expect(etcd.reasons.join(" ")).not.toMatch(/confirm it is published|No installable fix/);
  });

  it("when the proxy cannot be asked, the old note stands: confirm it is published", async () => {
    etcdProject();
    vi.stubGlobal("fetch", ((original) => async (input: string | URL, init?: RequestInit) => {
      if (String(input).endsWith("/@v/v3.4.44.info")) return new Response("bad gateway", { status: 502 });
      return original(input, init);
    })(globalThis.fetch as (input: string | URL, init?: RequestInit) => Promise<Response>));
    const { step } = await plan();
    const etcd = step("go.etcd.io/etcd");
    expect(etcd.targetVersion).toBe("v3.4.44");
    expect(etcd.reasons.join(" ")).toMatch(/3\.4\.44 is an advisory's fixed version newer than every release the registry listed when it was read: confirm it is published/);
  });
});

// ---------------------------------------------------------------------------
// A release its maintainer flagged
// ---------------------------------------------------------------------------

describe("a release deprecated by itself is never the target (lodash.template, M6)", () => {
  const RETIRED = "This package is deprecated. Use https://socket.dev/npm/package/eta instead.";
  const BAD = "Bad release. Please use lodash.template@4.5.0 instead.";
  /** registry.npmjs.org, 2026-11-11: every release carries the retirement notice, 4.18.0 its own. */
  const TEMPLATE: Record<string, string> = {
    "3.6.2": RETIRED, "4.0.0": RETIRED, "4.4.0": RETIRED, "4.5.0": RETIRED, "4.18.0": BAD, "4.18.1": RETIRED,
  };

  it("the rule: on a line that carries another notice, the release with its own message is flagged", () => {
    // The shared withdrawal rule withdraws nothing here: `latest` is deprecated.
    expect(npmExcludedVersions(TEMPLATE, "4.18.1")).toEqual([]);
    expect(npmFlaggedReleases(TEMPLATE, "4.18.1")).toEqual(["4.18.0"]);
    // A line whose releases all say the same thing flags nothing (glob 10.x keeps its target).
    const GLOB = "Old versions of glob are not supported";
    expect(npmFlaggedReleases({ "10.4.5": GLOB, "10.5.0": GLOB, "11.0.0": GLOB, "12.0.0": undefined }, "12.0.0")).toEqual([]);
    // Not retired: the newest release of the line is the odd one out among releases that share a notice.
    expect(npmFlaggedReleases({ "2.0.0": "2.x is no longer maintained", "2.1.0": "2.x is no longer maintained", "2.2.0": "Broken build, do not use", "3.0.0": undefined }, "3.0.0")).toEqual(["2.2.0"]);
    // Two messages on one line, the later one shared by the newest releases: the earlier ones are the flagged ones.
    expect(npmFlaggedReleases({ "1.0.0": "has a bug, use 1.2", "1.1.0": "has a bug, use 1.2", "1.2.0": "1.x is end of life", "1.3.0": "1.x is end of life", "2.0.0": undefined }, "2.0.0")).toEqual(["1.0.0", "1.1.0"]);
    // Nothing deprecated, a single release on a line, and prereleases: nothing to flag.
    expect(npmFlaggedReleases({ "1.0.0": undefined, "1.1.0": undefined, "2.0.0": "old", "3.0.0-rc.1": "do not use" }, "1.1.0")).toEqual([]);
    // `deprecated: true` is a notice like any other.
    expect(npmFlaggedReleases({ "1.0.0": true, "1.1.0": true, "1.2.0": "bad release" }, "1.1.0")).toEqual(["1.2.0"]);
  });

  function templateProject() {
    ADVISORIES["lodash.template"] = [adv("GHSA-35jh-r3h4-6jhm", "lodash.template", fixedIn("4.18.0")), adv("GHSA-r5fr-rjxr-66jc", "lodash.template", fixedIn("4.18.0"))];
    NPM["lodash.template"] = { latest: "4.18.1", versions: Object.fromEntries(Object.entries(TEMPLATE).map(([v, deprecated]) => [v, { deprecated }])) };
    project({ "lodash.template": "^4.5.0" }, { "lodash.template": { version: "4.5.0" } });
  }

  it("4.5.0 goes to 4.18.1, past the flagged 4.18.0, and the plan says both things", async () => {
    templateProject();
    const { step } = await plan();
    const row = step("lodash.template");
    expect(row).toMatchObject({ targetVersion: "4.18.1", action: "upgrade_direct", fixPathChecked: "all_advisories", withheld: ["4.18.0"] });
    const reasons = row.reasons.join(" | ");
    // The flagged release, in the registry's words, and why it was passed.
    expect(reasons).toMatch(/4\.18\.0 is deprecated on npm \(the registry's message is quoted in quoted_from_registry\); 4\.18\.1 is the smallest clean release/);
    // The target is deprecated too (the package is retired): said, never silent.
    expect(reasons).toMatch(/4\.18\.1 is deprecated on npm \(the registry's message is quoted in quoted_from_registry\), a notice on its whole line/);
    expect(row.upgradeCommands?.[0].command).toBe("npm update lodash.template");
  });

  it("vulnerability_scan offers 4.18.1 as well, and never 4.18.0 as an advisory's own fix", async () => {
    templateProject();
    const scan = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, await live())) as Record<string, any>;
    expect(scan.fix_targets["lodash.template@4.5.0"]).toMatchObject({ target: "4.18.1", checked: "all_advisories", withheld: ["4.18.0"] });
    for (const row of scan.vulnerabilities) expect(row).toMatchObject({ fixed_version: "4.18.1", withheld: ["4.18.0"] });
  });

  it("with no release past the flagged one, there is no installable fix (never the flagged release)", async () => {
    templateProject();
    delete NPM["lodash.template"].versions["4.18.1"];
    NPM["lodash.template"].latest = "4.5.0";
    const { step } = await plan();
    const row = step("lodash.template");
    expect(row).toMatchObject({ targetVersion: null, action: "no_fix_available" });
    expect(row.reasons.join(" ")).toMatch(/No installable fix: 4\.18\.0 is deprecated on npm \(the registry's message is quoted/);
  });
});

// ---------------------------------------------------------------------------
// A parent upgrade nobody needs
// ---------------------------------------------------------------------------

describe("when every installed parent already admits the fixed child, the step is a lockfile refresh (M7)", () => {
  /** navcal: tailwindcss -> sucrase -> glob, with the registries' real requirements. */
  function tailwindProject(tailwindRequiresSucrase = "^3.35.0") {
    ADVISORIES.glob = [adv("GHSA-3g3m-2fjr-6pw4", "glob", fixedIn("11.1.0"))];
    NPM.glob = { latest: "11.1.0", versions: { "10.3.10": {}, "10.5.0": {}, "11.0.0": {}, "11.1.0": {} } };
    NPM.sucrase = {
      latest: "3.35.1",
      versions: { "3.34.0": { dependencies: { glob: "7.1.6" } }, "3.35.0": { dependencies: { glob: "^10.3.10" } }, "3.35.1": { dependencies: { tinyglobby: "^0.2.11" } } },
    };
    NPM.tailwindcss = {
      latest: "3.4.19",
      versions: { "3.4.17": { dependencies: { sucrase: "^3.35.0" } }, "3.4.18": { dependencies: { sucrase: tailwindRequiresSucrase } }, "3.4.19": { dependencies: { sucrase: "^3.35.1" } } },
    };
    project({ tailwindcss: "^3.4.1" }, {
      tailwindcss: { version: "3.4.18", dependencies: { sucrase: tailwindRequiresSucrase } },
      sucrase: { version: "3.35.0", dependencies: { glob: "^10.3.10" } },
      glob: { version: "10.5.0" },
    });
  }

  it("glob through sucrase through tailwindcss: `npm update sucrase`, and no tailwindcss upgrade is named", async () => {
    tailwindProject();
    const { result, step } = await plan();
    const glob = step("glob");
    expect(glob).toMatchObject({ action: "lockfile_refresh", targetVersion: "11.1.0", scope: "transitive", fixPathChecked: "all_advisories" });
    expect(glob.refreshCommands).toEqual([{ dir: ".", command: "npm update sucrase" }]);
    expect(glob.parentUpgrades).toBeUndefined();
    const reason = glob.reasons.find((r: string) => r.startsWith("Transitive dependency"));
    expect(reason).toBe(
      'Transitive dependency: sucrase 3.35.0 requires "^10.3.10", which excludes glob 11.1.0; sucrase 3.35.1 is the smallest sucrase release that no longer depends on glob. ' +
        'The one installed parent of sucrase already admits it (tailwindcss 3.4.18 requires "^3.35.0"), so a lockfile refresh is enough and nothing this project declares has to be upgraded: `npm update sucrase` in .',
    );
    // The false claim, in any wording.
    expect(JSON.stringify(glob)).not.toMatch(/tailwindcss 3\.4\.19|upgrade tailwindcss|npm update tailwindcss|npm install/);
    expect(result.lockfileRefreshes).toBe(1);
    expect(result.parentUpgradeSteps).toBe(0);
    expect(result.summary).toMatch(/1 transitive, fixed by a lockfile refresh/);
  });

  it("when the installed parent does NOT admit it, the parent upgrade is still what is named", async () => {
    // tailwindcss 3.4.18 exact-pins sucrase 3.35.0 here: now the lever really has to move.
    tailwindProject("3.35.0");
    const { step } = await plan();
    const glob = step("glob");
    expect(glob.action).toBe("upgrade_parent");
    expect(glob.parentUpgrades[0]).toMatchObject({ parent: "sucrase", from: "3.35.0", to: "3.35.1" });
    expect(glob.parentUpgrades[0].levers[0]).toMatchObject({ name: "tailwindcss", version: "3.4.18", to: "3.4.19" });
    expect(glob.parentUpgrades[0].refreshOnly).toBeUndefined();
  });

  it("a parent release judged clean from a list the batch query contradicts is not named clean (blind audit round 5)", async () => {
    tailwindProject("3.35.0");
    // sucrase 3.35.1 has an advisory of its own that sucrase's list (/v1/query) leaves out.
    ADVISORIES.sucrase = [adv("GHSA-sucr-0000-0000", "sucrase", [{ introduced: "3.35.1" }])];
    QUERY_HIDES = ["GHSA-sucr-0000-0000"];
    const { step } = await plan();
    const glob = step("glob");
    const reason = glob.reasons.find((r: string) => r.startsWith("Transitive dependency"));
    // Named only as unchecked: before, the empty list called sucrase 3.35.1 clean, silently.
    expect(reason).toContain("not checked against sucrase's own advisories");
  });

  it("two installed parents: a refresh only when BOTH admit the fixed child", async () => {
    tailwindProject();
    NPM.other = { latest: "1.0.1", versions: { "1.0.0": { dependencies: { sucrase: "3.35.0" } }, "1.0.1": { dependencies: { sucrase: "^3.35.1" } } } };
    const lockPath = path.join(dir, "package-lock.json");
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8"));
    lock.packages[""].dependencies.other = "^1.0.0";
    lock.packages["node_modules/other"] = { version: "1.0.0", dependencies: { sucrase: "3.35.0" } };
    fs.writeFileSync(lockPath, JSON.stringify(lock));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: { tailwindcss: "^3.4.1", other: "^1.0.0" } }));
    const { step } = await plan();
    const glob = step("glob");
    // `other` exact-pins sucrase 3.35.0, so a refresh cannot move it: no lockfile_refresh claim.
    expect(glob.action).not.toBe("lockfile_refresh");
    expect(JSON.stringify(glob)).toMatch(/other/);
  });

  it("the parent still holds the child after the refresh: the child's own refresh follows", async () => {
    // @azure/identity -> @azure/msal-node: 4.14.1 requires ^7.1.0, which the installed 5.2.2 does not satisfy,
    // so the parent's refresh brings the fixed child in by itself (victauri, the second false claim).
    ADVISORIES["@azure/msal-node"] = [adv("GHSA-msal-0000-0001", "@azure/msal-node", fixedIn("7.1.0"))];
    NPM["@azure/msal-node"] = { latest: "7.2.1", versions: { "5.2.2": {}, "7.1.0": {}, "7.2.1": {} } };
    NPM["@azure/identity"] = { latest: "4.14.1", versions: { "4.13.1": { dependencies: { "@azure/msal-node": "^5.1.0" } }, "4.14.1": { dependencies: { "@azure/msal-node": "^7.1.0" } } } };
    NPM["@vscode/vsce"] = { latest: "4.0.0", versions: { "3.9.1": { dependencies: { "@azure/identity": "^4.1.0" } }, "3.9.2": { dependencies: { "@azure/identity": "^4.14.1" } }, "4.0.0": { dependencies: { "@azure/identity": "^4.14.1" } } } };
    project({ "@vscode/vsce": "^3.9.1" }, {
      "@vscode/vsce": { version: "3.9.1", dependencies: { "@azure/identity": "^4.1.0" } },
      "@azure/identity": { version: "4.13.1", dependencies: { "@azure/msal-node": "^5.1.0" } },
      "@azure/msal-node": { version: "5.2.2" },
    });
    const { step } = await plan();
    const msal = step("@azure/msal-node");
    expect(msal).toMatchObject({ action: "lockfile_refresh", targetVersion: "7.1.0" });
    expect(msal.refreshCommands).toEqual([{ dir: ".", command: "npm update @azure/identity" }]);
    expect(msal.reasons.join(" ")).toMatch(/The one installed parent of @azure\/identity already admits it \(@vscode\/vsce 3\.9\.1 requires "\^4\.1\.0"\)/);
    expect(JSON.stringify(msal)).not.toMatch(/@vscode\/vsce 4\.0\.0|a major upgrade|npm install/);
  });
});

// ---------------------------------------------------------------------------
// An override the project already has
// ---------------------------------------------------------------------------

describe("an existing override is the effective requirement", () => {
  /** 4da-ledger: request 2.88.2 requires qs ~6.5.2; the project overrides qs. */
  function requestProject(manifest: Record<string, unknown>) {
    ADVISORIES.qs = [adv("GHSA-qs00-0000-0001", "qs", fixedIn("6.16.1"))];
    NPM.qs = { latest: "6.16.1", versions: { "6.5.2": {}, "6.5.3": {}, "6.16.0": {}, "6.16.1": {} } };
    NPM.request = { latest: "2.88.2", versions: { "2.88.0": { dependencies: { qs: "~6.5.2" } }, "2.88.2": { deprecated: "request has been deprecated", dependencies: { qs: "~6.5.2" } } } };
    project({ request: "^2.88.2" }, { request: { version: "2.88.2", dependencies: { qs: "~6.5.2" } }, qs: { version: "6.16.0" } }, manifest);
  }

  it("npm `overrides` that admits the fix: `npm update qs`, not 'add overrides'", async () => {
    requestProject({ overrides: { qs: "^6.16.0" } });
    const { step } = await plan();
    const qs = step("qs");
    expect(qs).toMatchObject({ action: "lockfile_refresh", targetVersion: "6.16.1", fixPathChecked: "all_advisories" });
    expect(qs.refreshCommands).toEqual([{ dir: ".", command: "npm update qs" }]);
    const reason = qs.reasons.find((r: string) => r.startsWith("Transitive dependency"));
    expect(reason).toBe(
      'Transitive dependency: "overrides" in package.json forces qs to "^6.16.0", which replaces every parent\'s own requirement and already admits 6.16.1 (a refresh resolves it to 6.16.1), ' +
        "so a lockfile refresh is enough, no parent upgrade and no new override: `npm update qs` in .",
    );
    expect(JSON.stringify(qs)).not.toMatch(/add "overrides"|replace the parent|request 2\.88\.2 requires/);
  });

  it("without the override the parent's own requirement decides, as before", async () => {
    requestProject({});
    const { step } = await plan();
    const qs = step("qs");
    expect(qs.action).toBe("override_or_replace");
    expect(qs.reasons.join(" ")).toMatch(/request 2\.88\.2 requires "~6\.5\.2".*add "overrides": \{ "qs": "6\.16\.1" \}/);
  });

  it("an override that EXCLUDES the fix: change that entry; no parent is blamed and no second override is suggested", async () => {
    requestProject({ overrides: { qs: "6.16.0" } });
    const { step } = await plan();
    const qs = step("qs");
    expect(qs.action).toBe("override_or_replace");
    expect(qs.refreshCommands).toBeUndefined();
    const reason = qs.reasons.find((r: string) => r.startsWith("Transitive dependency"));
    expect(reason).toBe(
      'Transitive dependency: "overrides" in package.json already forces qs to "6.16.0", which replaces every parent\'s own requirement and excludes 6.16.1. ' +
        'Change that entry to "6.16.1" (or a range whose newest release is clean), then reinstall; no parent needs to move and no new override is needed',
    );
    expect(JSON.stringify(qs)).not.toMatch(/add "overrides"|request 2\.88\.2 requires/);
  });

  it("each tool reads its own tables; a parent-scoped entry and a `$` reference are not a plain override", () => {
    const npm = { overrides: { qs: "^6.16.0", lodash: "^4.18.1" } };
    expect(manifestOverride(npm, "qs", "package-lock")).toEqual({ spec: "^6.16.0", where: '"overrides" in package.json' });
    // Yarn ignores `overrides`; it reads `resolutions`, the glob form included.
    expect(manifestOverride(npm, "qs", "yarn")).toBeNull();
    expect(manifestOverride({ resolutions: { "**/qs": "^6.16.1" } }, "qs", "yarn-berry")).toEqual({ spec: "^6.16.1", where: '"resolutions" in package.json' });
    expect(manifestOverride({ resolutions: { "request/qs": "^6.16.1" } }, "qs", "yarn")).toBeNull();
    // pnpm: its own table first, and `resolutions`; npm's `overrides` field is not pnpm's.
    expect(manifestOverride({ pnpm: { overrides: { qs: "6.16.1" } } }, "qs", "pnpm")).toEqual({ spec: "6.16.1", where: '"pnpm.overrides" in package.json' });
    expect(manifestOverride({ pnpm: { overrides: { "request>qs": "6.16.1", "qs@<6.5": "6.16.1" } } }, "qs", "pnpm")).toBeNull();
    expect(manifestOverride(npm, "qs", "pnpm")).toBeNull();
    expect(manifestOverride({ overrides: { request: { qs: "^6.16.0" }, uuid: "$uuid", empty: "  " } }, "qs", "package-lock")).toBeNull();
    expect(manifestOverride({ overrides: { uuid: "$uuid" } }, "uuid", "package-lock")).toBeNull();
    expect(manifestOverride(npm, "qs", "cargo")).toBeNull();
    expect(manifestOverride(null, "qs", "package-lock")).toBeNull();
  });

  it("pnpm-workspace.yaml `overrides:` (where pnpm 10 keeps its settings)", () => {
    const yaml = ["packages:", "  - 'packages/*'", "overrides:", "  # pinned for GHSA-x", "  qs: ^6.16.0", '  "@scope/pkg": "1.2.3"  # why', "  request>tough-cookie: 4.1.3", "onlyBuiltDependencies:", "  - qs", ""].join("\n");
    expect(workspaceYamlOverride(yaml, "qs")).toBe("^6.16.0");
    expect(workspaceYamlOverride(yaml, "@scope/pkg")).toBe("1.2.3");
    expect(workspaceYamlOverride(yaml, "tough-cookie")).toBeNull();
    expect(workspaceYamlOverride("packages:\n  - qs: 1\n", "qs")).toBeNull();
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x" }));
    fs.writeFileSync(path.join(dir, "pnpm-workspace.yaml"), yaml);
    expect(projectOverride(dir, "qs", "pnpm")).toEqual({ spec: "^6.16.0", where: '"overrides" in pnpm-workspace.yaml' });
    expect(projectOverride(dir, "qs", "package-lock")).toBeNull();
  });
});
