// SPDX-License-Identifier: Apache-2.0
/**
 * Started in a workspace member with no lockfile anywhere, the workspace's own packages are still
 * the workspace's own: a sibling member's name, the member's own name, and a Cargo dependency the
 * member inherits (`{ workspace = true }`) from a root `[workspace.dependencies]` path entry are
 * never looked up.
 *
 * Privacy review of the 6.5.1 candidate (2026-11-24, cases auto-ws-member and cargo-nolock):
 * findWorkspaceRoot (project-tree.ts) switches to an ancestor only when that ancestor has a lockfile
 * listing the member, and the withheld-name pass read only the starting directory's own workspace
 * list, so `"@zqscope/zqrev-b": "^1.0.0"` and `"zqrev-c": "*"` (both siblings) went to
 * registry.npmjs.org, api.npmjs.org and hn.algolia.com, and the inherited path crate went to
 * index.crates.io. Membership is now read from the enclosing workspace root's manifests whether or
 * not a lockfile exists, within the same search bounds (inside the git repository, never at or
 * above the home directory). Stubbed fetch: nothing leaves the machine.
 */

import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeEcosystemPulse } from "../tools/ecosystem-pulse.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const INVENTED = /acme/i;
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const leaked = () => sent().filter((s) => INVENTED.test(s));

beforeEach(() => {
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.NPM = { ms: { latest: "2.1.3", versions: { "2.1.3": {} } } };
  h.CRATES = { smallvec: [{ vers: "1.13.2" }] };
  // The repository root bounds the search for a workspace root, as in a real checkout.
  h.write(".git/HEAD", "ref: refs/heads/main\n");
});
afterEach(() => h.dispose());

/** The live set a server started in `dir` holds. */
function liveIn(dir: string): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

async function everyTool(dir: string, ecosystem: string, names: string[]) {
  const live = liveIn(dir);
  await executeDependencyHealth(null, { include_dev: true }, live);
  await executeVulnerabilityScan(null, { project_path: dir }, live);
  await executeUpgradePlanner(null as never, { project_path: dir, include_dev: true }, live);
  await executeEcosystemPulse(null, {}, live);
  const check = (await executeDependencyCheck(null, { items: names.map((p) => ({ ecosystem, package: p, to: "1.0.1" })) }, live)) as { results: Array<{ verdict: string; not_checked?: string }> };
  return check;
}

describe("npm: a member of a workspace with no lockfile", () => {
  const member = () => path.join(h.dir, "packages", "a");
  beforeEach(() => {
    h.write("packages/a/package.json", JSON.stringify({ name: "@acme/a", version: "1.0.0", dependencies: { "@acme/b": "^1.0.0", "acme-c": "*", ms: "2.1.3" } }));
    h.write("packages/b/package.json", JSON.stringify({ name: "@acme/b", version: "1.0.0" }));
    h.write("packages/c/package.json", JSON.stringify({ name: "acme-c", version: "1.0.0" }));
  });

  it("package.json workspaces: siblings and the member's own name are never sent, ms is checked", async () => {
    h.write("package.json", JSON.stringify({ name: "acme-root", private: true, workspaces: ["packages/*"] }));
    const check = await everyTool(member(), "npm", ["@acme/b", "acme-c", "@acme/a"]);
    expect(leaked()).toEqual([]);
    expect(h.requests).toContain("https://registry.npmjs.org/ms");
    expect(check.results.map((r) => r.not_checked)).toEqual(["private", "private", "private"]);
  });

  it("pnpm-workspace.yaml packages", async () => {
    h.write("package.json", JSON.stringify({ name: "acme-root", private: true }));
    h.write("pnpm-workspace.yaml", "packages:\n  - packages/*\n");
    await everyTool(member(), "npm", ["@acme/b", "acme-c"]);
    expect(leaked()).toEqual([]);
  });

  it("started at the root, upgrade_planner on the member's path sends no member name", async () => {
    h.write("package.json", JSON.stringify({ name: "acme-root", private: true, workspaces: ["packages/*"] }));
    await executeUpgradePlanner(null as never, { project_path: member(), include_dev: true }, liveIn(h.dir));
    await executeVulnerabilityScan(null, { project_path: member() }, liveIn(h.dir));
    expect(leaked()).toEqual([]);
  });
});

describe("Cargo: a member that inherits a path dependency from the workspace root, no Cargo.lock", () => {
  it("the inherited crate and the sibling crate are never sent", async () => {
    h.write("Cargo.toml", '[package]\nname = "acme-app"\nversion = "0.1.0"\nedition = "2021"\n\n[workspace]\nmembers = ["crates/*"]\n\n[workspace.dependencies]\nacme-ws = { path = "crates/acme-ws", version = "0.1" }\n');
    h.write("crates/acme-member/Cargo.toml", '[package]\nname = "acme-member"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nacme-ws = { workspace = true }\nacme-sibling = "0.1"\nsmallvec = "1.13.2"\n');
    h.write("crates/acme-sibling/Cargo.toml", '[package]\nname = "acme-sibling"\nversion = "0.1.0"\nedition = "2021"\n');
    h.write("crates/acme-ws/Cargo.toml", '[package]\nname = "acme-ws"\nversion = "0.1.0"\nedition = "2021"\n');
    const check = await everyTool(path.join(h.dir, "crates", "acme-member"), "crates.io", ["acme-ws", "acme-sibling", "acme-member"]);
    expect(leaked()).toEqual([]);
    expect(check.results.map((r) => r.not_checked)).toEqual(["private", "private", "private"]);
  });
});
