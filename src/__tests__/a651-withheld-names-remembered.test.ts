// SPDX-License-Identifier: Apache-2.0
/**
 * A name a scan withholds because the project takes it from a path, git, a URL or a workspace (npm's
 * non-registry specs, a Cargo `path`/`git` crate, a uv/Poetry direct source) is private for the rest
 * of the process, as private-registry names already were (private-guard.ts, blind audit round 5, 4).
 *
 * Privacy review of the 6.5.1 candidate (2026-11-24, cases cross-lock3 and cross-project): after a
 * scan of one project, `what_should_i_know { project_path: <another>, task: "add zqrev-tgz ..." }`
 * sent zqrev-tgz, zqrev-gh, zqrev-file-dir and zqrev-member to OSV and the registry:
 * rememberPrivateName was called only for lockfile-private names (privateDeps). Stubbed fetch.
 */

import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { resetPrivateGuard } from "../live/private-guard.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const INVENTED = /acme/i;
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const leaked = () => sent().filter((s) => INVENTED.test(s));

beforeEach(() => {
  resetPrivateGuard();
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.NPM = { ms: { latest: "2.1.3", versions: { "2.1.3": {} } } };
  h.write(".git/HEAD", "ref: refs/heads/main\n");
});
afterEach(() => {
  h.dispose();
  resetPrivateGuard();
});

function liveIn(dir: string): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

describe("names withheld in one project stay withheld for another", () => {
  it("npm path, archive, git and workspace member names", async () => {
    h.write("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", workspaces: ["packages/*"], dependencies: { ms: "2.1.3", "acme-tgz": "file:vendor/acme-tgz-1.0.0.tgz", "acme-gh": "github:acmeorg/acme-gh", "acme-dir": "file:vendor/acme-dir" } }));
    h.write("a/packages/m/package.json", JSON.stringify({ name: "acme-member", version: "1.0.0" }));
    h.write("b/package.json", JSON.stringify({ name: "b", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    const live = liveIn(path.join(h.dir, "a"));
    await executeDependencyHealth(null, {}, live);
    await executeWhatShouldIKnow(null, { task: "add acme-tgz 1.0.0 and acme-gh 1.0.0 and acme-dir and acme-member", project_path: path.join(h.dir, "b") }, live);
    const other = liveIn(path.join(h.dir, "b"));
    await executeDependencyCheck(null, { items: ["acme-tgz", "acme-gh", "acme-dir", "acme-member"].map((p) => ({ ecosystem: "npm", package: p, to: "1.0.1" })) }, other);
    expect(leaked()).toEqual([]);
  });

  it("a Cargo path crate", async () => {
    h.CRATES = { smallvec: [{ vers: "1.13.2" }] };
    h.write("a/Cargo.toml", '[package]\nname = "a"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsmallvec = "1.13.2"\nacme-path = { path = "../acme-path" }\n');
    h.write("b/package.json", JSON.stringify({ name: "b", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    const live = liveIn(path.join(h.dir, "a"));
    await executeDependencyHealth(null, {}, live);
    await executeDependencyCheck(null, { items: [{ ecosystem: "crates.io", package: "acme-path", to: "1.0.1" }] }, liveIn(path.join(h.dir, "b")));
    expect(leaked()).toEqual([]);
  });
});
