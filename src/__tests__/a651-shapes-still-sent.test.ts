// SPDX-License-Identifier: Apache-2.0
/**
 * Shapes the re-check of 0d30b40 (2026-11-24) still saw sent: Cargo dotted inheritance
 * (`x.workspace = true` read as a crate named `x.workspace`; `x.path = "..."` not read), a uv
 * `{ workspace = true }` source, a symlinked npm workspace member, a member's own name asked at a
 * workspace root with no lockfile, and a server started below a project's folder (`src/lib`), where
 * nothing was known. Stubbed fetch: nothing leaves the machine.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { cargoManifestPrivate, pyprojectManifestPrivate } from "../live/private-packages.js";
import { cargoWorkspaceDeps } from "../project-manifests.js";
import { nearestProjectAbove, scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
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
  h.write(".git/HEAD", "ref: refs/heads/main\n");
});
afterEach(() => h.dispose());

function liveIn(dir: string): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}
async function ask(live: LiveIntelligence, ecosystem: string, names: string[]) {
  return (await executeDependencyCheck(null, { items: names.map((p) => ({ ecosystem, package: p, to: "1.0.1" })) }, live)) as { results: Array<{ not_checked?: string }> };
}

describe("Cargo dotted keys are the inline table form", () => {
  it("cargoManifestPrivate reads name.path, name.git, name.registry and name.package", () => {
    const names = cargoManifestPrivate('[dependencies]\nacme-p.path = "../p"\nacme-g.git = "https://git.acme.example/g"\nacme-r.version = "1"\nacme-r.registry = "acme"\nacme-k.package = "acme-real"\nacme-k.path = "../k"\nserde.version = "1"\n').map((p) => p.name).sort();
    expect(names).toEqual(["acme-g", "acme-k", "acme-p", "acme-r", "acme-real"]);
  });
  it("a workspace root's member that inherits with name.workspace = true names the crate, not name.workspace", () => {
    h.write("Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n\n[workspace.dependencies]\nsmallvec = "1.13"\n');
    h.write("crates/a/Cargo.toml", '[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\nsmallvec.workspace = true\n"zope.like" = "1"\n');
    const deps = cargoWorkspaceDeps(h.dir, fs.readFileSync(path.join(h.dir, "Cargo.toml"), "utf8")).deps.sort();
    expect(deps).toEqual(["smallvec", "zope.like"]);
  });
  it("at a virtual root with no Cargo.lock, an inherited path crate is never sent", async () => {
    h.write("Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n\n[workspace.dependencies]\nacme-wspath = { path = "libs/acme-wspath" }\nsmallvec = "1.13.2"\n');
    h.write("crates/a/Cargo.toml", '[package]\nname = "acme-a"\nversion = "0.1.0"\n\n[dependencies]\nacme-wspath.workspace = true\nsmallvec.workspace = true\n');
    h.write("libs/acme-wspath/Cargo.toml", '[package]\nname = "acme-wspath"\nversion = "0.1.0"\n');
    const live = liveIn(h.dir);
    await executeDependencyHealth(null, {}, live);
    await ask(live, "crates.io", ["acme-wspath", "acme-a"]);
    expect(leaked()).toEqual([]);
  });
});

describe("uv workspace sources", () => {
  it("{ workspace = true } is local code, inline or as a table", () => {
    expect(pyprojectManifestPrivate('[project]\nname = "app"\ndependencies = ["acme-member"]\n\n[tool.uv.sources]\nacme-member = { workspace = true }\n').map((p) => p.name)).toEqual(["acme-member"]);
    expect(pyprojectManifestPrivate('[project]\nname = "app"\n\n[tool.uv.sources.acme-other]\nworkspace = true\n').map((p) => p.name)).toEqual(["acme-other"]);
  });
});

describe("a Python project's own name", () => {
  it("[project].name asked directly is withheld", async () => {
    h.write("pyproject.toml", '[project]\nname = "acme-app"\nversion = "0.1.0"\ndependencies = ["requests==2.32.3"]\n');
    h.PYPI = { requests: { "2.32.3": {} } };
    const r = await ask(liveIn(h.dir), "PyPI", ["acme-app"]);
    expect(leaked()).toEqual([]);
    expect(r.results[0].not_checked).toBe("private");
  });
});

describe("npm workspaces", () => {
  it("a symlinked member's name is never sent", async () => {
    h.write("package.json", JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"], devDependencies: { ms: "2.1.3" } }));
    h.write("real/acme-sym/package.json", JSON.stringify({ name: "acme-sym", version: "1.0.0" }));
    fs.mkdirSync(path.join(h.dir, "packages"), { recursive: true });
    fs.symlinkSync(path.join(h.dir, "real", "acme-sym"), path.join(h.dir, "packages", "sym"), "junction");
    const live = liveIn(h.dir);
    await ask(live, "npm", ["acme-sym"]);
    expect(leaked()).toEqual([]);
  });

  it("at a root with no dependencies and no lockfile, a member's own name asked directly is withheld", async () => {
    h.write("package.json", JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }));
    h.write("packages/a/package.json", JSON.stringify({ name: "acme-mem-a", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    const r = await ask(liveIn(h.dir), "npm", ["acme-mem-a"]);
    expect(leaked()).toEqual([]);
    expect(r.results[0].not_checked).toBe("private");
  });
});

describe("started below a project's folder", () => {
  it("nearestProjectAbove finds the member; the server reads it and its workspace", async () => {
    h.write("package.json", JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }));
    h.write("packages/a/package.json", JSON.stringify({ name: "acme-a", version: "1.0.0", dependencies: { "acme-b": "^1.0.0", ms: "2.1.3" } }));
    h.write("packages/b/package.json", JSON.stringify({ name: "acme-b", version: "1.0.0" }));
    h.write("packages/a/src/lib/index.js", "export {};\n");
    const deep = path.join(h.dir, "packages", "a", "src", "lib");
    expect(nearestProjectAbove(deep)).toBe(path.join(h.dir, "packages", "a"));
    const live = liveIn(deep);
    await executeDependencyHealth(null, {}, live);
    await ask(live, "npm", ["acme-b", "acme-a"]);
    expect(leaked()).toEqual([]);
  });
});
