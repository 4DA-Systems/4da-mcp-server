// SPDX-License-Identifier: Apache-2.0
/**
 * A `catalog:` dependency is what its catalog entry says, read from the workspace file: pnpm's
 * pnpm-workspace.yaml (`catalog:` and `catalogs.<name>`, at the project or a workspace root above
 * it) and Bun's root package.json (`catalog` / `catalogs`, top level or under `workspaces`). The
 * resolved spec is classified by the same rules as any package.json spec, so a catalog entry that
 * is `link:`, `file:`, `workspace:`, git or a URL keeps its name off the network.
 *
 * Review of the 6.5.1 candidate (2026-11-24, p-npmspec.mjs): `"zqrev-lib": "catalog:"` with
 * `catalog: { zqrev-lib: link:../zqrev-lib }` and no lockfile sent the name to registry.npmjs.org,
 * api.npmjs.org, api.osv.dev and hn.algolia.com, because every `catalog:` was taken for a registry
 * range. A catalog entry that cannot be found, or a workspace file that cannot be read, withholds
 * the name too: what was not classified is never sent. A registry range in the catalog is still
 * checked, with the catalog's range as the declared range.
 *
 * Every request (URL and body) is recorded by the harness's stubbed fetch; nothing leaves the machine.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeEcosystemPulse } from "../tools/ecosystem-pulse.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { classifyNpmSpec } from "../live/npm-spec.js";
import { npmCatalogsFor } from "../live/npm-catalog.js";
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
});
afterEach(() => h.dispose());

/** Every tool that could send a dependency name, then dependency_check on `names`. */
async function everyTool(names: string[]) {
  const health = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
  await h.plan();
  await h.scan();
  const live = await h.live();
  await executeEcosystemPulse(null, {}, live);
  await executeWhatShouldIKnow(null, { task: `upgrade ${names.join(" and ")} and ms`, project_path: h.dir }, live);
  const check = (await executeDependencyCheck(null, { items: names.map((p) => ({ ecosystem: "npm", package: p, to: "1.0.1" })) }, live)) as { results: Array<{ verdict: string; not_checked?: string; reason?: string }> };
  return { health, check };
}

describe("classifyNpmSpec reads a catalog entry and classifies what it holds", () => {
  const catalogs = (entries: Record<string, string>, named: Record<string, Record<string, string>> = {}) => ({
    file: "/w/pnpm-workspace.yaml",
    lookup: (catalog: string, name: string) => (catalog === "default" ? entries[name] : named[catalog]?.[name]),
  });

  it("link:, file:, workspace:, git and a URL in the catalog are not registry releases", () => {
    const c = catalogs({ a: "link:../a", b: "file:./vendor/b-1.0.0.tgz", c: "workspace:*", d: "github:org/d", e: "https://npm.internal.example/e/-/e-1.0.0.tgz", f: "../f" });
    for (const n of ["a", "b", "c", "d", "e", "f"]) expect([n, classifyNpmSpec(n, "catalog:", c).kind]).not.toEqual([n, "registry"]);
  });

  it("a registry range in the catalog is that range; a named catalog is read by its name", () => {
    const c = catalogs({ ms: "^2.1.3", alias: "npm:string-width@^4.2.0" }, { legacy: { ms: "1.x" } });
    expect(classifyNpmSpec("ms", "catalog:", c)).toMatchObject({ kind: "registry", name: "ms", range: "^2.1.3" });
    expect(classifyNpmSpec("ms", "catalog:default", c)).toMatchObject({ kind: "registry", name: "ms", range: "^2.1.3" });
    expect(classifyNpmSpec("ms", "catalog:legacy", c)).toMatchObject({ kind: "registry", name: "ms", range: "1.x" });
    expect(classifyNpmSpec("alias", "catalog:", c)).toMatchObject({ kind: "registry", name: "string-width", range: "^4.2.0" });
  });

  it("an entry that is missing, a catalog that was not read, or a catalog: inside a catalog is withheld", () => {
    const c = catalogs({ loop: "catalog:" });
    expect(classifyNpmSpec("ms", "catalog:").kind).not.toBe("registry");
    expect(classifyNpmSpec("ms", "catalog:", c).kind).not.toBe("registry");
    expect(classifyNpmSpec("ms", "catalog:other", c).kind).not.toBe("registry");
    expect(classifyNpmSpec("loop", "catalog:", c).kind).not.toBe("registry");
  });
});

describe("npmCatalogsFor finds the workspace file a package manager reads", () => {
  it("pnpm-workspace.yaml at a workspace root above the member, block and flow forms, quoted keys", () => {
    h.write("pnpm-workspace.yaml", ["packages:", "  - packages/*", "catalog:", "  acme-a: link:../acme-a # local", "  '@acme/b': \"file:./b.tgz\"", "  ms: ^2.1.3", "catalogs:", "  legacy:", "    ms: 1.x", "  flow: { acme-c: 'workspace:*', ms: '2' }", ""].join("\n"));
    h.write("packages/app/package.json", JSON.stringify({ name: "app" }));
    const c = npmCatalogsFor(path.join(h.dir, "packages", "app"));
    expect(c.file).toBe(path.join(h.dir, "pnpm-workspace.yaml"));
    expect(c.lookup("default", "acme-a")).toBe("link:../acme-a");
    expect(c.lookup("default", "@acme/b")).toBe("file:./b.tgz");
    expect(c.lookup("default", "ms")).toBe("^2.1.3");
    expect(c.lookup("legacy", "ms")).toBe("1.x");
    expect(c.lookup("flow", "acme-c")).toBe("workspace:*");
    expect(c.lookup("default", "nope")).toBeUndefined();
  });

  it("a catalog block it cannot parse reads as unreadable: nothing is looked up from it", () => {
    h.write("pnpm-workspace.yaml", ["catalog:", "  acme-a: link:../acme-a", "  - not a mapping", ""].join("\n"));
    const c = npmCatalogsFor(h.dir);
    expect(c.error).toBeTruthy();
    expect(c.lookup("default", "acme-a")).toBeUndefined();
  });

  it("Bun: the root package.json's catalog and catalogs, top level or under workspaces", () => {
    h.write("package.json", JSON.stringify({ name: "root", workspaces: { packages: ["packages/*"], catalog: { "acme-a": "link:../acme-a" }, catalogs: { t: { ms: "2.x" } } } }));
    h.write("packages/app/package.json", JSON.stringify({ name: "app" }));
    const c = npmCatalogsFor(path.join(h.dir, "packages", "app"));
    expect(c.lookup("default", "acme-a")).toBe("link:../acme-a");
    expect(c.lookup("t", "ms")).toBe("2.x");
    h.write("package.json", JSON.stringify({ name: "root", workspaces: ["packages/*"], catalog: { ms: "^2" } }));
    expect(npmCatalogsFor(path.join(h.dir, "packages", "app")).lookup("default", "ms")).toBe("^2");
  });
});

describe("no lockfile: a catalog entry that is local code, an archive or git is never sent", () => {
  it("pnpm default catalog: link: and file: entries, ms still checked with the catalog's range", async () => {
    h.write("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: { "acme-lib": "catalog:", "acme-tgz": "catalog:", ms: "catalog:" } }));
    h.write("pnpm-workspace.yaml", "packages:\n  - '.'\ncatalog:\n  acme-lib: link:../acme-lib\n  acme-tgz: file:./vendor/acme-tgz-1.0.0.tgz\n  ms: ^2.1.3\n");
    const { health, check } = await everyTool(["acme-lib", "acme-tgz"]);
    expect(leaked()).toEqual([]);
    expect(h.requests).toContain("https://registry.npmjs.org/ms");
    const ms = health.dependencies.find((d: { name: string }) => d.name === "ms");
    expect(ms?.declaredRange ?? ms?.declared_range).toBe("^2.1.3");
    expect(check.results.map((r) => [r.verdict, r.not_checked])).toEqual([
      ["unknown", "private"],
      ["unknown", "private"],
    ]);
    expect(check.results[0].reason).toContain("link:../acme-lib");
  });

  it("a named catalog in a workspace root above the scanned member", async () => {
    h.write("pnpm-workspace.yaml", "packages:\n  - packages/*\ncatalogs:\n  internal:\n    acme-x: github:acmeorg/acme-x#main\n");
    h.write("package.json", JSON.stringify({ name: "root", private: true, devDependencies: { ms: "2.1.3" } }));
    h.write("packages/app/package.json", JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "acme-x": "catalog:internal", ms: "2.1.3" } }));
    await everyTool(["acme-x"]);
    expect(leaked()).toEqual([]);
  });

  it("an entry the catalog does not have, and an unreadable catalog, withhold the name and say so", async () => {
    h.write("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: { "acme-missing": "catalog:", "acme-named": "catalog:nope", ms: "2.1.3" } }));
    h.write("pnpm-workspace.yaml", "catalog:\n  ms: ^2.1.3\n");
    const { check } = await everyTool(["acme-missing", "acme-named"]);
    expect(leaked()).toEqual([]);
    expect(check.results.map((r) => [r.verdict, r.not_checked])).toEqual([
      ["unknown", "private"],
      ["unknown", "private"],
    ]);
    expect(check.results[0].reason).toMatch(/catalog/);
  });

  it("no workspace file at all: a catalog: dependency is withheld", async () => {
    h.write("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: { "acme-lib": "catalog:", ms: "2.1.3" } }));
    await everyTool(["acme-lib"]);
    expect(leaked()).toEqual([]);
    expect(h.requests).toContain("https://registry.npmjs.org/ms");
  });

  it("a workspace file whose catalog cannot be parsed withholds every catalog: name", async () => {
    h.write("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: { "acme-lib": "catalog:", ms: "2.1.3" } }));
    h.write("pnpm-workspace.yaml", "catalog:\n  acme-lib: ^1.0.0\n  [broken\n");
    await everyTool(["acme-lib"]);
    expect(leaked()).toEqual([]);
  });

  it("Bun: workspaces.catalog in the root package.json", async () => {
    h.write("package.json", JSON.stringify({ name: "root", private: true, devDependencies: { ms: "2.1.3" }, workspaces: { packages: ["packages/*"], catalog: { "acme-b": "link:../acme-b", ms: "^2.1.3" } } }));
    h.write("packages/app/package.json", JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "acme-b": "catalog:", ms: "catalog:" } }));
    await everyTool(["acme-b"]);
    expect(leaked()).toEqual([]);
  });

  it("an edit to the catalog is read on the next call", async () => {
    h.write("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: { "acme-lib": "catalog:", ms: "2.1.3" } }));
    h.write("pnpm-workspace.yaml", "catalog:\n  acme-lib: link:../acme-lib\n");
    const live = await h.live();
    await executeDependencyHealth(null, {}, live);
    expect(leaked()).toEqual([]);
    const file = path.join(h.dir, "pnpm-workspace.yaml");
    fs.writeFileSync(file, "catalog:\n  acme-lib: workspace:*\n  other: ^1.0.0\n");
    const later = new Date(Date.now() + 5000);
    fs.utimesSync(file, later, later);
    // What dispatchTool does before dependency_check (tool-dispatch.ts, READS_DEPENDENCY_SET).
    live.refreshIfLockfilesChanged();
    const check = (await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "acme-lib", to: "1.0.1" }] }, live)) as { results: Array<{ reason?: string }> };
    expect(leaked()).toEqual([]);
    expect(check.results[0].reason).toContain("workspace:*");
  });
});
