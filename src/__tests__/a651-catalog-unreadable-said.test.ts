// SPDX-License-Identifier: Apache-2.0
/**
 * A catalog that cannot be read is never silent. Re-check of 0d30b40 (2026-11-24, case b8-catclean):
 * a pnpm member with no lockfile declaring `react: catalog:` and `react-dom: catalog:`, the catalog
 * written with a YAML anchor (`react: &react ^18.2.0`, `react-dom: *react`, valid YAML that pnpm
 * reads), scanned `complete: true` with no dependency, health said no manifest was found, the
 * briefing called react private, and the workspace file was never named. 6.5.0 gave rows for both.
 * Now anchors and aliases are read; a catalog that still cannot be read (or that repeats a key, which
 * pnpm refuses) names the file and why, the scan is incomplete, the plan says NOT CHECKED, and the
 * dependency is "declared through a catalog that could not be read", not private.
 */

import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { npmCatalogsFor } from "../live/npm-catalog.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM = { react: { latest: "18.3.1", versions: { "18.2.0": {}, "18.3.1": {} } }, "react-dom": { latest: "18.3.1", versions: { "18.2.0": {}, "18.3.1": {} } }, ms: { latest: "2.1.3", versions: { "2.1.3": {} } } };
});
afterEach(() => h.dispose());

function liveIn(dir: string): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

describe("YAML anchors and repeated keys in a catalog", () => {
  it("an anchored value and its alias are read", () => {
    h.write("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\ncatalog:\n  react: &react ^18.2.0\n  react-dom: *react\ncatalogs:\n  legacy:\n    ms: &ms '2.1.3'\n    other: *ms\n");
    const c = npmCatalogsFor(h.dir);
    expect(c.error).toBeUndefined();
    expect(c.lookup("default", "react")).toBe("^18.2.0");
    expect(c.lookup("default", "react-dom")).toBe("^18.2.0");
    expect(c.lookup("legacy", "other")).toBe("2.1.3");
  });
  it("refused rather than guessed: an alias before its anchor, an anchor defined twice, catalog with catalogs.default", () => {
    // Check of round 2: the reader read every anchor in the file first (an alias before its anchor
    // passed), took the last of two definitions (pnpm takes the earlier one at the point of use), and
    // merged catalog with catalogs.default (pnpm refuses the file).
    h.write("pnpm-workspace.yaml", "catalog:\n  react-dom: *react\n  react: &react ^18.2.0\n");
    expect(npmCatalogsFor(h.dir).error).toBeTruthy();
    h.write("pnpm-workspace.yaml", "catalog:\n  react: &v ^18.2.0\n  vue: &v ^3.0.0\n  react-dom: *v\n");
    expect(npmCatalogsFor(h.dir).error).toBeTruthy();
    // An anchor defined twice that no catalog entry uses: pnpm reads the file, and so does the reader
    // (final check: unit/catalog-forms7 anchorTwiceUnused).
    h.write("pnpm-workspace.yaml", "a: &v 1\nb: &v 2\ncatalog:\n  react: ^18.2.0\n");
    expect(npmCatalogsFor(h.dir).error).toBeUndefined();
    expect(npmCatalogsFor(h.dir).lookup("default", "react")).toBe("^18.2.0");
    h.write("pnpm-workspace.yaml", "catalog:\n  react: ^18.2.0\ncatalogs:\n  default:\n    vue: ^3.0.0\n");
    expect(npmCatalogsFor(h.dir).error).toMatch(/catalogs\.default/);
  });
  it("a repeated key, or an alias of an unknown anchor, makes the catalog unreadable", () => {
    h.write("pnpm-workspace.yaml", "catalog:\n  acme-dup: link:../x\n  acme-dup: ^1.0.0\n");
    expect(npmCatalogsFor(h.dir).error).toMatch(/repeats a key/);
    h.write("pnpm-workspace.yaml", "catalog:\n  react: *nowhere\n");
    expect(npmCatalogsFor(h.dir).error).toBeTruthy();
  });
});

describe("a member whose catalog cannot be read", () => {
  const member = () => path.join(h.dir, "packages", "web");
  beforeEach(() => {
    h.write("package.json", JSON.stringify({ name: "root", private: true, devDependencies: { ms: "2.1.3" } }));
    h.write("packages/web/package.json", JSON.stringify({ name: "web", version: "1.0.0", dependencies: { react: "catalog:", "react-dom": "catalog:" } }));
  });

  it("anchors: rows for react and react-dom, as 6.5.0 gave", async () => {
    h.write("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\ncatalog:\n  react: &react ^18.2.0\n  react-dom: *react\n");
    const live = liveIn(member());
    const scan = (await executeVulnerabilityScan(null, { project_path: member() }, live)) as Record<string, any>;
    expect(JSON.stringify(scan.coverage)).not.toContain("pnpm-workspace.yaml");
    await executeDependencyHealth(null, {}, live);
    expect(h.requests).toContain("https://registry.npmjs.org/react");
    expect(h.requests).toContain("https://registry.npmjs.org/react-dom");
  });

  it("unreadable: the file and why are named, the scan is incomplete, the plan says NOT CHECKED, the item is not private", async () => {
    h.write("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\ncatalog:\n  react: ^18.2.0\n  react: ^18.3.0\n  react-dom: ^18.2.0\n");
    const scan = await h.scan();
    expect(scan.coverage.complete).toBe(false);
    expect(JSON.stringify(scan.coverage)).toContain("pnpm-workspace.yaml");
    expect(JSON.stringify(scan.coverage)).toContain("repeats a key");
    const { result: plan } = await h.plan();
    expect(plan.vulnerabilityDataAvailable).toBe(false);
    expect(String(plan.summary)).toMatch(/^NOT CHECKED/);
    const r = (await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "react", to: "18.3.1" }] }, await h.live())) as { results: Array<{ reason: string; not_checked?: string }> };
    expect(r.results[0].reason).toMatch(/^NOT CHECKED \(catalog not read\)/);
    expect(r.results[0].reason).toContain("declared through a catalog that could not be read");
    expect(r.results[0].reason).not.toMatch(/private package|private registry/);
  });

  it("an entry the catalog lacks is named too", async () => {
    h.write("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\ncatalog:\n  react: ^18.2.0\n");
    const scan = await h.scan();
    expect(scan.coverage.complete).toBe(false);
    expect(JSON.stringify(scan.coverage)).toContain("has no entry for react-dom");
  });
});
