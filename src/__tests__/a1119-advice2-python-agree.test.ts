// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, upgrade_planner and vulnerability_scan judge a release's marker-gated
 * requirements on the same Python: the one declared by the project that declares the package
 * (dependency-check-python.ts projectPythons), not only the repository root's. A Python project in
 * a sub-folder declaring `requires-python >=3.9` installs no `badpkg; python_version < "3.8"`, so
 * no tool may hold the target back for it.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import type { FourDADatabase } from "../db.js";
import { advisory, emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();
const PKG = "py-http2";

let net: Net;
let restore: () => void;
const dirs: string[] = [];
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  net.pypi[PKG] = {
    releases: { "2.25.1": [{ upload_time_iso_8601: daysAgo(900), requires_python: ">=3.7" }], "2.33.0": [{ upload_time_iso_8601: daysAgo(400), requires_python: ">=3.7" }] },
    requires: { "2.25.1": null, "2.33.0": ['badpkg==1.0; python_version < "3.8"'] },
  };
  net.pypi.badpkg = { releases: { "1.0": [{ upload_time_iso_8601: daysAgo(900) }], "1.1": [{ upload_time_iso_8601: daysAgo(800) }] }, requires: { "1.0": null, "1.1": null } };
  net.osv = [advisory("GHSA-http2-0001", "PyPI", PKG, "2.33.0", { severity: "HIGH" }), advisory("GHSA-badp-0001", "PyPI", "badpkg", "1.1", { severity: "HIGH" })];
  stubNet(net);
});
afterEach(() => {
  vi.unstubAllGlobals();
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function repo(): { dir: string; live: () => LiveIntelligence } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-pyagree-"));
  dirs.push(dir);
  fs.mkdirSync(path.join(dir, "services", "api"), { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), '{"name":"web"}');
  fs.writeFileSync(path.join(dir, "services", "api", "requirements.txt"), `${PKG}==2.25.1\n`);
  fs.writeFileSync(path.join(dir, "services", "api", "pyproject.toml"), '[project]\nname = "api"\nrequires-python = ">=3.9"\n');
  return {
    dir,
    live: () => {
      const live = new LiveIntelligence(new Database(":memory:"));
      const { entries, discovery } = scanProjectTree(dir);
      live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
      return live;
    },
  };
}

describe("the three tools judge requirement markers on the declaring project's Python", () => {
  it("a requirement no Python of services/api installs holds back no tool's target", async () => {
    const { dir, live } = repo();
    const check = (await executeDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", package: PKG, from: "2.25.1", to: "2.33.0" }] }, live())).results[0];
    expect(check.verdict).toBe("proceed");
    expect(JSON.stringify(check)).not.toMatch(/badpkg/);

    const plan = (await executeUpgradePlanner(null as never, { project_path: dir } as never, live())) as Record<string, any>;
    const row = plan.recommendations.find((r: { package: string }) => r.package === PKG);
    expect(row).toMatchObject({ targetVersion: "2.33.0", fixPathChecked: "all_advisories" });
    expect(JSON.stringify(row)).not.toMatch(/badpkg/);

    const scan = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, live())) as Record<string, any>;
    expect(scan.fix_targets[`${PKG}@2.25.1`]).toMatchObject({ target: "2.33.0", checked: "all_advisories" });
    expect(JSON.stringify(scan.fix_targets)).not.toMatch(/badpkg/);
  });
});
