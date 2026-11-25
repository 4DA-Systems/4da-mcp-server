// SPDX-License-Identifier: Apache-2.0
/**
 * A package-lock.json (or npm-shrinkwrap.json) with no entry for a dependency package.json
 * declares was written before that dependency was added: what npm would install for it was never
 * checked. pnpm-lock.yaml, yarn.lock and bun.lock were already cross-checked against package.json
 * this way (a PARTIAL read); npm's own lockfile was not. On 6.5.0 a project whose package.json
 * declares lodash beside a package-lock.json that holds only minimist got "Health: 100/100 ... all
 * healthy" from dependency_health, `coverage.complete: true` from vulnerability_scan and
 * `vulnerabilityDataAvailable: true` from upgrade_planner, with lodash checked by none of them.
 * Now the lockfile is a partial read: the health score is withheld (since audit 2026-11-25) and the summary says
 * so, the scan's coverage is not complete, and the plan is not CVE-aware.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM = {
    minimist: { latest: "1.2.8", versions: { "1.2.8": {} } },
    lodash: { latest: "4.17.21", versions: { "4.17.21": {} } },
  };
});
afterEach(() => h.dispose());

const health = async () => (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;

describe("an npm lockfile older than its package.json", () => {
  it("a declared dependency with no entry: the health score is withheld, and the summary leads with why", async () => {
    h.npmProject({ minimist: "1.2.8", lodash: "^4.17.21" }, {}, { minimist: { version: "1.2.8" } });
    const r = await health();
    expect(r.summary).not.toMatch(/all healthy/);
    // Audit 2026-11-25: a score beside an unread declared dependency read as reassurance; withheld since.
    expect(r.healthScore).toBeNull();
    expect(r.withheldReason).toBe("lockfile_partial");
    expect(r.summary).toMatch(/^NOT CHECKED: PARTIAL: 1 lockfile is older than its manifest: .*package\.json declares lodash .*no entry/);
  });

  it("the scan's coverage is not complete and the plan is not CVE-aware", async () => {
    h.npmProject({ minimist: "1.2.8", lodash: "^4.17.21" }, {}, { minimist: { version: "1.2.8" } });
    const scan = await h.scan();
    expect(scan.coverage.complete).toBe(false);
    const { result } = await h.plan();
    expect(result.vulnerabilityDataAvailable).toBe(false);
  });

  it("lockfileVersion 1 (top-level dependencies map) is cross-checked the same way", async () => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { minimist: "1.2.8", lodash: "^4.17.21" } }));
    h.write("package-lock.json", JSON.stringify({ name: "x", version: "1.0.0", lockfileVersion: 1, requires: true, dependencies: { minimist: { version: "1.2.8" } } }));
    const r = await health();
    expect(r.healthScore).toBeNull();
    expect(r.withheldReason).toBe("lockfile_partial");
  });

  it("controls: every declared dependency has an entry (an alias included): complete", async () => {
    // As npm writes it: an alias entry names the real package.
    const root = { name: "x", version: "1.0.0", dependencies: { minimist: "1.2.8", "my-lodash": "npm:lodash@4.17.21" } };
    h.write("package.json", JSON.stringify(root));
    h.write(
      "package-lock.json",
      JSON.stringify({
        name: "x",
        lockfileVersion: 3,
        packages: { "": root, "node_modules/minimist": { version: "1.2.8" }, "node_modules/my-lodash": { name: "lodash", version: "4.17.21" } },
      }),
    );
    const r = await health();
    expect(r.scoreCoverage).toBeUndefined();
    const scan = await h.scan();
    expect(scan.coverage.complete).toBe(true);
  });

  it("a peerDependency is owed no entry", async () => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { minimist: "1.2.8" }, peerDependencies: { lodash: "^4" } }));
    h.write("package-lock.json", JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", dependencies: { minimist: "1.2.8" } }, "node_modules/minimist": { version: "1.2.8" } } }));
    const r = await health();
    expect(r.scoreCoverage).toBeUndefined();
  });
});
