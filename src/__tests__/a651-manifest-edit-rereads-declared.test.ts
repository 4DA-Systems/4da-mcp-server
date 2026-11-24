// SPDX-License-Identifier: Apache-2.0
/**
 * A dependency added to (or removed from) a manifest while the server runs. A re-resolution
 * (refreshIfLockfilesChanged) read the changed files again, but with the dependency NAMES the
 * project scanner read at startup (ResolutionGroup.deps / devDeps): the versions and the advisory
 * set followed the files, the list of direct dependencies did not. On 6.5.0 and the 6.5.1
 * candidate, package.json `{ ms }` with no lockfile, then `lodash: 4.18.1` added: vulnerability_scan
 * scanned 2 pins, dependency_health answered `totalDeps: 1`, rows `["ms"]`, `treeDeps: 2`, on every
 * call until the server restarted. A dependency removed from the manifest stayed a row. Every
 * reader of getResolvedDeps() (dependency_health, upgrade_planner, upgrade_impact, the briefing,
 * get_context, knowledge_gaps, ecosystem_pulse, dependency_check's installed versions) saw the
 * startup list. Now a group that is re-resolved has its declared names read again.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import type { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool, READS_DEPENDENCY_SET } from "../tool-dispatch.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM = {
    ms: { latest: "2.1.3", versions: { "2.1.3": {} } },
    lodash: { latest: "4.18.1", versions: { "4.18.1": {} } },
  };
});
afterEach(() => h.dispose());

/** Rewrite a file and move its mtime on, so the change is seen whatever the file system's clock resolution. */
function rewrite(file: string, body: string): void {
  h.write(file, body);
  const later = new Date(Date.now() + 5_000);
  fs.utimesSync(path.join(h.dir, file), later, later);
}

const health = async (li: LiveIntelligence) => (await executeDependencyHealth(null, {}, li)) as unknown as Record<string, any>;
const rows = (r: Record<string, any>) => (r.dependencies as Array<{ name: string }>).map((d) => d.name).sort();
const direct = (li: LiveIntelligence, ecosystem: string) =>
  li
    .getResolvedDeps()
    .filter((d) => d.ecosystem === ecosystem)
    .map((d) => d.name)
    .sort();

describe("a dependency added to the manifest after the server started", () => {
  it("npm, no lockfile: dependency_health lists the added dependency (the reported case)", async () => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    const li = await h.live();
    expect(rows(await health(li))).toEqual(["ms"]);

    rewrite("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3", lodash: "4.18.1" } }));
    const after = await health(li);
    expect(rows(after)).toEqual(["lodash", "ms"]);
    expect(after.totalDeps).toBe(2);
    // A repeat call answers the same.
    expect(rows(await health(li))).toEqual(["lodash", "ms"]);
  });

  it("npm, no lockfile: a dependency removed from the manifest is no longer a row", async () => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3", lodash: "4.18.1" } }));
    const li = await h.live();
    expect(direct(li, "npm")).toEqual(["lodash", "ms"]);

    rewrite("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { lodash: "4.18.1" } }));
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expect(direct(li, "npm")).toEqual(["lodash"]);
    expect(li.getAuditDeps().map((d) => d.name)).not.toContain("ms");
  });

  it("npm with package-lock.json: a dependency installed after start is a direct row", async () => {
    h.npmProject({ ms: "2.1.3" }, {}, { ms: { version: "2.1.3" } });
    const li = await h.live();
    expect(direct(li, "npm")).toEqual(["ms"]);

    const root = { name: "x", version: "1.0.0", dependencies: { ms: "2.1.3", lodash: "4.18.1" }, devDependencies: {} };
    rewrite("package.json", JSON.stringify(root));
    rewrite(
      "package-lock.json",
      JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": root, "node_modules/ms": { version: "2.1.3" }, "node_modules/lodash": { version: "4.18.1" } } }),
    );
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expect(direct(li, "npm")).toEqual(["lodash", "ms"]);
    expect(li.getResolvedDeps().find((d) => d.name === "lodash")?.version).toBe("4.18.1");
  });

  it("Cargo.toml without Cargo.lock: the added crate is a row", async () => {
    h.write("Cargo.toml", '[package]\nname = "x"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = "1.0.200"\n');
    const li = await h.live();
    expect(direct(li, "crates.io")).toEqual(["serde"]);

    rewrite("Cargo.toml", '[package]\nname = "x"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = "1.0.200"\nanyhow = "1.0.80"\n');
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expect(direct(li, "crates.io")).toEqual(["anyhow", "serde"]);
  });

  it("requirements.txt pins: the added requirement is a row, a removed one is not", async () => {
    h.write("requirements.txt", "requests==2.32.3\n");
    const li = await h.live();
    expect(direct(li, "PyPI")).toEqual(["requests"]);

    rewrite("requirements.txt", "urllib3==2.2.2\nidna==3.7\n");
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expect(direct(li, "PyPI")).toEqual(["idna", "urllib3"]);
  });

  it("pyproject.toml exact pins, no lockfile: the added pin is a row", async () => {
    h.write("pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["requests==2.32.3"]\n');
    const li = await h.live();
    expect(direct(li, "PyPI")).toEqual(["requests"]);

    rewrite("pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["requests==2.32.3", "idna==3.7"]\n');
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expect(direct(li, "PyPI")).toEqual(["idna", "requests"]);
  });

  it("go.mod: the added requirement is a row", async () => {
    h.write("go.mod", "module example.com/x\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n");
    const li = await h.live();
    expect(direct(li, "Go")).toEqual(["github.com/google/uuid"]);

    rewrite("go.mod", "module example.com/x\n\ngo 1.22\n\nrequire (\n\tgithub.com/google/uuid v1.6.0\n\tgolang.org/x/text v0.16.0\n)\n");
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expect(direct(li, "Go")).toEqual(["github.com/google/uuid", "golang.org/x/text"]);
  });
});

describe("tools that never re-resolved the set themselves", () => {
  afterEach(() => clearLiveIntelligence());

  it("are the four that read it without refreshing", () => {
    expect([...READS_DEPENDENCY_SET].sort()).toEqual(["dependency_check", "ecosystem_pulse", "get_context", "knowledge_gaps"]);
  });

  it.each([
    ["dependency_check", { items: [{ ecosystem: "npm", package: "lodash", to: "4.18.1" }] }],
    ["ecosystem_pulse", {}],
  ])("%s re-resolves a changed manifest before it answers", async (tool, args) => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    const li = await h.live();
    setLiveIntelligence(li);
    rewrite("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3", lodash: "4.18.1" } }));
    await dispatchTool(tool, null, args as Record<string, unknown>);
    expect(direct(li, "npm")).toEqual(["lodash", "ms"]);
  });
});

describe("controls", () => {
  it("an unchanged manifest is never re-resolved: the check stays stat-only", async () => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    const li = await h.live();
    const at = li.getResolutionProvenance()?.resolvedAt;
    for (let i = 0; i < 3; i++) expect(li.refreshIfLockfilesChanged()).toBe(false);
    await health(li);
    await health(li);
    expect(li.getResolutionProvenance()?.resolvedAt).toBe(at);
    expect(direct(li, "npm")).toEqual(["ms"]);
  });

  it("with a lockfile read, a package.json edit alone (a script) re-resolves nothing, as before", async () => {
    h.npmProject({ ms: "2.1.3" }, {}, { ms: { version: "2.1.3" } });
    const li = await h.live();
    rewrite("package.json", JSON.stringify({ name: "x", version: "1.0.0", scripts: { test: "vitest" }, dependencies: { ms: "2.1.3" }, devDependencies: {} }));
    expect(li.refreshIfLockfilesChanged()).toBe(false);
    expect(direct(li, "npm")).toEqual(["ms"]);
  });
});
