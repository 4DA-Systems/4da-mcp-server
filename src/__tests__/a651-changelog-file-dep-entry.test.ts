// SPDX-License-Identifier: Apache-2.0
/**
 * What a package-lock.json owes a declared dependency, and the 6.5.1 CHANGELOG's word for it. The
 * candidate's CHANGELOG said "a `file:` / `link:` / `workspace:` dependency [is] owed no entry",
 * while the code (isLocalSpec, js-manifests.ts) excuses only `link:`, `portal:` and `workspace:`:
 * npm writes an entry for a `file:` dependency (a link entry for a directory, a `resolved: file:`
 * entry for an archive), so a lockfile without one is behind its package.json, and is said to be
 * (review of the candidate, 2026-11-24). The behaviour is pinned here and the text must match it.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM = { minimist: { latest: "1.2.8", versions: { "1.2.8": {} } } };
});
afterEach(() => h.dispose());

function project(extra: Record<string, string>) {
  const root = { name: "x", version: "1.0.0", dependencies: { minimist: "1.2.8", ...extra } };
  h.write("package.json", JSON.stringify(root));
  h.write("libs/local-lib/package.json", JSON.stringify({ name: "local-lib", version: "1.0.0" }));
  h.write(
    "package-lock.json",
    JSON.stringify({ name: "x", lockfileVersion: 3, requires: true, packages: { "": root, "node_modules/minimist": { version: "1.2.8", resolved: "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz" } } }),
  );
}

describe("a declared dependency the package-lock.json has no entry for", () => {
  it("a `file:` dependency is owed one: the lockfile is listed as partial", async () => {
    project({ "local-lib": "file:libs/local-lib" });
    const scan = await h.scan();
    expect(scan.coverage.complete).toBe(false);
    expect(JSON.stringify(scan.coverage)).toContain("local-lib");
  });

  it("a `link:` dependency is not", async () => {
    project({ "local-lib": "link:libs/local-lib" });
    const scan = await h.scan();
    expect(scan.coverage.complete).toBe(true);
  });

  it("the 6.5.1 CHANGELOG says the same", () => {
    const text = fs.readFileSync(path.join(__dirname, "..", "..", "CHANGELOG.md"), "utf8");
    const section = text.slice(text.indexOf("## 6.5.1"), text.indexOf("## 6.5.0"));
    const owed = section.split(/(?<=\.)\s/).filter((s) => /owed no entry/.test(s));
    expect(owed.length).toBeGreaterThan(0);
    for (const sentence of owed) expect(sentence).not.toMatch(/`file:`/);
    expect(section).toMatch(/`file:` dependency[^.]*is owed (?:one|an entry)/);
  });
});
