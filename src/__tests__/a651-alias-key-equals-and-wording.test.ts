// SPDX-License-Identifier: Apache-2.0
/**
 * `npm:<x>` with no range, check of round 2 (2026-11-24, alias-real, alias-lock):
 * - when the key is x itself (`"next": "npm:next"`, `"rc": "npm:rc"`) npm and Yarn agree: it is that
 *   package from the registry, and it is checked;
 * - an ambiguous one that stays withheld (`"nextjs": "npm:next"`, `"myrc": "npm:rc"`) is described as
 *   what it is (npm reads x as a package, Yarn as a tag or range of the key), never as git, a URL or
 *   a local archive;
 * - with a package-lock.json, the lockfile says which package was installed: `"myrc": "npm:rc"` is rc,
 *   and the rc row cand5 listed is not lost.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { classifyNpmSpec } from "../live/npm-spec.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  vi.stubGlobal("fetch", globalThis.fetch);
  h.NPM = { rc: { latest: "1.2.8", versions: { "1.2.8": {} } }, next: { latest: "15.0.0", versions: { "15.0.0": {} } } };
});
afterEach(() => h.dispose());

describe("npm:<x> under the key x", () => {
  it("is that package from the registry", () => {
    expect(classifyNpmSpec("next", "npm:next")).toEqual({ kind: "registry", name: "next", range: "*" });
    expect(classifyNpmSpec("rc", "npm:rc")).toEqual({ kind: "registry", name: "rc", range: "*" });
    expect(classifyNpmSpec("x", "npm:x")).toEqual({ kind: "registry", name: "x", range: "*" });
  });
});

describe("an ambiguous npm:<x> that stays withheld says what it is", () => {
  it("dependency_check names both readings, never git or a URL", async () => {
    h.write("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: { nextjs: "npm:next", rc: "npm:rc" } }));
    const r = (await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "nextjs", to: "1.0.0" }] }, await h.live())) as { results: Array<{ reason: string; not_checked?: string }> };
    expect(r.results[0].not_checked).toBe("private");
    expect(r.results[0].reason).toContain("npm reads");
    expect(r.results[0].reason).toContain("Yarn");
    expect(r.results[0].reason).not.toMatch(/git, a URL|source other than the npm registry/);
    const scan = await h.scan();
    expect(JSON.stringify(scan.coverage ?? {})).not.toMatch(/nextjs[^}]*"source":"url"/);
  });
});

describe("a package-lock.json resolves the ambiguity", () => {
  it("rc and myrc: the rc row is listed", async () => {
    const root = { name: "p", version: "1.0.0", dependencies: { rc: "npm:rc", myrc: "npm:rc" } };
    h.write("package.json", JSON.stringify(root));
    h.write(
      "package-lock.json",
      JSON.stringify({
        name: "p",
        lockfileVersion: 3,
        packages: {
          "": root,
          "node_modules/rc": { name: "rc", version: "1.2.8", resolved: "https://registry.npmjs.org/rc/-/rc-1.2.8.tgz" },
          "node_modules/myrc": { name: "rc", version: "1.2.8", resolved: "https://registry.npmjs.org/rc/-/rc-1.2.8.tgz" },
        },
      }),
    );
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    expect(r.dependencies.map((d: { name: string }) => d.name)).toContain("rc");
  });
});
