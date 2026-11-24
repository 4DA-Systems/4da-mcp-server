// SPDX-License-Identifier: Apache-2.0
/**
 * Yarn's `npm:` and `patch:` spellings, and the alias shapes npm refuses.
 *
 * Review of the 6.5.1 candidate (2026-11-24): `patch:lodash@npm%3A4.17.21#~/.yarn/patches/x.patch`
 * was read as an alias to a package named `4.17.21` (the inner `npm:4.17.21` went to the npm alias
 * rule, and `4.17.21` passes the package-name pattern), so registry.npmjs.org/4.17.21 was asked and
 * lodash was never checked; 6.5.0 looked up lodash. The same held with no `patch:` at all:
 * `"ms": "npm:2.1.3"` (Yarn's `npm:<version>`) made a row named `2.1.3`. Inside `patch:` and in a
 * bare `npm:<version-or-range>` Yarn's rule applies: that release of the SAME package; `npm:other@1`
 * is other's.
 *
 * npm-package-arg refuses an alias whose subspec is not a plain registry spec: an alias of an alias
 * (`npm:npm:x@1`), a URL, a patch, an empty `npm:`. What npm refuses to install is withheld.
 * Whitespace: npm-package-arg does not trim, so a protocol spelling with whitespace around it is not
 * that protocol and is withheld; a path stays a path, a range stays a range.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { classifyNpmSpec } from "../live/npm-spec.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

describe("Yarn's patch: wraps the release it patches", () => {
  it("npm:<version> inside a patch is that version of the SAME package, encoded or not, scoped or not", () => {
    expect(classifyNpmSpec("lodash", "patch:lodash@npm%3A4.17.21#~/.yarn/patches/lodash-npm-4.17.21-6382451519.patch")).toEqual({ kind: "registry", name: "lodash", range: "4.17.21" });
    expect(classifyNpmSpec("lodash", "patch:lodash@npm:4.17.21#~/.yarn/patches/x.patch")).toEqual({ kind: "registry", name: "lodash", range: "4.17.21" });
    expect(classifyNpmSpec("@scope/x", "patch:@scope/x@npm%3A1.0.0#./p.patch")).toEqual({ kind: "registry", name: "@scope/x", range: "1.0.0" });
    expect(classifyNpmSpec("x", "patch:x@npm%3A%5E1.2.0#./p.patch")).toEqual({ kind: "registry", name: "x", range: "^1.2.0" });
  });

  it("npm:other@1 inside a patch is other's release; nested patches unwrap", () => {
    expect(classifyNpmSpec("x", "patch:x@npm%3Aother%401.0.0#./p.patch")).toEqual({ kind: "registry", name: "other", range: "1.0.0" });
    expect(classifyNpmSpec("x", "patch:x@patch:x@npm%3A1.0.0#a#b")).toEqual({ kind: "registry", name: "x", range: "1.0.0" });
    expect(classifyNpmSpec("x", "patch:x@patch%3Ax%40npm%253A1.0.0%23a#b")).toEqual({ kind: "registry", name: "x", range: "1.0.0" });
  });

  it("a patch of a non-registry source is withheld as that source is", () => {
    expect(classifyNpmSpec("x", "patch:x@file%3A./vendor/x-1.0.0.tgz#./p.patch").kind).toBe("file");
    expect(classifyNpmSpec("x", "patch:x@github%3Aorg%2Fx#./p.patch").kind).toBe("git");
    expect(classifyNpmSpec("x", "patch:x@link%3A../x#./p.patch").kind).toBe("local");
    expect(classifyNpmSpec("x", "patch:x@https%3A%2F%2Fnpm.internal.example%2Fx.tgz#./p.patch").kind).toBe("url");
    expect(classifyNpmSpec("x", "patch:%E0%A4%A#p").kind).not.toBe("registry");
  });
});

describe("a bare npm:<version-or-range> is the key's own package", () => {
  it("npm:2.1.3 and npm:^1.2.0 name the key, never a package called 2.1.3", () => {
    expect(classifyNpmSpec("ms", "npm:2.1.3")).toEqual({ kind: "registry", name: "ms", range: "2.1.3" });
    expect(classifyNpmSpec("left-pad", "npm:1.3.0")).toEqual({ kind: "registry", name: "left-pad", range: "1.3.0" });
    expect(classifyNpmSpec("ms", "npm:^2.1.0")).toEqual({ kind: "registry", name: "ms", range: "^2.1.0" });
    expect(classifyNpmSpec("ms", "npm:~2.1.0")).toEqual({ kind: "registry", name: "ms", range: "~2.1.0" });
    expect(classifyNpmSpec("ms", "npm:2.x")).toEqual({ kind: "registry", name: "ms", range: "2.x" });
    // Still an alias when it names a package.
    expect(classifyNpmSpec("sw", "npm:string-width@^4.2.0")).toEqual({ kind: "registry", name: "string-width", range: "^4.2.0" });
    expect(classifyNpmSpec("sw", "npm:string-width")).toEqual({ kind: "registry", name: "string-width", range: "*" });
  });
});

describe("alias shapes npm refuses are withheld", () => {
  it("an alias of an alias, a URL, a patch, a catalog or nothing behind npm:", () => {
    for (const spec of ["npm:npm:x@1", "npm:x@npm:y@1", "npm:x@https://registry.npmjs.org/x/-/x-1.0.0.tgz", "npm:", "npm:x@patch:y@1#p", "npm:x@catalog:", "npm:x@file:../x", "npm:x@github:o/x"]) {
      expect([spec, classifyNpmSpec("k", spec).kind]).not.toEqual([spec, "registry"]);
    }
  });
});

describe("whitespace around a spec", () => {
  it("a protocol with whitespace around it is withheld; a path is still a path; a range is still a range", () => {
    for (const spec of [" npm:x@1", "npm:x@1 ", " catalog:", " patch:x@npm%3A1.0.0#p", " https://registry.npmjs.org/k/-/k-1.0.0.tgz", "\tnpm:x@1"]) {
      expect([spec, classifyNpmSpec("k", spec).kind]).not.toEqual([spec, "registry"]);
    }
    for (const spec of [" ../x", "../x ", " ./x", " /opt/x", " org/repo", "org/repo "]) expect([spec, classifyNpmSpec("k", spec).kind]).not.toEqual([spec, "registry"]);
    expect(classifyNpmSpec("k", " ^1.2.3 ")).toEqual({ kind: "registry", name: "k", range: "^1.2.3" });
  });
});

describe("no lockfile: the patched package is looked up, never its version as a name", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
    vi.stubGlobal("fetch", globalThis.fetch);
    h.NPM = {
      lodash: { latest: "4.17.21", versions: { "4.17.21": {} } },
      ms: { latest: "2.1.3", versions: { "2.1.3": {} } },
    };
  });
  afterEach(() => h.dispose());

  it("dependency_health asks for lodash and ms, never for 4.17.21 or 2.1.3", async () => {
    h.write("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: { lodash: "patch:lodash@npm%3A4.17.21#~/.yarn/patches/lodash-npm-4.17.21-6382451519.patch", ms: "npm:2.1.3" } }));
    h.write(".yarnrc.yml", "nodeLinker: node-modules\n");
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    expect(h.requests).toContain("https://registry.npmjs.org/lodash");
    expect(h.requests).toContain("https://registry.npmjs.org/ms");
    expect(h.requests.filter((u) => /registry\.npmjs\.org\/(?:4\.17\.21|2\.1\.3)$/.test(u))).toEqual([]);
    expect(r.dependencies.map((d: { name: string }) => d.name).sort()).toEqual(["lodash", "ms"]);
  });
});
