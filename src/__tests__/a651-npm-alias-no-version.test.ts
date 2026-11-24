// SPDX-License-Identifier: Apache-2.0
/**
 * `npm:<x>` with no `@<range>`: npm reads x as a package name, Yarn as the key's own release.
 *
 * Re-check of 0d30b40 (2026-11-24, unit/spec.mjs, case b-alias): the Yarn branch tested only a
 * PREFIX of x (a digit, `v` and a digit, `x`) before the package-name check, so
 * `"zqrev-akey-v8": "npm:v8-compile-cache"`, `npm:7zip-bin`, `npm:x`, `npm:2048` and `npm:x.js`
 * were read as the key's own range: the KEY went to registry.npmjs.org, api.npmjs.org and HN and the
 * target was never checked. The rule now (npm-spec.ts aliasSpec): the key's own release only when
 * the WHOLE of x is a semver range no package could be named, or a full version; an alias when x
 * is a package name and no range; withheld when x is both, or a common dist-tag. `npm:x-1.0.0.tgz`
 * names a tarball file, which npm refuses: withheld.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { classifyNpmSpec, isSemverRange } from "../live/npm-spec.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

describe("isSemverRange reads the whole string", () => {
  it("ranges and versions", () => {
    for (const r of ["1", "1.x", "x", "*", "2048", "^1 || ^2", ">=1 <2", "1.2.3-rc.1", "1.2.3", "~1.2", "1.0.0 - 2.0.0", "v1.2.3", ">= 1.2", "^1.2.3+build.5", "1.x || >=2.5.0 || 5.0.0 - 7.2.3"]) {
      expect([r, isSemverRange(r)]).toEqual([r, true]);
    }
  });
  it("names that start like a version are not ranges", () => {
    for (const r of ["v8-compile-cache", "7zip-bin", "x.js", "latest", "1.2.3.4", "x-1.0.0.tgz", "2048-game", "1x"]) expect([r, isSemverRange(r)]).toEqual([r, false]);
  });
});

describe("classifyNpmSpec on npm:<x> with no range", () => {
  const k = "acme-key";
  it("a package name is an alias to it: the key is never the name looked up", () => {
    expect(classifyNpmSpec(k, "npm:v8-compile-cache")).toEqual({ kind: "registry", name: "v8-compile-cache", range: "*" });
    expect(classifyNpmSpec(k, "npm:7zip-bin")).toEqual({ kind: "registry", name: "7zip-bin", range: "*" });
    expect(classifyNpmSpec(k, "npm:x.js")).toEqual({ kind: "registry", name: "x.js", range: "*" });
    expect(classifyNpmSpec(k, "npm:ms")).toEqual({ kind: "registry", name: "ms", range: "*" });
  });
  it("a range no package could be named, or a full version, is the key's own release", () => {
    for (const r of ["^1 || ^2", ">=1 <2", "^1.2.0", "*", "1.2.3-rc.1", "2.1.3"]) expect(classifyNpmSpec(k, `npm:${r}`)).toEqual({ kind: "registry", name: k, range: r });
  });
  it("both a range and a name, a common dist-tag, or a tarball file name: withheld", () => {
    for (const r of ["1", "1.x", "x", "2048", "latest", "next", "x-1.0.0.tgz"]) expect([r, classifyNpmSpec(k, `npm:${r}`).kind]).not.toEqual([r, "registry"]);
  });
  it("inside Yarn's patch: a range or tag is the key's own", () => {
    expect(classifyNpmSpec(k, "patch:acme-key@npm%3A1.x#./p.patch")).toEqual({ kind: "registry", name: k, range: "1.x" });
    expect(classifyNpmSpec(k, "patch:acme-key@npm%3Alatest#./p.patch")).toEqual({ kind: "registry", name: k, range: "latest" });
  });
});

describe("the key of an alias with no version is never sent", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
    vi.stubGlobal("fetch", globalThis.fetch);
    h.NPM = { "v8-compile-cache": { latest: "2.4.0", versions: { "2.4.0": {} } } };
  });
  afterEach(() => h.dispose());

  it("dependency_health and dependency_check send v8-compile-cache, never the key", async () => {
    h.write("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: { "acme-akey-v8": "npm:v8-compile-cache", "acme-akey-x": "npm:x", "acme-akey-2048": "npm:2048" } }));
    const live = await h.live();
    await executeDependencyHealth(null, {}, live);
    await executeDependencyCheck(null, { items: ["acme-akey-v8", "acme-akey-x", "acme-akey-2048"].map((p) => ({ ecosystem: "npm", package: p, to: "1.0.1" })) }, live);
    expect(h.requests.filter((u) => /acme/i.test(decodeURIComponent(u)))).toEqual([]);
    expect(h.requests).toContain("https://registry.npmjs.org/v8-compile-cache");
  });

  it("an override to an alias withholds the key it replaces, and a refused alias withholds its target", async () => {
    h.write("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: { "v8-compile-cache": "2.4.0", "acme-refused": "npm:acme-chain-dep@npm:ms" }, overrides: { "acme-akey-ovr": "npm:ms@2.1.3", ms: "npm:acme-akey-chain@npm:ms" } }));
    const live = await h.live();
    await executeDependencyHealth(null, {}, live);
    await executeDependencyCheck(null, { items: ["acme-akey-ovr", "acme-akey-chain", "acme-chain-dep", "acme-refused"].map((p) => ({ ecosystem: "npm", package: p, to: "1.0.1" })) }, live);
    expect(h.requests.filter((u) => /acme/i.test(decodeURIComponent(u)))).toEqual([]);
  });
});
