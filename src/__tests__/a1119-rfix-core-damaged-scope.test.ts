// SPDX-License-Identifier: Apache-2.0
/**
 * Dev-only is claimed only from a whole graph. A yarn.lock or bun.lock where
 * some entry names a dependency that has no entry (a truncated or damaged
 * file), or where an entry was dropped for an over-long line, leaves every
 * copy that only devDependencies reach with an unknown scope, which every tool
 * treats as runtime.
 */

import { afterEach, describe, expect, it } from "vitest";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { removeProject, tempProject } from "./helpers/a1119-readers.js";

/** What the lockfile reader says of each copy: true (dev-only), false (runtime) or "unknown". */
function lockScopes(dir: string): Record<string, boolean | "unknown"> {
  return Object.fromEntries(resolveVersionSource(dir, "npm").instances.map((i) => [`${i.name}@${i.version}`, i.dev ?? "unknown"]));
}

const PKG = JSON.stringify({ name: "app", dependencies: { a: "^1.0.0" }, devDependencies: { b: "^1.0.0" } });
const entry = (spec: string, version: string, deps: Record<string, string> = {}) =>
  `${spec}:\n  version "${version}"\n  resolved "https://registry.yarnpkg.com/x/-/x-${version}.tgz"\n` +
  (Object.keys(deps).length > 0 ? `  dependencies:\n${Object.entries(deps).map(([n, r]) => `    ${n} "${r}"\n`).join("")}` : "");
const yarnLock = (...entries: string[]) => `# yarn lockfile v1\n\n\n${entries.join("\n")}`;

describe("a damaged lockfile grades nothing dev-only", () => {
  const dirs: string[] = [];
  const project = (files: Record<string, string>) => {
    const dir = tempProject(files);
    dirs.push(dir);
    return dir;
  };
  afterEach(() => dirs.splice(0).forEach(removeProject));

  it("yarn: a whole lockfile grades what only devDependencies reach as dev-only", () => {
    const dir = project({
      "package.json": PKG,
      "yarn.lock": yarnLock(entry("a@^1.0.0", "1.0.0", { c: "^1.0.0" }), entry("b@^1.0.0", "1.0.0", { x: "^1.0.0" }), entry("c@^1.0.0", "1.0.0"), entry("x@^1.0.0", "1.0.0")),
    });
    expect(lockScopes(dir)).toMatchObject({ "a@1.0.0": false, "c@1.0.0": false, "b@1.0.0": true, "x@1.0.0": true });
  });

  it("yarn: a dependency with no entry leaves dev-only copies unknown", () => {
    const dir = project({
      "package.json": PKG,
      "yarn.lock": yarnLock(entry("a@^1.0.0", "1.0.0", { c: "^1.0.0" }), entry("b@^1.0.0", "1.0.0", { x: "^1.0.0" }), entry("x@^1.0.0", "1.0.0")),
    });
    const scopes = lockScopes(dir);
    expect(scopes["a@1.0.0"]).toBe(false);
    expect(scopes["b@1.0.0"]).toBe("unknown");
    expect(scopes["x@1.0.0"]).toBe("unknown");
  });

  it("yarn: an entry dropped for an over-long header line leaves dev-only copies unknown", () => {
    const longHeader = `c@^1.0.0, ${Array.from({ length: 400 }, (_, i) => `c@^1.${i}.0`).join(", ")}`;
    const dir = project({
      "package.json": PKG,
      "yarn.lock": yarnLock(entry("a@^1.0.0", "1.0.0"), entry("b@^1.0.0", "1.0.0", { x: "^1.0.0" }), entry(longHeader, "1.0.0"), entry("x@^1.0.0", "1.0.0")),
    });
    expect(longHeader.length).toBeGreaterThan(4096);
    const scopes = lockScopes(dir);
    expect(scopes["b@1.0.0"]).toBe("unknown");
    expect(scopes["x@1.0.0"]).toBe("unknown");
  });

  const bunLock = (packages: Record<string, unknown>) =>
    JSON.stringify({
      lockfileVersion: 1,
      workspaces: { "": { name: "app", dependencies: { a: "^1.0.0" }, devDependencies: { b: "^1.0.0" } } },
      packages,
    });

  it("bun: a whole lockfile grades what only devDependencies reach as dev-only", () => {
    const dir = project({
      "package.json": PKG,
      "bun.lock": bunLock({
        a: ["a@1.0.0", "", { dependencies: { c: "^1.0.0" } }, "sha512-A"],
        b: ["b@1.0.0", "", { dependencies: { x: "^1.0.0" } }, "sha512-B"],
        c: ["c@1.0.0", "", {}, "sha512-C"],
        x: ["x@1.0.0", "", {}, "sha512-X"],
      }),
    });
    expect(lockScopes(dir)).toMatchObject({ "a@1.0.0": false, "c@1.0.0": false, "b@1.0.0": true, "x@1.0.0": true });
  });

  it("bun: a dependency with no entry leaves dev-only copies unknown", () => {
    const dir = project({
      "package.json": PKG,
      "bun.lock": bunLock({
        a: ["a@1.0.0", "", { dependencies: { c: "^1.0.0" } }, "sha512-A"],
        b: ["b@1.0.0", "", { dependencies: { x: "^1.0.0" } }, "sha512-B"],
        x: ["x@1.0.0", "", {}, "sha512-X"],
      }),
    });
    const scopes = lockScopes(dir);
    expect(scopes["a@1.0.0"]).toBe(false);
    expect(scopes["b@1.0.0"]).toBe("unknown");
    expect(scopes["x@1.0.0"]).toBe("unknown");
  });

  it("bun: a peer that is not installed is not damage", () => {
    const dir = project({
      "package.json": PKG,
      "bun.lock": bunLock({
        a: ["a@1.0.0", "", {}, "sha512-A"],
        b: ["b@1.0.0", "", { peerDependencies: { react: "*" } }, "sha512-B"],
      }),
    });
    expect(lockScopes(dir)["b@1.0.0"]).toBe(true);
  });
});
