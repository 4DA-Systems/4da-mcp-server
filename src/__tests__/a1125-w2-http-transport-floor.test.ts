// SPDX-License-Identifier: Apache-2.0
// Audit 2026-11-25, H-8: HTTP mode must not serve on a vulnerable @hono/node-server that the
// installation folder already held. No package.json entry binds there, so the server checks the
// copy that will be loaded.
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { belowNodeServerFloor, nearestPackageJson, loadedNodeServerVersion, nodeServerProblem, NODE_SERVER_FLOOR } from "../http-transport-floor.js";

const made: string[] = [];
const tree = (files: Record<string, string>): string => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "a1125-floor-")));
  made.push(root);
  for (const [rel, text] of Object.entries(files)) {
    const p = join(root, ...rel.split("/"));
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, text);
  }
  return root;
};
afterEach(() => {
  for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("the @hono/node-server floor of HTTP mode", () => {
  it("reads releases below 2.1.6 as affected, every 1.x included", () => {
    for (const v of ["1.19.9", "1.19.18", "1.99.0", "2.0.0", "2.1.3", "2.1.5"]) expect(belowNodeServerFloor(v), v).toBe(true);
    for (const v of ["2.1.6", "2.1.11", "2.2.0", "3.0.0", "2.1.6-rc.1"]) expect(belowNodeServerFloor(v), v).toBe(false);
    for (const v of ["", "latest", "2.1", "v2.1.6", "2.1.x", "9".repeat(40) + ".0.0"]) expect(belowNodeServerFloor(v), v).toBeNull();
  });

  it("finds the copy a module would load: a nested one before a hoisted one", () => {
    const pkg = (version: string) => JSON.stringify({ name: "@hono/node-server", version });
    const hoisted = tree({
      "node_modules/@modelcontextprotocol/node/dist/index.mjs": "",
      "node_modules/@hono/node-server/package.json": pkg("1.19.9"),
      "node_modules/@4da/mcp-server/node_modules/@hono/node-server/package.json": pkg("2.1.11"),
    });
    // The copy nested under OUR package is not the one @modelcontextprotocol/node loads: the hoisted old one is.
    expect(nearestPackageJson(join(hoisted, "node_modules", "@modelcontextprotocol", "node", "dist", "index.mjs"), "@hono/node-server")).toBe(
      join(hoisted, "node_modules", "@hono", "node-server", "package.json"),
    );
    const nested = tree({
      "node_modules/@modelcontextprotocol/node/dist/index.mjs": "",
      "node_modules/@modelcontextprotocol/node/node_modules/@hono/node-server/package.json": pkg("2.1.11"),
      "node_modules/@hono/node-server/package.json": pkg("1.19.9"),
    });
    expect(nearestPackageJson(join(nested, "node_modules", "@modelcontextprotocol", "node", "dist", "index.mjs"), "@hono/node-server")).toBe(
      join(nested, "node_modules", "@modelcontextprotocol", "node", "node_modules", "@hono", "node-server", "package.json"),
    );
    expect(nearestPackageJson(join(tree({ "a/b.mjs": "" }), "a", "b.mjs"), "@hono/zz-not-installed-anywhere")).toBeNull();
  });

  it("refuses an affected copy with the version, the fix and the way out, and says nothing otherwise", () => {
    const text = nodeServerProblem("1.19.9");
    expect(text).toContain("@hono/node-server 1.19.9");
    expect(text).toContain(`fixed in ${NODE_SERVER_FLOOR}`);
    expect(text).toContain("npx -y @4da/mcp-server --http");
    expect(text).toContain("stdio server");
    expect(nodeServerProblem("2.1.3")).not.toBeNull();
    expect(nodeServerProblem("2.1.6")).toBeNull();
    expect(nodeServerProblem("not-a-version")).toBeNull();
    expect(nodeServerProblem(null)).toBeNull();
  });

  it("this repository's own installation is at or above the floor, so HTTP mode starts here", () => {
    const version = loadedNodeServerVersion();
    expect(version).not.toBeNull();
    expect(belowNodeServerFloor(version!)).toBe(false);
    expect(nodeServerProblem()).toBeNull();
  });
});
