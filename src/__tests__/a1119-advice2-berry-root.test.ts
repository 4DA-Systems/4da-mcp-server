// SPDX-License-Identifier: Apache-2.0
/**
 * At the root of a Yarn berry workspace, `yarn up "x@..."` is a project command: run with yarn
 * 4.9.1 (2026-11-19) it rewrote a member's `~0.0.8` as well as the root's own `0.0.8`. `yarn add
 * <spec>` at the root moved only the root's declaration, keeping its section and operator. So the
 * root's step names `yarn add`, and a member's declaration is moved by that member's own step.
 * A berry project with no workspaces keeps `yarn up`, the form verified for it before.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { directFix } from "../live/fix-paths.js";

const BERRY_LOCK = "__metadata:\n  version: 8\n  cacheKey: 10c0\n";

describe("yarn berry at a workspace root", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((d) => fs.rmSync(d, { recursive: true, force: true })));
  const project = (files: Record<string, string>) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-berryroot-"));
    dirs.push(dir);
    for (const [rel, body] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), body);
    }
    return dir;
  };

  it("names `yarn add`, which leaves the members' declarations alone", () => {
    const dir = project({
      "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"], devDependencies: { minimist: "0.0.8" }, dependencies: { qs: "~6.5.2" } }),
      "packages/web/package.json": JSON.stringify({ name: "web", dependencies: { minimist: "~0.0.8" } }),
      "yarn.lock": BERRY_LOCK,
    });
    expect(directFix(dir, "npm", "minimist", "0.0.8", "0.2.4")).toEqual({ command: "yarn add minimist@0.2.4" });
    expect(directFix(dir, "npm", "qs", "6.5.2", "6.14.1")).toEqual({ command: 'yarn add "qs@~6.14.1"' });
  });

  it("a berry project with no workspaces keeps `yarn up`", () => {
    const dir = project({ "package.json": JSON.stringify({ name: "app", dependencies: { minimist: "0.0.8" } }), "yarn.lock": BERRY_LOCK });
    expect(directFix(dir, "npm", "minimist", "0.0.8", "0.2.4")).toEqual({ command: "yarn up minimist@0.2.4" });
  });
});
