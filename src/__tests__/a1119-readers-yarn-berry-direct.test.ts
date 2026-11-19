// SPDX-License-Identifier: Apache-2.0
/**
 * yarn berry: the copy a direct dependency resolves to is the one its
 * package.json range names, also when the lockfile entry answers several
 * descriptors (`"minimist@npm:^1.2.0, minimist@npm:^1.2.5":`).
 *
 * The fixture is a real Yarn 4 lockfile: package.json asks for minimist ^1.2.0
 * (resolved 1.2.8) and the devDependency mkdirp 0.5.1 pulls minimist 0.0.8.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { readYarnLock } from "../live/js-lockfile-readers.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { fixtureProject, npmAdvisory, removeProject, scanProject, stubOsv } from "./helpers/a1119-readers.js";

describe("yarn berry entries that answer several descriptors", () => {
  let dir: string;
  let priorOffline: string | undefined;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fixtureProject("yarn-berry-multi");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    removeProject(dir);
  });

  it("records every descriptor of a berry key under its own spec", () => {
    const specs = new Map<string, string>();
    readYarnLock(fs.readFileSync(path.join(dir, "yarn.lock"), "utf-8"), new Map(), undefined, specs);
    expect(specs.get("minimist@^1.2.0")).toBe("1.2.8");
    expect(specs.get("minimist@^1.2.5")).toBe("1.2.8");
    expect(specs.get("minimist@0.0.8")).toBe("0.0.8");
    expect([...specs.keys()].filter((k) => k.includes('"'))).toEqual([]);
  });

  it("reads classic (v1) keys, each descriptor quoted on its own, the same way", () => {
    const specs = new Map<string, string>();
    readYarnLock('"@babel/runtime@7.12.0", "@babel/runtime@^7.0.0":\n  version "7.12.0"\n\nminimist@^1.2.0, minimist@^1.2.5:\n  version "1.2.8"\n', new Map(), undefined, specs);
    expect(Object.fromEntries(specs)).toEqual({
      "@babel/runtime@7.12.0": "7.12.0",
      "@babel/runtime@^7.0.0": "7.12.0",
      "minimist@^1.2.0": "1.2.8",
      "minimist@^1.2.5": "1.2.8",
    });
  });

  it("resolves the direct dependency to the copy its range names", () => {
    const read = resolveVersionSource(dir, "npm");
    expect(read.versions.get("minimist")).toBe("1.2.8");
    expect(read.instances.map((i) => `${i.name}@${i.version}`).sort()).toEqual(["gonzales-pe@4.3.0", "minimist@0.0.8", "minimist@1.2.8", "mkdirp@0.5.1"]);
  });

  it("reports mkdirp's minimist 0.0.8 as a transitive copy, never as the direct dependency", async () => {
    stubOsv([npmAdvisory("GHSA-xvch-5gv4-984h", "minimist", "0.2.4", "CRITICAL")]);
    const answer = await scanProject(dir);
    const rows = answer.vulnerabilities as Array<Record<string, unknown>>;
    expect(rows.map((r) => `${r.package}@${r.current_version}`)).toEqual(["minimist@0.0.8"]);
    expect(rows[0].is_direct).toBe(false);
    // The direct minimist is 1.2.8, which the advisory does not affect: nothing tells the user to move it to 0.2.4.
    expect(JSON.stringify(answer)).not.toMatch(/upgrade_direct/);
  });
});
