// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know keys packages by ecosystem and name. "bump jsonwebtoken to 12 in relay" in
 * 4DA gave one row, `ecosystem: crates.io`, `installed: ["11.1.0", "9.0.3"]`, `majors_crossed: 3`:
 * 9.0.3 is the npm package of that name in another directory. A name installed in two ecosystems
 * is two packages, one row each, each with its own copies and its own distance.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { adv, appDb, cargoLock, emptyNetwork, fixedIn, liveFor, npmProject, projectDir, stubNetwork, write, type Network } from "./helpers/a1123-advice.js";

let dir: string;
let net: Network;

beforeEach(() => {
  dir = projectDir();
  net = emptyNetwork();
  write(dir, "relay/Cargo.toml", '[package]\nname = "relay"\nversion = "0.1.0"\n\n[dependencies]\njsonwebtoken = "11"\n');
  write(
    dir,
    "relay/Cargo.lock",
    cargoLock([
      { name: "relay", version: "0.1.0", deps: ["jsonwebtoken"], root: true },
      { name: "jsonwebtoken", version: "11.1.0" },
    ]),
  );
  npmProject(dir, { jsonwebtoken: "^9.0.0" }, { jsonwebtoken: { version: "9.0.3" } }, "editors/vscode");
});

afterEach(() => {
  vi.unstubAllGlobals();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("one package per ecosystem and name in the briefing", () => {
  it("a name installed on crates.io and on npm is two rows, each with its own copies and distance", async () => {
    stubNetwork(net);
    const briefing = await executeWhatShouldIKnow(appDb().db, { task: "bump jsonwebtoken to 12 in relay" }, await liveFor(dir));

    const rows = briefing.task_dependencies.filter((d) => d.package === "jsonwebtoken");
    expect(rows.map((d) => ({ ecosystem: d.ecosystem, installed: d.installed, majors_crossed: d.majors_crossed })).sort((a, b) => a.ecosystem.localeCompare(b.ecosystem))).toEqual([
      { ecosystem: "crates.io", installed: ["11.1.0"], majors_crossed: 1 },
      { ecosystem: "npm", installed: ["9.0.3"], majors_crossed: 3 },
    ]);
    // Said apart wherever the name alone would not say which.
    expect(briefing.summary).toMatch(/jsonwebtoken \(crates\.io\) 11\.1\.0/);
    expect(briefing.summary).toMatch(/jsonwebtoken \(npm\) 9\.0\.3/);
    expect(briefing.delegation_assessment.reason).toMatch(/1 major version of jsonwebtoken \(crates\.io\)/);
    expect(briefing.delegation_assessment.reason).toMatch(/3 major versions of jsonwebtoken \(npm\)/);
  });

  it("each row carries only its own ecosystem's findings", async () => {
    net.advisories.jsonwebtoken = [adv("GHSA-npm-jwt-0001", "jsonwebtoken", fixedIn("9.0.4"), "npm", "HIGH")];
    net.npm.jsonwebtoken = { latest: "9.0.4", versions: { "9.0.3": {}, "9.0.4": {} } };
    stubNetwork(net);
    const briefing = await executeWhatShouldIKnow(appDb().db, { task: "bump jsonwebtoken" }, await liveFor(dir));

    const crate = briefing.task_dependencies.find((d) => d.package === "jsonwebtoken" && d.ecosystem === "crates.io")!;
    const npm = briefing.task_dependencies.find((d) => d.package === "jsonwebtoken" && d.ecosystem === "npm")!;
    expect(crate.vulnerabilities).toEqual([]);
    expect(npm.vulnerabilities.map((v) => v.id)).toEqual(["GHSA-npm-jwt-0001"]);
    const titles = briefing.advisories.filter((a) => a.scope === "task").map((a) => a.title);
    expect(titles).toEqual(["jsonwebtoken (npm) 9.0.3: 1 confirmed vulnerability, highest high"]);
  });
});
