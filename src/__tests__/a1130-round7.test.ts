// SPDX-License-Identifier: Apache-2.0
/**
 * Round 7: the fifth independent check's five blockers and eight majors under the smaller contract (canonical
 * command grammar, raw package-source words, versions per pair, the ledger as dependency_check's line). Registries
 * and OSV.dev are the planner harness's stubbed fetch (a name not filled in is a 404); nothing leaves the machine.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { runDependencyCheck } from "../tools/dependency-check.js";
import { SOURCE_HELD } from "../tools/briefing-confirm.js";
import { validateToolArgs } from "../tool-args.js";
import { whatShouldIKnowTool } from "../tools/what-should-i-know.js";
import { serverDataDir } from "../db.js";
import { LEDGER_FILE } from "../check-ledger.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
beforeEach(() => {
  h = createHarness();
  for (const n of ["zod", "ky", "zqxok", "test", "lodash"]) h.NPM[n] = { latest: "1.2.0", versions: { "1.0.0": {}, "1.2.0": {} } };
  h.NPM.zqxevil = { latest: "1.0.1", versions: { "1.0.1": {} } };
  h.NPM.zqxcrit4 = { latest: "2.0.0", versions: { "1.0.0": {}, "2.0.0": {} } };
  h.NPM.zqxlatebad = { latest: "2.0.0", versions: { "1.0.0": {}, "2.0.0": {} } };
  h.PYPI.zqxlatebad = { "1.0.0": {}, "2.0.0": {} };
  h.PYPI.zqxok = { "1.0.0": {} };
  h.CRATES.zqxevilrs = [{ vers: "1.0.0" }];
  h.ADVISORIES.zqxevil = [adv("MAL-2026-99001", "zqxevil", [{ introduced: "0" }], "npm", "CRITICAL")];
  h.ADVISORIES.zqxcrit4 = [adv("GHSA-zq4c-0000-0001", "zqxcrit4", fixedIn("2.0.0"), "npm", "CRITICAL")];
});
afterEach(() => {
  live = null;
  h.dispose();
});
const npmProject = () => h.npmProject({ zod: "1.2.0" }, {}, { zod: { version: "1.2.0" } });
const brief = async (args: Record<string, unknown>) => {
  live ??= await h.live();
  return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
};
const waiting = (r: Record<string, any>) => (r.task_packages.to_confirm as Array<{ name: string; ecosystems: string[] }>).map((e) => `${e.name}/${e.ecosystems.join("|")}`);

describe("B1 (C3): a package source named in the task: no name it adds is looked up, also declared public", () => {
  it.each([
    ["npm.cmd --registry https://npm.corp.example install zqxok", "npm"],
    ["npm install --@zqx:registry=https://npm.corp.example zqxok", "npm"],
    ["pip3.12 install -i https://pypi.corp.example/simple zqxok", "PyPI"],
    ["pip.exe install -f https://wheels.corp.example zqxok", "PyPI"],
    ["uv.exe add --default-index https://pypi.corp.example zqxok", "PyPI"],
    ['$env:npm_config_registry="https://npm.corp.example"; npm install zqxok', "npm"],
    ['$env:PIP_INDEX_URL="https://pypi.corp.example/simple"; pip install zqxok', "PyPI"],
    ["Add to pyproject: [[tool.uv.index]] url = \"https://pypi.corp.example\" and uv add zqxok", "PyPI"],
  ])("%s", async (task, ecosystem) => {
    npmProject();
    const r = await brief({ task, packages: [{ ecosystem, name: "zqxok", public: true }] });
    expect(h.requests.filter((u) => u.includes("zqxok"))).toEqual([]);
    // Said once: SOURCE_HELD, or the screen's own "not looked up" for a name a command takes from its own source.
    expect(JSON.stringify(r.task_packages.not_read)).toMatch(/"shown":"zqxok","reason":"not looked up/);
    expect(SOURCE_HELD).toMatch(/^not looked up: the task names a package source of its own/);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});

describe("B2 (C4): a spec applies only to the pair it is written on", () => {
  it("the npm manifest spec does not narrow the PyPI declaration: PyPI is checked at latest", async () => {
    npmProject();
    const r = await brief({ task: 'Add "zqxlatebad": "^1.0.0" to package.json and pip install zqxlatebad', packages: [{ ecosystem: "PyPI", name: "zqxlatebad", public: true }] });
    const pypi = (r.new_packages ?? []).filter((p: { ecosystem: string }) => p.ecosystem === "PyPI");
    expect(pypi.map((p: { version?: string }) => p.version ?? "latest")).toEqual(["latest"]);
  });
});

describe("B3 (C1): a scaffold or runner verb is never read whole", () => {
  it.each(["npm create zqxfoo", "npm init @zqxs", "yarn create zqxfoo", "pnpm create zqxfoo", "bun create zqxfoo", "npx zqxevil"])("%s", async (task) => {
    npmProject();
    const r = await brief({ task, packages: [{ ecosystem: "npm", name: "zqxfoo", public: true }] });
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(r.delegation_assessment.reason).toMatch(/could not read whole \(it fetches and runs a package/);
  });
});

describe("B4 (C1): every operand of a canonical command waits, English-looking or not", () => {
  it.each([
    ["npm i -D test zqxevil", ["test/npm", "zqxevil/npm"]],
    ["pnpm add when zqxevil", ["when/npm", "zqxevil/npm"]],
    ["npm install to zqxevil", ["to/npm", "zqxevil/npm"]],
  ])("%s", async (task, pairs) => {
    npmProject();
    const r = await brief({ task, packages: [] });
    for (const p of pairs) expect(waiting(r)).toContain(p);
    expect(r.delegation_assessment.level).toBe("confirmation_needed");
  });
});

describe("B5 (C5): a Cargo rename names the real crate", () => {
  it('foo = { package = "zqxevilrs", version = "1" } waits as zqxevilrs', async () => {
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n');
    const r = await brief({ task: 'Add to Cargo.toml:\n[dependencies]\nfoo = { package = "zqxevilrs", version = "1" }', packages: [] });
    expect(waiting(r)).toContain("zqxevilrs/crates.io");
  });

  it("an entry shape it does not read makes the snippet not read whole", async () => {
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n');
    const r = await brief({ task: "Add to Cargo.toml:\n[dependencies]\nzqxok.workspace = true", packages: [{ ecosystem: "crates.io", name: "zqxok", public: true }] });
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});

describe("M2 (C7): to_confirm never carries a version from the task", () => {
  it("npm install zqxok@1.0.0", async () => {
    npmProject();
    const r = await brief({ task: "npm install zqxok@1.0.0" });
    expect(JSON.stringify(r.task_packages.to_confirm)).not.toContain("1.0.0");
  });
});

describe("M4 (C6): the declared item goes to the engine as written, and the ledger is its line", () => {
  // dependency_check itself drops build metadata before any lookup (it may name a private build): the briefing's line
  // for the declared item is exactly the line dependency_check writes for the same item, and neither holds the label.
  it("lodash@4.17.21+build7: the briefing's ledger line is dependency_check's line, without the label", async () => {
    npmProject();
    const file = path.join(serverDataDir(), LEDGER_FILE);
    const read = () => (fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "").split("\n").filter((l) => l.includes('"lodash"')).map((l) => JSON.stringify({ ...JSON.parse(l), t: undefined }));
    await brief({ task: "npm install lodash@4.17.21+build7", packages: [{ ecosystem: "npm", name: "lodash", public: true }] });
    await new Promise((res) => setTimeout(res, 300));
    const briefing = read();
    fs.rmSync(file, { force: true });
    await runDependencyCheck(null, { items: [{ ecosystem: "npm", package: "lodash", to: "4.17.21+build7" }] }, await h.live());
    await new Promise((res) => setTimeout(res, 300));
    expect(briefing.length).toBeGreaterThan(0);
    expect(briefing).toEqual(read());
    expect(briefing.join("\n")).not.toContain("build7");
  });
});

describe("M5 (C2): a strict pair settles only by its exact name", () => {
  it("ZqxCrit4 declared for npm i zqxcrit4@1.0.0 leaves zqxcrit4 waiting", async () => {
    npmProject();
    const r = await brief({ task: "npm i zqxcrit4@1.0.0", packages: [{ ecosystem: "npm", name: "ZqxCrit4", public: true }] });
    expect(waiting(r)).toContain("zqxcrit4/npm");
    const right = await brief({ task: "npm i zqxcrit4@1.0.0", packages: [{ ecosystem: "npm", name: "zqxcrit4", public: true }] });
    expect(right.delegation_assessment.level).toBe("human_only");
  });
});

describe("M6 (C9a): a dependency the project has, declared private, is never said 'not looked up' by any path", () => {
  it("zod declared private", async () => {
    npmProject();
    const r = await brief({ task: "Upgrade zod to latest", packages: [{ ecosystem: "npm", name: "zod", public: false }] });
    expect(JSON.stringify({ d: r.delegation_assessment, s: r.summary, a: r.advisories })).not.toMatch(/nothing about it was looked up|zod is private \([^)]*\) and was not checked/);
  });
});

describe("M7 (C10): versions in prose tied to no package hold nothing", () => {
  it.each(["Write unit tests for parseDate in src/date.ts, covering 2024-02-29 and 1.5.3 style inputs", "Support versions 1.2, 1.3 and 2.0 of the config format in src/config.ts"])("%s", async (task) => {
    npmProject();
    const r = await brief({ task, packages: [] });
    expect(r.delegation_assessment.reason).not.toMatch(/could not tie to a package/);
  });
});

describe("M8 (C1/C2): a comma in a command's list: not read whole, never settled by another ecosystem", () => {
  it("npm install zqxok, zqxdual + {PyPI, zqxdual}", async () => {
    npmProject();
    const r = await brief({ task: "npm install zqxok, zqxdual", packages: [{ ecosystem: "PyPI", name: "zqxdual", public: true }, { ecosystem: "npm", name: "zqxok", public: true }] });
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});

describe("C7, C9b, C9c: arguments", () => {
  it("a null, number or array entry refuses that entry, not the call", () => {
    expect(validateToolArgs("what_should_i_know", whatShouldIKnowTool.inputSchema as never, { task: "x", packages: [null, 3, ["a"], { ecosystem: "npm", name: "zod", public: true }] })).toBeNull();
  });

  it("an over-long task's error repeats none of it", () => {
    const secret = ["npm", "_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"].join("");
    const msg = validateToolArgs("what_should_i_know", whatShouldIKnowTool.inputSchema as never, { task: `NPM_TOKEN=${secret} ${"x".repeat(250_000)}` });
    expect(msg).not.toBeNull();
    expect(msg).not.toContain(secret.slice(0, 10));
  });

  it('public: "false" (a string) refuses the entry and forbids its name', async () => {
    npmProject();
    await brief({ task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "zqxok", public: "false" }, { ecosystem: "npm", name: "zqxok", public: true }] });
    expect(h.requests.filter((u) => u.includes("zqxok"))).toEqual([]);
  });
});

describe("C1: a command opened by a parenthesis ends at its close", () => {
  it.each([
    ["Add structured logging with pino (npm install pino) and replace console.log in the server.", "pino"],
    ["Store uploads in S3 with boto3 (pip install boto3).", "boto3"],
  ])("%s", async (task, name) => {
    npmProject();
    const r = await brief({ task });
    expect(r.delegation_assessment.reason).not.toMatch(/could not read whole/);
    // The operand is the only pair (pino and boto3 are bundled-list names: looked up, not waiting); nothing after ")".
    expect(waiting(r)).toEqual([]);
    expect(JSON.stringify(r.new_packages ?? [])).toContain(name);
  });
});
