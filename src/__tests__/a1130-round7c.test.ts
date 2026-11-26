// SPDX-License-Identifier: Apache-2.0
/**
 * Round 7c: the docs lane's findings against the round-7b build, each swept over its class.
 * F1 a word the grammar consumed (program, verb, switch, option, option value) is no package for any reader;
 * F5 C3 source words match in their own case and for their own manager; F6 a `!`-escaped Go path is refused at the
 * declaration as dependency_check refuses it, and neither records it; F2 a snippet's git entry is said as the
 * task's own source; F3 a key the snippet grammar read is no prose candidate; F4 a snippet not read whole offers
 * nothing; R3 one row and one clause per (pair, version); R4 each row states its own basis. Stubbed fetch.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { runDependencyCheck } from "../tools/dependency-check.js";
import { RAW_SOURCE } from "../tools/briefing-command-check.js";
import { serverDataDir } from "../db.js";
import { LEDGER_FILE } from "../check-ledger.js";
import { createHarness, fixedIn, adv, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
beforeEach(() => {
  h = createHarness();
  for (const n of ["ms", "install", "add", "npm", "pip", "go", "cargo", "yarn", "bun", "uv", "poetry", "i", "update", "get", "lodash", "zqxok", "zqxreal"]) h.NPM[n] = { latest: "2.1.3", versions: { "2.1.3": {}, "4.17.20": {}, "4.17.21": {} } };
  for (const n of ["requests", "install", "pip", "black"]) h.PYPI[n] = { "2.32.3": {} };
  for (const n of ["serde", "install", "add", "zqxreal", "cargo"]) h.CRATES[n] = [{ vers: "1.0.0" }];
  h.ADVISORIES.lodash = [adv("GHSA-zq7c-0000-0001", "lodash", fixedIn("4.17.21"), "npm", "HIGH")];
});
afterEach(() => {
  live = null;
  h.dispose();
});
const brief = async (args: Record<string, unknown>) => {
  live ??= await h.live();
  return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
};
const named = (r: Record<string, any>) =>
  [...(r.new_packages ?? []).map((p: { name: string }) => p.name), ...(r.requested_versions ?? []).map((p: { name: string }) => p.name), ...(r.task_dependencies ?? []).map((p: { package: string }) => p.package), ...(r.task_packages?.to_confirm ?? []).map((p: { name: string }) => p.name)].map((x: string) => x.toLowerCase());

describe("F1: no word the grammar consumed is offered, looked up or weighed", () => {
  const COMMANDS: Array<[string, string, string[]]> = [
    ["npm install ms@2.1.3", "ms", ["npm", "install"]],
    ["npm i -D ms", "ms", ["npm", "i"]],
    ["npm update ms", "ms", ["npm", "update"]],
    ["yarn add ms", "ms", ["yarn", "add"]],
    ["bun add ms", "ms", ["bun", "add"]],
    ["pip install requests==2.32.3", "requests", ["pip", "install"]],
    ["python -m pip install requests", "requests", ["pip", "install"]],
    ["uv add requests", "requests", ["uv", "add"]],
    ["poetry add requests", "requests", ["poetry", "add"]],
    ["cargo add serde", "serde", ["cargo", "add"]],
    ["cargo install serde", "serde", ["cargo", "install"]],
    ["go get github.com/pkg/errors@v0.9.1", "github.com/pkg/errors", ["go", "get"]],
    ["pipx install black", "black", ["pipx", "install"]],
  ];
  const FORMS = [(c: string) => c, (c: string) => `Please run \`${c}\` now.`, (c: string) => `Use ${c}`, (c: string) => `Add it (${c}) today.`];
  it.each(COMMANDS.flatMap(([c, op, words]) => FORMS.map((f) => [f(c), op, words] as const)))("%s", async (task, op, words) => {
    h.npmProject({}, {}, {});
    const r = await brief({ task, packages: [{ ecosystem: task.includes("pip") || task.includes("uv ") || task.includes("poetry") ? "PyPI" : task.includes("cargo") ? "crates.io" : task.includes("go get") ? "Go" : "npm", name: op, public: true }] });
    expect(named(r).filter((n) => words.includes(n))).toEqual([]);
    expect(h.requests.filter((u) => words.some((w) => new RegExp(`/(?:${w})(?:/|$|\\?)`).test(u)))).toEqual([]);
    expect(r.delegation_assessment.reason).not.toMatch(/\b(?:install|add|npm)\b \(unknown\)/);
  });
});

describe("F5: C3 source words match in their own case and manager", () => {
  it.each(["cargo add -F derive zqxserde", "cargo add zqxserde -F derive", "npm install -f zqxok", "bun add -i zqxok", "Add Registry= notes to the README"])("%s names no source", (task) => {
    expect(RAW_SOURCE.test(task)).toBe(false);
  });
  it.each(["pip install -i https://pypi.corp.example/simple zqxok", "pip install -f https://corp.example/links zqxok", "uv pip install -i https://x/simple zqxok", "YARN_REGISTRY=https://npm.corp yarn add zqxok", "npm install --registry https://npm.corp zqxok", "GOPRIVATE=corp.example go get corp.example/x"])("%s names a source", (task) => {
    expect(RAW_SOURCE.test(task)).toBe(true);
  });
  it("cargo add -F derive serde is checked, not held as a source", async () => {
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n');
    const r = await brief({ task: "cargo add -F derive serde", packages: [{ ecosystem: "crates.io", name: "serde", public: true }] });
    expect(JSON.stringify(r.task_packages.not_read)).not.toContain("package source");
  });
});

describe("F6: a `!`-escaped Go path is refused at the declaration, as dependency_check refuses it; neither records it", () => {
  it("both tools refuse it and write no ledger line", async () => {
    h.npmProject({}, {}, {});
    const file = path.join(serverDataDir(), LEDGER_FILE);
    const lines = () => (fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "").split("\n").filter((l) => l.includes("zqx!evil"));
    const r = await brief({ task: "go get github.com/!zqx!evil/mod@v1.0.0", packages: [{ ecosystem: "Go", name: "github.com/!zqx!evil/mod", public: true }] });
    expect(JSON.stringify(r.task_packages.not_read)).toContain("refused");
    expect(h.requests.filter((u) => u.includes("zqx"))).toEqual([]);
    live ??= await h.live();
    const dc = (await runDependencyCheck(null, { items: [{ ecosystem: "Go", package: "github.com/!zqx!evil/mod", to: "v1.0.0" }, { ecosystem: "npm", package: "ms", to: "2.1.3" }] }, live)) as { results: Array<{ verdict: string; not_checked?: string }> };
    expect(dc.results[0]).toMatchObject({ verdict: "unknown", not_checked: "input" });
    await new Promise((res) => setTimeout(res, 300));
    expect(lines()).toEqual([]);
  });
});

describe("F2/F3/F4: manifest snippets", () => {
  it("F2: a git entry of the task's snippet is said as the snippet's own source", async () => {
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n');
    const r = await brief({ task: 'Add to Cargo.toml:\n[dependencies]\nzqxgit = { git = "https://git.corp.example/zqxgit" }', packages: [] });
    const row = (r.task_packages.private as Array<{ name: string; basis: string }>).find((p) => p.name === "zqxgit");
    expect(row?.basis).toBe("the manifest snippet in the task takes it from git, a path, a registry or the workspace, not the public registry");
  });
  it("F3: an alias key is never a prose candidate; the real pair waits", async () => {
    h.npmProject({}, {}, {});
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n');
    const r = await brief({ task: 'Add to Cargo.toml:\n[dependencies]\nzqxalias = { package = "zqxrealcrate", version = "1.0" }' });
    const names = (r.task_packages.to_confirm as Array<{ name: string; ecosystems: string[] }>).map((e) => `${e.name}/${e.ecosystems.join("|")}`);
    expect(names).toEqual(["zqxrealcrate/crates.io"]);
  });
  it('F4: a snippet not read whole offers nothing, not even its readable entries', async () => {
    h.npmProject({}, {}, {});
    const r = await brief({ task: 'Add to package.json: "dependencies": { "zqxokentry": "1.0.0", "zqxbad": 12 }' });
    expect(JSON.stringify(r.task_packages)).not.toMatch(/zqxokentry|zqxbad/);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(r.delegation_assessment.reason).toMatch(/manifest snippet this briefing could not read whole/);
  });
});

describe("R3/R4: one row and one clause per (pair, version), each with its own basis", () => {
  it("npm install lodash@4.17.20 with lodash installed and declared: one row, one clause, basis by origin", async () => {
    h.npmProject({ lodash: "4.17.20" }, {}, { lodash: { version: "4.17.20" } });
    const r = await brief({ task: "npm install lodash@4.17.20", packages: [{ ecosystem: "npm", name: "lodash", public: true }] });
    const rows = [...(r.new_packages ?? []), ...(r.requested_versions ?? [])].map((p: { version?: string; to?: string }) => p.to ?? p.version);
    expect(rows.filter((v) => v === "4.17.20")).toHaveLength(1);
    const reason = r.delegation_assessment.reason as string;
    const clause = /lodash[^.;]*4\.17\.20[^.;]*/.exec(reason)?.[0] ?? "";
    expect(clause).not.toBe("");
    expect(reason.split(clause).length - 1).toBe(1);
    const checked = r.task_packages.checked as Array<{ version: string; basis: string }>;
    expect(checked.filter((c) => c.version === "4.17.20")).toEqual([expect.objectContaining({ basis: "confirmed public by you" })]);
  });
  it("R4: a row from the briefing's own lookup does not say 'confirmed public by you'", async () => {
    h.npmProject({ lodash: "4.17.20" }, {}, { lodash: { version: "4.17.20" } });
    const r = await brief({ task: "bump lodash to 4.17.21", packages: [{ ecosystem: "npm", name: "zod", version: "2.1.3", public: true }] });
    const own = (r.task_packages.checked as Array<{ name: string; basis: string }>).filter((c) => c.name === "lodash");
    for (const c of own) expect(c.basis).not.toBe("confirmed public by you");
  });
});

describe("F5: the source check stays linear", () => {
  it("15,000 pip commands on one line", () => {
    const t0 = process.cpuUsage();
    RAW_SOURCE.test("pip install x ".repeat(15_000));
    const used = process.cpuUsage(t0);
    expect((used.user + used.system) / 1000).toBeLessThan(500);
  });
});
