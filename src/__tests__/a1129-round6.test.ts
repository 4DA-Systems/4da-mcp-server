// SPDX-License-Identifier: Apache-2.0
/**
 * Round 6: the fourth independent check (review-confirm4) found these with the sentence method. One block per
 * item of the round; registries and OSV.dev are the planner harness's stubbed fetch (a name not filled in is a
 * 404), nothing leaves the machine, and token-shaped strings are assembled at run time.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
beforeEach(() => {
  h = createHarness();
  for (const n of ["zod", "ky", "hono", "prisma", "@prisma/client", "zqxok", "lodash"]) h.NPM[n] = { latest: "1.2.0", versions: { "1.0.0": {}, "1.2.0": {} } };
  h.NPM.zqxdual = { latest: "1.0.0", versions: { "1.0.0": {} } };
  h.PYPI.zqxdual = { "1.0.0": {} };
  h.PYPI.requests = { "2.32.3": {} };
  h.PYPI.zqxdualpy = { "1.0.0": {} };
  h.PYPI["zqx-okpy"] = { "1.0.0": {} };
  h.CRATES.zqxdual = [{ vers: "1.0.0" }];
  h.ADVISORIES.zqxdual = [adv("MAL-2026-99031", "zqxdual", [{ introduced: "0" }], "npm", "CRITICAL")];
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

describe("item 8: the only two of the reviewer's 80 ordinary tasks that failed", () => {
  it("o02: a path after the command's connective is no package candidate", async () => {
    npmProject();
    const r = await brief({ task: "Run npm install hono to replace the express-style router in src/server.ts with a Hono app.", packages: [{ ecosystem: "npm", name: "hono", public: true }] });
    expect(JSON.stringify(r.task_packages.not_read)).not.toContain("src/server.ts");
    // Round 7, C1: "src/server.ts" is no plain name, so the command is not read whole (review_needed, said by its
    // manager and verb), but the path itself is never a withheld word.
    expect(r.delegation_assessment.reason).not.toMatch(/was not looked up/);
  });

  it("o31: a backtick closing the command after an option ends the command there", async () => {
    npmProject();
    const r = await brief({
      task: "Run `npm install prisma --save-dev` and `npm install @prisma/client`, then generate the client.",
      packages: [{ ecosystem: "npm", name: "prisma", public: true }, { ecosystem: "npm", name: "@prisma/client", public: true }],
    });
    expect(JSON.stringify(r.task_packages.not_read)).not.toContain("--save-dev");
    expect(r.delegation_assessment.reason).not.toMatch(/was not looked up|not read/);
  });
});

describe("item 4: what a declaration does and does not change", () => {
  it("4a: an installed dependency dismissed or marked private: the answer says the project's scan still reads it", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    h.PYPI.flask = { "3.0.3": {} };
    const r = await brief({ task: "refactor the flask views", packages: [], not_packages: ["Flask"] });
    const text = JSON.stringify({ d: r.delegation_assessment, s: r.summary });
    expect(text).not.toMatch(/flask was not sent/i);
    expect(text).toContain("it does not change this project's own vulnerability scan");
  });

  it("4b: a refused public: false entry still forbids its name", async () => {
    npmProject();
    await brief({ task: "npm install lodash", packages: [{ ecosystem: "npm", name: "lodash", version: "%%%", public: false }] });
    expect(h.requests.filter((u) => /lodash/.test(u))).toEqual([]);
  });

  // Round 7c, F6: the `!` form is refused at the declaration, as dependency_check refuses it; refused, a
  // `public: false` entry still forbids its name in both forms, so nothing about it is sent.
  it("4b: a Go path in its !-escaped form is refused, and still forbids its sibling", async () => {
    h.write("go.mod", "module example.com/app\n\ngo 1.21\n");
    const r = await brief({ task: "go get github.com/Zqxcorp/lib@v1.0.0", packages: [{ ecosystem: "Go", name: "github.com/!zqxcorp/lib", public: false }] });
    expect(r.task_packages.not_read.filter((n: { reason: string }) => /refused/.test(n.reason))).toHaveLength(1);
    expect(h.requests.filter((u) => /zqxcorp/i.test(u))).toEqual([]);
  });

  it("4c: a declared version whose label has a credential shape is refused, never sent", async () => {
    npmProject();
    const label = ["AK", "IAABCDEFGHIJKLMNOP"].join("");
    const r = await brief({ task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "zqxok", version: `1.0.0-${label}`, public: true }] });
    expect(JSON.stringify(r)).not.toContain(label);
    expect(h.requests.filter((u) => u.includes(label))).toEqual([]);
    expect(JSON.stringify(r.task_packages.not_read)).toContain("looks like a credential");
  });
});

// Round 7, C6: a Poetry `^` / `~` declared for PyPI is refused, as dependency_check refuses it (the smaller change of
// "both accept or neither"); to_confirm offers no version at all (C7).
describe("item 7 (round 7): the declaration accepts what dependency_check accepts, and refuses what it refuses", () => {
  it.each(["^2.32", "~2.32"])("PyPI requests %s is refused, as dependency_check refuses it", async (version) => {
    npmProject();
    const r = await brief({ task: "add requests", packages: [{ ecosystem: "PyPI", name: "requests", version, public: true }] });
    expect(JSON.stringify(r.task_packages.not_read)).toContain("refused");
    expect(JSON.stringify(r)).not.toContain(version);
  });

  it.each([
    ["npm", "zod", "^1.2.0"],
    ["npm", "zod", "~1.2"],
    ["npm", "zod", ">=1 <2"],
    ["npm", "zod", "1.x"],
    ["npm", "zod", "latest"],
    ["PyPI", "requests", "==2.32.3"],
    ["PyPI", "requests", ">=2.0,<3"],
    ["PyPI", "requests", "~=2.32"],
    ["crates.io", "zqxdual", "^1.0"],
    ["crates.io", "zqxdual", "=1.0.0"],
    ["Go", "github.com/pkg/errors", "v0.9.1"],
  ])("%s %s %s is accepted", async (ecosystem, name, version) => {
    npmProject();
    const r = await brief({ task: `add ${name}`, packages: [{ ecosystem, name, version, public: true }] });
    expect(JSON.stringify(r.task_packages.not_read)).not.toContain("refused");
  });
});

export { brief, npmProject, waiting, h };

describe("item 1: manifest snippets and options between manager and verb give strict pairs", () => {
  it.each([
    ['Add to package.json: "dependencies": {"zqxdual":"1.0.0"}', "zqxdual/npm"],
    ['```json\n{"dependencies": {"zqxdual": "^1.0.0"}}\n```', "zqxdual/npm"],
    ["Add to requirements.txt: zqxdual==1.0.0", "zqxdual/PyPI"],
    ['pyproject.toml: dependencies = ["zqxdual>=1.0"]', "zqxdual/PyPI"],
    // Round 7, C5/C6: a Poetry `^` is no spec dependency_check reads for PyPI, so a table holding one is not read whole
    // (item 6 below); an entry with a plain version is a strict pair.
    ['[tool.poetry.dependencies]\npython = "^3.11"\nzqxdual = "1.0"', "zqxdual/PyPI"],
    ['Cargo.toml:\n[dependencies]\nzqxdual = { version = "1.0", features = ["x"] }', "zqxdual/crates.io"],
    ["npm -w web install zqxdual", "zqxdual/npm"],
    ["npm --workspace web install zqxdual", "zqxdual/npm"],
    ["yarn global add zqxdual", "zqxdual/npm"],
    ["yarn workspace web add zqxdual", "zqxdual/npm"],
    ["cargo +nightly install zqxdual", "zqxdual/crates.io"],
  ])("%s", async (task, pair) => {
    npmProject();
    const r = await brief({ task, packages: [] });
    expect(waiting(r)).toContain(pair);
    expect(r.delegation_assessment.level).toBe("confirmation_needed");
  });

  it("another ecosystem's declaration does not settle a manifest entry: the npm malware is checked once declared", async () => {
    npmProject();
    const task = 'Add to package.json: "dependencies": {"zqxdual":"1.0.0"}';
    const wrong = await brief({ task, packages: [{ ecosystem: "PyPI", name: "zqxdual", public: true }] });
    expect(waiting(wrong)).toContain("zqxdual/npm");
    const right = await brief({ task, packages: [{ ecosystem: "npm", name: "zqxdual", public: true }] });
    expect(right.delegation_assessment.level).toBe("human_only");
  });
});

describe("item 2: substitution and unclosed quotes are read on the raw text", () => {
  it("npm install $(cat pkgs.txt): could not read whole, never safe", async () => {
    npmProject();
    const r = await brief({ task: "npm install $(cat pkgs.txt)", packages: [] });
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toContain("This task holds a command (npm install) this briefing could not read whole");
    expect(r.delegation_assessment.reason).not.toContain("pkgs.txt");
  });

  it('npm i zqxok "unterminated: could not read whole, nothing offered from inside the quote', async () => {
    npmProject();
    const r = await brief({ task: 'npm i zqxok "unterminated', packages: [{ ecosystem: "npm", name: "zqxok", public: true }] });
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(JSON.stringify(r.task_packages.to_confirm)).not.toContain("unterminated");
  });
});

describe("item 3: an unknown option's value is never offered, never repeated", () => {
  it.each([
    ["pip install --pw hunter2zz zqx-okpy", "hunter2zz", "--pw"],
    ["pip install --zqxflag zqvalue7 zqx-okpy", "zqvalue7", "--zqxflag"],
    ["npm install --ca-pin zqpin55 zod", "zqpin55", "--ca-pin"],
  ])("%s", async (task, value, flag) => {
    h.write("requirements.txt", "flask==3.0.3\n");
    const r = await brief({ task, packages: [] });
    expect(JSON.stringify({ t: r.task_packages, d: r.delegation_assessment, s: r.summary })).not.toContain(value);
    // Round 7b, item 2: the grammar says the command not read whole (K3, by manager and verb); no "the word after".
    expect(JSON.stringify(r.task_packages.not_read)).not.toContain(`the word after ${flag}`);
    expect(r.delegation_assessment.reason).toMatch(/could not read whole \(an option this briefing does not read\)/);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(h.requests.filter((u) => u.includes(value))).toEqual([]);
  });

  it("a known value option's value (--workspace web, --omit dev) is never offered either", async () => {
    npmProject();
    const r = await brief({ task: "npm install --workspace web --omit dev zod" });
    expect(JSON.stringify(r.task_packages.to_confirm)).not.toMatch(/"web"|"dev"/);
  });
});

// Round 7, C1/C5: a comma in a command's list, or a manifest entry it cannot read, makes it not read whole: nothing of
// it is offered, review_needed at most.
describe("item 6 (round 7): a comma in a command's list: not read whole", () => {
  it.each([
    ["pip install requests, zqxdualpy", "zqxdualpy"],
    ["npm i zod, zqxdual", "zqxdual"],
    ['[tool.poetry.dependencies]\nzqxdual = "^1.0"', "zqxdual"],
  ])("%s", async (task, name) => {
    npmProject();
    h.write("requirements.txt", "requests==2.32.3\n");
    const r = await brief({ task, packages: [] });
    expect(waiting(r).map((w) => w.split("/")[0])).not.toContain(name);
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toMatch(/could not read whole/);
  });
});
