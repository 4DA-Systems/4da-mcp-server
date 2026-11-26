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
    expect(r.delegation_assessment.reason).not.toMatch(/was not looked up|not read/);
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

  it("4b: a Go path in its !-escaped form is read unescaped, and forbids its sibling", async () => {
    h.write("go.mod", "module example.com/app\n\ngo 1.21\n");
    const r = await brief({ task: "go get github.com/Zqxcorp/lib@v1.0.0", packages: [{ ecosystem: "Go", name: "github.com/!zqxcorp/lib", public: false }] });
    expect(r.task_packages.not_read.filter((n: { reason: string }) => /refused/.test(n.reason))).toEqual([]);
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

describe("item 7: the declaration accepts what to_confirm offers", () => {
  it.each([
    ["npm", "zod", "^1.2.0"],
    ["npm", "zod", "~1.2"],
    ["npm", "zod", ">=1 <2"],
    ["npm", "zod", "1.x"],
    ["npm", "zod", "latest"],
    ["PyPI", "requests", "==2.32.3"],
    ["PyPI", "requests", ">=2.0,<3"],
    ["PyPI", "requests", "~=2.32"],
    ["PyPI", "requests", "^2.32"],
    ["PyPI", "requests", "~2.32"],
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
