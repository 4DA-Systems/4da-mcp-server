// SPDX-License-Identifier: Apache-2.0
/**
 * Round 4, the contract of the level (what-should-i-know.ts, K1-K3) and the fixes the third independent check's
 * rows needed under it (V1-V7). Registries and OSV.dev are the planner harness's stubbed fetch: nothing leaves
 * the machine, a name not filled in is a 404.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { RESTS_ON_DECLARATION } from "../tools/briefing-confirm.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  for (const n of ["zod", "ky", "hono"]) h.NPM[n] = { latest: "1.2.0", versions: { "1.0.0": {}, "1.2.0": {} } };
  h.NPM.lodash = { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } };
  h.NPM.zqxevil = { latest: "1.0.1", versions: { "1.0.1": {} } };
  h.NPM.zqxdual = { latest: "1.0.0", versions: { "1.0.0": {} } };
  h.PYPI.zqxdual = { "1.0.0": {} };
  h.PYPI.zqxevilpy = { "1.0.0": {} };
  h.PYPI.flask = { "3.0.3": {} };
  h.ADVISORIES.lodash = [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21"), "npm", "CRITICAL")];
  h.ADVISORIES.zqxevil = [adv("MAL-2026-99001", "zqxevil", [{ introduced: "0" }], "npm", "CRITICAL")];
  h.ADVISORIES.zqxevilpy = [adv("MAL-2026-99002", "zqxevilpy", [{ introduced: "0" }], "PyPI", "CRITICAL")];
});
afterEach(() => {
  live = null;
  h.dispose();
});

const npmProject = () => h.npmProject({ zod: "1.2.0", lodash: "4.17.21" }, {}, { zod: { version: "1.2.0" }, lodash: { version: "4.17.21" } });
// One live layer per test, as one server keeps one: its cache carries across calls.
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
const brief = async (args: Record<string, unknown>) => {
  live ??= await h.live();
  return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
};
const waiting = (r: Record<string, any>) => (r.task_packages.to_confirm as Array<{ name: string; ecosystems: string[]; hint?: string }>).map((e) => `${e.name}/${e.ecosystems.join("|")}`);

describe("K1: the level rests on the declaration, and says so", () => {
  it("a safe reason ends with the sentence; next_step says to_confirm can miss names", async () => {
    npmProject();
    const bare = await brief({ task: "add ky to the http client" });
    expect(bare.task_packages.next_step).toContain("to_confirm can miss names and ecosystems: declare every package the task adds or changes, in each ecosystem it is added to, whether it is listed here or not");
    const r = await brief({ task: "refactor the signup form", packages: [] });
    expect(r.delegation_assessment.level, r.delegation_assessment.reason).toBe("safe_to_delegate");
    expect(r.delegation_assessment.reason.endsWith(RESTS_ON_DECLARATION)).toBe(true);
  });
});

describe("K2: strict pairs wait until settled; a prose candidate is the caller's word", () => {
  it("names tied to two manifest files are two pairs: declaring one leaves the other waiting", async () => {
    npmProject();
    h.write("requirements.txt", "flask==3.0.3\n");
    const r = await brief({ task: "Add zqxdual to package.json and to requirements.txt", packages: [{ ecosystem: "PyPI", name: "zqxdual", public: true }] });
    expect(waiting(r)).toEqual(["zqxdual/npm"]);
    expect(r.delegation_assessment.level).toBe("confirmation_needed");
  });

  it("a prose candidate is offered once with every ecosystem the project uses, and any declaration settles it", async () => {
    npmProject();
    h.write("requirements.txt", "flask==3.0.3\n");
    const bare = await brief({ task: "Add zqxdual to the web app and the python worker" });
    const entry = bare.task_packages.to_confirm.find((e: { name: string }) => e.name === "zqxdual");
    expect(entry.ecosystems.sort()).toEqual(["PyPI", "npm"]);
    expect(entry.hint).toMatch(/this project uses (npm and PyPI|PyPI and npm): declare it in each one you add it to/);
    const r = await brief({ task: "Add zqxdual to the web app and the python worker", packages: [{ ecosystem: "PyPI", name: "zqxdual", public: true }] });
    expect(waiting(r)).toEqual([]);
    expect(r.delegation_assessment.reason).toContain(RESTS_ON_DECLARATION);
  });

  it.each([
    ["npm.exe i zqxevil", "zqxevil/npm"],
    ["Run `npx.cmd zqxevil --init` in the setup script.", "zqxevil/npm"],
    ["npm install v8-zqxevil", "v8-zqxevil/npm"],
    ["Run `npm install 1-zqxevil` for the parser.", "1-zqxevil/npm"],
    ["In setup.cmd:\nnpm install --save ^\n  zqxevil", "zqxevil/npm"],
    ["In setup.ps1:\nnpm install --save `\n  zqxevil", "zqxevil/npm"],
    ["Install the package with npm: zqxevil.", "zqxevil/npm"],
    ["Run <code>npm i zqxdual</code> first.", "zqxdual/npm"],
    ["install papaparse (npm) for the CSV import", "papaparse/npm"],
  ])("%s: the operand waits in its ecosystem, never safe on packages: []", async (task, pair) => {
    npmProject();
    const r = await brief({ task, packages: [] });
    expect(waiting(r)).toContain(pair);
    expect(r.delegation_assessment.level).toBe("confirmation_needed");
  });

  it("declared, the strict pair is checked: the malware is human_only", async () => {
    npmProject();
    const r = await brief({ task: "npm.exe i zqxevil", packages: [{ ecosystem: "npm", name: "zqxevil", public: true }] });
    expect(r.delegation_assessment.level).toBe("human_only");
  });
});

describe("K3: 'could not read whole' only for a shape that cannot be parsed, and no unscreened text is repeated", () => {
  it("a substitution among a command's words: review_needed, said by manager and verb only", async () => {
    npmProject();
    const r = await brief({ task: "npm install `cat zqxlist.txt`", packages: [] });
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toContain("This task holds a command (npm install) this briefing could not read whole (a command substitution among its words)");
    expect(r.delegation_assessment.reason).not.toContain("zqxlist");
  });

  it("an option's value is never repeated in any reason, hint or entry", async () => {
    npmProject();
    const secret = ["zq", "Sec", "ret", "77xx"].join("");
    const r = await brief({ task: `npm install --token ${secret} zod`, packages: [] });
    expect(JSON.stringify({ d: r.delegation_assessment, t: r.task_packages, s: r.summary })).not.toContain(secret);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});

describe("V1-V7", () => {
  it("V1: the spec written on the operand is checked, a version in the prose in addition", async () => {
    npmProject();
    const r = await brief({ task: "Pin lodash back: run `npm install lodash@4.17.20` because 4.17.21 broke the templates.", packages: [] });
    expect((r.requested_versions ?? []).map((x: { name: string; to: string }) => `${x.name}@${x.to}`)).toContain("lodash@4.17.20");
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it("V1: a pre-release or build label written on an operand is never sent by the operand check", async () => {
    npmProject();
    await brief({ task: "npm install lodash@4.17.21-zqx003", packages: [] });
    expect(h.requests.filter((u) => /zqx003/.test(u))).toEqual([]);
  });

  it("V2: a requirements file the task installs with -r holds task packages: its malware is human_only", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    h.write("requirements-extra.txt", "zqxevilpy==1.0.0\n");
    const r = await brief({ task: "Run `pip install -r requirements-extra.txt` on the build host.", packages: [{ ecosystem: "PyPI", name: "zqxevilpy", version: "1.0.0", public: true }] });
    expect(r.delegation_assessment.level).toBe("human_only");
    const bare = await brief({ task: "Run `pip install -r requirements-extra.txt` on the build host.", packages: [] });
    expect(bare.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  it("V5: a not-found answer is cached: a second call asks the registry nothing new for it", async () => {
    npmProject();
    await brief({ task: "npm install zqxmissing", packages: [{ ecosystem: "npm", name: "zqxmissing", public: true }] });
    const before = h.requests.filter((u) => u.includes("registry.npmjs.org/zqxmissing")).length;
    await brief({ task: "npm install zqxmissing", packages: [{ ecosystem: "npm", name: "zqxmissing", public: true }] });
    const after = h.requests.filter((u) => u.includes("registry.npmjs.org/zqxmissing")).length;
    expect(before).toBeGreaterThan(0);
    expect(after, JSON.stringify(h.requests.filter((u) => u.includes("zqxmissing")))).toBe(before);
  });

  it("V6: `make pip install -e . work` offers no 'work'", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    const r = await brief({ task: "Make pip install -e . work" });
    expect(waiting(r).map((w) => w.split("/")[0])).not.toContain("work");
  });

  it("V7: a name the task installs from its own private index is not sent, and the answer says so", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    const r = await brief({ task: "pip install -i https://pypi.zqxcorp.internal/simple zqxsecretpy", packages: [{ ecosystem: "PyPI", name: "zqxsecretpy", public: true }] });
    expect(h.requests.filter((u) => u.toLowerCase().includes("zqxsecretpy")), JSON.stringify(r.task_packages)).toEqual([]);
    expect(JSON.stringify(r.task_packages.private)).toContain("zqxsecretpy");
  });
});
