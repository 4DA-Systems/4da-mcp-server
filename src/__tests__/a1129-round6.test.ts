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

export { brief, npmProject, waiting, h };
