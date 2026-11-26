// SPDX-License-Identifier: Apache-2.0
/**
 * Round 6b: sentences the docs lane proved false on 79bcb5b, one block per item. Registries and OSV.dev are the
 * planner harness's stubbed fetch (a name not filled in is a 404); token-shaped strings are assembled at run time.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { executeDependencyCheck, runDependencyCheck } from "../tools/dependency-check.js";
import { upgradePlannerTool } from "../tools/upgrade-planner.js";
import { versionLooksSecret } from "../tools/dependency-check-screen.js";
import { serverDataDir } from "../db.js";
import { LEDGER_FILE } from "../check-ledger.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
beforeEach(() => {
  h = createHarness();
  h.NPM.zod = { latest: "1.2.0", versions: { "1.0.0": {}, "1.2.0": {} } };
  h.NPM.zqxok = { latest: "1.0.0", versions: { "1.0.0": {} } };
  h.PYPI.flask = { "3.0.3": {} };
});
afterEach(() => {
  live = null;
  h.dispose();
});
const brief = async (args: Record<string, unknown>) => {
  live ??= await h.live();
  return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
};
const AK = ["AK", "IAABCDEFGHIJKLMNOP"].join("");

describe("item 1: every packages entry refused", () => {
  it("says the entries were refused, by class, never their values, and is never safe", async () => {
    h.npmProject({ zod: "1.2.0" }, {}, { zod: { version: "1.2.0" } });
    const r = await brief({
      task: "refactor the signup form",
      packages: [
        { ecosystem: "npm", name: "Bad Name", public: true },
        { ecosystem: "npm", name: "zod", version: "%%zq", public: true },
      ],
    });
    const reason: string = r.delegation_assessment.reason;
    expect(reason).toContain("None of your 2 `packages` entries could be read, so nothing you declared was checked.");
    expect(reason).toContain("1 with a name its registry cannot have, 1 with a version dependency_check cannot read");
    expect(reason).not.toContain("You declared that the task adds or changes no package");
    expect(JSON.stringify({ reason, s: r.summary })).not.toMatch(/words? in the task/);
    expect(JSON.stringify(r)).not.toContain("%%zq");
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});

describe("item 2: dependency_check's NOT CHECKED sentence", () => {
  it("one item, and several", async () => {
    const one = await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "zqxnothere1", to: "1.0.0" }] }, await h.live());
    expect(one.summary).toMatch(/^NOT CHECKED: the item could not be checked \(/);
    const two = await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "zqxnothere1", to: "1.0.0" }, { ecosystem: "npm", package: "zqxnothere2", to: "1.0.0" }] }, await h.live());
    expect(two.summary).toMatch(/^NOT CHECKED: none of the 2 items could be checked \(/);
  });
});

describe("item 3: a private status from the task's own index is said as such", () => {
  it("basis names the command in the task", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    const r = await brief({ task: "pip install -i https://pypi.zqx.internal/simple zqxpriv", packages: [{ ecosystem: "PyPI", name: "zqxpriv", public: true }] });
    const row = (r.task_packages.private as Array<{ name: string; basis: string }>).find((p) => p.name === "zqxpriv");
    expect(row?.basis).toMatch(/^the command in the task installs it from its own package index or registry/);
  });
});

describe("item 4: no doubled period after the scan sentence", () => {
  it("an installed dependency dismissed", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    const r = await brief({ task: "refactor the flask views", packages: [], not_packages: ["flask"] });
    expect(JSON.stringify({ d: r.delegation_assessment, s: r.summary })).not.toContain("GOPRIVATE)..");
  });
});

describe("item 5: upgrade_planner says which steps carry if_it_fails", () => {
  it("JavaScript steps and npm pkg set are named", () => {
    expect(upgradePlannerTool.description).toContain("`npm pkg set`");
    expect(upgradePlannerTool.description).toContain("a JavaScript install that sets a version");
  });
});

describe("item 6: dependency_check refuses a credential-shaped version label", () => {
  it("refused, not sent, not shown, not recorded", async () => {
    const r = await runDependencyCheck(null, { items: [{ ecosystem: "npm", package: "zqxok", to: `1.0.0-${AK}` }, { ecosystem: "npm", package: "zqxok", to: "1.0.0" }] }, await h.live());
    const text = JSON.stringify(r);
    expect(text).not.toContain(AK);
    expect(text).toContain("looks like a credential");
    expect(h.requests.filter((u) => u.includes(AK))).toEqual([]);
    await new Promise((res) => setTimeout(res, 300));
    const ledger = path.join(serverDataDir(), LEDGER_FILE);
    expect(fs.existsSync(ledger) ? fs.readFileSync(ledger, "utf8") : "").not.toContain(AK);
  });

  it.each(["1.0.0", "1.0.0-beta.1", "1.0.0-rc.2+build.5", "v0.0.0-20191109021931-daa7c04131f5", "1.0.0+g1a2b3c4", "1.0.0-SNAPSHOT", "2.0.0-M1", ">=1.0,<2", "~=2.32", "^1.2.3"])("a real version shape is kept: %s", (v) => {
    expect(versionLooksSecret(v)).toBe(false);
  });

  it.each([`1.0.0-${AK}`, ["1.0.0-gh", "p-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join(""), ["1.0.0+gl", "pat-abcdefghij0123456789"].join("")])("a credential-shaped label is refused: %s", (v) => {
    expect(versionLooksSecret(v)).toBe(true);
  });
});
