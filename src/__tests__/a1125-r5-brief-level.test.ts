// SPDX-License-Identifier: Apache-2.0
/**
 * Third blind check of the 2026-11-25 fixes, item 2: handing names back must never read softer than
 * 6.5.1. A near-miss of a popular name, judged offline, is human_only until dependency_check has
 * answered (npm took 12 of 12 such typosquats down as malware). Any other name the briefing did not
 * check keeps review_needed, but the reason leads with NOT ASSESSED and never says "Delegate, then
 * review". And a pip `--hash` value is no credential: the package beside it is listed. Stubbed fetch.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("a near-miss judged offline is human_only until checked", () => {
  it.each(["npm install lodahs", "add lodahs", "npm install electorn", "npm install babelcli", "npm install mongose", "npm install nodesass"])("%s", async (task) => {
    const r = await brief(task);
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason).toMatch(/a possible typosquat of [\w.-]+\): this briefing did not look it up\. Do not install it before dependency_check has answered/);
    expect([...(r.check_these?.arguments.items ?? []).map((i: { package: string }) => i.package), ...(r.unverified_words ?? []).map((w: { word: string }) => w.word)]).toContain(task.split(" ").pop());
  });
});

describe("unchecked names: review_needed, led by NOT ASSESSED, never 'delegate'", () => {
  it.each(["npm install qzflux", "add qzflux to the project", "cargo add tokio@1.8.0"])("%s", async (task) => {
    const r = await brief(task);
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toMatch(/^NOT ASSESSED: 1 package the task names was not checked by this briefing\. Do not delegate the write until dependency_check has answered for it; if it answers avoid or names malware for any, this task is human_only\./);
    expect(r.delegation_assessment.reason).not.toContain("Delegate, then review");
  });
});

describe("a pip --hash value is no credential", () => {
  it("pip install PyJWT==1.7.1 --hash=sha256:... lists or judges PyJWT at 1.7.1", async () => {
    const r = await brief("pip install PyJWT==1.7.1 --hash=sha256:a3b52a3e8b8e4e5f1e8a1f0d4c2b9a6e7d8c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1");
    const listed = (r.check_these?.arguments.items ?? []).find((i: { package: string }) => i.package.toLowerCase() === "pyjwt");
    const judged = (r.requested_versions ?? []).find((v: { name: string }) => v.name.toLowerCase() === "pyjwt");
    expect(listed?.to ?? judged?.to).toBe("1.7.1");
    expect(JSON.stringify(r.withheld_from_task ?? [])).not.toMatch(/pyjwt/i);
  });
});
