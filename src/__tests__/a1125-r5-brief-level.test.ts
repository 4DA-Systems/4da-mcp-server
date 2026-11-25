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

describe("a near-miss judged offline is noted, never held (fourth blind check, item 4)", () => {
  it.each(["npm install lodahs", "add lodahs", "npm install electorn", "npm install babelcli", "npm install mongose", "npm install nodesass"])("%s", async (task) => {
    const r = await brief(task);
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toMatch(/^NOT ASSESSED: /);
    expect(r.delegation_assessment.reason).not.toContain("a human decides once it has");
    expect(r.unverified_words.find((w: { word: string }) => w.word === task.split(" ").pop()).note).toMatch(/^one edit from [\w.-]+: check the spelling$/);
    expect((r.unverified_words ?? []).map((w: { word: string }) => w.word)).toContain(task.split(" ").pop());
  });
});

describe("unchecked names: review_needed, led by NOT ASSESSED, never 'delegate'", () => {
  it.each(["npm install qzflux", "add qzflux to the project", "cargo add tokio@1.8.0"])("%s", async (task) => {
    const r = await brief(task);
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toMatch(/^NOT ASSESSED: 1 name the task may mean as packages was not looked up by this briefing \(it looks up only packages this project already uses and well-known names\)\. Before writing any of them, call dependency_check for the ones that are public packages you mean to add; if it answers avoid or names malware, this task is human_only\./);
    expect(r.delegation_assessment.reason).not.toContain("Delegate, then review");
  });
});

describe("a pip --hash value is no credential", () => {
  it("pip install PyJWT==1.7.1 --hash=sha256:... lists or judges PyJWT at 1.7.1", async () => {
    const r = await brief("pip install PyJWT==1.7.1 --hash=sha256:a3b52a3e8b8e4e5f1e8a1f0d4c2b9a6e7d8c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1");
    const listed = (r.unverified_words ?? []).find((i: { word: string }) => i.word.toLowerCase() === "pyjwt");
    const judged = (r.requested_versions ?? []).find((v: { name: string }) => v.name.toLowerCase() === "pyjwt");
    expect(listed?.version?.replace(/^==/, "") ?? judged?.to).toBe("1.7.1");
    expect(JSON.stringify(r.withheld_from_task ?? [])).not.toMatch(/pyjwt/i);
  });
});
