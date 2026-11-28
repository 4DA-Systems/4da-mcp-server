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
import { waitingWords, notReadWords } from "./helpers/a1127-task-packages.js";

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
    expect(r.delegation_assessment.level).toBe("confirmation_needed");
    expect(r.delegation_assessment.reason).toMatch(/^1 name the task may mean as packages waits for your confirmation/);
    expect(r.delegation_assessment.reason).not.toContain("a human decides once it has");
    expect(waitingWords(r)?.find((w: { word: string }) => w.word === task.split(" ").pop())?.hint).toMatch(/^one edit from [\w.-]+: if you mean /);
    expect((waitingWords(r) ?? []).map((w: { word: string }) => w.word)).toContain(task.split(" ").pop());
  });
});

describe("unchecked names: confirmation_needed (wave 2), never 'delegate'", () => {
  it.each(["npm install qzflux", "add qzflux to the project", "cargo add tokio@1.8.0"])("%s", async (task) => {
    const r = await brief(task);
    expect(r.delegation_assessment.level).toBe("confirmation_needed");
    expect(r.delegation_assessment.reason).toMatch(/^1 name the task may mean as packages waits for your confirmation \(task_packages\.to_confirm\): do task_packages\.next_step; the level follows from the answers\./);
    expect(r.delegation_assessment.reason).not.toContain("Delegate, then review");
  });
});

describe("a pip --hash value is no credential", () => {
  // Round 8, m10: `--hash` is no option of pip's command line (a requirements-file option): the command is not read
  // whole, nothing of it is offered or looked up, and the hash is never treated as a credential.
  it("pip install PyJWT==1.7.1 --hash=sha256:... is not read whole; the hash is no credential", async () => {
    const r = await brief("pip install PyJWT==1.7.1 --hash=sha256:a3b52a3e8b8e4e5f1e8a1f0d4c2b9a6e7d8c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1");
    expect(r.delegation_assessment.reason).toMatch(/could not read whole/);
    expect(JSON.stringify(notReadWords(r) ?? [])).not.toMatch(/pyjwt/i);
  });
});
