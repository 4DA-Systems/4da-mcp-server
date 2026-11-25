// SPDX-License-Identifier: Apache-2.0
/**
 * Wave 2, two additions to package confirmation (lead, 2026-11-27, from the real-agent evaluation):
 * 1. A dismissal never makes the briefing reassuring about a name that stands where a package stands: a
 *    candidate read as an install command's operand or a manifest entry, or one with a near-miss hint, that
 *    the caller puts in not_packages is listed under dismissed, and the level is at least review_needed,
 *    naming it. `npm install lodahs` answered with lodash public and lodahs dismissed ended safe_to_delegate.
 * 2. A call that declares no package and leaves nothing waiting says, in task_packages.note and in a
 *    safe_to_delegate reason, that the reader reads names only in the plain forms.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { UNDECLARED_NOTE } from "../tools/briefing-confirm.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
  h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.21": {} } } };
});
afterEach(() => h.dispose());

async function brief(task: string, more: Record<string, unknown> = {}): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir, ...more } as never, await h.live())) as Record<string, any>;
}

describe("a dismissed name that stands where a package stands keeps the task at review_needed at least", () => {
  it.each([
    ["npm install lodahs", "lodahs", "in the task's command"],
    ['add "zqxthing": "1.0.0" to package.json', "zqxthing", "in a manifest entry of the task"],
    ["add lodahs to the helpers", "lodahs", "one edit from lodash"],
  ])("%s", async (task, word, where) => {
    const r = await brief(task, { packages: [{ ecosystem: "npm", name: "lodash", public: true }], not_packages: [word] });
    expect(r.task_packages.dismissed).toEqual([word]);
    expect(r.task_packages.to_confirm).toEqual([]);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(r.delegation_assessment.reason).toContain(`ou said ${word} is not a package`);
    expect(r.delegation_assessment.reason).toContain(where);
    expect(r.delegation_assessment.reason).toContain("make sure nothing installs it");
  });

  it("a word read only after an adding verb in prose can be dismissed without that", async () => {
    const r = await brief("add zqxcandidate", { not_packages: ["zqxcandidate"] });
    expect(r.task_packages.dismissed).toEqual(["zqxcandidate"]);
    expect(r.delegation_assessment.reason).not.toContain("make sure nothing installs it");
  });
});

describe("a call that declares nothing says the reader reads plain forms only", () => {
  it("complete with no packages argument: the note, and the safe reason's clause", async () => {
    const r = await brief("refactor the logging setup");
    expect(r.task_packages.status).toBe("complete");
    expect(r.task_packages.note).toBe(UNDECLARED_NOTE);
    if (r.delegation_assessment.level === "safe_to_delegate") expect(r.delegation_assessment.reason).toContain(UNDECLARED_NOTE);
  });

  it("no note when packages were declared, or while names wait", async () => {
    expect((await brief("refactor the logging setup", { packages: [] })).task_packages.note).toBeUndefined();
    expect((await brief("add zqxcandidate")).task_packages.note).toBeUndefined();
  });
});
