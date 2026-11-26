// SPDX-License-Identifier: Apache-2.0
/**
 * Wave 2, two additions to package confirmation (lead, 2026-11-27, from the real-agent evaluation):
 * 1. A dismissal never makes the briefing reassuring about a name that stands where a package stands: a
 *    candidate read as an install command's operand or a manifest entry, or one with a near-miss hint, that
 *    the caller puts in not_packages is listed under dismissed, and the level is at least review_needed,
 *    naming it. `npm install lodahs` answered with lodash public and lodahs dismissed ended safe_to_delegate.
 * 2. (Superseded by change A: a call that declares no package never ends complete; and change B: not_read
 *    weighs only what stands where a package stands.)
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { DECLARE_STEP } from "../tools/briefing-confirm.js";
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

describe("safe_to_delegate needs a declaration (wave 2, change A)", () => {
  it.each(["refactor the logging setup", "Set up msw so the frontend tests can mock the API", "Move the HTTP server to fastify 5"])("%s: a bare call is never complete", async (task) => {
    const r = await brief(task);
    expect(r.task_packages.status).toBe("confirmation_needed");
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    if (r.task_packages.to_confirm.length === 0) {
      expect(r.task_packages.next_step).toBe(DECLARE_STEP);
      expect(r.delegation_assessment.level).toBe("confirmation_needed");
      expect(r.delegation_assessment.reason).toContain("This call declared no packages");
    }
  });

  it("packages: [] is a declaration: complete, and the reason says what it rests on", async () => {
    const r = await brief("refactor the logging setup", { packages: [] });
    expect(r.task_packages.status).toBe("complete");
    expect(r.task_packages.next_step).toBeUndefined();
    expect(r.delegation_assessment.reason).toContain("You declared that the task adds or changes no package.");
  });

  it("a declaration of packages says how many it rests on", async () => {
    const r = await brief("add lodash", { packages: [{ ecosystem: "npm", name: "lodash", public: true }] });
    expect(r.task_packages.status).toBe("complete");
    expect(r.delegation_assessment.reason).toContain("You declared 1 package.");
  });
});

describe("not_read weighs only what stands where a package stands (wave 2, change B)", () => {
  it("an environment assignment of a credential is listed and does not weigh", async () => {
    const token = ["np", "m_", "ZQXabcdefghijklmnopqrstuvwxyz0123"].join("");
    const r = await brief(`Set NPM_TOKEN=${token} in the CI config, then npm install lodash`, { packages: [{ ecosystem: "npm", name: "lodash", public: true }] });
    expect(r.task_packages.not_read).toEqual([expect.objectContaining({ shown: "a setting named NPM_TOKEN" })]);
    // The level rests on lodash's own verdict; the setting is not in the reason.
    expect(r.delegation_assessment.reason).not.toMatch(/NPM_TOKEN|not_read|check it with your own registry/);
  });

  it("an option value in an install command keeps review_needed", async () => {
    const r = await brief("npm install lodash --_authToken zqxa1", { packages: [{ ecosystem: "npm", name: "lodash", public: true }] });
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toContain("if one is a package after all, call dependency_check on it");
  });

  it("a withheld value the caller lists in not_packages moves to dismissed, shown without its value", async () => {
    const uuid = "98e62aac-d9e2-44a1-946d-1fbf082c44aa";
    const r = await brief(`npm install ${uuid}`, { packages: [], not_packages: [uuid] });
    expect(r.task_packages.not_read).toEqual([]);
    expect(r.task_packages.dismissed.join(" ")).not.toContain("98e62aac-d9e2");
    expect(r.task_packages.dismissed.length).toBe(1);
    // It stood as the command's operand: dismissed, and the level stays review_needed.
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toContain("make sure nothing installs it");
  });
});
