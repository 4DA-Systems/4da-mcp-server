// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25: the words what_should_i_know withholds from a task before reading it (a
 * credential shape, a package the task's own command takes from a private registry, git or a path,
 * an over-long word) were listed as "NOT CHECKED: N more package(s) named in the task", which they
 * are not. They are now `withheld_from_task` (how each is shown and why) with their own sentence;
 * the delegation level stays review_needed. Genuinely further packages keep "more packages".
 * Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
const PROXY_VARS = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of PROXY_VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  h = createHarness();
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
  h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.21": {} } }, express: { latest: "4.21.2", versions: { "4.21.2": {} } } };
});
afterEach(() => {
  h.dispose();
  for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
});

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("words withheld from the task", () => {
  it.each([
    ["Add ghp_ZQXTOK0123456789abcdefABCDEF012345 as the GH_TOKEN secret", "ghp_... (38 characters)", /credential/],
    ["Run npm install --registry https://npm.zqxcorp.internal zqx-cli-tool", "zqx-cli-tool", /not looked up/],
    ["cargo add zqx-cargo-path --path ../zqx-cargo-path", "zqx-cargo-path", /not looked up/],
    [`add ${"a".repeat(400)} to the deps`, "a word of 400 characters", /longer than any package name/],
  ])("%s: its own field and sentence, never 'more packages'", async (task, shown, reason) => {
    const r = await brief(task);
    expect(r.withheld_from_task).toEqual(expect.arrayContaining([expect.objectContaining({ shown, reason: expect.stringMatching(reason) })]));
    expect(r.summary).toMatch(/NOT CHECKED: \d+ words? in the task (was|were) not looked up \(/);
    expect(r.summary).toMatch(/nothing about (it|them) was sent\./);
    expect(r.summary).toContain(shown);
    expect(r.summary).not.toMatch(/more packages? named in the task/);
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toMatch(/not looked up/);
  });

  it("a plain task has no withheld_from_task", async () => {
    const r = await brief("add express");
    expect(r.withheld_from_task).toBeUndefined();
    expect(r.summary).not.toMatch(/words? in the task (was|were) not looked up/);
  });

  it("a package installed by a manager this server does not read is still 'more packages'", async () => {
    const r = await brief("gem install rails");
    expect(r.summary).toMatch(/NOT CHECKED: 1 more package named in the task \(rails/);
    expect(r.withheld_from_task).toBeUndefined();
  });
});
