// SPDX-License-Identifier: Apache-2.0
/**
 * Fifth blind check of the 2026-11-25 fixes, item 4: a manager or language word in prose selected another
 * ecosystem's bundled list: "the python side should use ctx" in an npm-only project looked PyPI's ctx up,
 * as did "like pip does, add django" and "in the rust service add rustdecimal". Only the project's own
 * ecosystems, a command with operands or a manifest file the task names decide one; the name is listed.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { waitingWords } from "./helpers/a1127-task-packages.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("a prose language or manager word decides no ecosystem", () => {
  it.each([
    ["the python side should use ctx", "ctx"],
    ["like pip does, add django", "django"],
    ["in the rust service add rustdecimal", "rustdecimal"],
  ])("%s: %s is listed, not looked up", async (task, name) => {
    const r = await brief(task);
    expect(h.requests.filter((u) => u.includes(name))).toEqual([]);
    expect((waitingWords(r) ?? []).map((w: { word: string }) => w.word)).toContain(name);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  it.each([
    ["pip install ctx", "pypi.org/pypi/ctx/"],
    ["add ctx to requirements.txt", "pypi.org/pypi/ctx/"],
    ["cargo add rustdecimal", "crates.io"],
  ])("%s: a command or a manifest file decides it", async (task, url) => {
    await brief(task);
    expect(h.requests.some((u) => u.includes(url))).toBe(true);
  });
});
