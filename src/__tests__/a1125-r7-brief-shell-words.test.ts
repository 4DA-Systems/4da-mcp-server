// SPDX-License-Identifier: Apache-2.0
/**
 * Fifth blind check of the 2026-11-25 fixes, item 3: `npm install lodash P4ss$w0rdzqx` showed the two
 * halves in two lists, and `${zqxsecret99}` was shown as `${zqxsecret99`. A word with `$NAME`, `${`, `$(` or `%NAME%`
 * in it is withheld whole (a backtick is markdown: sixth blind check, item 1) and shown only as "a word with a shell expansion in it". Stubbed fetch.
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

describe("a word with a shell expansion in it is withheld whole", () => {
  it.each([
    ["npm install lodash P4ss$w0rdzqx", /P4ss|w0rdzqx/],
    ["npm install ${zqxsecret99}", /zqxsecret99/],
    ["npm install %ZQX_SECRET224%", /ZQX_SECRET224/i],
    ["npm install $(cat zqxfile226)", /zqxfile226/],
  ])("%s", async (task, secret) => {
    const r = await brief(task);
    expect(JSON.stringify({ ...r, task: undefined })).not.toMatch(secret);
    expect(r.withheld_from_task).toContainEqual(expect.objectContaining({ shown: "a word with a shell expansion in it" }));
    expect(h.requests.some((u) => secret.test(decodeURIComponent(u)))).toBe(false);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  it.each(["make the page 50% faster", "it costs $5 a month", "run `npm test` first"])("%s: no expansion", async (task) => {
    const r = await brief(task);
    expect(JSON.stringify(r.withheld_from_task ?? [])).not.toContain("shell expansion");
  });
});
