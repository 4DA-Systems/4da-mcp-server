// SPDX-License-Identifier: Apache-2.0
/**
 * Sixth blind check of the 2026-11-25 fixes, item 1: a backtick is markdown, not shell. A code span that
 * touched punctuation (`**`x@1.2.5`**`, `` `x`@1.2.5 ``, `` `a`,`b` ``, a markdown link) was held whole as "a word
 * with a shell expansion in it", and the package and its version were lost. Only `$NAME`, `${`, `$(` and
 * `%NAME%` make a word an expansion now, and a code span touching other text loses its backticks.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.npmProject({ minimist: "1.2.8" }, {}, { minimist: { version: "1.2.8" } });
  h.NPM = { minimist: { latest: "1.2.8", versions: { "1.2.5": {}, "1.2.8": {} } } };
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("a code span is read as ordinary text", () => {
  it.each([
    "install **`minimist@1.2.5`** for argv parsing",
    "npm install `minimist@1.2.5`,`lodash@4.17.20`",
    "add `minimist@1.2.5`/`yargs` to the cli",
    "pin `minimist`@1.2.5 in the cli",
    "use `minimist@1.2.5`-based parsing",
    "add `minimist@1.2.5`—it is tiny",
    "add [`minimist@1.2.5`](https://www.npmjs.com/package/minimist) to the cli",
    "add `minimist@1.2.5` to the cli",
  ])("%s: minimist at 1.2.5", async (task) => {
    const r = await brief(task);
    expect(r.requested_versions).toContainEqual(expect.objectContaining({ name: "minimist", to: "1.2.5" }));
    expect(JSON.stringify(r.withheld_from_task ?? [])).not.toContain("shell expansion");
  });

  it("an expansion is still one: $NAME, ${, $( and %NAME%", async () => {
    for (const task of ["npm install $ZQX1", "npm install ${ZQX2}", "npm install $(cat zqx3)", "npm install %ZQX4%"]) {
      const r = await brief(task);
      expect(JSON.stringify(r.withheld_from_task ?? [])).toContain("shell expansion");
    }
  });
});
