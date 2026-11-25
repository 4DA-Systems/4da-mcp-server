// SPDX-License-Identifier: Apache-2.0
/**
 * Third blind check of the 2026-11-25 fixes, item 4: in a project of four ecosystems, a name decided in one
 * (a dependency there, or a bundled-list name there) was also listed in the others: 33 of 190 ordinary
 * tasks became review_needed only for that, and following the list judged the wrong registry ("use
 * crossenv" -> PyPI's crossenv 1.6.2, proceed). A name is read in several ecosystems only when nothing
 * decides. Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.npmProject({ minimist: "1.2.5", react: "18.2.0" }, {}, { minimist: { version: "1.2.5" }, react: { version: "18.2.0" } });
  h.write("requirements.txt", "requests==2.31.0\nflask==2.3.3\n");
  h.write("Cargo.toml", '[package]\nname = "poly"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = "1.0.190"\n');
  h.write("go.mod", "module example.com/poly\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.5\n");
  h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.21": {} } }, crossenv: { latest: "6.1.1", versions: { "6.1.1": {} } }, express: { latest: "4.21.2", versions: { "4.21.2": {}, "5.0.0": {} } } };
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("a name decided in one ecosystem is not listed in the others", () => {
  it.each(["use crossenv", "add express", "upgrade express to 5", "add the lodash package"])("%s", async (task) => {
    const r = await brief(task);
    expect(r.unverified_words).toBeUndefined();
    expect(h.requests.some((u) => /pypi\.org\/pypi\/(?:crossenv|express|lodash)\/|index\.crates\.io\/.*(?:crossenv|express|lodash)/.test(u))).toBe(false);
  });

  it("a name nothing decides is read in every ecosystem the project uses", async () => {
    const r = await brief("add qzframe");
    expect(r.unverified_words).toEqual([{ word: "qzframe", read_as: "npm or PyPI or crates.io" }]);
  });
});
