// SPDX-License-Identifier: Apache-2.0
/**
 * Fourth blind check of the 2026-11-25 fixes, item 3 (a new false clean): in an npm-only project a name
 * on ANOTHER ecosystem's bundled list was judged only there and vanished: "use loguru instead of the
 * logging module", "use pydantic v2", "add fastapi and uvicorn", "use pyjwt" answered safe_to_delegate
 * with nothing listed, where 6.5.1 said human_only (npm took loguru down as malware). A bundled-list
 * match counts only for an ecosystem the project uses or the task's own manager names; otherwise the
 * name is listed in task_packages.to_confirm for the project's ecosystem, and the task is not safe. Stubbed fetch.
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

describe("another ecosystem's bundled list is no evidence in an npm-only project", () => {
  it.each([
    ["use loguru instead of the logging module", ["loguru"]],
    ["use pydantic v2 for the settings", ["pydantic"]],
    ["add fastapi and uvicorn", ["fastapi", "uvicorn"]],
    ["use pyjwt to verify the tokens", ["pyjwt"]],
    ["bring in rustdecimal", ["rustdecimal"]],
  ])("%s", async (task, words) => {
    const r = await brief(task);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect((waitingWords(r) ?? []).map((w: { word: string; read_as: string }) => `${w.word}/${w.read_as}`)).toEqual(words.map((w) => `${w}/npm`));
    expect(h.requests.some((u) => /pypi\.org|crates\.io/.test(u) && words.some((w) => u.includes(w)))).toBe(false);
  });

  it("the task's own manager decides: pip install loguru is judged on PyPI", async () => {
    h.PYPI = { loguru: { "0.7.2": {} } };
    await brief("pip install loguru");
    expect(h.requests.some((u) => u.includes("pypi.org/pypi/loguru/"))).toBe(true);
  });
});
