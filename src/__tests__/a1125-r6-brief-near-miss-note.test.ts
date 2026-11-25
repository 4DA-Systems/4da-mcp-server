// SPDX-License-Identifier: Apache-2.0
/**
 * Fourth blind check of the 2026-11-25 fixes, item 4: an offline near-miss was a hold (human_only, "a human
 * decides once it has"), and a name itself on a bundled popular list could be one. Now a name on any
 * bundled list is never a near-miss; any other near-miss is listed in unverified_words with the note "one
 * edit from <popular name>: check the spelling", the task review_needed with the NOT ASSESSED reason. A
 * known-malicious bundled name is still looked up and human_only. Stubbed fetch.
 */

import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { knownPublicName, offlineNearMiss } from "../tools/briefing-task-screen.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import { POPULAR_PYPI } from "../live/popular-pypi.js";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("a name on a bundled list is never a near-miss", () => {
  it("in any ecosystem: every bundled npm and PyPI name", () => {
    const listed = [...POPULAR_NPM, ...POPULAR_PYPI].map((n) => (typeof n === "string" ? n : (n as { name: string }).name));
    for (const name of listed) {
      expect(offlineNearMiss(name, "npm"), name).toBeNull();
      expect(offlineNearMiss(name, "PyPI"), name).toBeNull();
    }
  });

  it("the fourth reviewer's 213 popular names", () => {
    const tasks = [
      ...(JSON.parse(readFileSync("C:/4da-wt/fix-1125/review-pass4/pop-npm.json", "utf8")) as string[]),
      ...(JSON.parse(readFileSync("C:/4da-wt/fix-1125/review-pass4/pop-py.json", "utf8")) as string[]),
    ];
    expect(tasks).toHaveLength(213);
    for (const t of tasks) {
      const [manager, , name] = t.split(" ");
      const eco = manager === "pip" ? "PyPI" : "npm";
      if (knownPublicName(name, eco)) expect(offlineNearMiss(name, eco), t).toBeNull();
    }
  });
});

describe("any other near-miss is a note, not a hold", () => {
  it.each([
    ["npm install lodahs", "lodahs", "lodash"],
    ["add lodahs", "lodahs", "lodash"],
    ["npm install electorn", "electorn", "electron"],
    ["pip install reqeusts", "reqeusts", "requests"],
  ])("%s", async (task, word, of) => {
    const r = await brief(task);
    expect(r.unverified_words).toMatchObject([{ word, note: `one edit from ${of}: check the spelling` }]);
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toMatch(/^NOT ASSESSED: /);
    expect(r.delegation_assessment.reason).not.toContain("a human decides once it has");
    expect(r.new_packages).toBeUndefined();
    expect(h.requests.some((u) => u.includes(word))).toBe(false);
  });

  it("a known-malicious bundled name is still looked up and human_only", async () => {
    h.NPM = { crossenv: { latest: "6.1.1", versions: { "6.1.1": {} } } };
    h.ADVISORIES = { crossenv: [adv("MAL-2017-1", "crossenv", [{ introduced: "0" }], "npm", "CRITICAL")] };
    const r = await brief("npm install crossenv");
    expect(h.requests.some((u) => u.includes("crossenv"))).toBe(true);
    expect(r.unverified_words).toBeUndefined();
    expect(r.delegation_assessment.level).toBe("human_only");
  });
});
