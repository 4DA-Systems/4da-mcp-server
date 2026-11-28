// SPDX-License-Identifier: Apache-2.0
/**
 * Round 18: the sixteenth independent check (review-confirm16). N1 the copy on disk the drift check reads, and what an
 * answer about malware says (E2-E5); N2 TASK_FOLDED by a generated differential; N4 no unchecked-word or
 * nothing-confirmed sentence where it is false; N5 DISMISSED_KNOWN; N6 a task names an installed package by the fold;
 * N7 lockfiles the scan did not read; N8 one sentence per installed copy.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { BLANKS, executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { DISMISSED_KNOWN, NOT_SCANNED_LOCKFILES, TASK_FOLDED } from "../tools/briefing-confirm.js";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { brokenTextRules } from "./helpers/a1137-text-rules.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM.zod = { latest: "3.24.1", versions: { "3.24.1": {} } };
  h.NPM.hono = { latest: "4.6.14", versions: { "4.6.14": {} } };
  h.NPM.lodash = { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } };
  h.NPM.uaparserjsq = { latest: "0.7.29", versions: { "0.7.28": {}, "0.7.29": {} } };
  h.ADVISORIES.uaparserjsq = [adv("MAL-2026-91001", "uaparserjsq", [{ introduced: "0" }, { fixed: "0.7.29" }], "npm", "CRITICAL")];
  h.ADVISORIES.lodash = [adv("GHSA-aaaa-0000-0001", "lodash", [{ introduced: "0" }, { fixed: "4.17.21" }], "npm", "HIGH"), adv("GHSA-aaaa-0000-0002", "lodash", [{ introduced: "0" }, { fixed: "4.17.21" }], "npm", "HIGH")];
});
afterEach(() => h.dispose());
const brief = async (args: Record<string, unknown>) => (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, await h.live())) as Record<string, any>;
const driftProject = () => {
  h.npmProject({ zod: "3.24.1", uaparserjsq: "0.7.29" }, {}, { zod: { version: "3.24.1" }, uaparserjsq: { version: "0.7.29" } });
  h.write("node_modules/uaparserjsq/package.json", JSON.stringify({ name: "uaparserjsq", version: "0.7.28" }));
  h.write("node_modules/zod/package.json", JSON.stringify({ name: "zod", version: "3.24.1" }));
};

describe("N1: the copy on disk of a direct dependency, and what an answer about malware says", () => {
  it("a task naming the drifted malware: human_only; the copy on disk is the installed one (E2); no reinstall-is-the-whole-fix (E3), no vulnerability-to-accept (E4), no Delegate-then-review (E5)", async () => {
    driftProject();
    const args = { task: "Refactor how we use uaparserjsq in the user-agent helper.", packages: [] };
    const r = await brief(args);
    expect(r.delegation_assessment.level).toBe("human_only");
    const dep = (r.task_dependencies as Array<Record<string, any>>).find((d) => d.package === "uaparserjsq")!;
    expect(dep.installed).toEqual(["0.7.28"]);
    const text = JSON.stringify(r);
    expect(text).not.toMatch(/the reinstall is the whole fix|accepting the risk|Delegate, then review/);
    expect(JSON.stringify(r.advisories)).toMatch(/recorded as malware/);
    expect(brokenTextRules(r, args)).toEqual([]);
  });
  it("an unrelated task on the same project: human_only, and no Delegate-then-review", async () => {
    driftProject();
    const r = await brief({ task: "Fix the typo in the README.", packages: [] });
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason).not.toMatch(/Delegate, then review|nothing version-confirmed/);
  });
});

describe("N2: TASK_FOLDED is said exactly where the field differs from the task in more than BLANKS (generated)", () => {
  it("over generated tasks: task_note iff the field and the input differ once BLANKS are removed", async () => {
    h.npmProject({ hono: "4.6.14" }, {}, { hono: { version: "4.6.14" } });
    const live = await h.live();
    const pieces = ["npm", " ", "  ", "\t", "\r", "\r\n", "\n", "\u0085", " ", " ", " ", "​", "﻿", "ｈ", "%41", "%1B", "**", "__", "<code>", "a", "hono", "‐", "⧸", "\\\n", "x"];
    let seed = 18;
    const rnd = () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32;
    const strip = (t: string) => t.replace(BLANKS, "");
    let folded = 0;
    for (let n = 0; n < 150; n++) {
      let task = "install hono";
      for (let k = 0; k < 1 + Math.floor(rnd() * 6); k++) task += pieces[Math.floor(rnd() * pieces.length)];
      const r = (await executeWhatShouldIKnow(null, { task, packages: [], project_path: h.dir } as never, live)) as Record<string, any>;
      const differs = strip(String(r.task)) !== strip(task);
      expect(r.task_note === TASK_FOLDED, JSON.stringify(task)).toBe(differs);
      if (differs) folded++;
    }
    expect(folded).toBeGreaterThan(20);
  }, 120_000);
});

describe("N4: no sentence where it is false", () => {
  it.each([
    ["a 1,999-character word", `Refactor the config loader ${"q".repeat(1999)} module.`],
    ["a word with a shell expansion", "Refactor the $(cat list) loader."],
  ])("%s: a safe answer's summary does not say NOT CHECKED words", async (_l, task) => {
    h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
    const r = await brief({ task, packages: [] });
    if (r.delegation_assessment.level === "safe_to_delegate") expect(r.summary).not.toMatch(/NOT CHECKED: \d+ words? in the task/);
    expect(brokenTextRules(r, { task, packages: [] })).toEqual([]);
  });
  it("a dismissed name on the bundled malicious list: human_only without the nothing-confirmed sentence", async () => {
    h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
    const args = { task: "npm install crossenv@1.0.0", packages: [], not_packages: ["crossenv"] };
    const r = await brief(args);
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason).not.toMatch(/nothing version-confirmed/);
    expect(brokenTextRules(r, args)).toEqual([]);
  });
});

describe("N5: DISMISSED_KNOWN", () => {
  it("npm install lodash@1.2.3 with lodash dismissed, lodash not installed: the reason says DISMISSED_KNOWN, never safe", async () => {
    h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
    const r = await brief({ task: "npm install lodash@1.2.3", packages: [], not_packages: ["lodash"] });
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(r.delegation_assessment.reason.toLowerCase()).toContain(DISMISSED_KNOWN("lodash").toLowerCase());
  });
});

describe("N6: a task names an installed package by the fold (generated over the spellings the fold equates)", () => {
  it.each(["qzv-data-kit", "qzv_data_kit", "QZV_DATA_KIT", "qzv.data.kit", "Qzv-Data_Kit", "qzv__data--kit"])("PyPI installed qzv-data-kit, the task says %s: touched", async (spelling) => {
    h.PYPI["qzv-data-kit"] = { "1.0.0": {}, "1.0.1": {} };
    h.ADVISORIES["qzv-data-kit"] = [adv("GHSA-qzvd-0000-0001", "qzv-data-kit", [{ introduced: "0" }, { fixed: "1.0.1" }], "PyPI", "HIGH")];
    h.write("requirements.txt", "qzv-data-kit==1.0.0\n");
    const r = await brief({ task: `Refactor how we call ${spelling} in the loader.`, packages: [] });
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(JSON.stringify(r.advisories)).not.toContain("Not about this task");
  });
  it.each(["golang.org/x/text", "golang.org/x/text/language", "golang.org/x/text/encoding/unicode"])("Go installed golang.org/x/text, the task says %s: touched", async (spelling) => {
    h.GO["golang.org/x/text"] = ["v0.3.5", "v0.3.8"];
    h.GOMOD["golang.org/x/text@v0.3.5"] = "1.21";
    h.ADVISORIES["golang.org/x/text"] = [adv("GHSA-gotx-0000-0001", "golang.org/x/text", [{ introduced: "0" }, { fixed: "0.3.8" }], "Go", "HIGH")];
    h.write("go.mod", "module example.com/svc\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.5\n");
    h.write("go.sum", "golang.org/x/text v0.3.5 h1:x=\ngolang.org/x/text v0.3.5/go.mod h1:y=\n");
    const r = await brief({ task: `Use ${spelling} for the parser.`, packages: [] });
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(JSON.stringify(r.advisories)).not.toContain("Not about this task");
  });
});

describe("N7: lockfiles the scan found and did not read", () => {
  it("a lockfile under a test-fixture folder: a ready scan says so in the safe reason", async () => {
    h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
    h.write("test/fixtures/old/package.json", JSON.stringify({ name: "old", version: "1.0.0", dependencies: { lodash: "4.17.20" } }));
    h.write("test/fixtures/old/package-lock.json", JSON.stringify({ name: "old", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "old", version: "1.0.0", dependencies: { lodash: "4.17.20" } }, "node_modules/lodash": { version: "4.17.20" } } }));
    const args = { task: "Fix the typo in the README.", packages: [] };
    const r = await brief(args);
    expect(r.lockfiles_not_scanned).toBeGreaterThan(0);
    if (r.delegation_assessment.level === "safe_to_delegate") expect(r.delegation_assessment.reason).toContain(NOT_SCANNED_LOCKFILES(r.lockfiles_not_scanned));
    expect(brokenTextRules(r, args)).toEqual([]);
  });
});

describe("N8: one sentence per installed copy, listing its advisories", () => {
  it("declared lodash, installed 4.17.20 with two advisories: one sentence naming both ids", async () => {
    h.npmProject({ zod: "3.24.1", lodash: "4.17.20" }, {}, { zod: { version: "3.24.1" }, lodash: { version: "4.17.20" } });
    const r = await brief({ task: "Bump the utility library to the patched release.", packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.21", public: true }] });
    const reason = String(r.delegation_assessment.reason);
    expect(reason.match(/the installed lodash 4\.17\.20 has/g)?.length).toBe(1);
    expect(reason).toContain("the installed lodash 4.17.20 has 2 confirmed vulnerabilities (GHSA-aaaa-0000-0001, GHSA-aaaa-0000-0002)");
  });
});
