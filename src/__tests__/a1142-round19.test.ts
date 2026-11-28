// SPDX-License-Identifier: Apache-2.0
/**
 * Round 19: the seventeenth independent check (review-confirm17). Q1 the drift check reads shrinkwrap folders, optional
 * and peer direct dependencies, and an alias's own folder; Q2 lockfiles found and not read, counted by reason (an
 * incomplete scan is never safe); Q3 the task field is never rewritten by the directory escape; M2-M5.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow, readingCopy } from "../tools/what-should-i-know.js";
import { NOT_SCANNED_LOCKFILES, PRIVATE_INSTALLED, SCAN_INCOMPLETE } from "../tools/briefing-confirm.js";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { brokenTextRules } from "./helpers/a1137-text-rules.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM.zod = { latest: "3.24.1", versions: { "3.24.1": {} } };
  h.NPM.lodash = { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } };
  h.NPM.ky = { latest: "1.7.4", versions: { "1.7.4": {} } };
  h.NPM.uaparserjsq = { latest: "0.7.29", versions: { "0.7.28": {}, "0.7.29": {} } };
  h.NPM["qzx-cart-kit"] = { latest: "1.0.2", versions: { "1.0.1": {}, "1.0.2": {} } };
  h.ADVISORIES.uaparserjsq = [adv("MAL-2026-91001", "uaparserjsq", [{ introduced: "0" }, { fixed: "0.7.29" }], "npm", "CRITICAL")];
  h.ADVISORIES["qzx-cart-kit"] = [adv("MAL-2026-91077", "qzx-cart-kit", [{ introduced: "0" }, { fixed: "1.0.2" }], "npm", "CRITICAL")];
  h.ADVISORIES.lodash = [adv("GHSA-aaaa-0000-0001", "lodash", [{ introduced: "0" }, { fixed: "4.17.21" }], "npm", "HIGH")];
});
afterEach(() => h.dispose());
const brief = async (args: Record<string, unknown>, live?: unknown) => (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, (live ?? (await h.live())) as never)) as Record<string, any>;
const lock = (root: Record<string, unknown>, entries: Record<string, Record<string, unknown>>) => JSON.stringify({ name: "svc", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": root, ...entries } });

describe("Q1: the drift check reads more direct dependencies (best effort)", () => {
  const disk = (key: string, name: string, version: string) => h.write(`node_modules/${key}/package.json`, JSON.stringify({ name, version }));
  it.each([
    ["npm-shrinkwrap.json", "dependencies"],
    ["package-lock.json", "optionalDependencies"],
    ["package-lock.json", "peerDependencies"],
  ])("%s with the malware copy on disk as a direct %s: human_only", async (file, section) => {
    const root = { name: "svc", version: "1.0.0", dependencies: { zod: "3.24.1" }, ...(section === "dependencies" ? {} : { [section]: { uaparserjsq: "0.7.29" } }) };
    if (section === "dependencies") (root.dependencies as Record<string, string>).uaparserjsq = "0.7.29";
    h.write("package.json", JSON.stringify({ ...root, private: true }));
    h.write(file, lock(root, { "node_modules/zod": { version: "3.24.1" }, "node_modules/uaparserjsq": { version: "0.7.29", ...(section === "optionalDependencies" ? { optional: true } : section === "peerDependencies" ? { peer: true } : {}) } }));
    disk("zod", "zod", "3.24.1");
    disk("uaparserjsq", "uaparserjsq", "0.7.28");
    const r = await brief({ task: "Fix the typo in the README.", packages: [] });
    expect(r.delegation_assessment.level, r.delegation_assessment.reason).toBe("human_only");
    expect(r.delegation_assessment.reason).toMatch(/uaparserjsq@0\.7\.28 \(in node_modules of \.; the lockfile pins 0\.7\.29\) installed, which is recorded as malware/);
  });
  it("a direct dependency under an npm alias is read under its key", async () => {
    const root = { name: "svc", version: "1.0.0", dependencies: { zod: "3.24.1", cart: "npm:qzx-cart-kit@1.0.2" } };
    h.write("package.json", JSON.stringify({ ...root, private: true }));
    h.write("package-lock.json", lock(root, { "node_modules/zod": { version: "3.24.1" }, "node_modules/cart": { name: "qzx-cart-kit", version: "1.0.2" } }));
    disk("zod", "zod", "3.24.1");
    disk("cart", "qzx-cart-kit", "1.0.1");
    const r = await brief({ task: "Fix the typo in the README.", packages: [] });
    expect(r.delegation_assessment.level, r.delegation_assessment.reason).toBe("human_only");
  });
});

describe("Q2: lockfiles found and not read, by reason, every one counted (generated)", () => {
  const REASONS: Array<[string, string, boolean]> = [
    ["gitignored_directory", "under ignored, excluded or test-fixture folders", false],
    ["excluded_directory", "under ignored, excluded or test-fixture folders", false],
    ["depth", "deeper than the scan goes", true],
    ["project_limit", "past the project limit", true],
    ["symlink_outside_root", "behind a link outside the project", true],
    ["unreadable", "in a folder that could not be listed", true],
  ];
  it.each(REASONS.flatMap(([reason, words, incomplete]) => [1, 50, 51, 300].map((n) => [`${reason} x ${n}`, reason, words, incomplete, n] as const)))("%s", async (_l, reason, words, incomplete, n) => {
    h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
    const live = await h.live();
    const base = live.getDiscovery?.() ?? null;
    const discovery = { ...(base ?? {}), skipped: Array.from({ length: Math.min(n, 50) }, (_, i) => ({ path: `x${i}/package-lock.json`, reason })), skippedCount: n, skippedByReason: { [reason]: n } };
    const patched = Object.assign(Object.create(live), { getDiscovery: () => discovery });
    const args = { task: "Fix the typo in the README.", packages: [] };
    const r = await brief(args, patched);
    expect(r.lockfiles_not_scanned).toBe(n);
    // Ignored, excluded or fixture folders alone keep round 18's sentence; any other reason is said by count and reason.
    if (incomplete) expect(r.delegation_assessment.reason).toContain(`${n} ${words}`);
    else expect(r.delegation_assessment.reason).toContain(NOT_SCANNED_LOCKFILES(n));
    if (incomplete) {
      expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
      expect(r.delegation_assessment.reason).toContain(SCAN_INCOMPLETE);
    } else expect(r.delegation_assessment.level).toBe("safe_to_delegate");
    expect(brokenTextRules(r, args)).toEqual([]);
  });
  it("55 git-ignored lockfiles on disk are said as 55", async () => {
    h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
    h.write(".gitignore", "ignored/\n");
    for (let i = 0; i < 55; i++) {
      h.write(`ignored/p${i}/package.json`, JSON.stringify({ name: `p${i}`, version: "1.0.0" }));
      h.write(`ignored/p${i}/package-lock.json`, lock({ name: `p${i}`, version: "1.0.0" }, {}));
    }
    const r = await brief({ task: "Fix the typo in the README.", packages: [] });
    expect(r.lockfiles_not_scanned).toBe(55);
    if (r.delegation_assessment.level === "safe_to_delegate") expect(r.delegation_assessment.reason).toContain(NOT_SCANNED_LOCKFILES({ ignored: 55, depth: 0, projectLimit: 0, outside: 0, unreadable: 0 }));
  });
});

describe("Q3: the task field is the reading copy, never rewritten by the directory escape (generated over unsafe names)", () => {
  it.each(["web(1)", "a$b", "@tools", "x;y", "`tick`", "-dash", "a&b", "q'uote"])("a sub-folder named %j", async (dir) => {
    h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
    h.write(`${dir}/package.json`, JSON.stringify({ name: "sub", version: "1.0.0" }));
    h.write(`${dir}/package-lock.json`, lock({ name: "sub", version: "1.0.0" }, {}));
    const task = `Fix the README in ${dir}.`;
    const r = await brief({ task, packages: [] });
    expect(r.task).toBe(readingCopy(task));
    expect(r.task_note).toBeUndefined();
  });
});

describe("M2-M5", () => {
  it("M2/M3: a sub-project's malware is named with its folder, and not listed as 'Not about this task'", async () => {
    h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
    h.NPM.crossenvq = { latest: "1.0.1", versions: { "1.0.1": {} } };
    h.ADVISORIES.crossenvq = [adv("MAL-2026-91003", "crossenvq", [{ introduced: "0" }], "npm", "CRITICAL")];
    const sub = { name: "web", version: "1.0.0", dependencies: { crossenvq: "1.0.1" } };
    h.write("packages/web/package.json", JSON.stringify({ ...sub, private: true }));
    h.write("packages/web/package-lock.json", lock(sub, { "node_modules/crossenvq": { version: "1.0.1" } }));
    const r = await brief({ task: "Fix the typo in the README.", packages: [] });
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason).toContain("crossenvq@1.0.1 (in packages/web) installed");
    expect(JSON.stringify(r.advisories)).not.toMatch(/Not about this task[^"]*crossenvq/);
  });
  it("M4: the task names lodash and declares the fixed version: the installed-copy sentence is said", async () => {
    h.npmProject({ zod: "3.24.1", lodash: "4.17.20" }, {}, { zod: { version: "3.24.1" }, lodash: { version: "4.17.20" } });
    const r = await brief({ task: "Upgrade lodash to 4.17.21.", packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.21", public: true }] });
    expect(r.delegation_assessment.reason).toContain("the installed lodash 4.17.20 has a confirmed vulnerability (GHSA-aaaa-0000-0001); the declared lodash 4.17.21 was checked");
  });
  it("M5: an installed dependency private by configuration is said in a safe reason", async () => {
    process.env.FOURDA_PRIVATE_PACKAGES = "ky";
    try {
      h.npmProject({ zod: "3.24.1", ky: "1.7.4" }, {}, { zod: { version: "3.24.1" }, ky: { version: "1.7.4" } });
      const args = { task: "Fix the typo in the README.", packages: [] };
      const r = await brief(args);
      expect(r.private_installed).toBe(1);
      if (r.delegation_assessment.level === "safe_to_delegate") expect(r.delegation_assessment.reason).toContain(PRIVATE_INSTALLED(1));
      expect(brokenTextRules(r, args)).toEqual([]);
    } finally {
      delete process.env.FOURDA_PRIVATE_PACKAGES;
    }
  });
});
