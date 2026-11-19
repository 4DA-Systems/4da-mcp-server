// SPDX-License-Identifier: Apache-2.0
/**
 * The mutation check (scripts/mutation) refuses a mutant that no longer applies before it
 * changes anything, so a mutant cannot rot into a no-op that "survives"; it reads a vitest
 * report's failures, a file that failed to load included; and its list is well formed.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { applied, failures, locate, validate } from "../../scripts/mutation/lib.mjs";
import { mutations } from "../../scripts/mutation/mutations.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
let root: string;
const base = { id: "M1", area: "test", file: "src/a.ts", intent: "the bound becomes exclusive" };

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "a1119-mutation-"));
  mkdirSync(join(root, "src", "__tests__"), { recursive: true });
  writeFileSync(join(root, "src", "a.ts"), "export const lo = (v: number) => v >= 1;\nexport const hi = (v: number) => v >= 1;\nexport const one = 1;\n");
  writeFileSync(join(root, "src", "__tests__", "a.test.ts"), "");
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("a mutant that no longer applies is refused, never run", () => {
  it("text that is gone", () => {
    const problems = validate([{ ...base, find: "v > 1;", replace: "v >= 1;" }], root);
    expect(problems).toEqual([expect.stringMatching(/^M1: the text to replace is no longer in src\/a\.ts/)]);
  });

  it("text that occurs twice without nth, and an nth past the last occurrence", () => {
    expect(validate([{ ...base, find: "v >= 1;", replace: "v > 1;" }], root)).toEqual([expect.stringMatching(/occurs 2 times in src\/a\.ts; give nth/)]);
    expect(validate([{ ...base, find: "v >= 1;", nth: 3, replace: "v > 1;" }], root)).toEqual([expect.stringMatching(/nth 3, but the text occurs 2 times/)]);
  });

  it("a missing file or test file, a replacement equal to the text, a duplicate id, no intent", () => {
    expect(validate([{ ...base, file: "src/gone.ts", find: "x", replace: "y" }], root)).toEqual(["M1: src/gone.ts does not exist"]);
    expect(validate([{ ...base, find: "one = 1", replace: "one = 2", tests: ["src/__tests__/gone.test.ts"] }], root)).toEqual([
      "M1: test file src/__tests__/gone.test.ts does not exist",
    ]);
    expect(validate([{ ...base, find: "one = 1", replace: "one = 1" }], root)).toEqual(["M1: find must be non-empty and differ from replace"]);
    const twice = [{ ...base, find: "one = 1", replace: "one = 2" }, { ...base, find: "one = 1", replace: "one = 0" }];
    expect(validate(twice, root)).toEqual(["M1: missing or duplicate id"]);
    expect(validate([{ ...base, intent: "", find: "one = 1", replace: "one = 2" }], root)).toEqual([expect.stringMatching(/no intent/)]);
  });

  it("applies the chosen occurrence only, and reports its line", () => {
    const m = { ...base, find: "v >= 1;", nth: 2, replace: "v > 1;" };
    expect(validate([m], root)).toEqual([]);
    const loc = locate(m, root);
    expect(loc.line).toBe(2);
    expect(applied(m, loc)).toBe("export const lo = (v: number) => v >= 1;\nexport const hi = (v: number) => v > 1;\nexport const one = 1;\n");
    expect(readFileSync(join(root, "src", "a.ts"), "utf8")).toContain("hi = (v: number) => v >= 1;");
  });
});

describe("reading a vitest JSON report", () => {
  it("names each failed test, and a file that failed to load", () => {
    const report = {
      numTotalTests: 3,
      numPassedTests: 1,
      testResults: [
        { name: "C:\\repo\\src\\__tests__\\x.test.ts", status: "failed", assertionResults: [{ status: "failed", fullName: "x > breaks" }, { status: "passed", fullName: "x > holds" }] },
        { name: "/repo/src/__tests__/y.test.ts", status: "failed", message: "SyntaxError: bad\nstack", assertionResults: [] },
      ],
    };
    expect(failures(JSON.stringify(report))).toEqual({
      total: 3,
      passed: 1,
      failed: ["src/__tests__/x.test.ts :: x > breaks", "src/__tests__/y.test.ts :: (the file failed to run) SyntaxError: bad"],
    });
  });

  it("no report is null; an unreadable one is a failure, never a pass", () => {
    expect(failures(null)).toBeNull();
    expect(failures("{ not json").failed).toEqual([expect.stringMatching(/^\(unreadable report/)]);
  });
});

describe("the mutant list", () => {
  it("is well formed: unique ids, an intent each, likely tests that exist, a reason for each equivalent", () => {
    expect(mutations.length).toBeGreaterThan(80);
    const ids = mutations.map((m) => m.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const m of mutations) {
      expect(m.intent, m.id).toBeTruthy();
      expect(m.find, m.id).not.toBe(m.replace);
      for (const t of m.tests ?? []) expect(() => readFileSync(join(repo, t)), `${m.id}: ${t}`).not.toThrow();
    }
    expect(mutations.filter((m) => m.equivalent).map((m) => m.id).sort()).toEqual(["L09", "X04"]);
  });
});
