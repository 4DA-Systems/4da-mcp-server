// SPDX-License-Identifier: Apache-2.0
/**
 * pnpm-workspace.yaml with a flow mapping (`{ ... }`). Three blind checks of this lane showed that a
 * hand-written reader of YAML's flow syntax cannot be made right in small steps (`''` escapes, tags
 * and anchors before a quote, JSON-style `"k":"v"`, quotes carried across lines, block scalars
 * holding braces): each misread let an avoided version through, the worst one an override in a
 * block section BELOW a misread flow mapping. So the hook no longer reads flow syntax at all:
 *
 * - The new text "has a brace" when a line that is not a `#` line holds `{` or `}` once each exact
 *   empty mapping (`{}`, `{ }`) is taken out.
 * - Then any change of its content lines (non-blank, non-`#` lines, trailing blanks, CRLF and BOM
 *   aside) is held as not read, and no verdict releases it: the denial says to rewrite the flow
 *   mapping(s) as block lines. A re-save, or a comment or blank line changed, holds nothing.
 * - Without a brace, the block reader runs as before.
 *
 * The cases are the reviewers' own (fixtures/a1125-hook-pnpm-flow-cases.json, from review-hook,
 * review-hook2 and review-hook3 of the 2026-11-25 fix round).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { pnpmUnplainLine } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial, timed, timedWithin } from "./helpers/a1125-hook-run.js";

interface Case {
  review: string;
  name: string;
  files: Record<string, string>;
  ledger: Array<Record<string, string>>;
  tool: "Edit" | "Write";
  input: { file_path: string; content?: string; old_string?: string; new_string?: string; replace_all?: boolean };
  expect: "allow" | "deny" | null;
}

const CASES = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "fixtures", "a1125-hook-pnpm-flow-cases.json"), "utf8")) as Case[];
const NOT_READ = "No dependency_check verdict releases this edit. To make the file readable: write each flow mapping as block lines";
const AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "advisories" };
const HEAD = "packages:\n  - 'packages/*'\n";

/** The rule, written out once more for the test: a brace on a content line, once `{}` is taken out. */
const contentLines = (text: string) =>
  text
    .replace(/^\uFEFF/, "")
    .split("\n")
    .map((l) => l.trimEnd())
    .filter((l) => l);
/**
 * Block-style spellings with no brace that 6.5.1 lets through as well, left as documented limits
 * by the lead (not flow syntax): a value with an anchor or a tag, a value on the next line, a block
 * scalar, a merge key, an explicit key.
 */
const KNOWN_LIMITS = new Set(["value anchor", "value tag", "value on next line", "block scalar", "merge key from anchor", "explicit key"]);

function after(c: Case, disk: string): string {
  if (c.tool === "Write") return c.input.content ?? "";
  const from = c.input.old_string ?? "";
  const to = c.input.new_string ?? "";
  return c.input.replace_all ? disk.split(from).join(to) : disk.replace(from, to);
}

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

function runCase(c: Case) {
  s.ledger(c.ledger.map((e) => ({ ecosystem: "npm", ...e })));
  for (const [rel, text] of Object.entries(c.files)) s.file(rel, text);
  const input = { ...c.input, file_path: join(s.project, c.input.file_path) };
  return s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: c.tool, tool_input: input });
}

describe("every bypass spelling from the three reviews is held", () => {
  it.each(CASES.filter((c) => c.expect === "deny" && !KNOWN_LIMITS.has(c.name)).map((c) => [`${c.review}: ${c.name}`, c] as const))("%s", (_label, c) => {
    const run = runCase(c);
    expect(run.decision, run.text).toBe("deny");
  });

  it("the known block-style limits are what 6.5.1 does too (no brace: read by the block reader)", () => {
    expect(CASES.filter((c) => KNOWN_LIMITS.has(c.name))).toHaveLength(KNOWN_LIMITS.size);
  });

  it("a `#` line inside a quoted scalar that runs over lines counts as a change in a brace file", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", `${HEAD}catalog: { a: "x\n# ", lodash: ^4.17.21 }\n`);
    const run = s.edit(file, "# \", lodash: ^4.17.21", "# \", lodash: 4.17.20");
    expect(run.text).toContain(NOT_READ);
  });
});

// Round 14 (R7): the line between read and held is the positive grammar (pnpmUnplainLine), no longer a
// brace: a quoted brace is a plain scalar, an empty flow (`{}`, `[]`) is not.
describe("the reviewers' allow rows: a file with a line that is not plain YAML is held exactly when its content lines change; a plain one is read by the block reader", () => {
  it.each(CASES.filter((c) => c.expect !== "deny").map((c) => [`${c.review}: ${c.name}`, c] as const))("%s", (_label, c) => {
    const disk = c.files["pnpm-workspace.yaml"] ?? "";
    const now = after(c, disk);
    const run = runCase(c);
    const changed = contentLines(disk).join("\n") !== contentLines(now).join("\n");
    if (pnpmUnplainLine(now) !== null) {
      expect(run.decision, run.text).toBe(changed ? "deny" : "allow");
      if (changed) expect(run.text).toContain(NOT_READ);
    } else {
      // Judged by the block reader: let through, or held for a verdict, never as not read.
      expect(run.text).not.toContain("could not be read");
    }
  });
});

describe("rule 2 in detail", () => {
  it("the reviewers' valid YAML files that the old reader thought open: an unrelated real change is held with the rewrite remedy, a re-save is not", () => {
    const tail = "overrides:\n  lodash: ^4.17.21\nonlyBuiltDependencies:\n  - esbuild\n";
    for (const [i, text] of [
      `${HEAD}catalog: { a: foo\n  'bar, react: ^18.2.0 }\n${tail}`,
      `${HEAD}catalog:\n  note: |\n    { it's\n  react: ^18.2.0\n${tail}`,
      `${HEAD}catalog: { a: 'it'' #1', react: ^18.2.0 }\n${tail}`,
    ].entries()) {
      const file = s.file(`e${i}/pnpm-workspace.yaml`, text);
      const run = s.edit(file, "  - esbuild", "  - esbuild\n  - sharp");
      expect(run.decision).toBe("deny");
      expect(run.text).toContain(NOT_READ);
      expect(s.write(file, text).decision).toBe("allow");
      expect(s.write(file, text.replace(/\n/g, "\r\n")).decision).toBe("allow");
      expect(s.edit(file, "packages:\n", "packages:\n\n").decision).toBe("allow");
      // A `#` line counts: one can sit inside a quoted scalar that runs over lines (`"x\n# "`).
      expect(s.edit(file, "packages:\n", "# workspace\npackages:\n").text).toContain(NOT_READ);
    }
  });

  it("no verdict releases a brace-file change, even proceed for the exact version", () => {
    s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed" }]);
    const file = s.file("pnpm-workspace.yaml", `${HEAD}catalog: { react: ^18.2.0 }\noverrides:\n  lodash: ^4.17.21\n`);
    const run = s.edit(file, "lodash: ^4.17.21", "lodash: 4.17.21");
    expect(run.decision).toBe("deny");
    expect(run.text).toContain(NOT_READ);
    expect(run.items).toBeNull();
  });

  it("a Write that creates a brace file is held the same way", () => {
    const run = s.write(join(s.project, "pnpm-workspace.yaml"), `${HEAD}catalog: { lodash: ^4.17.21 }\n`);
    expect(run.decision).toBe("deny");
    expect(run.text).toContain(NOT_READ);
  });

  it("`catalog: {}` / `overrides: {}` added to a brace-free file, and a brace only in a `#` line: read as usual", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", `${HEAD}catalog:\n  react: ^18.2.0\n`);
    // Round 14 (R7): an empty flow is no plain line: held as not read.
    expect(s.edit(file, "catalog:\n", "overrides: {}\noverrides2: { }\ncatalog:\n").text).toContain(NOT_READ);
    expect(s.edit(file, "catalog:\n", "# catalog: { lodash: 4.17.20 }\ncatalog:\n").decision).toBe("allow");
    expect(s.edit(file, "react: ^18.2.0", "react: ^18.2.0\n  lodash: 4.17.20").text).toContain("answered avoid");
  });

  it("a brace in a simply quoted value (`debug: '}'`) is a plain scalar (round 14, R7): the file is read, the version judged", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", `${HEAD}overrides:\n  debug: '}'\n  lodash: ^4.17.21\n`);
    const run = s.edit(file, "lodash: ^4.17.21", "lodash: 4.17.20");
    expect(run.text).not.toContain("could not be read");
    expect(run.text).toContain("answered avoid");
  });

  it("following the remedy literally passes: the same versions rewritten as block lines, the verdicts the denial then names recorded", () => {
    const text = `${HEAD}catalog: { lodash: ^4.17.21, react: ^18.2.0 }\ncatalogs:\n  legacy: { left-pad: 1.3.0 }\n`;
    const file = s.file("pnpm-workspace.yaml", text);
    const held = s.edit(file, "lodash: ^4.17.21", "lodash: 4.17.21");
    expect(held.text).toContain(NOT_READ);
    const block = `${HEAD}catalog:\n  lodash: ^4.17.21\n  react: ^18.2.0\ncatalogs:\n  legacy:\n    left-pad: 1.3.0\n`;
    const rewrite = s.write(file, block);
    expect(rewrite.decision).toBe("deny");
    expect(rewrite.text).not.toContain("could not be read");
    answerDenial(s, rewrite);
    expect(s.write(file, block).decision).toBe("allow");
  });
});

describe("size and time", () => {
  it("7 MB and 200,000 lines with a brace: held on a change, not held when re-saved, inside the CPU bound", () => {
    const entries = Array.from({ length: 200_000 }, (_, i) => `  package-number-${i}: 1.0.${i}`).join("\n");
    const text = `${HEAD}catalogs:\n  legacy: { left-pad: 1.3.0 }\ncatalog:\n${entries}\n`;
    expect(text.length).toBeGreaterThan(6.5 * 1024 * 1024);
    const file = s.file("pnpm-workspace.yaml", text);
    const write = (content: string) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: file, content } });
    const held = timedWithin(s.home, write(text.replace("package-number-7: 1.0.7", "package-number-7: 1.0.8")), 1000);
    expect(held.decision).toBe("deny");
    expect(held.text).toContain(NOT_READ);
    expect(timedWithin(s.home, write(text), 1000).decision).toBe("allow");
  });

  it("a brace file is cheaper than the block reader on the same text", () => {
    const entries = Array.from({ length: 100_000 }, (_, i) => `  package-number-${i}: 1.0.${i}`).join("\n");
    const block = `${HEAD}catalog:\n${entries}\n`;
    const brace = `${HEAD}catalogs:\n  legacy: { left-pad: 1.3.0 }\ncatalog:\n${entries}\n`;
    const fb = s.file("a/pnpm-workspace.yaml", block);
    const fr = s.file("b/pnpm-workspace.yaml", brace);
    const w = (file: string, content: string) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: file, content } });
    const cpu = (file: string, content: string) => Math.min(timed(s.home, w(file, content)).cpu, timed(s.home, w(file, content)).cpu);
    expect(cpu(fr, brace)).toBeLessThan(cpu(fb, block) * 1.5 + 50);
  });
});
