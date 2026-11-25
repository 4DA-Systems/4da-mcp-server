// SPDX-License-Identifier: Apache-2.0
/**
 * pnpm-workspace.yaml `overrides` keyed by a selector (`'lodash@<4.17.21': 4.17.20`, the shape
 * `pnpm audit --fix` writes) or by a parent path (`'express>lodash': 4.17.20`) set the version of
 * the package the key ends in. The hook skipped those keys as "not one package's version", so a
 * version with an `avoid` on record went through (audit 2026-11-25, D-B1, confirmed in a live
 * session). The same keys in package.json `pnpm.overrides` were held; now both are read alike: the
 * package is the key's last part before its version selector, and the value is what is judged.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial, timedWithin } from "./helpers/a1125-hook-run.js";

const AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "advisories: GHSA-35jh-r3h4-6jhm (high)" };
const HEAD = "packages:\n  - 'packages/*'\n";
const AUDIT_FIX = `${HEAD}overrides:\n  lodash@<4.17.21: '>=4.17.21'\n`;

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

describe("a selector or parent-path override key is read as the package it ends in", () => {
  it.each([
    ["quoted selector", "'lodash@<4.17.21': 4.17.20"],
    ["plain selector (what pnpm audit --fix writes)", "lodash@<4.17.21: 4.17.20"],
    ["double-quoted selector", '"lodash@<4.17.21": "4.17.20"'],
    ["parent>child", "'express>lodash': 4.17.20"],
    ["parent with a version>child", "'express@4>lodash': 4.17.20"],
    ["selector whose range holds >", "'lodash@>=4.0.0 <4.17.21': 4.17.20"],
    ["selector with ||", "'lodash@<3 || >=4.0.0 <4.17.21': 4.17.20"],
    ["parent>child@selector", "'express>lodash@<4.17.21': 4.17.20"],
  ])("%s, with an avoid on record: held", (_label, line) => {
    s.ledger([AVOID]);
    const run = s.write(s.file("pnpm-workspace.yaml", HEAD), `${HEAD}overrides:\n  ${line}\n`);
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain('"lodash" "4.17.20" (npm): dependency_check answered avoid');
  });

  it("an Edit of the file pnpm audit --fix wrote, putting the avoided version in: held", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", AUDIT_FIX);
    const run = s.edit(file, "'>=4.17.21'", "4.17.20");
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain("answered avoid");
  });

  it("a scoped package behind a selector is named whole", () => {
    const run = s.write(s.file("pnpm-workspace.yaml", HEAD), `${HEAD}overrides:\n  '@types/node@<18': 18.19.0\n  'a>@scope/b': 2.0.0\n`);
    expect(run.items).toEqual([
      { ecosystem: "npm", package: "@types/node", to: "18.19.0" },
      { ecosystem: "npm", package: "@scope/b", to: "2.0.0" },
    ]);
  });
});

describe("the denial's own call releases it", () => {
  it.each([
    ["an exact version", "'lodash@<4.17.21': 4.17.21", { ecosystem: "npm", package: "lodash", to: "4.17.21" }],
    ["a range (what pnpm audit --fix writes)", "lodash@<4.17.21: '>=4.17.21'", { ecosystem: "npm", package: "lodash", to: ">=4.17.21" }],
    ["a parent path", "'express>qs': 6.11.0", { ecosystem: "npm", package: "qs", to: "6.11.0" }],
  ])("%s", (_label, line, item) => {
    const file = s.file("pnpm-workspace.yaml", HEAD);
    const content = `${HEAD}overrides:\n  ${line}\n`;
    const first = s.write(file, content);
    expect(first.items).toEqual([item]);
    answerDenial(s, first);
    expect(s.write(file, content).decision).toBe("allow");
  });

  it("an avoid answer keeps it held", () => {
    const file = s.file("pnpm-workspace.yaml", HEAD);
    const content = `${HEAD}overrides:\n  'lodash@<4.17.21': 4.17.20\n`;
    answerDenial(s, s.write(file, content), "avoid");
    expect(s.write(file, content).decision).toBe("deny");
  });
});

describe("what changes no version is not held, with an avoid on record for the line already there", () => {
  const ON_DISK = `${HEAD}overrides:\n  'lodash@<4.17.21': 4.17.20\n  'express>lodash': 4.17.20\n`;

  it("re-saving the file unchanged", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", ON_DISK);
    expect(s.write(file, ON_DISK).decision).toBe("allow");
  });

  it("an edit elsewhere in the file", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", ON_DISK);
    expect(s.edit(file, "'packages/*'", "'packages/*'\n  - 'apps/*'").decision).toBe("allow");
  });

  it("moving the selector line, quoting it differently, or dropping it", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", ON_DISK);
    expect(s.edit(file, "'lodash@<4.17.21': 4.17.20", '"lodash@<4.17.21": "4.17.20"').decision).toBe("allow");
    expect(s.edit(file, "  'express>lodash': 4.17.20\n", "").decision).toBe("allow");
  });

  it("an override that removes a package (`-`) or refers to a direct dependency (`$lodash`) is not a version", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", HEAD);
    expect(s.write(file, `${HEAD}overrides:\n  'express>lodash': '-'\n  'lodash@<4.17.21': $lodash\n`).decision).toBe("allow");
  });
});

describe("line endings, a byte order mark and size", () => {
  it("CRLF: held with an avoid, re-saved unchanged not held", () => {
    s.ledger([AVOID]);
    const crlf = `${HEAD}overrides:\n  'lodash@<4.17.21': 4.17.20\n`.replace(/\n/g, "\r\n");
    expect(s.write(s.file("a/pnpm-workspace.yaml", HEAD.replace(/\n/g, "\r\n")), crlf).decision).toBe("deny");
    const file = s.file("b/pnpm-workspace.yaml", crlf);
    expect(s.write(file, crlf).decision).toBe("allow");
    expect(s.edit(file, "'packages/*'", "'apps/*'").decision).toBe("allow");
    expect(s.edit(file, "4.17.20", "4.17.19").decision).toBe("deny");
  });

  it("a byte order mark before `overrides:` on the first line: held; re-saved unchanged not held", () => {
    s.ledger([AVOID]);
    const bom = "\uFEFFoverrides:\n  'lodash@<4.17.21': 4.17.20\n";
    expect(s.write(s.file("a/pnpm-workspace.yaml", ""), bom).decision).toBe("deny");
    const file = s.file("b/pnpm-workspace.yaml", bom);
    expect(s.write(file, bom).decision).toBe("allow");
  });

  it("1,000 lines: the selector line in the middle is held, an edit elsewhere is not", () => {
    s.ledger([AVOID]);
    const globs = Array.from({ length: 500 }, (_, i) => `  - 'packages/p${i}'`).join("\n");
    const pins = Array.from({ length: 498 }, (_, i) => `  'pkg-${i}>dep-${i}': 1.0.${i}`).join("\n");
    const before = `packages:\n${globs}\noverrides:\n${pins}\n`;
    const file = s.file("pnpm-workspace.yaml", before);
    const after = before.replace("  'pkg-250>dep-250': 1.0.250\n", "  'pkg-250>dep-250': 1.0.250\n  'lodash@<4.17.21': 4.17.20\n");
    const run = timedWithin(s.home, { hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: file, content: after } }, 500);
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain('"lodash" "4.17.20" (npm): dependency_check answered avoid');
    expect(s.edit(file, "'packages/p7'", "'packages/q7'").decision).toBe("allow");
  });

  it("7 MB: held with the avoid, and a re-save of it is not held, inside the CPU bound", () => {
    s.ledger([AVOID]);
    const globs = Array.from({ length: 205_000 }, (_, i) => `  - 'packages/project-number-${i}'`).join("\n");
    const before = `packages:\n${globs}\noverrides:\n  'express>qs': 6.11.0\n`;
    expect(before.length).toBeGreaterThan(7 * 1024 * 1024);
    const file = s.file("pnpm-workspace.yaml", before);
    const after = `${before}  'lodash@<4.17.21': 4.17.20\n`;
    const write = (content: string) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: file, content } });
    const held = timedWithin(s.home, write(after), 1000);
    expect(held.decision, held.text).toBe("deny");
    expect(held.text).toContain("answered avoid");
    const resaved = timedWithin(s.home, write(before), 1000);
    expect(resaved.decision, resaved.text).toBe("allow");
  });
});
