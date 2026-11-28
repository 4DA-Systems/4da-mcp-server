// SPDX-License-Identifier: Apache-2.0
/**
 * pnpm-workspace.yaml sections the hook did not see (audit 2026-11-25, D-M1): a comment after the
 * section key (`catalog: # shared versions`) hid the whole section, and so did a quoted key
 * (`"catalog":`). A flow mapping (`catalog: { lodash: 4.17.20 }`) is not read: when it changes it
 * is held as not read, with a remedy that releases it (write it as block lines); when it does not
 * change, nothing is held. A catalog alias (`lodash: npm:lodash@4.17.20`) is the package and
 * version it names.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial, timedWithin } from "./helpers/a1125-hook-run.js";

const AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "advisories: GHSA-35jh-r3h4-6jhm (high)" };
const HEAD = "packages:\n  - 'packages/*'\n";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

describe("a comment after a section key, or a quoted key, no longer hides the section", () => {
  it.each([
    ["catalog: # comment", "catalog: # shared versions\n  lodash: ^4.17.21\n", "lodash: ^4.17.21", "lodash: 4.17.20"],
    ["overrides: # comment", "overrides: # pins\n  lodash: ^4.17.21\n", "lodash: ^4.17.21", "lodash: 4.17.20"],
    ["catalogs: # comment", "catalogs: # named\n  legacy:\n    lodash: ^4.17.21\n", "lodash: ^4.17.21", "lodash: 4.17.20"],
    ["a named catalog with a comment", "catalogs:\n  legacy: # old apps\n    lodash: ^4.17.21\n", "lodash: ^4.17.21", "lodash: 4.17.20"],
    ['"catalog":', '"catalog":\n  lodash: ^4.17.21\n', "lodash: ^4.17.21", "lodash: 4.17.20"],
    ["'overrides':", "'overrides':\n  lodash: ^4.17.21\n", "lodash: ^4.17.21", "lodash: 4.17.20"],
    ["catalog alias npm:", "catalog:\n  lodash: ^4.17.21\n", "lodash: ^4.17.21", "lodash: npm:lodash@4.17.20"],
    ["an alias under another key", "catalog:\n  utils: ^1.0.0\n", "utils: ^1.0.0", "utils: npm:lodash@4.17.20"],
  ])("%s, with an avoid on record: an Edit putting it in is held", (_label, section, from, to) => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", HEAD + section);
    const run = s.edit(file, from, to);
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain('"lodash" "4.17.20" (npm): dependency_check answered avoid');
  });

  it("the denial's own call releases it", () => {
    const file = s.file("pnpm-workspace.yaml", `${HEAD}catalog: # shared versions\n  lodash: ^4.17.21\n`);
    const first = s.edit(file, "lodash: ^4.17.21", "lodash: 4.17.21");
    expect(first.items).toEqual([{ ecosystem: "npm", package: "lodash", to: "4.17.21" }]);
    answerDenial(s, first);
    expect(s.edit(file, "lodash: ^4.17.21", "lodash: 4.17.21").decision).toBe("allow");
    const alias = s.edit(file, "lodash: ^4.17.21", "lodash: npm:lodash@4.17.21");
    expect(alias.decision).toBe("allow");
  });

  it("re-saved unchanged, or edited elsewhere: not held", () => {
    s.ledger([AVOID]);
    const text = `${HEAD}catalog: # shared versions\n  lodash: 4.17.20\n  other: npm:lodash@4.17.20\n"overrides":\n  lodash: 4.17.20\n`;
    const file = s.file("pnpm-workspace.yaml", text);
    expect(s.write(file, text).decision).toBe("allow");
    expect(s.edit(file, "'packages/*'", "'apps/*'").decision).toBe("allow");
    expect(s.edit(file, "# shared versions", "# all the versions").decision).toBe("allow");
  });

  // Round 25 (W3): an entry with no value is held (pnpm refuses it).
  it("a value that is only a comment is no value: held", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", HEAD);
    expect(s.write(file, `${HEAD}catalog:\n  lodash: # set below\n`).decision).toBe("deny");
  });
});

describe("line endings, a byte order mark and size", () => {
  it("CRLF and a BOM: a commented section is held, re-saved not held", () => {
    s.ledger([AVOID]);
    for (const [rel, text] of [
      ["a/pnpm-workspace.yaml", `catalog: # shared\n  lodash: 4.17.20\n`.replace(/\n/g, "\r\n")],
      ["b/pnpm-workspace.yaml", `\uFEFFcatalog: # shared\n  lodash: 4.17.20\n`],
      ["c/pnpm-workspace.yaml", `\uFEFFcatalog: { lodash: 4.17.20 }\r\n`],
    ] as const) {
      expect(s.write(s.file(rel, ""), text).decision, rel).toBe("deny");
      const file = s.file(`same-${rel}`, text);
      expect(s.write(file, text).decision, rel).toBe("allow");
    }
  });

  it("1,000 lines and 7 MB: held when a version changes, not held when re-saved, inside the CPU bound", () => {
    s.ledger([AVOID]);
    // 7 MB of workspace globs around a catalog of 990 entries. (7 MB of catalog entries alone take
    // about as long on 6.5.1 as here, past these bounds on a loaded machine: not this change's cost.)
    for (const [globs, limit] of [
      [0, 500],
      [205_000, 1000],
    ] as const) {
      const entries = Array.from({ length: 990 }, (_, i) => `  package-number-${i}: 1.0.${i}`).join("\n");
      const packages = Array.from({ length: globs }, (_, i) => `  - 'packages/project-number-${i}'`).join("\n");
      const before = `packages:\n${packages}\ncatalog: # shared versions\n${entries}\n  lodash: ^4.17.21\ncatalogs:\n  legacy:\n    left-pad: 1.3.0\n`;
      if (globs > 0) expect(before.length).toBeGreaterThan(7 * 1024 * 1024);
      const count = globs;
      const file = s.file(`n${count}/pnpm-workspace.yaml`, before);
      const write = (content: string) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: file, content } });
      const held = timedWithin(s.home, write(before.replace("lodash: ^4.17.21", "lodash: 4.17.20")), limit);
      expect(held.decision, held.text).toBe("deny");
      expect(held.text).toContain("answered avoid");
      expect(timedWithin(s.home, write(before), limit).decision).toBe("allow");
    }
  });
});
