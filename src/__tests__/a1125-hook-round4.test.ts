// SPDX-License-Identifier: Apache-2.0
/**
 * Fourth blind check of the a1125 hook lane:
 * 1. YAML ends a line at a lone CR too, so `# note\roverrides:` is a comment and a section, not one
 *    comment line: pnpm-workspace.yaml is split on CR, CRLF and LF.
 * 2. A version set behind a selector (`lodash@<4`), a parent path (`foo>lodash`), under a parent
 *    (npm's nested overrides) or under another name (an alias) is not a declaration of that name for
 *    the whole tree: it no longer lets the same version pass elsewhere in the manifest unchecked, in
 *    pnpm-workspace.yaml and in package.json (where 6.5.1 had the same hole). A plain key still is.
 * 3. The brace denial names each shape a brace can take, and following it makes the file readable.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const H = "packages:\n  - 'packages/*'\n";
const CAT = `${H}catalog:\n  lodash: ^4.17.21\n`;
const AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "x" };
const NOT_READ = "No dependency_check verdict releases this edit. To make the file readable";
const json = (doc: unknown) => JSON.stringify(doc, null, 2) + "\n";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

describe("a lone CR ends a line", () => {
  it.each([
    ["# comment CR then flow catalog", H, `${H}# note\rcatalog: { lodash: 4.17.20 }\n`],
    ["# comment CR then block catalog", H, `${H}# note\rcatalog:\r  lodash: 4.17.20\n`],
    ["whole file CR only", "", `packages:\r  - 'packages/*'\rcatalog:\r  lodash: 4.17.20\r`],
  ])("%s: held", (_label, before, after) => {
    s.ledger([AVOID]);
    expect(s.write(s.file("pnpm-workspace.yaml", before), after).decision).toBe("deny");
  });

  it("an edit that adds a CR line: held", () => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", CAT);
    expect(s.edit(file, "lodash: ^4.17.21", "lodash: ^4.17.21\r  # x\r  lodash: 4.17.20").decision).toBe("deny");
  });

  it("CRLF files behave as before: a change held with the avoid, a re-save and an edit elsewhere not", () => {
    s.ledger([AVOID]);
    const crlf = CAT.replace(/\n/g, "\r\n");
    const file = s.file("pnpm-workspace.yaml", crlf);
    expect(s.edit(file, "lodash: ^4.17.21", "lodash: 4.17.20").text).toContain("answered avoid");
    expect(s.write(file, crlf).decision).toBe("allow");
    expect(s.edit(file, "'packages/*'", "'apps/*'").decision).toBe("allow");
  });
});

describe("a narrow key is judged, but declares no version for the whole tree", () => {
  it.each([
    ["selector", `${H}overrides:\n  "lodash@<4": 3.10.1\ncatalog:\n  lodash: ^4.17.21\n`, "lodash: ^4.17.21", "lodash: 3.10.1"],
    ["parent path", `${H}overrides:\n  "foo>lodash": 3.10.1\ncatalog:\n  lodash: ^4.17.21\n`, "lodash: ^4.17.21", "lodash: 3.10.1"],
    ["alias under another name", `${H}catalog:\n  old-lodash: npm:lodash@3.10.1\noverrides:\n  lodash: ^4.17.21\n`, "lodash: ^4.17.21", "lodash: 3.10.1"],
  ])("pnpm-workspace.yaml, %s on disk: the same version put on the plain name is held, empty ledger", (_label, text, from, to) => {
    const file = s.file("pnpm-workspace.yaml", text);
    const run = s.edit(file, from, to);
    expect(run.decision).toBe("deny");
    expect(run.items).toEqual([{ ecosystem: "npm", package: "lodash", to: "3.10.1" }]);
    expect(s.write(file, text).decision).toBe("allow");
  });

  it("pnpm-workspace.yaml, the other direction: a plain declaration still covers a narrow key that repeats its version; a changed narrow value is held", () => {
    const text = `${H}catalog:\n  lodash: 3.10.1\noverrides:\n  "foo>lodash": 3.10.0\n`;
    const file = s.file("pnpm-workspace.yaml", text);
    // (round 15, H3: an unknown top-level key is held; a setting known to install nothing is not)
    expect(s.edit(file, "catalog:\n", "nodeLinker: hoisted\ncatalog:\n").decision).toBe("allow");
    // Round 23 (W1): each section on its own: the catalog's 3.10.1 no longer covers the override.
    expect(s.edit(file, '"foo>lodash": 3.10.0', '"foo>lodash": 3.10.1').decision).toBe("deny");
    expect(s.edit(file, '"foo>lodash": 3.10.0', '"foo>lodash": 3.10.2').items).toEqual([{ ecosystem: "npm", package: "lodash", to: "3.10.2", from: "3.10.0" }]);
    expect(s.edit(file, '"foo>lodash": 3.10.0', '"bar>lodash": 3.10.0').decision).toBe("deny");
  });

  it("pnpm-workspace.yaml: a plain override key no longer covers the catalog (round 23, W1)", () => {
    const file = s.file("pnpm-workspace.yaml", `${H}overrides:\n  lodash: 3.10.1\ncatalog:\n  lodash: ^4.17.21\n`);
    expect(s.edit(file, "lodash: ^4.17.21", "lodash: 3.10.1").decision).toBe("deny");
  });

  it.each([
    ["pnpm.overrides parent path", { pnpm: { overrides: { "foo>lodash": "3.10.1" } } }],
    ["pnpm.overrides selector", { pnpm: { overrides: { "lodash@<4": "3.10.1" } } }],
    ["npm overrides under a parent", { overrides: { foo: { lodash: "3.10.1" } } }],
    ["Yarn resolutions path", { resolutions: { "**/lodash": "3.10.1" } }],
    ["npm overrides alias", { overrides: { lodash: "npm:other-lodash@3.10.1" } }],
  ])("package.json, %s on disk: the same version put in dependencies is held (6.5.1 let it through)", (_label, extra) => {
    const name = Object.keys(extra)[0] === "overrides" && JSON.stringify(extra).includes("other-lodash") ? "other-lodash" : "lodash";
    const before = json({ name: "r", ...extra, dependencies: { [name]: "^4.17.21" } });
    const file = s.file("package.json", before);
    const run = s.edit(file, `"${name}": "^4.17.21"`, `"${name}": "3.10.1"`);
    expect(run.decision).toBe("deny");
    expect(run.items).toEqual([{ ecosystem: "npm", package: name, to: "3.10.1" }]);
    expect(s.write(file, before).decision).toBe("allow");
  });

  it("package.json: a plain override no longer covers dependencies (round 23, W1), and an unchanged narrow key holds nothing", () => {
    const before = json({ name: "r", overrides: { lodash: "3.10.1", foo: { qs: "6.11.0" } }, pnpm: { overrides: { "a>b": "1.0.0" } }, dependencies: { lodash: "^4.17.21" } });
    const file = s.file("package.json", before);
    expect(s.edit(file, '"lodash": "^4.17.21"', '"lodash": "3.10.1"').decision).toBe("deny");
    expect(s.edit(file, '"name": "r"', '"name": "s"').decision).toBe("allow");
  });
});

describe("the brace denial's wording, followed for each shape, makes the file readable", () => {
  it.each([
    ["a flow mapping", `${H}catalog: { lodash: ^4.17.21 }\n`, `${H}catalog:\n  lodash: ^4.17.21\n`],
    ["a brace glob", `${H}publicHoistPattern:\n  - '*{eslint,prettier}*'\ncatalog:\n  lodash: ^4.17.21\n`, `${H}publicHoistPattern:\n  - '*eslint*'\n  - '*prettier*'\ncatalog:\n  lodash: ^4.17.21\n`],
    ["a brace glob in packages", `packages:\n  - 'packages/{a,b}'\ncatalog:\n  lodash: ^4.17.21\n`, `packages:\n  - 'packages/a'\n  - 'packages/b'\ncatalog:\n  lodash: ^4.17.21\n`],
    ["a quoted brace", `${H}settings:\n  x: '}'\ncatalog:\n  lodash: ^4.17.21\n`, `${H}catalog:\n  lodash: ^4.17.21\n`],
    ["a block scalar", `${H}notes: |\n  { see }\ncatalog:\n  lodash: ^4.17.21\n`, `${H}catalog:\n  lodash: ^4.17.21\n`],
    ["a trailing comment", `${H}catalog: # see {issue}\n  lodash: ^4.17.21\n`, `${H}# see {issue}\ncatalog:\n  lodash: ^4.17.21\n`],
  ])("%s", (label, braced, readable) => {
    s.ledger([AVOID]);
    const file = s.file("pnpm-workspace.yaml", braced);
    const held = s.edit(file, "lodash: ^4.17.21", "lodash: 4.17.20");
    // Round 14 (R7): a quoted brace and a brace in a trailing comment are plain YAML: read, judged.
    if (["a brace glob", "a brace glob in packages", "a quoted brace", "a trailing comment"].includes(label)) {
      expect(held.text).not.toContain("could not be read");
      expect(held.text).toContain("answered avoid");
      return;
    }
    expect(held.text).toContain(NOT_READ);
    expect(held.text).toContain("brace glob");
    // Following the wording: the readable file is judged by its versions, not held as not read.
    const rewritten = s.write(file, readable.replace("lodash: ^4.17.21", "lodash: 4.17.20"));
    expect(rewritten.decision).toBe("deny");
    expect(rewritten.text).toContain("answered avoid");
    expect(rewritten.text).not.toContain("could not be read");
  });
});
