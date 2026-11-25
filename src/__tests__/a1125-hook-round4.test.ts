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
