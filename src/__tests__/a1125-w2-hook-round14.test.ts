// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14, from the twelfth independent check: a cut. Fewer things go ahead, decided by positive
 * evidence. Each rule (R1-R12) with the reviewer's cases.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("R1 / R2: changes the round-14 cut makes to earlier rows", () => {
  it.each([
    "pnpm add --trust-policy no-downgrade lodash@4.17.21",
    "go get -u github.com/pkg/errors@upgrade",
    "pip install --no-index --find-links ./wheels requests",
  ])("%s: held as not read (off the allow list, or more than one source)", (command) => {
    expect(run(command).text).toContain("could not be read");
  });
});

describe("R7: pnpm-workspace.yaml is read only when every line is plain", () => {
  const write = (content: string) => s.write(`${s.project}/pnpm-workspace.yaml`, content);
  it.each([
    ["a tag", "catalog:\n  lodash: !!str 4.17.20\n"],
    ["an anchor and an alias", "x: &v 4.17.20\ncatalog:\n  lodash: *v\n"],
    ["a literal block scalar", "catalog:\n  lodash: |\n    4.17.20\n"],
    ["a folded block scalar", "catalog:\n  lodash: >-\n    4.17.20\n"],
    ["an explicit key at the top", "? lodash\n: 4.17.20\n"],
    ["an explicit key in a section", "catalog:\n  ? lodash\n  : 4.17.20\n"],
    ["a merge key", "base: &b\n  lodash: 4.17.20\ncatalog:\n  <<: *b\n"],
    ["a flow mapping", "catalog: { lodash: 4.17.20 }\n"],
    ["a flow sequence", "packages: ['a', 'b']\ncatalog:\n  lodash: 4.17.20\n"],
    ["a second document", "catalog:\n  ms: 2.1.3\n---\ncatalog:\n  lodash: 4.17.20\n"],
    ["a value on the next line", "catalog:\n  lodash:\n    4.17.20\n"],
    ["a range starting with an indicator, unquoted", "catalog:\n  lodash: >=4.17.20\n"],
    ["a lone CR before a flow line", "# note\rcatalog: { lodash: 4.17.20 }\n"],
  ])("%s: held, with the rewrite remedy", (_label, content) => {
    const r = write(content);
    expect(r.decision, content).toBe("deny");
    expect(r.text).toContain("rewrite as plain `name: version` lines");
  });
  it.each([
    ["plain lines", "packages:\n  - 'packages/*'\ncatalog:\n  lodash: 4.17.20\n"],
    ["quoted keys and values", "catalog:\n  'lodash': '4.17.20'\n  \"@types/node\": \"20.0.0\"\n"],
    ["a quoted range", "catalog:\n  lodash: '>=4.17.20'\n"],
    ["comments", "# top\ncatalog: # the catalog\n  lodash: 4.17.20 # pinned\n"],
    ["a document start first", "---\ncatalog:\n  lodash: 4.17.20\n"],
  ])("%s: read, the version judged", (_label, content) => {
    const r = write(content);
    expect(r.text).not.toContain("could not be read");
    expect(r.decision).toBe("deny");
  });
});
