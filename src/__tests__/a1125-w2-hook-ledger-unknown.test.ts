// SPDX-License-Identifier: Apache-2.0
/**
 * Seventh independent check, D10: an avoid on a line cut short, or stamped past the clock's slack,
 * must not be dropped in favour of an older proceed. Such a line makes that package's verdict
 * unknown from that line on; a later answer releases it.
 */

import { appendFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const at = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
const line = (e: Record<string, string>) => JSON.stringify({ sv: "6.6.0", ...e });
const PROCEED = { ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed" };
const cmd = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const write = (lines: string[]) => writeFileSync(join(s.home, "check-ledger.jsonl"), lines.join("\n"));

describe("D10: an unreadable or future-dated newest line holds its package", () => {
  it("control: a proceed on record goes ahead", () => {
    write([line({ t: at(60_000), ...PROCEED }), ""]);
    expect(cmd("npm i lodash@4.17.21").decision).toBe("allow");
  });

  it("an avoid cut short after the proceed: held", () => {
    write([line({ t: at(60_000), ...PROCEED }), '{"t":"' + at(1000) + '","ecosystem":"npm","package":"lodash","version":"4.17.21","verdict":"avo']);
    const r = cmd("npm i lodash@4.17.21");
    expect(r.decision, r.text).toBe("deny");
  });

  it("an avoid stamped an hour ahead, after the proceed: held", () => {
    write([line({ t: at(60_000), ...PROCEED }), line({ t: new Date(Date.now() + 3600_000).toISOString(), ...PROCEED, verdict: "avoid", reason: "x" }), ""]);
    expect(cmd("npm i lodash@4.17.21").decision).toBe("deny");
  });

  it("a later answer releases it; another package is not touched", () => {
    write([line({ t: at(60_000), ...PROCEED }), line({ t: at(60_000), ecosystem: "npm", package: "ms", version: "2.1.3", verdict: "proceed" }), '{"t":"x","ecosystem":"npm","package":"lodash","verd']);
    expect(cmd("npm i lodash@4.17.21").decision).toBe("deny");
    expect(cmd("npm i ms@2.1.3").decision).toBe("allow");
    appendFileSync(join(s.home, "check-ledger.jsonl"), "\n" + line({ t: at(1000), ...PROCEED }) + "\n");
    expect(cmd("npm i lodash@4.17.21").decision).toBe("allow");
  });
});
