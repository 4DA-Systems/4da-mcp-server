// SPDX-License-Identifier: Apache-2.0
/**
 * The child-CPU helper's own behaviour (helpers/child-cpu.ts), with small scripts: a child that printed its figures and
 * then lingered past the wall timeout gives its figures; a child that never finished says which stage it reached; the
 * child gets FOURDA_OFFLINE, its own FOURDA_MCP_HOME and an empty folder from the parent.
 */
import { mkdtempSync, rmSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runChildScript } from "./helpers/child-cpu.js";

let home: string;
let cwd: string;
beforeEach(() => {
  home = mkdtempSync(path.join(os.tmpdir(), "4da-childcpu-t-home-"));
  cwd = mkdtempSync(path.join(os.tmpdir(), "4da-childcpu-t-cwd-"));
});
afterEach(() => {
  for (const d of [home, cwd]) rmSync(d, { recursive: true, force: true });
});

describe("the child-CPU helper", () => {
  it("a child that printed its figures and then did not exit: the figures stand", () => {
    const script = `import { writeSync } from "node:fs"; writeSync(1, "@@cpu [12.5,7]\\n"); setInterval(() => {}, 1000);`;
    expect(runChildScript(script, { input: "", timeoutMs: 3000, cwd, home })).toEqual([12.5, 7]);
  }, 30_000);
  it("a child that never finished: the error names the last stage it reached", () => {
    const script = `import { writeSync } from "node:fs"; writeSync(2, "@@stage before-import\\n"); writeSync(2, "@@stage after-import\\n"); setInterval(() => {}, 1000);`;
    expect(() => runChildScript(script, { input: "", timeoutMs: 3000, cwd, home })).toThrow(/did not finish in the child within 3000 ms .*last stage reached: after-import/);
  }, 30_000);
  it("the child's environment and folder come from the parent", () => {
    const script = `process.stdout.write("@@cpu [" + (process.env.FOURDA_OFFLINE === "true" ? 1 : 0) + "," + (process.env.FOURDA_MCP_HOME === ${JSON.stringify(home)} ? 1 : 0) + "," + (process.cwd().toLowerCase() === ${JSON.stringify(cwd.toLowerCase())} ? 1 : 0) + "]\\n", () => process.exit(0));`;
    expect(runChildScript(script, { input: "", timeoutMs: 30_000, cwd, home })).toEqual([1, 1, 1]);
  }, 60_000);
});
