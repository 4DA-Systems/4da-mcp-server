// SPDX-License-Identifier: Apache-2.0
/**
 * Sixth blind check of the 2026-11-25 fixes, item 3: the setting screen looked a `key: value` match's line
 * up with lastIndexOf / indexOf each, quadratic on one long line (5.0 s on 199 KB of " a:", 2.7 s on
 * `npm install --a=b,c,d,e:f` repeated, 2.3 s on `a{i}_secret: v`). Judged on process CPU time.
 */

import { describe, expect, it } from "vitest";
import { screenTask } from "../tools/briefing-task-screen.js";

const N = 199_000;
const fill = (u: string) => u.repeat(Math.floor(N / u.length));
const gen = (f: (i: number) => string) => {
  let s = "";
  for (let i = 0; s.length < N - 40; i++) s += f(i);
  return s;
};

describe("the screen is linear in a long line of key: value pairs", () => {
  it.each([
    ["setColonRun", fill(" a:")],
    ["optGlued", `npm install ${gen(() => "--a=b,c,d,e:f ")}`],
    ["setColonOneLine", gen((i) => `a${i}_secret: v `)],
  ])("%s", (_name, task) => {
    const t0 = process.cpuUsage();
    screenTask(task);
    const used = process.cpuUsage(t0);
    // About 0.5 s alone, more beside the rest of the suite; the quadratic one took 5 s.
    expect((used.user + used.system) / 1000).toBeLessThan(2000);
  });
});
