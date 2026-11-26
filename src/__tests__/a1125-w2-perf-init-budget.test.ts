// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, Track F, M1: on 20 lockfiles of 62 MB the first call took 64-78 s against its
 * 20 s budget, because the tool call waited for the project's init before its budget was raced.
 * Now a call whose budget ends while the init is still reading says so plainly (NOT CHECKED, how
 * many MB, call again), the init goes on, and a later call gets the whole answer. A call never
 * finishes the init synchronously in that state.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { resultText, serverEntry, stdioSession } from "./helpers/stdio-session.js";

let dir: string;

beforeAll(() => {
  dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-init-budget-")));
  // About 30,000 entries (made-up names; the session's fetch is refused anyway).
  const packages: Record<string, unknown> = { "": { name: "app", version: "1.0.0", dependencies: { "zqpkg-0": "^1.0.0" } } };
  for (let i = 0; i < 30_000; i++) {
    const name = `zqpkg-${i}`;
    packages[`node_modules/${name}`] = { version: "1.0.0", resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`, dependencies: i + 1 < 30_000 ? { [`zqpkg-${i + 1}`]: "^1.0.0" } : undefined };
  }
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "zqpkg-0": "^1.0.0" } }));
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "app", version: "1.0.0", lockfileVersion: 3, requires: true, packages }));
});

afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("a call whose budget ends while the project is still being read (audit 2026-11-25, F-M1)", () => {
  it.skipIf(!fs.existsSync(serverEntry))("says so, keeps reading, and a later call gets the whole answer", async () => {
    const calls: Array<[string, Record<string, unknown>]> = Array.from({ length: 60 }, () => ["vulnerability_scan", {}]);
    // A 40 ms budget: the init of a 30,000-entry lockfile takes longer than one call has.
    const session = await stdioSession(dir, calls, { FOURDA_CALL_BUDGET_MS: "40", FOURDA_OFFLINE: "1" }, { requestTimeoutMs: 10_000 });
    const texts = session.results.map(resultText);
    // How many MB is said once the walk has found the lockfiles; a call that ran out before that says no size.
    expect(texts[0]).toMatch(/^\{"error":"NOT CHECKED: this project's lockfiles (\(\d[\d,]* MB in 1 project\) )?were still being read when this call's 40 ms ran out/);
    expect(texts.some((t) => /\(\d[\d,]* MB in 1 project\) were still being read/.test(t))).toBe(true);
    expect(session.results[0].isError).toBe(true);
    expect(texts[0]).toContain("call again");
    // The init went on: a later call answered from the read project.
    const later = texts.findIndex((t) => !t.includes("were still being read"));
    expect(later).toBeGreaterThan(0);
    expect(texts[later]).toMatch(/30,00\d|30000|NOT CHECKED/);
    expect(texts.slice(later).every((t) => !t.includes("were still being read"))).toBe(true);
  }, 120_000);
});
