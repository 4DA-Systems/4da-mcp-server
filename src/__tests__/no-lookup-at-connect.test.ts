// SPDX-License-Identifier: Apache-2.0
/**
 * Nothing leaves the machine until a tool that needs it is called (audit 2026-11-11 A1 #7,
 * confirmed): with zero tool calls, `initialize` + `tools/list` started the background init,
 * whose vulnerability warmup sent every dependency name in the project to OSV.dev (a cache row
 * `osv:v3:npm:lodash:...` appeared). The spawned server's `fetch` records every attempt.
 *
 * Runs dist/ (CI builds before testing); skipped when there is no build.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { serverEntry, stdioSession } from "./helpers/stdio-session.js";

let scratch: string;

describe.skipIf(!fs.existsSync(serverEntry))("a session with no tool call makes no outbound request", () => {
  beforeAll(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-no-connect-lookup-"));
    fs.writeFileSync(path.join(scratch, "package.json"), JSON.stringify({ name: "app", dependencies: { lodash: "4.17.20" } }));
    fs.writeFileSync(
      path.join(scratch, "package-lock.json"),
      JSON.stringify({
        name: "app",
        lockfileVersion: 3,
        packages: { "": { name: "app", dependencies: { lodash: "4.17.20" } }, "node_modules/lodash": { version: "4.17.20" } },
      }),
    );
  });

  afterAll(() => {
    try {
      fs.rmSync(scratch, { recursive: true, force: true });
    } catch {
      // Windows can hold a just-exited child's files for a moment.
    }
  });

  it("initialize + tools/list + resources/list, then idle: zero fetches", async () => {
    // The background init runs 50 ms after the first listing: wait until it has scanned the
    // project (a fresh database on a loaded host can take many seconds), then 3 s more.
    const session = await stdioSession(scratch, [], {}, { idleAfterListMs: 3_000, idleUntilStderr: "Standalone mode: scanned" });
    expect(session.tools).toContain("dependency_check");
    expect(session.stderr).toContain("Standalone mode: scanned");
    expect(session.fetches).toEqual([]);
  }, 120_000);

  it("a tool that needs no network sends nothing either; a scan is what starts the lookups", async () => {
    const session = await stdioSession(scratch, [["decision_memory", { action: "list" }], ["vulnerability_scan", {}]], {}, { idleAfterListMs: 500 });
    expect(session.fetches.length).toBeGreaterThan(0);
    expect(session.fetches.every((u) => u.includes("osv.dev"))).toBe(true);
  }, 180_000);
});
