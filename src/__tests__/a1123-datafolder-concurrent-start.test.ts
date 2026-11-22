// SPDX-License-Identifier: Apache-2.0
/**
 * Servers started together on a fresh data folder, through the built server. One of them creates
 * `standalone.db`; the others used to find the file before its schema was committed, took it for
 * the desktop app's database (no marker yet), listed 11 tools and later 16, and answered
 * `get_context` with another project's stack. The own store is now known by its path.
 *
 * Runs dist/ (CI builds before testing); skipped when there is no build. Offline: the preload in
 * stdioSession refuses every fetch, and only tools that make no lookup are called.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { resultText, serverEntry, stdioSession } from "./helpers/stdio-session.js";

const SPAWN_TIMEOUT_MS = 240_000;
let scratch: string;

const write = (rel: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(scratch, rel)), { recursive: true });
  fs.writeFileSync(path.join(scratch, rel), content);
};

beforeAll(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-concurrent-"));
  write("js/package.json", JSON.stringify({ name: "js-app", dependencies: { lodash: "4.17.21" } }));
  write("js/package-lock.json", JSON.stringify({ name: "js-app", lockfileVersion: 3, packages: { "": { name: "js-app" }, "node_modules/lodash": { version: "4.17.21" } } }));
  write("py/requirements.txt", "requests==2.32.3\n");
  for (let k = 0; k < 4; k++) fs.mkdirSync(path.join(scratch, `empty-${k}`), { recursive: true });
});

afterAll(() => {
  try {
    fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    // Windows can hold a just-exited child's files for a moment; left for the OS temp cleaner.
  }
});

describe.skipIf(!fs.existsSync(serverEntry))("servers started together on one fresh data folder", () => {
  it("every session runs on the server's own store: 11 tools throughout, its own project's stack, writes kept", async () => {
    for (let rep = 0; rep < 3; rep++) {
      const home = path.join(scratch, `home-${rep}`);
      fs.mkdirSync(home, { recursive: true });
      const cwds = [path.join(scratch, "js"), path.join(scratch, "py"), ...[0, 1, 2, 3].map((k) => path.join(scratch, `empty-${k}`))];
      const sessions = await Promise.all(
        cwds.map((cwd, k) =>
          stdioSession(
            cwd,
            k < 2
              ? [["get_context", {}], ["agent_memory", { action: "store", subject: `race-${rep}-${k}`, content: "kept" }]]
              : [["agent_memory", { action: "store", subject: `race-${rep}-${k}`, content: "kept" }]],
            { FOURDA_MCP_HOME: home },
            { listAfterCalls: true },
          ),
        ),
      );
      for (const [k, s] of sessions.entries()) {
        expect(s.tools, `rep ${rep} session ${k}: tools/list`).toHaveLength(11);
        expect(s.stderr, `rep ${rep} session ${k}`).not.toMatch(/tracks no project|Database validated — 0 tables/);
        for (const r of s.results) expect(r.isError, `rep ${rep} session ${k}: ${resultText(r).slice(0, 200)}`).toBeFalsy();
      }
      const stack = (k: number) => (JSON.parse(resultText(sessions[k].results[0])) as { tech_stack: string[] }).tech_stack;
      expect(stack(0), `rep ${rep}: the JavaScript project`).toEqual(["javascript"]);
      expect(stack(1), `rep ${rep}: the Python project`).toEqual(["python"]);
    }
  }, SPAWN_TIMEOUT_MS);
});
