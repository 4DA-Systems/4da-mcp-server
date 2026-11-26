// SPDX-License-Identifier: Apache-2.0
/**
 * Sixth review (focused check 6): after OSV.dev answers 500 or closes the connection, the same
 * querybatch body was sent up to 4 times in one call. Retries of one body are now bounded per call.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { runWithCallBudget } from "../call-budget.js";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";

let dir: string;

const lock = (deps: Record<string, string>) =>
  JSON.stringify({
    name: "app",
    version: "1.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { name: "app", version: "1.0.0", dependencies: deps },
      ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` }])),
    },
  });

beforeEach(() => {
  dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-osv-retry-")));
  const deps = { lodash: "4.17.20", minimist: "1.2.5" };
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", version: "1.0.0", dependencies: deps }));
  fs.writeFileSync(path.join(dir, "package-lock.json"), lock(deps));
});

afterEach(() => {
  vi.unstubAllGlobals();
  fs.rmSync(dir, { recursive: true, force: true });
});

function faultyOsv(kind: "500" | "close"): Map<string, number> {
  const sends = new Map<string, number>();
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const body = String(init?.body);
      sends.set(body, (sends.get(body) ?? 0) + 1);
      if (kind === "close") throw new TypeError("fetch failed", { cause: Object.assign(new Error("other side closed"), { code: "UND_ERR_SOCKET" }) });
      return new Response("oops", { status: 500 });
    }
    return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
  });
  return sends;
}

describe("one OSV body is sent at most twice in a call (focused check 6)", () => {
  const tools: Array<[string, (li: LiveIntelligence) => Promise<unknown>]> = [
    ["vulnerability_scan", (li) => executeVulnerabilityScan(null, {}, li)],
    ["what_should_i_know", (li) => executeWhatShouldIKnow(null, { task: "upgrade lodash to 4.17.21 and minimist to 1.2.6" }, li)],
    ["dependency_check", (li) => executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "lodash", to: "4.17.21", from: "4.17.20" }, { ecosystem: "npm", package: "minimist", to: "1.2.6" }] } as never, li)],
    ["upgrade_planner", (li) => executeUpgradePlanner(null, {}, li)],
  ];
  for (const kind of ["500", "close"] as const) {
    for (const [tool, run] of tools) {
      it(`${tool}, after a ${kind === "500" ? "500" : "closed connection"}`, async () => {
        const sends = faultyOsv(kind);
        const li = new LiveIntelligence(new Database(":memory:"));
        li.initFromProjectTree(dir, [{ dir, language: "javascript", deps: ["lodash", "minimist"], devDeps: [], targets: {} }]);
        await runWithCallBudget(Date.now(), () => run(li));
        const most = Math.max(0, ...sends.values());
        expect(most, JSON.stringify([...sends.values()])).toBeLessThanOrEqual(2);
      }, 60_000);
    }
  }
});
