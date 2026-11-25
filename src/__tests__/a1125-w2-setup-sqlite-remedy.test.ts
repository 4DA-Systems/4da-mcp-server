// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, H-5 and Track F m2: with no usable SQLite driver the server's message told users
 * to run `npx clear-npx-cache` (a third-party package, unpinned), named npm 12 steps on a Node.js that
 * npm 12 does not run on (better-sqlite3 is needed only on 22.0-22.12 and 23.0-23.3), printed the
 * whole remedy twice in one line, cut the cause to "The module '...better_sqlite3.node'" (dropping
 * "was compiled against a different Node.js version ... NODE_MODULE_VERSION"), and told a Node 23.0
 * user to upgrade to 22.13. Now: one paragraph, said once, the whole cause, the minimum for that Node
 * line, and no command that runs anyone else's code.
 */
import { describe, expect, it } from "vitest";

import { nativeBindingCause, nativeBindingMessage, nativeBindingRemedy } from "../native-bindings.js";
import { resolveSqliteDriver } from "../sqlite-driver.js";

const ABI = new Error(
  "The module '\\\\?\\C:\\app\\node_modules\\better-sqlite3\\build\\Release\\better_sqlite3.node'\n" +
    "was compiled against a different Node.js version using\n" +
    "NODE_MODULE_VERSION 127. This version of Node.js requires\n" +
    "NODE_MODULE_VERSION 115. Please try re-compiling or re-installing\n" +
    "the module (for instance, using `npm rebuild` or `npm install`).",
);
const MISSING = new Error("Could not locate the bindings file. Tried:\n → /t/node_modules/better-sqlite3/build/better_sqlite3.node");

/** Nothing that runs a package or a script: no npx, no third-party cache cleaner, no npm 12 steps. */
function expectNoForeignCommand(text: string): void {
  expect(text).not.toMatch(/\bnpx\s/);
  expect(text).not.toContain("clear-npx-cache");
  expect(text).not.toContain("allow-scripts");
  expect(text).not.toContain("install-scripts approve");
  expect(text).not.toMatch(/npm 12/);
}

describe("the remedy names the minimum for the Node line that runs the server", () => {
  it("22.0-22.12: 22.13", () => {
    for (const v of ["22.0.0", "22.12.0"]) {
      const r = nativeBindingRemedy(v);
      expect(r).toContain("Node.js 22.13 and later have a built-in SQLite driver");
      expect(r).toContain(`this is ${v}`);
      expectNoForeignCommand(r);
    }
  });

  it("23.0-23.3: 23.4, never 'upgrade to 22.13'", () => {
    for (const v of ["23.0.0", "23.3.0"]) {
      const r = nativeBindingRemedy(v);
      expect(r).toContain("Node.js 23.4 and later (22.13 and later have it too)");
      expect(r).not.toMatch(/upgrade Node\.js to 22/);
      expectNoForeignCommand(r);
    }
  });

  it("a Node that has the built-in driver: says so (better-sqlite3 was forced, or failed besides it)", () => {
    for (const v of ["22.13.0", "23.4.0", "24.15.0", "26.0.0"]) {
      const r = nativeBindingRemedy(v);
      expect(r).toContain(`This Node.js (${v}) has the built-in SQLite driver`);
      expect(r).toContain("FOURDA_SQLITE_DRIVER");
      expectNoForeignCommand(r);
    }
  });

  it("the reinstall is in words: npm's own cache folder, no command that runs a package", () => {
    const r = nativeBindingRemedy("22.12.0");
    expect(r).toContain("reinstall @4da/mcp-server with the Node.js that runs it");
    expect(r).toContain("npm config get cache");
    expect(r).toContain("not --ignore-scripts");
  });
});

describe("the cause is kept whole", () => {
  it("an ABI mismatch keeps 'compiled against a different Node.js version' and both module versions", () => {
    const cause = nativeBindingCause(ABI);
    expect(cause).toContain("was compiled against a different Node.js version");
    expect(cause).toContain("NODE_MODULE_VERSION 127");
    expect(cause).toContain("NODE_MODULE_VERSION 115");
    expect(cause).not.toContain("\n");
  });

  it("a missing module drops its list of paths", () => {
    expect(nativeBindingCause(MISSING)).toBe("Could not locate the bindings file");
  });

  it("a very long cause is capped", () => {
    expect(nativeBindingCause(new Error("x".repeat(5000))).length).toBeLessThan(410);
  });
});

describe("the driver problem says the remedy once", () => {
  const nodeMissing = () => {
    throw new Error("No such built-in module: node:sqlite");
  };
  const abiBroken = (() => function () {
    throw ABI;
  }) as unknown as Parameters<typeof resolveSqliteDriver>[0]["better"];

  it("no driver: the cause of each, then one remedy", () => {
    const res = resolveSqliteDriver({ node: nodeMissing as never, better: abiBroken }, {});
    expect(res.driver).toBeNull();
    const problem = res.problem!;
    expect(problem.split("reinstall @4da/mcp-server").length - 1).toBe(1);
    expect(problem).toContain("was compiled against a different Node.js version");
    expectNoForeignCommand(problem);
  });

  it("forced better-sqlite3: the cause, no remedy paragraph, and 'unset it'", () => {
    const res = resolveSqliteDriver({ node: nodeMissing as never, better: abiBroken }, { FOURDA_SQLITE_DRIVER: "better" });
    expect(res.problem).toContain("Unset it");
    expect(res.problem).toContain("NODE_MODULE_VERSION 115");
    expect(res.problem!.split("reinstall @4da/mcp-server").length - 1).toBe(0);
  });

  it("the message db.ts prints alone has the cause and the remedy, once each", () => {
    const m = nativeBindingMessage(ABI);
    expect(m.split("NODE_MODULE_VERSION 115").length - 1).toBe(1);
    expect(m.split("reinstall @4da/mcp-server").length - 1).toBe(1);
    expectNoForeignCommand(m);
  });
});
