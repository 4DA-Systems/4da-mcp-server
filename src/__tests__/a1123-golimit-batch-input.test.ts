// SPDX-License-Identifier: Apache-2.0
/**
 * One item the server refuses no longer fails the whole batch: the others are answered, and the
 * refused one is unknown in its place with the refusal as its reason (`not_checked: "input"`). A
 * call whose every item is refused is still refused whole. An npm name written as a scope without
 * its `@` (`babel/core`) is not a package name npm can have: it is refused as such, with the scoped
 * spelling suggested, and never sent (the registry answered it HTTP 405, which read as "registry
 * could not be reached").
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { runWithCallBudget } from "../call-budget.js";
import { executeDependencyCheck, runDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, npmDoc, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-23T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  net.npm["left-pad"] = npmDoc("left-pad", { "1.2.0": { at: daysAgo(1200) }, "1.3.0": { at: daysAgo(900) } });
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

const check = (items: unknown[]) => executeDependencyCheck(noDb, { items }, new LiveIntelligence(new Database(":memory:")), { now: NOW });
const sentFor = (name: string) => net.requests.filter((r) => r.includes(name));
const GOOD = { ecosystem: "npm", package: "left-pad", to: "1.3.0" };

describe("a batch with an item the server refuses", () => {
  it("answers the other items, and the refused one in its place with why", async () => {
    const out = await check([GOOD, { ecosystem: "npm", package: "typescript", to: "beta" }, { ecosystem: "PyPI", package: "requests", to: "^2.19" }]);
    expect(out.results).toHaveLength(3);
    expect(out.results[0]).toMatchObject({ package: "left-pad", to: "1.3.0", verdict: "proceed" });
    expect(out.results[1]).toMatchObject({ ecosystem: "npm", package: "typescript", to: "beta", verdict: "unknown", not_checked: "input" });
    expect(out.results[1].reason).toMatch(/^NOT CHECKED: items\[1\]\.to must be an exact version, "latest", or a npm version constraint/);
    expect(out.results[1].reason).toContain("Nothing was looked up for it");
    expect(out.results[2]).toMatchObject({ ecosystem: "PyPI", package: "requests", verdict: "unknown", not_checked: "input" });
    expect(out.results[2].reason).toContain('items[2].to must be an exact version, "latest", or a PyPI version constraint');
    expect(sentFor("typescript")).toEqual([]);
    expect(sentFor("requests")).toEqual([]);
    expect(out.summary).toMatch(/^NOT CHECKED: 2 of 3 items were refused as written \(not_checked: "input"; each reason says why\)/);
  });

  it("the same inside a tool call's time budget, where items are checked one by one", async () => {
    const out = await runWithCallBudget(Date.now(), () => check([{ ecosystem: "cargo", package: "serde", to: "1.0.0" }, GOOD]));
    expect(out.results.map((r) => [r.package, r.verdict, r.not_checked])).toEqual([
      ["serde", "unknown", "input"],
      ["left-pad", "proceed", undefined],
    ]);
    expect(out.results[0].reason).toContain('items[0].ecosystem must be one of "npm", "crates.io", "PyPI", "Go"');
  });

  it("the concise answer carries not_checked for the refused item", async () => {
    const out = (await runDependencyCheck(noDb, { items: [GOOD, { ecosystem: "npm", package: "typescript", to: "beta" }] }, new LiveIntelligence(new Database(":memory:")))) as { results: Array<Record<string, unknown>> };
    expect(out.results[1]).toMatchObject({ verdict: "unknown", not_checked: "input" });
  });

  it("a call whose every item is refused is refused whole, as before", async () => {
    await expect(check([{ ecosystem: "npm", package: "typescript", to: "beta" }])).rejects.toThrow(/items\[0\]\.to must be an exact version/);
    await expect(check([{ ecosystem: "npm", package: "", to: "1.0.0" }, { ecosystem: "golang", package: "x", to: "v1.0.0" }])).rejects.toThrow(/items\[0\]\.package must be a non-empty string/);
    await expect(check([])).rejects.toThrow(/items must be an array of 1 to 25/);
  });
});

describe("an npm scope written without its @", () => {
  it("babel/core alone: not a valid npm package name, @babel/core suggested, nothing sent, never 'registry could not be reached'", async () => {
    const out = await check([{ ecosystem: "npm", package: "babel/core", to: "7.0.0" }]);
    expect(out.results[0]).toMatchObject({ package: "babel/core", verdict: "unknown", not_checked: "input" });
    expect(out.results[0].reason).toBe(
      'NOT CHECKED: "babel/core" is not a valid npm package name: a scoped package is written "@scope/name" (did you mean "@babel/core"?). Nothing was sent to the npm registry or OSV.dev: correct it and ask again. This is not a clean result.',
    );
    expect(sentFor("babel")).toEqual([]);
    expect(out.summary).toMatch(/^NOT CHECKED: 1 of 1 item was refused as written/);
  });

  it("a private name written that way is still answered as private, never sent", async () => {
    const prior = process.env.FOURDA_PRIVATE_PACKAGES;
    process.env.FOURDA_PRIVATE_PACKAGES = "npm:@acme/*";
    try {
      const out = await check([{ ecosystem: "npm", package: "acme/ui", to: "1.0.0" }]);
      expect(out.results[0]).toMatchObject({ verdict: "unknown", not_checked: "private" });
      expect(sentFor("acme")).toEqual([]);
    } finally {
      if (prior === undefined) delete process.env.FOURDA_PRIVATE_PACKAGES;
      else process.env.FOURDA_PRIVATE_PACKAGES = prior;
    }
  });

  it("in a batch: that item is refused in its place, the others answered, and nothing about it is sent", async () => {
    const out = await check([{ ecosystem: "npm", package: "types/node", to: "latest" }, GOOD]);
    expect(out.results[0]).toMatchObject({ package: "types/node", verdict: "unknown", not_checked: "input" });
    expect(out.results[0].reason).toContain('did you mean "@types/node"?');
    expect(out.results[0].reason).not.toMatch(/could not be reached|HTTP 405/);
    expect(out.results[1].verdict).toBe("proceed");
    expect(sentFor("types")).toEqual([]);
  });

  it("other malformed scopes are refused without a guess; a well-formed scoped or plain name is looked up", async () => {
    const out = await check([
      { ecosystem: "npm", package: "@babel", to: "7.0.0" },
      { ecosystem: "npm", package: "@babel/core/extra", to: "7.0.0" },
      { ecosystem: "npm", package: "@babel/core", to: "7.0.0" },
      GOOD,
    ]);
    expect(out.results.slice(0, 2).map((r) => r.not_checked)).toEqual(["input", "input"]);
    expect(out.results[0].reason).not.toContain("did you mean");
    expect(out.results[2].not_checked).toBeUndefined();
    expect(sentFor("@babel%2fcore").length + sentFor("@babel/core").length).toBeGreaterThan(0);
    expect(sentFor("extra")).toEqual([]);
  });
});
