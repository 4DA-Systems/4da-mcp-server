// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish review 2026-11-26 (integration build), dependency_check leftovers:
 * 1. an item field the tool does not define (`registry`, `index_url`) was ignored and the package
 *    looked up publicly: the item is refused as written, item by item;
 * 2. crates.io build metadata (`1.0.0+build`) went to crates.io and OSV.dev: Cargo ignores it, so
 *    it is dropped before any lookup and the answer says so;
 * 3. an npm alias in `to` checks the package it installs: the answer names that package first.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
let sent: string[];
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  sent = [];
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    sent.push(`${String(input)} ${typeof init?.body === "string" ? init.body : ""}`);
    return new Response(JSON.stringify({}), { status: 404, headers: { "content-type": "application/json" } });
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const check = async (items: unknown[]) =>
  (await executeDependencyCheck(noDb, { items } as never, new LiveIntelligence(new Database(":memory:")))) as { summary: string; results: Array<Record<string, any>> };

describe("1: an item field this tool does not define refuses that item, and nothing is sent", () => {
  it.each([
    [{ ecosystem: "npm", package: "zqx-ok-name", to: "latest", registry: "https://npm.zqxcorp.internal" }, "registry"],
    [{ ecosystem: "PyPI", package: "zqx_req_x", to: "1.0", index_url: "https://pypi.zqxcorp.internal/simple" }, "index_url"],
    [{ ecosystem: "crates.io", package: "zqx-c", to: "1.0.0", source: "git" }, "source"],
  ])("%j", async (item, field) => {
    const { results } = await check([item, { ecosystem: "npm", package: "lodash", to: "4.17.21" }]);
    expect(results[0]).toMatchObject({ verdict: "unknown", not_checked: "input" });
    expect(results[0].reason).toContain(`unknown field "${field}": this tool reads only the public registry`);
    expect(results[0].reason).toMatch(/nothing was sent/);
    // The rest of the batch is still answered.
    expect(results[1].not_checked).not.toBe("input");
    expect(sent.some((s) => s.includes("lodash"))).toBe(true);
    expect(sent.filter((s) => /zqx/i.test(s))).toEqual([]);
  });

  it("the four defined fields are accepted", async () => {
    const { results } = await check([{ ecosystem: "npm", package: "lodash", to: "4.17.21", from: "4.17.20" }]);
    expect(results[0].not_checked).not.toBe("input");
  });
});

describe("2: crates.io build metadata is ignored, as Cargo ignores it, and never sent", () => {
  it('serde "1.0.0+zqxbuild" is checked as 1.0.0, and the answer says the metadata was ignored', async () => {
    const { results } = await check([{ ecosystem: "crates.io", package: "serde", to: "1.0.0+zqxbuild", from: "0.9.0+zqxfrom" }]);
    expect(results[0].to).toBe("1.0.0");
    expect(results[0].reason).toMatch(/^Build metadata in "1\.0\.0\+\.\.\." was ignored, as Cargo ignores it when resolving: checked 1\.0\.0/);
    expect(sent.some((s) => s.includes("serde"))).toBe(true);
    expect(sent.filter((s) => /zqx/i.test(s))).toEqual([]);
  });

  it("a version without metadata carries no such note", async () => {
    const { results } = await check([{ ecosystem: "crates.io", package: "serde", to: "1.0.0" }]);
    expect(results[0].reason).not.toMatch(/Build metadata/);
  });
});

describe("3: an npm alias in `to` names the package actually checked first", () => {
  it('{lodash, "npm:zqx-alias-to@1.0.0"} leads with the alias target, never reads as lodash', async () => {
    const { results } = await check([{ ecosystem: "npm", package: "lodash", to: "npm:zqx-alias-to@1.0.0" }]);
    expect(results[0].package).toBe("zqx-alias-to");
    expect(results[0].reason).toMatch(/^Checked zqx-alias-to@1\.0\.0, the package this alias installs, not lodash\. \| /);
  });

  it("an alias naming the same package adds nothing", async () => {
    const { results } = await check([{ ecosystem: "npm", package: "lodash", to: "npm:lodash@4.17.21" }]);
    expect(results[0].reason).not.toMatch(/the package this alias installs/);
  });
});
