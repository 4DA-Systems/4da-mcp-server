// SPDX-License-Identifier: Apache-2.0
/**
 * Wave 2 review: an item field written " to" (a leading blank) was refused as `unknown field "to"`,
 * which names a field the tool defines. The refusal keeps the blank and says so.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  vi.stubGlobal("fetch", async () => new Response("{}", { status: 404 }));
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const refusal = async (item: Record<string, unknown>) => {
  const out = (await executeDependencyCheck(noDb, { items: [item, { ecosystem: "npm", package: "lodash", to: "4.17.21" }] } as never, new LiveIntelligence(new Database(":memory:")))) as {
    results: Array<{ not_checked?: string; reason: string }>;
  };
  expect(out.results[0].not_checked).toBe("input");
  return out.results[0].reason;
};

describe("an unknown field is named as written, blanks included", () => {
  it('" to": a leading blank', async () => {
    expect(await refusal({ ecosystem: "npm", package: "lodash", " to": "4.17.21", to: "4.17.21" })).toContain('unknown field " to" (with a leading blank)');
  });
  it('"to ": a trailing blank', async () => {
    expect(await refusal({ ecosystem: "npm", package: "lodash", "to ": "4.17.21", to: "4.17.21" })).toContain('unknown field "to " (with a trailing blank)');
  });
  it("a plain unknown field carries no blank note, and a '|' cannot split the reason", async () => {
    const reason = await refusal({ ecosystem: "npm", package: "lodash", to: "4.17.21", "a|b": "x" });
    expect(reason).toContain('unknown field "a/b": this tool');
    expect(reason).not.toMatch(/blank\)/);
  });
});
