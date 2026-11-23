// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check records each final verdict in a local ledger in the data folder
 * (check-ledger.ts), which the plugin hook reads before an edit runs. The ledger holds the exact
 * version judged (a constraint's pick, with the constraint beside it), the verdict and the time;
 * it is bounded, survives writers running together, and a ledger that cannot be written never
 * changes the tool's answer.
 */

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Database from "better-sqlite3";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { LEDGER_FILE, LEDGER_MAX_BYTES, LEDGER_PREVIOUS_FILE, ledgerEntries, recordVerdicts, type LedgerEntry } from "../check-ledger.js";
import type { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { runDependencyCheck } from "../tools/dependency-check.js";
import { advisory, emptyNet, npmDoc, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();

let home: string;
let outerHome: string | undefined;
let net: Net;
let restore: () => void;

beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  outerHome = process.env.FOURDA_MCP_HOME;
  home = mkdtempSync(join(tmpdir(), "a1123-guard-ledger-"));
  process.env.FOURDA_MCP_HOME = home;
  net = emptyNet();
  net.npm["lodash"] = npmDoc("lodash", { "4.17.20": { at: daysAgo(900) }, "4.17.21": { at: daysAgo(700) }, "4.18.1": { at: daysAgo(60) } });
  net.osv = [advisory("GHSA-lodash-test", "npm", "lodash", "4.17.21", { severity: "HIGH" })];
  stubNet(net);
});
afterEach(async () => {
  await recordVerdicts([]);
  vi.unstubAllGlobals();
  if (outerHome === undefined) delete process.env.FOURDA_MCP_HOME;
  else process.env.FOURDA_MCP_HOME = outerHome;
  rmSync(home, { recursive: true, force: true });
});

const lines = (dir: string, file = LEDGER_FILE): LedgerEntry[] =>
  readFileSync(join(dir, file), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as LedgerEntry);

const check = async (items: unknown[]) => {
  const answer = (await runDependencyCheck(noDb, { items }, new LiveIntelligence(new Database(":memory:")))) as { results: Array<Record<string, unknown>> };
  // The tool does not wait for the ledger; an empty record call waits for the writes queued before it.
  await recordVerdicts([]);
  return answer;
};

describe("dependency_check records each final verdict in the data folder", () => {
  it("one line per item: ecosystem, package, the exact version judged, verdict, time", async () => {
    const before = Date.now();
    const answer = await check([
      { ecosystem: "npm", package: "lodash", to: "4.17.20" },
      { ecosystem: "npm", package: "lodash", to: "4.18.1", from: "4.17.20" },
    ]);
    expect(answer.results.map((r) => r.verdict)).toEqual(["avoid", "proceed"]);
    const entries = lines(home);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid" });
    expect(entries[1]).toMatchObject({ ecosystem: "npm", package: "lodash", version: "4.18.1", verdict: "proceed" });
    for (const e of entries) {
      expect(Date.parse(e.t)).toBeGreaterThanOrEqual(before - 1000);
      expect(Date.parse(e.t)).toBeLessThanOrEqual(Date.now() + 1000);
    }
    // The avoid carries the server's own one-line reason, for the hook to repeat.
    expect(entries[0].reason).toBe(answer.results[0].reason);
    expect(entries[0].reason).toContain("GHSA-lodash-test");
  });

  it("a constraint is recorded at the release it resolved to, with the constraint beside it", async () => {
    const answer = await check([{ ecosystem: "npm", package: "lodash", to: "^4.17.0" }]);
    const r = answer.results[0];
    const [entry] = lines(home);
    expect(entry).toMatchObject({ ecosystem: "npm", package: "lodash", version: r.to, verdict: r.verdict, requested: "^4.17.0" });
    expect(entry.version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("a ledger that cannot be written leaves the answer as it was", async () => {
    const answer = await check([{ ecosystem: "npm", package: "lodash", to: "4.17.20" }]);
    // The data folder is a file: nothing can be written under it.
    const blocked = join(home, "blocked");
    writeFileSync(blocked, "not a folder");
    process.env.FOURDA_MCP_HOME = blocked;
    const again = await check([{ ecosystem: "npm", package: "lodash", to: "4.17.20" }]);
    expect(again.results).toEqual(answer.results);
    expect(statSync(blocked).isFile()).toBe(true);
  });

  it("a refused call (bad input) records nothing", async () => {
    await expect(check([{ ecosystem: "npm", package: "lodash", to: "beta" }])).rejects.toThrow();
    expect(existsSync(join(home, LEDGER_FILE))).toBe(false);
  });
});

describe("the ledger stays small and tolerates writers together", () => {
  const item = (n: number, reason = "No advisory, age, trust or new-dependency concern found.") => ({ ecosystem: "npm", package: `pkg-${n}`, to: `1.0.${n}`, verdict: "proceed", reason });

  it("past its bound it is moved aside and a new one started; the two together stay bounded", async () => {
    const dir = mkdtempSync(join(tmpdir(), "a1123-guard-rotate-"));
    try {
      // About 500 bytes a line, 2,500 lines: well past twice the bound in all.
      for (let round = 0; round < 100; round++) await recordVerdicts(Array.from({ length: 25 }, (_, i) => item(round * 25 + i, "r".repeat(380))), { dir });
      const size = (f: string) => (existsSync(join(dir, f)) ? statSync(join(dir, f)).size : 0);
      expect(size(LEDGER_PREVIOUS_FILE)).toBeGreaterThan(LEDGER_MAX_BYTES / 2);
      expect(size(LEDGER_FILE)).toBeLessThanOrEqual(LEDGER_MAX_BYTES);
      expect(size(LEDGER_FILE) + size(LEDGER_PREVIOUS_FILE)).toBeLessThanOrEqual(2 * LEDGER_MAX_BYTES);
      // The newest entry is in the current file.
      expect(lines(dir).at(-1)).toMatchObject({ package: "pkg-2499", version: "1.0.2499" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("many writes started together all land, each on its own whole line", async () => {
    const dir = mkdtempSync(join(tmpdir(), "a1123-guard-many-"));
    try {
      await Promise.all(Array.from({ length: 50 }, (_, n) => recordVerdicts([item(n), item(n + 1000)], { dir })));
      const entries = lines(dir);
      expect(entries).toHaveLength(100);
      expect(new Set(entries.map((e) => e.package)).size).toBe(100);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a reason is kept to one capped line; control characters do not survive", () => {
    const [e] = ledgerEntries([{ ecosystem: "npm", package: "x", to: "1.0.0", verdict: "avoid", reason: `bad\nline\u001b[31m ${"y".repeat(2000)}` }]);
    expect(e.reason).not.toContain("\n");
    expect(e.reason).not.toContain("\u001b");
    expect(e.reason!.length).toBeLessThanOrEqual(400);
  });

  it("a folder that does not exist yet is created", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "a1123-guard-new-")), "nested", "home");
    try {
      await recordVerdicts([item(1)], { dir });
      expect(lines(dir)).toHaveLength(1);
    } finally {
      rmSync(join(dir, "..", ".."), { recursive: true, force: true });
    }
  });

  it("an existing torn line does not stop the next append", async () => {
    const dir = mkdtempSync(join(tmpdir(), "a1123-guard-torn-"));
    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, LEDGER_FILE), '{"t":"2026-11-23T00:00:00.000Z","ecosystem":"npm","pack');
      await recordVerdicts([item(7)], { dir });
      const parsed = readFileSync(join(dir, LEDGER_FILE), "utf8")
        .split("\n")
        .flatMap((l) => {
          try {
            return [JSON.parse(l) as LedgerEntry];
          } catch {
            return [];
          }
        });
      expect(parsed).toEqual([expect.objectContaining({ package: "pkg-7", version: "1.0.7", verdict: "proceed" })]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
