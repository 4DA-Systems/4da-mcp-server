// SPDX-License-Identifier: Apache-2.0
/**
 * Round 16 (J3), end to end: a name from a registry that is not private by its shape is judged; the
 * server, told the name is private (FOURDA_PRIVATE_PACKAGES), records it so in the ledger without
 * looking it up (no network: every fetch fails), and the hook then lets the same command through.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Database from "better-sqlite3";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

import { recordVerdicts, startLedger } from "../check-ledger.js";
import type { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { runDependencyCheck } from "../tools/dependency-check.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");
let home: string;
let project: string;
const saved: Record<string, string | undefined> = {};
beforeEach(async () => {
  home = mkdtempSync(join(tmpdir(), "a1125-r16-private-home-"));
  project = mkdtempSync(join(tmpdir(), "a1125-r16-private-proj-"));
  for (const k of ["FOURDA_MCP_HOME", "FOURDA_PRIVATE_PACKAGES", "HTTPS_PROXY", "HTTP_PROXY"]) saved[k] = process.env[k];
  process.env.FOURDA_MCP_HOME = home;
  process.env.FOURDA_PRIVATE_PACKAGES = "zqx-acme-widget";
  process.env.HTTPS_PROXY = process.env.HTTP_PROXY = "http://127.0.0.1:9";
  vi.stubGlobal("fetch", async () => {
    throw new Error("no network in this test");
  });
  writeFileSync(join(home, "check-ledger.jsonl"), "");
  await startLedger({ dir: home });
});
afterEach(async () => {
  await recordVerdicts([]);
  vi.unstubAllGlobals();
  for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k];
  else process.env[k] = v;
  rmSync(home, { recursive: true, force: true });
  rmSync(project, { recursive: true, force: true });
});

const hook = (command: string) => {
  const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: home };
  delete env.FOURDA_GUARD;
  return spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ session_id: "s", cwd: project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } }), encoding: "utf8", env }).stdout;
};

it("judged, recorded private by the server, then let through", async () => {
  const command = "npm install --registry https://npm.mycorp.com zqx-acme-widget@1.0.0";
  const held = hook(command);
  expect(held).toContain('"deny"');
  expect(held).toContain("FOURDA_PRIVATE_PACKAGES");
  const answer = (await runDependencyCheck(null as unknown as FourDADatabase, { items: [{ ecosystem: "npm", package: "zqx-acme-widget", to: "1.0.0" }] }, new LiveIntelligence(new Database(":memory:")))) as { results: Array<{ not_checked?: string }> };
  expect(answer.results[0].not_checked).toBe("private");
  await recordVerdicts([]);
  expect(hook(command)).toBe("");
});
