// SPDX-License-Identifier: Apache-2.0
/**
 * A dependency_check verdict the client has read is in the check ledger once the server has
 * exited, even when the host closes stdin the moment the answer arrives (MCP's stdio shutdown).
 * The guard hook reads that ledger: a verdict lost at shutdown is a checked version the hook
 * keeps stopping.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { LEDGER_FILE, ledgerWritesSettled, recordVerdicts } from "../check-ledger.js";
import { resetShutdownForTests, shutdown } from "../shutdown.js";
import { serverEntry } from "./helpers/stdio-session.js";

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-triage-ledger-"));
afterAll(() => {
  try {
    fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    // Windows can hold a just-exited child's files for a moment; left for the OS temp cleaner.
  }
});

/** One session: initialize, one dependency_check, stdin closed as soon as it is answered. Returns the ledger text after exit. */
async function checkThenClose(n: number): Promise<{ ledger: string; answered: boolean }> {
  const home = path.join(scratch, `home-${n}`);
  const proj = path.join(scratch, `proj-${n}`);
  fs.mkdirSync(proj, { recursive: true });
  fs.writeFileSync(path.join(proj, "package.json"), JSON.stringify({ name: "guard-app", version: "1.0.0", dependencies: { minimist: "^1.2.0" } }));
  const preload = path.join(scratch, "no-network.cjs");
  fs.writeFileSync(preload, `globalThis.fetch = async (u) => { throw new TypeError("fetch blocked in test: " + String(u)); };\n`);
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const k of Object.keys(env)) if (/^FOURDA_/i.test(k) || k === "NODE_OPTIONS") delete env[k];
  Object.assign(env, { FOURDA_MCP_HOME: home, FOURDA_DATA_DIR: path.join(scratch, `no-app-${n}`) });
  const child = spawn(process.execPath, ["--require", preload, serverEntry], { cwd: proj, env, stdio: ["pipe", "pipe", "pipe"] });
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  let buffer = "";
  let answered = false;
  child.stderr.resume();
  child.stdout.on("data", (d) => {
    buffer += d;
    let i: number;
    while ((i = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, i).trim();
      buffer = buffer.slice(i + 1);
      if (!line) continue;
      const m = JSON.parse(line) as { id?: number };
      if (m.id === 1) {
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
        child.stdin.write(
          JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "dependency_check", arguments: { items: [{ ecosystem: "npm", package: "minimist", to: "1.2.8" }] } } }) + "\n",
        );
      } else if (m.id === 2) {
        answered = true;
        child.stdin.end();
      }
    }
  });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } } }) + "\n");
  const killer = setTimeout(() => child.kill(), 60_000);
  await exited;
  clearTimeout(killer);
  const file = path.join(home, LEDGER_FILE);
  return { ledger: fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "", answered };
}

describe.skipIf(!fs.existsSync(serverEntry))("the built server records a verdict before it exits on stdin close", () => {
  it("every session's answered verdict is in its ledger after exit", { timeout: 120_000 }, async () => {
    const runs = await Promise.all([0, 1, 2, 3, 4].map((n) => checkThenClose(n)));
    for (const r of runs) {
      expect(r.answered).toBe(true);
      const entries = r.ledger.split("\n").filter(Boolean).map((l) => JSON.parse(l) as { package: string; version: string });
      expect(entries.some((e) => e.package === "minimist" && e.version === "1.2.8")).toBe(true);
    }
  });
});

describe("ledgerWritesSettled", () => {
  it("a shutdown that waits on it exits only after the queued write is on disk", async () => {
    const dir = path.join(scratch, "in-process");
    void recordVerdicts([{ ecosystem: "npm", package: "minimist", to: "1.2.8", verdict: "proceed" }], { dir });
    let atExit = "";
    resetShutdownForTests();
    await new Promise<void>((resolve) => {
      shutdown("test", {
        close: [() => ledgerWritesSettled()],
        exit: () => {
          const file = path.join(dir, LEDGER_FILE);
          atExit = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
          resolve();
        },
      });
    });
    resetShutdownForTests();
    expect(atExit).toContain('"package":"minimist"');
  });
});
