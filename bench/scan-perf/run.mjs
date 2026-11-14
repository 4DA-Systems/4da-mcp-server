// SPDX-License-Identifier: Apache-2.0
/**
 * Scan-performance bench (blind audit round 6). Spawns the built server over stdio and measures,
 * for one project directory:
 *   - scan 1 (cold or warm, depending on the server home's cache)
 *   - scan 2 in the same process, with the outbound requests it made
 *   - the worst `ping` reply time while each scan runs (one ping every 50 ms)
 * and optionally upgrade_planner.
 *
 *   node bench/scan-perf/run.mjs <project-dir> [--home <dir>] [--server <dist/index.js>] [--planner] [--scans N]
 *
 * --as-root starts the server for the project (FOURDA_PROJECT_DIR) and omits project_path, as a host
 * launched in that project does; otherwise every call passes project_path (a fresh resolution per call).
 * --home keeps the server's cache between runs (a fresh temp dir when omitted: a cold run).
 * Outbound requests are counted by a preload that wraps fetch (count-fetch.mjs); proxy variables
 * are cleared so every request goes through fetch.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const project = path.resolve(args[0]);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const home = opt("--home") ?? fs.mkdtempSync(path.join(os.tmpdir(), "scan-perf-"));
fs.mkdirSync(home, { recursive: true });
const server = path.resolve(opt("--server") ?? path.join(here, "..", "..", "dist", "index.js"));
const scans = Number(opt("--scans") ?? 2);
const tool = args.includes("--planner") ? "upgrade_planner" : "vulnerability_scan";

const asRoot = args.includes("--as-root");
const env = { ...process.env, FOURDA_MCP_HOME: home, FOURDA_DB_PATH: path.join(home, "standalone.db"), ...(asRoot ? { FOURDA_PROJECT_DIR: project } : {}) };
for (const k of Object.keys(env)) if (/^(https?|all|no)_proxy$/i.test(k)) delete env[k];
const child = spawn(process.execPath, ["--import", pathToFileURL(path.join(here, "count-fetch.mjs")).href, server], { env, stdio: ["pipe", "pipe", "pipe"] });

let fetches = [];
let errBuf = "";
child.stderr.on("data", (d) => {
  errBuf += d.toString();
  let nl;
  while ((nl = errBuf.indexOf("\n")) >= 0) {
    const line = errBuf.slice(0, nl);
    errBuf = errBuf.slice(nl + 1);
    if (line.startsWith("FETCH ")) fetches.push(line.slice(6));
    else if (process.env.SCAN_PERF_TRACE) console.log(`  [server] ${line}`);
  }
});
const pending = new Map();
let outBuf = "";
child.stdout.on("data", (d) => {
  outBuf += d.toString();
  let nl;
  while ((nl = outBuf.indexOf("\n")) >= 0) {
    const line = outBuf.slice(0, nl).trim();
    outBuf = outBuf.slice(nl + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    const p = pending.get(msg.id);
    if (p) {
      pending.delete(msg.id);
      p(msg);
    }
  }
});
let nextId = 1;
const rpc = (method, params = {}) =>
  new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });

function summarise(list) {
  const by = {};
  for (const f of list) {
    const u = f.split(" ")[1];
    const k = u.includes("/v1/querybatch") ? "osv querybatch" : u.includes("/v1/query") ? "osv /v1/query" : u.includes("/v1/vulns/") ? "osv vulns" : new URL(u).host;
    by[k] = (by[k] ?? 0) + 1;
  }
  return by;
}

async function timed(name, params) {
  fetches = [];
  let worstPing = 0;
  let pings = 0;
  let running = true;
  const pinger = (async () => {
    while (running) {
      const t = performance.now();
      await rpc("ping");
      worstPing = Math.max(worstPing, performance.now() - t);
      pings++;
      await new Promise((r) => setTimeout(r, 50));
    }
  })();
  const t0 = performance.now();
  const res = await rpc("tools/call", { name, arguments: params });
  const ms = performance.now() - t0;
  running = false;
  await pinger;
  const text = res.result?.content?.[0]?.text ?? JSON.stringify(res.error ?? res);
  return { list: fetches, ms: Math.round(ms), worstPingMs: Math.round(worstPing), pings, requests: fetches.length, by: summarise(fetches), text };
}

await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "scan-perf-bench", version: "0" } });
child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
const where = asRoot ? {} : { project_path: project };
const params = tool === "vulnerability_scan" ? { ...where, response_format: "detailed" } : where;
const out = [];
for (let i = 1; i <= scans; i++) {
  const r = await timed(tool, params);
  out.push(r);
  console.log(`${tool} #${i}: ${r.ms} ms, worst ping ${r.worstPingMs} ms (${r.pings} pings), ${r.requests} requests ${JSON.stringify(r.by)}`);
}
const dump = opt("--dump");
if (dump) fs.writeFileSync(dump, out[out.length - 1].text);
const log = opt("--log");
if (log) fs.writeFileSync(log, out.map((r, i) => `## scan ${i + 1}\n${r.list.join("\n")}`).join("\n"));
console.log(`home: ${home}`);
// Close stdin so the server exits on its own (and writes a --cpu-prof profile when NODE_OPTIONS asks).
child.stdin.end();
await Promise.race([new Promise((r) => child.on("exit", r)), new Promise((r) => setTimeout(r, 20000))]);
child.kill();
process.exit(0);
