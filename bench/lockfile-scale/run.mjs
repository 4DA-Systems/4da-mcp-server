// SPDX-License-Identifier: Apache-2.0
/**
 * Lockfile-scale bench (pre-publish round 7): how long the FIRST tool call blocks, the worst
 * `ping` reply while it runs, and the server's peak memory, for one generated project.
 *
 *   node bench/lockfile-scale/gen.mjs npm 100000 <dir>
 *   node bench/lockfile-scale/run.mjs <dir> [--server <dist/index.js>] [--tool vulnerability_scan]
 *
 * The names gen.mjs writes are made up, so every lookup goes to a dead proxy (127.0.0.1:9) and
 * fails at once: nothing leaves the machine, and every dependency comes back unanswered (NOT
 * CHECKED), the path that overflowed the stack at 150,000 entries in 6.3.0 before round 7.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const project = path.resolve(args[0]);
const opt = (flag) => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};
const server = path.resolve(opt("--server") ?? path.join(here, "..", "..", "dist", "index.js"));
const tool = opt("--tool") ?? "vulnerability_scan";
const home = fs.mkdtempSync(path.join(os.tmpdir(), "lockfile-scale-"));

const env = { ...process.env, FOURDA_MCP_HOME: home, FOURDA_DB_PATH: path.join(home, "standalone.db"), FOURDA_PROJECT_DIR: project };
for (const k of Object.keys(env)) if (/^(https?|all|no)_proxy$/i.test(k)) delete env[k];
env.HTTPS_PROXY = "http://127.0.0.1:9";
env.HTTP_PROXY = "http://127.0.0.1:9";
delete env.FOURDA_OFFLINE;

const child = spawn(process.execPath, ["--import", pathToFileURL(path.join(here, "peak-rss.mjs")).href, server], { cwd: project, env, stdio: ["pipe", "pipe", "pipe"] });
let peakKiB = 0;
let stderrTail = "";
let errBuf = "";
child.stderr.on("data", (d) => {
  errBuf += d.toString();
  let nl;
  while ((nl = errBuf.indexOf("\n")) >= 0) {
    const line = errBuf.slice(0, nl);
    errBuf = errBuf.slice(nl + 1);
    const m = /^PEAKRSS (\d+)/.exec(line);
    if (m) peakKiB = Math.max(peakKiB, Number(m[1]));
    else stderrTail = `${stderrTail}${line}\n`.slice(-4000);
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
    pending.get(msg.id)?.(msg);
    pending.delete(msg.id);
  }
});
let exited = null;
child.on("exit", (code) => {
  exited = code;
  for (const resolve of pending.values()) resolve({ error: { message: `server exited (${code})` } });
  pending.clear();
});
let nextId = 1;
const rpc = (method, params = {}) =>
  new Promise((resolve) => {
    if (exited !== null) return resolve({ error: { message: `server exited (${exited})` } });
    const id = nextId++;
    pending.set(id, resolve);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });

await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "lockfile-scale-bench", version: "0" } });
child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
const baseKiB = peakKiB;

let worstPing = 0;
let pings = 0;
let running = true;
const pinger = (async () => {
  while (running && exited === null) {
    const t = performance.now();
    await rpc("ping");
    worstPing = Math.max(worstPing, performance.now() - t);
    pings++;
    await new Promise((r) => setTimeout(r, 50));
  }
})();
const t0 = performance.now();
const res = await rpc("tools/call", { name: tool, arguments: tool === "vulnerability_scan" ? { response_format: "detailed" } : {} });
const ms = performance.now() - t0;
running = false;
await pinger;
await new Promise((r) => setTimeout(r, 250));
const text = res.result?.content?.[0]?.text ?? JSON.stringify(res.error ?? res);
let summary = text.slice(0, 220);
try {
  const parsed = JSON.parse(text);
  summary = `${String(parsed.summary ?? parsed.error ?? "").slice(0, 220)} | scanned ${parsed.total_scanned ?? parsed.totalScanned ?? "?"}`;
} catch {
  // not JSON: keep the raw start
}
console.log(
  JSON.stringify(
    { project, tool, first_call_ms: Math.round(ms), worst_ping_ms: Math.round(worstPing), pings, peak_rss_mb: Math.round(peakKiB / 1024), rss_after_init_mb: Math.round(baseKiB / 1024), exited, summary },
    null,
    2,
  ),
);
if (/Maximum call stack|RangeError/.test(text + stderrTail)) console.log(`STACK OVERFLOW SEEN:\n${stderrTail}`);
const gone = new Promise((r) => (exited !== null ? r() : child.once("exit", r)));
// Closing stdin lets the server exit on its own (a --cpu-prof profile is written then); killed after 5 s.
child.stdin.end();
const killer = setTimeout(() => child.kill(), 5000);
await gone;
clearTimeout(killer);
try {
  fs.rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
} catch {
  // a cache file still held on Windows: left in the temp directory
}
