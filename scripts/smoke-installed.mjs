// SPDX-License-Identifier: Apache-2.0
/**
 * Smoke-test the package as a user installs it: from the packed tarball, in
 * a scratch project, through npm's own bin links. Nothing in CI did this, so a
 * bin that only worked from source shipped: on macOS and Linux npm links bins
 * as symlinks, and `4da-mcp-setup` exited 0 having done nothing (audit 6.2.5
 * E-2, E-7).
 *
 *   node scripts/smoke-installed.mjs <dir holding node_modules/@4da/mcp-server>
 *
 * Checks: `4da-mcp --version` prints the package version; the stdio server
 * answers initialize and lists its standalone tools; `4da-mcp-setup --dry-run`
 * runs (prints its header) with HOME pointed at an empty scratch directory.
 */
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const project = path.resolve(process.argv[2] ?? ".");
const pkgDir = path.join(project, "node_modules", "@4da", "mcp-server");
const { version } = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));
const binDir = path.join(project, "node_modules", ".bin");
const bin = (name) => path.join(binDir, process.platform === "win32" ? `${name}.cmd` : name);
const home = fs.mkdtempSync(path.join(os.tmpdir(), "4da-smoke-home-"));
const env = {
  ...process.env,
  HOME: home,
  USERPROFILE: home,
  APPDATA: path.join(home, "AppData", "Roaming"),
  LOCALAPPDATA: path.join(home, "AppData", "Local"),
  FOURDA_MCP_HOME: path.join(home, "4da-mcp"),
};
for (const k of Object.keys(env)) if (k.startsWith("FOURDA_") && k !== "FOURDA_MCP_HOME") delete env[k];

function fail(message) {
  console.error(`smoke-installed: FAIL: ${message}`);
  process.exit(1);
}

function runBin(name, args) {
  // .cmd shims need a shell on Windows; on POSIX the bin is the symlink npm made.
  const result = spawnSync(bin(name), args, { env, encoding: "utf8", shell: process.platform === "win32", timeout: 60_000 });
  return { code: result.status, out: `${result.stdout ?? ""}${result.stderr ?? ""}` };
}

const v = runBin("4da-mcp", ["--version"]);
if (v.code !== 0 || !v.out.includes(version)) fail(`4da-mcp --version: exit ${v.code}, output ${JSON.stringify(v.out.slice(0, 300))}`);
console.log(`4da-mcp --version: ${v.out.trim()}`);

const setup = runBin("4da-mcp-setup", ["--dry-run"]);
if (setup.code !== 0 || !/Setup/.test(setup.out) || !/DRY RUN/.test(setup.out)) {
  fail(`4da-mcp-setup --dry-run printed nothing it should: exit ${setup.code}, output ${JSON.stringify(setup.out.slice(0, 300))}`);
}
console.log("4da-mcp-setup --dry-run: ran");

const child = spawn(process.execPath, [path.join(pkgDir, "dist", "index.js")], { cwd: home, env, stdio: ["pipe", "pipe", "pipe"] });
let buffer = "";
const waiting = new Map();
child.stdout.on("data", (chunk) => {
  buffer += chunk.toString();
  let at;
  while ((at = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, at).trim();
    buffer = buffer.slice(at + 1);
    if (!line) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      fail(`non-JSON-RPC bytes on stdout: ${JSON.stringify(line.slice(0, 200))}`);
    }
    waiting.get(message.id)?.(message);
  }
});
let nextId = 1;
const rpc = (method, params) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => reject(new Error(`${method} timed out`)), 60_000);
    waiting.set(id, (m) => {
      clearTimeout(timer);
      resolve(m);
    });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });

try {
  const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "smoke-installed", version: "1" } });
  if (init.result?.serverInfo?.version !== version) fail(`initialize: serverInfo ${JSON.stringify(init.result?.serverInfo)}`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  const list = await rpc("tools/list", {});
  const tools = list.result?.tools?.map((t) => t.name) ?? [];
  if (tools.length < 11 || !tools.includes("vulnerability_scan") || !tools.includes("dependency_check")) fail(`tools/list: ${JSON.stringify(tools)}`);
  console.log(`stdio server ${version}: ${tools.length} tools`);
} catch (error) {
  fail(String(error));
} finally {
  // Windows holds a child's working directory until it exits.
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill();
  await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 5_000))]);
  try {
    fs.rmSync(home, { recursive: true, force: true });
  } catch {
    // a scratch directory left in the temp folder is not a failure
  }
}
console.log("smoke-installed: OK");
