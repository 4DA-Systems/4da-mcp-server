// SPDX-License-Identifier: Apache-2.0
/**
 * The built server over stdio with better-sqlite3 unloadable: what a default
 * `npx @4da/mcp-server` under npm 12 gets, since npm 12 blocks the install
 * script that builds better-sqlite3's native module.
 *
 * Measured 2026-10-03 (npm 12.2.0): every tool failed with "Could not locate
 * the bindings file". Until 6.1.0 the server also exited at import when the
 * package itself was missing. It now runs on node:sqlite, and with no SQLite
 * driver at all it still starts and the dependency tools still answer.
 *
 * Runs dist/ (CI builds before testing); skipped when there is no build.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const entry = path.join(root, "dist", "index.js");
/** node:sqlite exists from Node 22.13; CI also runs Node 22.12. */
const [major, minor] = process.versions.node.split(".").map(Number);
const HAS_NODE_SQLITE = major > 22 || (major === 22 && minor >= 13);

interface ToolResult {
  isError?: boolean;
  content?: { text?: string }[];
}

let scratch: string;
let preload: string;
let project: string;

/** A hermetic environment: no real app database, no network, temp data dirs. */
function env(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const e: NodeJS.ProcessEnv = { ...process.env };
  for (const k of ["FOURDA_DB_PATH", "FOURDA_SQLITE_DRIVER", "FOURDA_SQL_CORPUS", "NODE_OPTIONS"]) delete e[k];
  const home = fs.mkdtempSync(path.join(scratch, "home-"));
  return {
    ...e,
    APPDATA: home,
    LOCALAPPDATA: home,
    XDG_DATA_HOME: home,
    HOME: home,
    USERPROFILE: home,
    FOURDA_MCP_HOME: path.join(home, "4da-mcp"),
    FOURDA_DATA_DIR: path.join(home, "no-app"),
    FOURDA_OFFLINE: "true",
    ...extra,
  };
}

/** Run the server with better-sqlite3 unbuilt, make the calls, return the results and stderr. */
async function session(
  calls: [string, Record<string, unknown>][],
  extraEnv: Record<string, string> = {},
): Promise<{ tools: string[]; results: ToolResult[]; stderr: string }> {
  const child = spawn(process.execPath, ["--require", preload, entry], {
    cwd: project,
    env: env(extraEnv),
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  let buffer = "";
  const pending = new Map<number, (m: { result?: unknown; error?: unknown }) => void>();
  child.stderr.on("data", (d) => (stderr += d));
  child.stdout.on("data", (d) => {
    buffer += d;
    let i: number;
    while ((i = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, i).trim();
      buffer = buffer.slice(i + 1);
      if (!line) continue;
      const message = JSON.parse(line) as { id?: number; result?: unknown; error?: unknown };
      if (message.id !== undefined) pending.get(message.id)?.(message);
    }
  });
  const exited = new Promise<never>((_, reject) =>
    child.on("exit", (code) => reject(new Error(`server exited (${code}): ${stderr.slice(-2000)}`))),
  );
  let id = 0;
  const rpc = (method: string, params: unknown) =>
    Promise.race([
      new Promise<{ result?: unknown; error?: unknown }>((resolve) => {
        pending.set(++id, resolve);
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      }),
      exited,
    ]);
  try {
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    const list = (await rpc("tools/list", {})).result as { tools: { name: string }[] };
    const results: ToolResult[] = [];
    for (const [name, args] of calls) {
      const r = await rpc("tools/call", { name, arguments: args });
      results.push((r.result ?? { isError: true, content: [{ text: JSON.stringify(r.error) }] }) as ToolResult);
    }
    return { tools: list.tools.map((t) => t.name), results, stderr };
  } finally {
    exited.catch(() => undefined);
    // Wait for the exit: on Windows a live child keeps the project directory locked.
    const gone = child.exitCode !== null ? Promise.resolve() : new Promise((resolve) => child.once("exit", resolve));
    child.kill();
    await gone;
  }
}

const text = (r: ToolResult) => (r.content ?? []).map((c) => c.text ?? "").join("\n");

describe.skipIf(!fs.existsSync(entry))("built server with better-sqlite3 unbuilt (npm 12)", () => {
  beforeAll(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-no-native-"));
    preload = path.join(scratch, "unbuilt-better-sqlite3.cjs");
    // npm 12 with install scripts blocked: better-sqlite3 is installed, its
    // native module is not, so the first `new Database()` cannot find it.
    fs.writeFileSync(
      preload,
      `const Module = require("module");
const resolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === "bindings") return require.resolve("./bindings-missing.cjs");
  return resolve.call(this, request, ...rest);
};
`,
    );
    fs.writeFileSync(
      path.join(scratch, "bindings-missing.cjs"),
      'module.exports = () => { throw new Error("Could not locate the bindings file. Tried: build/better_sqlite3.node"); };\n',
    );
    project = path.join(scratch, "project");
    fs.mkdirSync(project);
    fs.writeFileSync(
      path.join(project, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { "left-pad": "1.3.0" } }),
    );
    fs.writeFileSync(
      path.join(project, "package-lock.json"),
      JSON.stringify({
        name: "fixture",
        version: "1.0.0",
        lockfileVersion: 3,
        packages: {
          "": { name: "fixture", version: "1.0.0", dependencies: { "left-pad": "1.3.0" } },
          "node_modules/left-pad": { version: "1.3.0" },
        },
      }),
    );
  });

  afterAll(() => {
    fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  it("the simulation holds: better-sqlite3 imports, then cannot open a database", () => {
    const run = spawnSync(
      process.execPath,
      ["--require", preload, "-e", "const D = require('better-sqlite3'); new D(':memory:')"],
      { cwd: root, encoding: "utf8" },
    );
    expect(run.status).not.toBe(0);
    expect(run.stderr).toContain("Could not locate the bindings file");
  });

  it.runIf(HAS_NODE_SQLITE)("serves every database tool on node:sqlite, with no ExperimentalWarning on stderr", async () => {
    const { tools, results, stderr } = await session([
      ["get_context", {}],
      ["agent_memory", { action: "store", subject: "driver", content: "stored through node:sqlite" }],
      ["agent_memory", { action: "recall", query: "driver" }],
      ["decision_memory", { action: "record", decision_type: "tech_choice", subject: "sqlite", decision: "node:sqlite", rationale: "npm 12" }],
      ["dependency_check", { items: [{ ecosystem: "npm", package: "left-pad", to: "1.3.0" }] }],
      ["vulnerability_scan", {}],
    ]);
    expect(tools).toContain("vulnerability_scan");
    for (const r of results) expect(r.isError, text(r)).toBeFalsy();
    expect(text(results[2])).toContain("stored through node:sqlite");
    expect(stderr).not.toMatch(/ExperimentalWarning|bindings file|better_sqlite3\.node/);
  }, 60_000);

  it("with no SQLite driver at all: starts, keeps the dependency tools, and says how to fix the rest", async () => {
    const { tools, results, stderr } = await session(
      [
        ["dependency_check", { items: [{ ecosystem: "npm", package: "left-pad", to: "1.3.0" }] }],
        ["vulnerability_scan", {}],
        ["get_context", {}],
      ],
      { FOURDA_SQLITE_DRIVER: "none" },
    );
    expect(tools.length).toBeGreaterThan(0);
    expect(results[0].isError, text(results[0])).toBeFalsy();
    expect(results[1].isError, text(results[1])).toBeFalsy();
    expect(results[2].isError).toBe(true);
    expect(text(results[2])).toContain("FOURDA_SQLITE_DRIVER=none");
    expect(stderr).toContain("still run, without a database");
  }, 60_000);

  it.runIf(!HAS_NODE_SQLITE)("on a Node without node:sqlite: starts, keeps the dependency tools, and says to upgrade Node or allow the build", async () => {
    const { results } = await session([
      ["dependency_check", { items: [{ ecosystem: "npm", package: "left-pad", to: "1.3.0" }] }],
      ["get_context", {}],
    ]);
    expect(results[0].isError, text(results[0])).toBeFalsy();
    expect(results[1].isError).toBe(true);
    expect(text(results[1])).toContain("upgrade Node.js to 22.13.0 or later");
    expect(text(results[1])).toContain("npm install-scripts approve better-sqlite3");
  }, 60_000);

  it.runIf(HAS_NODE_SQLITE)("--doctor names the driver in use", () => {
    const run = spawnSync(process.execPath, ["--require", preload, entry, "--doctor"], {
      cwd: project,
      env: env(),
      encoding: "utf8",
    });
    expect(run.stdout).toMatch(/SQLite driver.*node:sqlite \(built into Node/);
    expect(run.stderr).not.toMatch(/ExperimentalWarning/);
  }, 30_000);
});
