// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish robustness and protocol round 7 (independent audit of 5d709ff):
 *
 *  1. A lockfile of 130,000+ entries whose lookups went unanswered came back NOT CHECKED "the scan
 *     failed (Maximum call stack size exceeded)": `unanswered.push(...outcome.unanswered)`.
 *  2. `GET http://[` (one unauthenticated request) ended the --http server: `new URL()` threw.
 *  3. stdio: `{"jsonrpc":"2.0"}` and `{"jsonrpc":"2.0","id":77}` got no reply.
 *  4. FOURDA_OFFLINE=1 stayed online (only "true" was read).
 *  5. The first call was slower than 6.2.7: a quadratic requested-by map (npm) and a
 *     character-by-character JSONC pass (bun); a second scan still asked the network.
 *  6. `constructor`, `__proto__`, `toString` passed as known tool parameters.
 *  7. Invalid params on initialize, resources/read, prompts/get answered -32603.
 *  8. HTTP served JSON-RPC batches that stdio refuses.
 *  9. `--port 80abc` bound port 80; `--bogus` started the server.
 * 10. A warm scan's `_meta.offline` was null (call-budget-and-scope.test.ts holds it to false).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { execFileSync, spawn } from "node:child_process";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { request as httpRequest } from "node:http";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { InMemoryTransport, Server } from "@modelcontextprotocol/server";

import { maxOf, pushAll } from "../array-utils.js";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { OsvScanner, type AdvisorySource } from "../live/osv-scanner.js";
import { RateLimiter, DEFAULT_RATE_LIMITS } from "../live/rate-limiter.js";
import type { ResolvedDependency } from "../live/types.js";
import { readPackageLock } from "../live/lockfile-parsers.js";
import { stripTrailingCommas } from "../live/bun-lockfile.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { startHttpServer, requestPathname, resolveSecurityPolicy, type HttpServerHandle } from "../http-transport.js";
import { StdioGate } from "../stdio-gate.js";
import { envFlag, flagWarning, isOfflineMode, parseFlagValue } from "../env-flags.js";
import { cleanStrings, lengthProblem, validateToolArgs } from "../tool-args.js";
import { FourDAServer, ownHandler } from "../mcp-server.js";
import { readResource, unknownPromptError } from "../schema-registry.js";
import { parseCliArgs, parsePort } from "../cli-args.js";
import { processErrorOutcome } from "../process-guards.js";
import { setFixPathWarming, verifyFixPaths } from "../tools/upgrade-planner-fixpaths.js";
import type { FourDADatabase } from "../db.js";
import { serverEntry } from "./helpers/stdio-session.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const noDb = null as unknown as FourDADatabase;
const dep = (name: string): ResolvedDependency => ({
  name, version: "1.0.0", ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [],
});

const realError = console.error;
const ENV_KEYS = ["FOURDA_OFFLINE", "MCP_AUTH_REQUIRED", "MCP_AUTH_SECRET", "FOURDA_GITHUB_CHANGELOG", "FOURDA_MAX_LOCKFILE_BYTES"] as const;
const savedEnv: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
});
afterEach(() => {
  console.error = realError;
  vi.unstubAllGlobals();
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

// 1 -----------------------------------------------------------------------------------------------
describe("1: no array is spread into a call", () => {
  it("pushAll and maxOf take arrays far past the argument limit", () => {
    const big = Array.from({ length: 500_000 }, (_, i) => i);
    expect(() => [].push(...(big as never[]))).toThrow(RangeError);
    expect(pushAll([-1], big)).toHaveLength(500_001);
    expect(maxOf(big)).toBe(499_999);
    expect(maxOf([])).toBe(-Infinity);
    expect(maxOf([1, Number.NaN, 3])).toBeNaN();
  });

  it("200,000 dependencies OSV.dev did not answer are 200,000 unchecked, not a stack overflow", async () => {
    const source: AdvisorySource = {
      network: false,
      query: async (deps) => ({ ids: deps.map(() => null), failure: "OSV.dev unreachable (test)" }),
      details: async () => new Map(),
    };
    const scanner = new OsvScanner(new LiveCache(new Database(":memory:")), new RateLimiter(DEFAULT_RATE_LIMITS), source);
    const deps = Array.from({ length: 200_000 }, (_, i) => dep(`synth-pkg-${i}`));
    const result = await scanner.scan(deps, os.tmpdir());
    expect(result.offline).toBe(true);
    expect(result.unchecked).toBe(200_000);
    expect(JSON.stringify(result.uncheckedReason ?? "")).not.toMatch(/call stack/);
  });

  describe.each(["npm", "yarn", "pnpm", "bun"] as const)("a 200,000-entry %s lockfile with the network blocked", (format) => {
    it("answers NOT CHECKED for every dependency, for the network's reason", async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), `r7-${format}-`));
      execFileSync(process.execPath, [path.join(root, "bench", "lockfile-scale", "gen.mjs"), format, "200000", dir], { stdio: "ignore" });
      // 200,000 npm entries are 66 MB, past the 64 MB lockfile limit (bounded-read.ts).
      process.env.FOURDA_MAX_LOCKFILE_BYTES = String(256 * 1024 * 1024);
      vi.stubGlobal("fetch", async () => {
        throw new TypeError("fetch failed (network blocked in this test)");
      });
      console.error = () => {};
      const li = new LiveIntelligence(new Database(":memory:"));
      const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
      const { entries, discovery } = scanProjectTree(dir);
      li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
      const result = (await executeVulnerabilityScan(noDb, { response_format: "detailed" }, li)) as { summary: string };
      expect(result.summary).toMatch(/^NOT CHECKED/);
      expect(result.summary).not.toMatch(/call stack|scan failed/);
      expect(result.summary).toMatch(/200,0\d\d of 200,0\d\d dependencies have no vulnerability answer/);
      fs.rmSync(dir, { recursive: true, force: true });
    }, 120_000);
  });
});

// 2 + 8 -------------------------------------------------------------------------------------------
function factory(): Server {
  const server = new Server({ name: "t", version: "0" }, { capabilities: { tools: {} } });
  server.setRequestHandler("tools/list", async () => ({ tools: [] }));
  return server;
}

function raw(port: number, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => socket.write(text));
    let out = "";
    socket.on("data", (d) => (out += d.toString()));
    socket.on("end", () => resolve(out));
    socket.on("error", reject);
    setTimeout(() => {
      socket.destroy();
      resolve(out);
    }, 3000);
  });
}

function post(port: number, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/mcp",
        method: "POST",
        headers: { host: `127.0.0.1:${port}`, "content-type": "application/json", accept: "application/json, text/event-stream", "content-length": Buffer.byteLength(data), ...headers },
      },
      (res) => {
        let text = "";
        res.on("data", (d) => (text += d));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

describe("2 and 8: the HTTP transport", () => {
  let handle: HttpServerHandle;
  let port: number;
  beforeEach(async () => {
    console.error = () => {};
    handle = await startHttpServer(factory, { port: 0, host: "127.0.0.1" });
    const address = handle.server.address();
    port = typeof address === "object" && address ? address.port : 0;
  });
  afterEach(async () => {
    await handle.close();
  });

  it("a request target that is not a URL is answered 400 and the server keeps serving", async () => {
    expect(requestPathname("http://[")).toBeNull();
    expect(requestPathname("/mcp?x=1")).toBe("/mcp");
    const reply = await raw(port, "GET http://[ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    expect(reply).toMatch(/^HTTP\/1\.1 400/);
    const health = await raw(port, `GET / HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
    expect(health).toMatch(/^HTTP\/1\.1 200/);
  });

  it("with authentication required too: the bad target is refused before auth, never a crash", async () => {
    await handle.close();
    process.env.MCP_AUTH_REQUIRED = "1";
    process.env.MCP_AUTH_SECRET = "s";
    expect(resolveSecurityPolicy("127.0.0.1").authRequired).toBe(true);
    handle = await startHttpServer(factory, { port: 0, host: "127.0.0.1" });
    const address = handle.server.address();
    port = typeof address === "object" && address ? address.port : 0;
    expect(await raw(port, "GET http://[ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")).toMatch(/^HTTP\/1\.1 400/);
    expect(await raw(port, `GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`)).toMatch(/^HTTP\/1\.1 401/);
  });

  it("a batch is refused as stdio refuses it when the request speaks 2025-06-18 or later", async () => {
    const batch = [{ jsonrpc: "2.0", id: 1, method: "ping" }];
    for (const version of ["2025-06-18", "2025-11-25"]) {
      const res = await post(port, batch, { "mcp-protocol-version": version });
      expect(res.status, version).toBe(400);
      expect(JSON.parse(res.text)).toEqual({ jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("JSON-RPC batches are not supported by MCP since protocol revision 2025-06-18") } });
    }
    // An initialize inside the batch names the version when no header does.
    const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } };
    expect((await post(port, [init])).status).toBe(400);
  });

  it("a 2025-03-26 batch is still served: that revision requires a server to accept one", async () => {
    const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } };
    const res = await post(port, [init]);
    expect(res.text).not.toMatch(/batches are not supported by MCP since/);
    // A single message is untouched by the peek, and the SDK still parses what it reads.
    const single = await post(port, init);
    expect(single.status).toBe(200);
    expect(single.text).toContain('"protocolVersion"');
  });
});

// 3 -----------------------------------------------------------------------------------------------
async function gate(lines: string[]) {
  const replies: Array<Record<string, unknown>> = [];
  const g = new StdioGate((m) => replies.push(m));
  const passed: string[] = [];
  g.on("data", (d: Buffer) => pushAll(passed, d.toString().split("\n").filter(Boolean)));
  for (const line of lines) g.write(`${line}\n`);
  g.end();
  await new Promise((resolve) => g.on("end", resolve));
  return { passed, replies };
}

describe("3: a message with no method that is not a response gets -32600", () => {
  it("with its id when it has one, else id null; a response passes", async () => {
    const response = '{"jsonrpc":"2.0","id":5,"result":{}}';
    const { passed, replies } = await gate(['{"jsonrpc":"2.0"}', '{"jsonrpc":"2.0","id":77}', '{"jsonrpc":"2.0","id":"a"}', response]);
    expect(replies).toEqual([
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining('needs a "method"') } },
      { jsonrpc: "2.0", id: 77, error: { code: -32600, message: expect.stringContaining('needs a "method"') } },
      { jsonrpc: "2.0", id: "a", error: { code: -32600, message: expect.stringContaining('needs a "method"') } },
    ]);
    expect(passed).toEqual([response]);
  });
});

// 4 -----------------------------------------------------------------------------------------------
describe("4: boolean environment variables", () => {
  it("1 / true / yes / on in any case is on; 0 / false / no / off / empty is off", () => {
    for (const v of ["1", "true", "TRUE", " Yes ", "on", "On"]) expect(parseFlagValue(v), v).toBe(true);
    for (const v of ["0", "false", "No", "off", "", undefined]) expect(parseFlagValue(v), String(v)).toBe(false);
    expect(parseFlagValue("please")).toBeNull();
  });

  it("FOURDA_OFFLINE=1 turns live lookups off", () => {
    process.env.FOURDA_OFFLINE = "1";
    expect(isOfflineMode()).toBe(true);
    expect(new LiveIntelligence(new Database(":memory:")).isEnabled()).toBe(false);
    process.env.FOURDA_OFFLINE = "0";
    expect(new LiveIntelligence(new Database(":memory:")).isEnabled()).toBe(true);
  });

  it("an unreadable value is read as the safe side, and said once on stderr", () => {
    const lines: string[] = [];
    console.error = (line: string) => lines.push(line);
    expect(envFlag("FOURDA_OFFLINE", { FOURDA_OFFLINE: "enabled-r7" })).toBe(true);
    expect(envFlag("FOURDA_OFFLINE", { FOURDA_OFFLINE: "enabled-r7" })).toBe(true);
    expect(envFlag("MCP_AUTH_REQUIRED", { MCP_AUTH_REQUIRED: "maybe-r7" })).toBe(true);
    expect(envFlag("FOURDA_GITHUB_CHANGELOG", { FOURDA_GITHUB_CHANGELOG: "sure-r7" })).toBe(false);
    expect(lines).toHaveLength(3);
    expect(lines[0]).toMatch(/FOURDA_OFFLINE="enabled-r7" is not one of .*read as on \(offline/);
    expect(flagWarning("FOURDA_OFFLINE", "1")).toBeNull();
  });
});

// 5 -----------------------------------------------------------------------------------------------
describe("5: lockfile reading is linear", () => {
  it("npm: 60,000 packages requesting the same ten hubs read in well under the quadratic time", () => {
    const packages: Record<string, { version: string; resolved: string; dependencies: Record<string, string> }> = {};
    for (let i = 0; i < 60_000; i++) {
      packages[`node_modules/p${i}`] = { version: "1.0.0", resolved: `https://registry.npmjs.org/p${i}/-/p${i}-1.0.0.tgz`, dependencies: { [`p${i % 10}`]: "^1.0.0", [`p${(i * 7) % 10}`]: "^1.0.0" } };
    }
    const t = performance.now();
    const read = readPackageLock({ packages });
    const ms = performance.now() - t;
    expect(read.instances.size).toBe(60_000);
    // Quadratic (5d709ff): ~4 s here. Linear: ~0.2 s.
    expect(ms).toBeLessThan(2_000);
  });

  it("bun: trailing commas are dropped in one pass, strings untouched", () => {
    const tricky = '{"a": [1, 2, ], "s": "x, ]", "e": "\\", }", "n": {"k": "v" ,\n\t } , }';
    expect(JSON.parse(stripTrailingCommas(tricky))).toEqual({ a: [1, 2], s: "x, ]", e: '", }', n: { k: "v" } });
    expect(stripTrailingCommas('{"a":1}')).toBe('{"a":1}');
    const big = `{${Array.from({ length: 400_000 }, (_, i) => `"k${i}": ["v${i}", "", {}, "sha512-xxxxxxxxxxxxxxxxxxxx"],`).join("\n")}\n}`;
    const t = performance.now();
    const out = stripTrailingCommas(big);
    const ms = performance.now() - t;
    expect(Object.keys(JSON.parse(out))).toHaveLength(400_000);
    // Character by character (5d709ff): ~2 s for these 20 MB. One pass with slices: ~0.1 s.
    expect(ms).toBeLessThan(800);
  });

  it("rows the call's budget left unstarted are worked out in the background, so the next call finds them cached", async () => {
    const calls: string[] = [];
    const sources = new Proxy({}, { get: (_t, name) => async () => (calls.push(String(name)), null) });
    const intel = { getFixPathSources: () => sources, lockfileFor: () => null, getProjectRoot: () => os.tmpdir(), getResolvedDeps: () => [] };
    const input = () => ({
      step: { package: "leaf", ecosystem: "npm", currentVersion: "1.0.0", targetVersion: "1.0.1", upgradeType: "patch" as const, reasons: [], breaking: false, scope: "transitive" as const, action: "waiting_on_upstream" },
      fixes: ["1.0.1"],
      sourceDirs: [os.tmpdir()],
    });
    setFixPathWarming(false);
    expect(await verifyFixPaths([input()], intel as never, 0)).toBe(1);
    await new Promise((r) => setTimeout(r, 150));
    expect(calls).toEqual([]);
    setFixPathWarming(true);
    expect(await verifyFixPaths([input()], intel as never, 0)).toBe(1);
    expect(calls).toEqual([]);
    await new Promise((r) => setTimeout(r, 150));
    expect(calls.length).toBeGreaterThan(0);
  });
});

// 6 -----------------------------------------------------------------------------------------------
describe("6: only a tool's own parameters are parameters", () => {
  const schema = { properties: { limit: { type: "number" } }, required: [] };
  it("constructor, __proto__, toString and hasOwnProperty are unknown parameters", () => {
    for (const name of ["constructor", "toString", "hasOwnProperty", "valueOf"]) {
      expect(validateToolArgs("t", schema, { [name]: "x" }), name).toMatch(new RegExp(`unknown parameter "${name}"`));
    }
    const proto = JSON.parse('{"__proto__": "x"}') as Record<string, unknown>;
    expect(validateToolArgs("t", schema, proto)).toMatch(/unknown parameter "__proto__"/);
    expect(lengthProblem("w", "toString", "x".repeat(10))).toBeNull();
    expect(validateToolArgs("t", { properties: {}, required: ["toString"] }, {})).toMatch(/missing required parameter "toString"/);
  });

  it("an own __proto__ key in a result stays a key, never the prototype", () => {
    const value = JSON.parse('{"__proto__": {"polluted": true}, "a": "b"}') as Record<string, unknown>;
    const cleaned = cleanStrings(value) as Record<string, unknown>;
    expect(Object.getPrototypeOf(cleaned)).toBe(Object.prototype);
    expect((cleaned as { polluted?: boolean }).polluted).toBeUndefined();
    expect(Object.hasOwn(cleaned, "__proto__")).toBe(true);
  });
});

// 7 -----------------------------------------------------------------------------------------------
async function rpc(messages: Array<Record<string, unknown>>): Promise<Array<{ id?: unknown; result?: unknown; error?: { code: number; message: string } }>> {
  const server = new FourDAServer({ name: "t", version: "0" }, { capabilities: { tools: {}, resources: {}, prompts: {} } });
  server.setRequestHandler("resources/read", ownHandler(async (request) => readResource(request.params.uri)));
  server.setRequestHandler("prompts/get", ownHandler(async (request) => {
    if (request.params.name === "boom") throw new TypeError("a bug in a handler");
    throw unknownPromptError(request.params.name);
  }));
  const [client, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const replies: Array<Record<string, unknown>> = [];
  client.onmessage = (m) => replies.push(m as Record<string, unknown>);
  await client.start();
  for (const m of messages) await client.send(m as never);
  const want = messages.filter((m) => m.id !== undefined).length;
  const deadline = Date.now() + 5000;
  while (replies.length < want && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
  return replies as never;
}

describe("7: params the SDK rejects are -32602, a fault in a handler stays -32603", () => {
  const init = (params: Record<string, unknown>) => ({ jsonrpc: "2.0", id: 1, method: "initialize", params });
  const good = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } };

  it("initialize without protocolVersion", async () => {
    const [reply] = await rpc([init({ capabilities: {}, clientInfo: { name: "t", version: "0" } })]);
    expect(reply.error?.code).toBe(-32602);
    expect(reply.error?.message).toMatch(/^Invalid params for initialize/);
  });

  it("resources/read without uri, prompts/get without name; an unknown prompt and a handler bug keep their codes", async () => {
    const replies = await rpc([
      init(good),
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "resources/read", params: {} },
      { jsonrpc: "2.0", id: 3, method: "prompts/get", params: {} },
      { jsonrpc: "2.0", id: 4, method: "prompts/get", params: { name: "nope" } },
      { jsonrpc: "2.0", id: 5, method: "prompts/get", params: { name: "boom" } },
    ]);
    const code = (id: number) => replies.find((r) => r.id === id)?.error?.code;
    expect(replies.find((r) => r.id === 1)?.result).toBeDefined();
    expect(code(2)).toBe(-32602);
    expect(code(3)).toBe(-32602);
    expect(code(4)).toBe(-32602);
    expect(code(5)).toBe(-32603);
  });
});

// 9 -----------------------------------------------------------------------------------------------
describe("9: command-line arguments", () => {
  it("a port is digits only, 1 to 65535", () => {
    for (const bad of ["80abc", "0", "65536", "-1", "8.0", " 80", "1e3", "0x50", ""]) expect(parsePort(bad), bad).toBeNull();
    expect(parsePort("80")).toBe(80);
    expect(parsePort("65535")).toBe(65535);
  });

  it("unknown flags, bad ports and stray values are errors; the known forms parse", () => {
    for (const argv of [["--bogus"], ["--http", "--port", "80abc"], ["--http", "--port"], ["--http", "--port", "0"], ["extra"], ["--port", "80"], ["--http", "--port=99999"], ["--dry-run"]]) {
      expect(parseCliArgs(argv).ok, argv.join(" ")).toBe(false);
    }
    expect(parseCliArgs([])).toEqual({ ok: true, command: { kind: "stdio" } });
    expect(parseCliArgs(["--http"])).toEqual({ ok: true, command: { kind: "http", port: 4840, host: "127.0.0.1" } });
    expect(parseCliArgs(["--http", "--port", "8080", "--host", "::1"])).toEqual({ ok: true, command: { kind: "http", port: 8080, host: "::1" } });
    expect(parseCliArgs(["--port=8081", "--http"])).toEqual({ ok: true, command: { kind: "http", port: 8081, host: "127.0.0.1" } });
    expect(parseCliArgs(["--setup", "--dry-run"])).toEqual({ ok: true, command: { kind: "setup", dryRun: true } });
    expect(parseCliArgs(["doctor"])).toEqual({ ok: true, command: { kind: "doctor" } });
    expect(parseCliArgs(["-v"])).toEqual({ ok: true, command: { kind: "version" } });
  });
});

// 2 (process level) -------------------------------------------------------------------------------
describe("2: an error no request handled does not end the server", () => {
  it("is logged and served on; a closed stdout or out of memory ends it", () => {
    expect(processErrorOutcome(new TypeError("Invalid URL")).exit).toBeNull();
    expect(processErrorOutcome("a rejection that is no Error").exit).toBeNull();
    expect(processErrorOutcome(Object.assign(new Error("write EPIPE"), { code: "EPIPE" })).exit).toBe(0);
    expect(processErrorOutcome(new RangeError("Array buffer allocation failed")).exit).toBe(1);
  });
});

// Built server, real processes (2, 3, 4, 9) --------------------------------------------------------
describe.skipIf(!fs.existsSync(serverEntry))("the built server", () => {
  const home = () => {
    const h = fs.mkdtempSync(path.join(os.tmpdir(), "4da-r7-"));
    const env: NodeJS.ProcessEnv = { ...process.env, FOURDA_MCP_HOME: h, FOURDA_DATA_DIR: path.join(h, "no-app"), HTTPS_PROXY: "http://127.0.0.1:9", HTTP_PROXY: "http://127.0.0.1:9" };
    delete env.FOURDA_DB_PATH;
    delete env.FOURDA_OFFLINE;
    return { h, env };
  };
  const run = (args: string[], env: NodeJS.ProcessEnv, cwd: string) =>
    new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
      const child = spawn(process.execPath, [serverEntry, ...args], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
      let out = "";
      let err = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      const timer = setTimeout(() => child.kill(), 15_000);
      child.on("exit", (code) => {
        clearTimeout(timer);
        resolve({ code, out, err });
      });
      child.stdin.end();
    });

  it("9: --bogus and --port 80abc exit 2 with the usage, and nothing is served", async () => {
    const { h, env } = home();
    for (const args of [["--bogus"], ["--http", "--port", "80abc"]]) {
      const r = await run(args, env, h);
      expect(r.code, args.join(" ")).toBe(2);
      expect(r.err).toMatch(/Usage:/);
      expect(r.err).not.toMatch(/listening on/);
    }
  }, 60_000);

  it("3 and 4: stdio answers a method-less message, and FOURDA_OFFLINE=1 is offline", async () => {
    const { h, env } = home();
    const child = spawn(process.execPath, [serverEntry], { cwd: h, env: { ...env, FOURDA_OFFLINE: "1" }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    const send = (m: unknown) => child.stdin.write(`${typeof m === "string" ? m : JSON.stringify(m)}\n`);
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } });
    send('{"jsonrpc":"2.0"}');
    send('{"jsonrpc":"2.0","id":77}');
    send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "vulnerability_scan", arguments: {} } });
    const lines = () => out.split("\n").filter(Boolean).map((l) => JSON.parse(l) as { id: unknown; error?: { code: number }; result?: { content?: Array<{ text: string }> } });
    const deadline = Date.now() + 40_000;
    while (lines().length < 4 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    child.kill();
    expect(lines().find((l) => l.id === null)?.error?.code).toBe(-32600);
    expect(lines().find((l) => l.id === 77)?.error?.code).toBe(-32600);
    expect(lines().find((l) => l.id === 2)?.result?.content?.[0]?.text).toMatch(/Live intelligence disabled|FOURDA_OFFLINE/);
  }, 60_000);

  it("2: GET http://[ does not end an --http server, with authentication required", async () => {
    const { h, env } = home();
    const port = 20_000 + Math.floor(Math.random() * 20_000);
    const child = spawn(process.execPath, [serverEntry, "--http", "--port", String(port)], { cwd: h, env: { ...env, MCP_AUTH_REQUIRED: "true", MCP_AUTH_SECRET: "s" }, stdio: ["pipe", "pipe", "pipe"] });
    let err = "";
    child.stderr.on("data", (d) => (err += d));
    const deadline = Date.now() + 20_000;
    while (!/listening on/.test(err) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    const reply = await raw(port, "GET http://[ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    const health = await raw(port, `GET / HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
    const alive = child.exitCode === null;
    child.kill();
    expect(reply).toMatch(/^HTTP\/1\.1 400/);
    expect(health).toMatch(/^HTTP\/1\.1 200/);
    expect(alive).toBe(true);
    expect(err).not.toMatch(/Invalid URL/);
  }, 60_000);
});
