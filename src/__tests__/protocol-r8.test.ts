// SPDX-License-Identifier: Apache-2.0
/**
 * Blind audit of e3aba98 (protocol and process):
 *  1. the tail of an over-10 MB stdio line ran as a request (it stored a decision);
 *  2. after stdin closed the server worked on for up to 60 s;
 *  3. stdio refused JSON-RPC batches even on a 2025-03-26 connection (HTTP served them);
 *  4. --doctor said "All clear" through a dead proxy;
 *  5. an offline vulnerability_scan did not open NOT CHECKED;
 *  6. `setup --http` / `--doctor --http` were accepted, and an absolute-form HTTP target was a 500;
 *  7. the pnpm read split a 150,000-entry lockfile into arrays of every line three times over.
 */
import { describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { Server } from "@modelcontextprotocol/server";
import { MAX_LINE, StdioGate } from "../stdio-gate.js";
import { parseCliArgs } from "../cli-args.js";
import { absoluteFormTarget, startHttpServer } from "../http-transport.js";
import { checkLookupReachability } from "../doctor-network.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { pnpmLockDamage, readPnpmLock, textLines } from "../live/js-lockfile-readers.js";
import { serverEntry } from "./helpers/stdio-session.js";

const req = (id: number, method: string, params: Record<string, unknown> = {}) => JSON.stringify({ jsonrpc: "2.0", id, method, params });

function hermeticEnv(home: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, FOURDA_MCP_HOME: path.join(home, "4da-mcp"), FOURDA_DATA_DIR: path.join(home, "no-app"), HTTPS_PROXY: "http://127.0.0.1:9", HTTP_PROXY: "http://127.0.0.1:9", ...extra };
  for (const k of ["FOURDA_DB_PATH", "NODE_OPTIONS", "NO_PROXY", "no_proxy"]) delete env[k];
  return env;
}

describe("1: an over-long stdio line is discarded whole", () => {
  it("answers once and passes nothing of it on, however it is split; the next line is read", async () => {
    const replies: Array<Record<string, unknown>> = [];
    const gate = new StdioGate((m) => replies.push(m));
    const passed: string[] = [];
    gate.on("data", (d: Buffer) => passed.push(...d.toString().split("\n").filter(Boolean)));
    gate.write(`${req(1, "initialize")}\n`);
    // Exactly past the limit at a chunk boundary, then a request as the line's tail.
    gate.write("A".repeat(MAX_LINE + 1));
    gate.write(`${req(99, "tools/call", { name: "decision_memory" })}\n`);
    gate.write(`${req(5, "ping")}\n`);
    gate.end();
    await new Promise((resolve) => gate.on("end", resolve));
    expect(passed.map((l) => JSON.parse(l).id)).toEqual([1, 5]);
    expect(replies).toEqual([{ jsonrpc: "2.0", id: null, error: { code: -32700, message: expect.stringContaining("discarded up to its newline") } }]);
  });

  it("refuses an over-long line under the id its opening names", async () => {
    const replies: Array<Record<string, unknown>> = [];
    const gate = new StdioGate((m) => replies.push(m));
    gate.resume();
    gate.write(`${req(1, "initialize")}\n`);
    gate.write(`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"x":"${"B".repeat(MAX_LINE)}"}}\n`);
    gate.end();
    await new Promise((resolve) => gate.on("end", resolve));
    expect(replies).toEqual([{ jsonrpc: "2.0", id: 42, error: { code: -32600, message: expect.stringContaining("10 MB") } }]);
  });

  it.skipIf(!fs.existsSync(serverEntry))("the built server runs nothing from the tail (it stored a decision)", async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "4da-r8-1-"));
    const child = spawn(process.execPath, [serverEntry], { cwd: home, env: hermeticEnv(home, { FOURDA_OFFLINE: "true" }), stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    const w = (s: string) => new Promise((r) => child.stdin.write(s, r));
    await w(`${req(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } })}\n`);
    await w('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
    await w("A".repeat(MAX_LINE + 1));
    await new Promise((r) => setTimeout(r, 300));
    await w(`${req(99, "tools/call", { name: "decision_memory", arguments: { action: "record", subject: "SMUGGLED", decision: "tail ran", rationale: "x" } })}\n`);
    await w(`${req(5, "ping")}\n`);
    const deadline = Date.now() + 30_000;
    while (!out.includes('"id":5') && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    await new Promise((r) => setTimeout(r, 500));
    child.kill();
    const lines = out.split("\n").filter(Boolean).map((l) => JSON.parse(l) as { id: unknown });
    expect(lines.map((l) => l.id)).toEqual([1, null, 5]);
    expect(out).not.toContain("SMUGGLED");
  }, 60_000);
});

describe.skipIf(!fs.existsSync(serverEntry))("2: the server exits promptly when stdin closes", () => {
  it("with lookups hanging on a proxy that never answers, it exits within 2 s", async () => {
    const proj = fs.mkdtempSync(path.join(os.tmpdir(), "4da-r8-2-"));
    const names = ["lodash", "express", "minimist", "qs", "ws"];
    const packages: Record<string, unknown> = { "": { name: "p", version: "1.0.0", dependencies: Object.fromEntries(names.map((n) => [n, "1.0.0"])) } };
    for (const n of names) packages[`node_modules/${n}`] = { version: "1.0.0" };
    fs.writeFileSync(path.join(proj, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", dependencies: Object.fromEntries(names.map((n) => [n, "1.0.0"])) }));
    fs.writeFileSync(path.join(proj, "package-lock.json"), JSON.stringify({ name: "p", version: "1.0.0", lockfileVersion: 3, requires: true, packages }));
    const sockets = new Set<net.Socket>();
    const proxy = net.createServer((s) => {
      sockets.add(s);
      s.on("error", () => undefined);
    });
    await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", r));
    const port = (proxy.address() as net.AddressInfo).port;
    const url = `http://127.0.0.1:${port}`;
    const child = spawn(process.execPath, [serverEntry], { cwd: proj, env: hermeticEnv(path.join(proj, ".home"), { HTTPS_PROXY: url, HTTP_PROXY: url }), stdio: ["pipe", "pipe", "pipe"] });
    const exited = new Promise<number | null>((r) => child.on("exit", (code) => r(code)));
    child.stdin.write(`${req(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } })}\n`);
    child.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
    child.stdin.write(`${req(2, "tools/call", { name: "vulnerability_scan", arguments: {} })}\n`);
    const deadline = Date.now() + 20_000;
    while (sockets.size === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    expect(sockets.size).toBeGreaterThan(0); // a lookup is hanging on the proxy
    const closedAt = Date.now();
    child.stdin.end();
    const code = await Promise.race([exited, new Promise<"alive">((r) => setTimeout(() => r("alive"), 5000))]);
    const ms = Date.now() - closedAt;
    if (code === "alive") child.kill();
    for (const s of sockets) s.destroy();
    proxy.close();
    expect(code).toBe(0);
    expect(ms).toBeLessThan(2000);
  }, 60_000);
});

describe("3: stdio serves a batch exactly when the connection negotiated 2025-03-26", () => {
  async function session(version: string, batch: unknown[]): Promise<unknown[]> {
    const written: unknown[] = [];
    const gate = new StdioGate(() => undefined);
    const output = gate.output((text) => written.push(JSON.parse(text)));
    // Stand in for the SDK: answer every request that reaches it, through `output`.
    gate.on("data", (d: Buffer) => {
      for (const line of d.toString().split("\n").filter(Boolean)) {
        const m = JSON.parse(line) as { id?: unknown; method: string };
        if (m.id === undefined) continue;
        const result = m.method === "initialize" ? { protocolVersion: version } : { echoed: m.method };
        output.write(`${JSON.stringify({ jsonrpc: "2.0", id: m.id, result })}\n`);
      }
    });
    gate.write(`${req(1, "initialize", { protocolVersion: version })}\n`);
    gate.write(`${JSON.stringify(batch)}\n`);
    await new Promise((r) => setImmediate(r));
    return written.slice(1);
  }
  const batch = [JSON.parse(req(2, "ping")), JSON.parse(req(3, "tools/list")), { jsonrpc: "2.0", method: "notifications/x" }, { jsonrpc: "1.0", id: 4, method: "ping" }];

  it("2025-03-26: one array with every answer the batch calls for", async () => {
    const [answer] = (await session("2025-03-26", batch)) as Array<Array<{ id: unknown; error?: { code: number } }>>;
    expect(Array.isArray(answer)).toBe(true);
    expect(answer.map((a) => a.id).sort()).toEqual([2, 3, 4]);
    expect(answer.find((a) => a.id === 4)?.error?.code).toBe(-32600);
  });

  it("2025-06-18 and later, or before initialize: one -32600 with id null, nothing run", async () => {
    for (const version of ["2025-06-18", "2025-11-25"]) {
      expect(await session(version, batch)).toEqual([{ jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("batches are not supported") } }]);
    }
    const replies: Array<Record<string, unknown>> = [];
    const gate = new StdioGate((m) => replies.push(m));
    gate.resume();
    gate.write(`${JSON.stringify(batch)}\n`);
    await new Promise((r) => setImmediate(r));
    expect(replies[0]).toMatchObject({ id: null, error: { code: -32600 } });
  });
});

describe("4: --doctor asks each lookup host through the proxy", () => {
  it("a proxy nothing listens on fails every endpoint", async () => {
    const saved = { HTTPS_PROXY: process.env.HTTPS_PROXY, HTTP_PROXY: process.env.HTTP_PROXY, FOURDA_OFFLINE: process.env.FOURDA_OFFLINE };
    process.env.HTTPS_PROXY = "http://127.0.0.1:9";
    process.env.HTTP_PROXY = "http://127.0.0.1:9";
    delete process.env.FOURDA_OFFLINE;
    try {
      const checks = await checkLookupReachability({ timeoutMs: 4000 });
      expect(checks.length).toBe(5);
      for (const c of checks) {
        expect(c.status, c.name).toBe("fail");
        expect(c.detail).toMatch(/not reachable through the configured proxy/);
      }
    } finally {
      for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }, 30_000);

  it("an endpoint that answers passes", async () => {
    const checks = await checkLookupReachability({ env: {}, endpoints: [{ name: "x", url: "https://x.invalid/" }], fetcher: async () => new Response("", { status: 404 }) });
    expect(checks).toEqual([{ name: "Reach x", status: "pass", detail: expect.stringContaining("HTTP 404") }]);
  });
});

describe("5: an offline vulnerability_scan opens NOT CHECKED", () => {
  it("the first field says nothing was checked", async () => {
    const answer = (await executeVulnerabilityScan(null, {}, null)) as Record<string, unknown>;
    expect(Object.keys(answer)[0]).toBe("summary");
    expect(String(answer.summary)).toMatch(/^NOT CHECKED \(offline\)/);
    expect(JSON.stringify(answer).startsWith('{"summary":"NOT CHECKED')).toBe(true);
  });
});

describe("6: CLI flag combinations and absolute-form request targets", () => {
  it("two modes, or an HTTP flag with another mode, are refused", () => {
    for (const argv of [["setup", "--http"], ["--setup", "--dry-run", "--http"], ["--doctor", "--http"], ["--setup", "--doctor"], ["--doctor", "--port", "5000"], ["--setup", "--host", "0.0.0.0"]]) {
      expect(parseCliArgs(argv).ok, argv.join(" ")).toBe(false);
    }
    expect(parseCliArgs(["--http", "--port", "5000"]).ok).toBe(true);
    expect(parseCliArgs(["--setup", "--dry-run"]).ok).toBe(true);
    expect(parseCliArgs(["--doctor"]).ok).toBe(true);
  });

  it("absoluteFormTarget: origin-form untouched, an allowed host rewritten, any other 400", () => {
    const allowed = ["127.0.0.1", "localhost"];
    expect(absoluteFormTarget("/mcp", allowed)).toBeNull();
    expect(absoluteFormTarget("http://127.0.0.1:4840/mcp?x=1", allowed)).toEqual({ ok: true, path: "/mcp?x=1" });
    expect(absoluteFormTarget("http://evil.example/mcp", allowed)).toMatchObject({ ok: false });
    expect(absoluteFormTarget("ftp://127.0.0.1/mcp", allowed)).toMatchObject({ ok: false });
    expect(absoluteFormTarget("http://[", allowed)).toMatchObject({ ok: false });
  });

  it("the server answers an absolute-form POST to /mcp, never 500", async () => {
    const errors = console.error;
    console.error = () => undefined;
    const handle = await startHttpServer(() => new Server({ name: "t", version: "0" }, { capabilities: { tools: {} } }), { port: 0, host: "127.0.0.1", handleSignals: false });
    try {
      const port = (handle.server.address() as net.AddressInfo).port;
      const body = req(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
      const send = (target: string) =>
        new Promise<string>((resolve, reject) => {
          const s = net.connect(port, "127.0.0.1", () =>
            s.write(`POST ${target} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`),
          );
          let out = "";
          s.on("data", (d) => (out += d));
          s.on("end", () => resolve(out));
          s.on("error", reject);
        });
      expect((await send(`http://127.0.0.1:${port}/mcp`)).split("\r\n")[0]).toBe("HTTP/1.1 200 OK");
      expect((await send("http://evil.example/mcp")).split("\r\n")[0]).toBe("HTTP/1.1 400 Bad Request");
    } finally {
      await handle.close();
      console.error = errors;
    }
  });
});

describe("7: the pnpm read walks lines without arrays of them", () => {
  it("textLines yields what split(/\\r?\\n/) does", () => {
    for (const text of ["", "a", "a\n", "a\r\nb\n\nc", "\r\n", "x\ry\n"]) expect([...textLines(text)]).toEqual(text.split(/\r?\n/));
  });

  it("the damage check with the reader's installs says what it said without them", () => {
    const lock = ["lockfileVersion: '9.0'", "", "importers:", "  .:", "    dependencies:", "      a:", "        specifier: ^1", "        version: 1.0.0", "", "packages:", "  a@1.0.0:", "    resolution: {integrity: sha512-x}", "  b@2.0.0:", "    resolution: {integrity: sha512-y}", "", "snapshots:", "  a@1.0.0:", "    dependencies:", "      b: 2.0.0", "      c: 3.0.0", ""].join("\n");
    const report = { uncheckable: [], missingDirect: [] as string[], incomplete: 0 };
    const installs = readPnpmLock(lock, new Map(), undefined, report as never);
    const withInstalls = pnpmLockDamage(lock, report.missingDirect, installs);
    expect(withInstalls).toEqual(pnpmLockDamage(lock, report.missingDirect));
    expect(withInstalls?.reason).toMatch(/c@3\.0\.0/);
    expect(withInstalls?.reason).toMatch(/b@2\.0\.0/); // b has no snapshots entry
  });
});
