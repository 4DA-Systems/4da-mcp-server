// SPDX-License-Identifier: Apache-2.0
/**
 * Protocol nits from the pre-publish audit (2026-11-13): a malformed JSON-RPC line got no answer
 * at all, and tools/call before initialize was run. The stdio gate (stdio-gate.ts) answers the
 * first with -32700 and refuses the second with -32600; a 2026-07-28 request (protocol version
 * in `_meta`) needs no handshake and passes.
 */
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import { spawn } from "node:child_process";
import * as os from "node:os";
import * as path from "node:path";
import { StdioGate } from "../stdio-gate.js";
import { serverEntry } from "./helpers/stdio-session.js";

async function run(lines: string[]): Promise<{ passed: string[]; replies: Array<Record<string, unknown>> }> {
  const replies: Array<Record<string, unknown>> = [];
  const gate = new StdioGate((m) => replies.push(m));
  const passed: string[] = [];
  gate.on("data", (d: Buffer) => passed.push(...d.toString().split("\n").filter(Boolean)));
  for (const line of lines) gate.write(`${line}\n`);
  gate.end();
  await new Promise((resolve) => gate.on("end", resolve));
  return { passed, replies };
}

const req = (id: number, method: string, params: Record<string, unknown> = {}) => JSON.stringify({ jsonrpc: "2.0", id, method, params });

describe("the stdio gate", () => {
  it("answers a line that is not JSON with -32700 and passes nothing on", async () => {
    const { passed, replies } = await run(["{not json"]);
    expect(passed).toEqual([]);
    expect(replies).toEqual([{ jsonrpc: "2.0", id: null, error: { code: -32700, message: expect.stringContaining("Parse error") } }]);
  });

  it("answers a JSON-RPC batch, or JSON that is no message, with -32600 and passes nothing on (blind audit 2026-11-14)", async () => {
    const { passed, replies } = await run([JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "ping" }]), "5", "null"]);
    expect(passed).toEqual([]);
    expect(replies).toEqual([
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("batches are not supported") } },
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("must be a JSON object") } },
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("must be a JSON object") } },
    ]);
  });

  it("answers a message that is not JSON-RPC 2.0, or a request with a null id, with -32600 (blind audit round 3)", async () => {
    const { passed, replies } = await run([
      req(3, "initialize"),
      JSON.stringify({ jsonrpc: "1.0", id: 4, method: "ping" }),
      JSON.stringify({ id: 5, method: "ping" }),
      JSON.stringify({ jsonrpc: "2.0", id: null, method: "ping" }),
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    ]);
    expect(replies).toEqual([
      { jsonrpc: "2.0", id: 4, error: { code: -32600, message: expect.stringContaining('"jsonrpc" must be "2.0"') } },
      { jsonrpc: "2.0", id: 5, error: { code: -32600, message: expect.stringContaining('"jsonrpc" must be "2.0"') } },
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("never null") } },
    ]);
    expect(passed.map((l) => JSON.parse(l).method)).toEqual(["initialize", "notifications/initialized"]);
  });

  it("answers a request whose id is an object, an array or a boolean with -32600 and id null (blind audit round 4)", async () => {
    const { passed, replies } = await run([
      req(3, "initialize"),
      JSON.stringify({ jsonrpc: "2.0", id: { a: 1 }, method: "ping" }),
      JSON.stringify({ jsonrpc: "2.0", id: [1], method: "tools/list" }),
      JSON.stringify({ jsonrpc: "2.0", id: true, method: "ping" }),
      JSON.stringify({ jsonrpc: "2.0", id: "s-1", method: "ping" }),
    ]);
    expect(replies).toEqual([
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("got a JSON object") } },
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("got an array") } },
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("got a boolean") } },
    ]);
    expect(passed.map((l) => JSON.parse(l).id)).toEqual([3, "s-1"]);
  });

  it('answers a request with "params": null, a string, a number or an array with -32602 under its own id (blind audit round 4)', async () => {
    const line = (id: number, params: unknown) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/list", params });
    const { passed, replies } = await run([
      req(1, "initialize"),
      line(2, null),
      line(3, "x"),
      line(4, 5),
      line(5, [1]),
      JSON.stringify({ jsonrpc: "2.0", id: 6, method: "tools/list" }),
      line(7, {}),
    ]);
    expect(replies).toEqual([2, 3, 4, 5].map((id) => ({ jsonrpc: "2.0", id, error: { code: -32602, message: expect.stringContaining("params must be a JSON object") } })));
    expect(passed.map((l) => JSON.parse(l).id)).toEqual([1, 6, 7]);
  });

  it("refuses a request before initialize, then passes everything after it", async () => {
    const { passed, replies } = await run([req(1, "tools/call", { name: "x" }), req(2, "ping"), req(3, "initialize"), req(4, "tools/call", { name: "x" })]);
    expect(replies).toEqual([{ jsonrpc: "2.0", id: 1, error: { code: -32600, message: expect.stringContaining("Server not initialized") } }]);
    expect(passed.map((l) => JSON.parse(l).id)).toEqual([2, 3, 4]);
  });

  it("passes a 2026-07-28 request that claims its protocol version, and server/discover", async () => {
    const claimed = req(1, "tools/list", { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } });
    expect((await run([claimed])).passed).toHaveLength(1);
    expect((await run([req(1, "server/discover")])).passed).toHaveLength(1);
  });

  it("passes a split line whole, and a CRLF line", async () => {
    const replies: Array<Record<string, unknown>> = [];
    const gate = new StdioGate((m) => replies.push(m));
    const passed: string[] = [];
    gate.on("data", (d: Buffer) => passed.push(d.toString()));
    const line = req(1, "initialize");
    gate.write(line.slice(0, 10));
    gate.write(`${line.slice(10)}\r\n`);
    gate.end();
    await new Promise((resolve) => gate.on("end", resolve));
    expect(replies).toEqual([]);
    expect(passed.join("")).toBe(`${line}\n`);
  });
});

describe.skipIf(!fs.existsSync(serverEntry))("the built server over stdio", () => {
  it("answers a malformed line with -32700 and a call before initialize with -32600", async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "4da-gate-"));
    const env = { ...process.env, FOURDA_OFFLINE: "true", FOURDA_MCP_HOME: home, FOURDA_DATA_DIR: path.join(home, "no-app") };
    delete env.FOURDA_DB_PATH;
    const child = spawn(process.execPath, [serverEntry], { cwd: home, env, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stdin.write("{not json\n");
    child.stdin.write(`${req(7, "tools/call", { name: "decision_memory", arguments: { action: "list" } })}\n`);
    const deadline = Date.now() + 30_000;
    while (out.split("\n").filter(Boolean).length < 2 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    child.kill();
    const lines = out.split("\n").filter(Boolean).map((l) => JSON.parse(l) as { id: unknown; error?: { code: number } });
    expect(lines.find((l) => l.id === null)?.error?.code).toBe(-32700);
    expect(lines.find((l) => l.id === 7)?.error?.code).toBe(-32600);
  }, 60_000);

  it('answers "params": null and an object id on stdout (blind audit round 4)', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "4da-gate-"));
    const env = { ...process.env, FOURDA_OFFLINE: "true", FOURDA_MCP_HOME: home, FOURDA_DATA_DIR: path.join(home, "no-app") };
    delete env.FOURDA_DB_PATH;
    const child = spawn(process.execPath, [serverEntry], { cwd: home, env, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    const init = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } };
    child.stdin.write(`${req(1, "initialize", init)}\n`);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: null })}\n`);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: { x: 1 }, method: "ping" })}\n`);
    const deadline = Date.now() + 30_000;
    while (out.split("\n").filter(Boolean).length < 3 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    child.kill();
    const lines = out.split("\n").filter(Boolean).map((l) => JSON.parse(l) as { id: unknown; error?: { code: number } });
    expect(lines.find((l) => l.id === 2)?.error?.code).toBe(-32602);
    expect(lines.find((l) => l.id === null)?.error?.code).toBe(-32600);
  }, 60_000);
});
