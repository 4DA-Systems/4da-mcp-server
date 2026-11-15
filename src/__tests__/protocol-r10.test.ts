// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish round 10, W1: JSON-RPC batches (protocol 2025-03-26) that hold a cancelled request.
 *
 * Blind check of ebd6391: on stdio the batch `[tools/call 20, notifications/cancelled 20, ping 21]`
 * was never answered (the SDK never answers a cancelled request and the gate waited for every id),
 * and a later single `ping 20` was folded into it as `[{id:21},{id:20}]`. Over HTTP (stateless, no
 * session id) the same batch held its response open with no end. Both transports now read a batch
 * through `batchCancellation` (stdio-gate.ts), and stdio bounds every open batch.
 *
 * Both run the real SDK (`serveStdio`, `createMcpHandler`) around a server whose `slow` tool sleeps
 * `ms` milliseconds, or forever for a negative `ms`.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { Server } from "@modelcontextprotocol/server";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { CANCEL_SETTLE_MS, StdioGate, batchCancellation } from "../stdio-gate.js";
import { startHttpServer, type HttpServerHandle } from "../http-transport.js";

type Message = Record<string, unknown> & { id?: unknown; result?: unknown; error?: { code: number; message: string } };

const rpc = (id: number | string, method: string, params: Record<string, unknown> = {}) => ({ jsonrpc: "2.0", id, method, params });
const cancel = (requestId: number | string) => ({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId, reason: "test" } });
const slowCall = (id: number | string, ms: number) => rpc(id, "tools/call", { name: "slow", arguments: { ms } });
const note = { jsonrpc: "2.0", method: "notifications/roots/list_changed" };
const initParams = (protocolVersion: string) => ({ protocolVersion, capabilities: {}, clientInfo: { name: "t", version: "0" } });
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function slowServer(): Server {
  const server = new Server({ name: "t", version: "0" }, { capabilities: { tools: {} } });
  server.setRequestHandler("tools/list", async () => ({ tools: [] }));
  server.setRequestHandler("tools/call", async (request) => {
    const ms = Number((request.params.arguments as { ms?: unknown } | undefined)?.ms ?? 0);
    await new Promise((r) => (ms < 0 ? undefined : setTimeout(r, ms)));
    return { content: [{ type: "text", text: `slept ${ms}` }] };
  });
  return server;
}

// stdio -------------------------------------------------------------------------------------------
/** A 2025-03-26 stdio connection wired as index.ts wires it: everything written to stdout, in order. */
async function stdioConnection(batchDeadlineMs?: number) {
  const out: Array<Message | Message[]> = [];
  const gate = new StdioGate((m) => out.push(m as Message), batchDeadlineMs === undefined ? {} : { batchDeadlineMs });
  const output = gate.output((text) => {
    for (const line of text.split("\n")) if (line.trim()) out.push(JSON.parse(line) as Message | Message[]);
  });
  serveStdio(slowServer, { transport: new StdioServerTransport(gate, output), onerror: () => undefined });
  const send = (m: unknown) => gate.write(`${JSON.stringify(m)}\n`);
  send(rpc(1, "initialize", initParams("2025-03-26")));
  const deadline = Date.now() + 5000;
  while (out.length === 0 && Date.now() < deadline) await wait(10);
  expect((out[0] as Message).result).toMatchObject({ protocolVersion: "2025-03-26" });
  send({ jsonrpc: "2.0", method: "notifications/initialized" });
  out.length = 0;
  const until = async (test: () => boolean, ms = 3000) => {
    const end = Date.now() + ms;
    while (!test() && Date.now() < end) await wait(10);
  };
  return { out, send, until, close: () => gate.end() };
}

const ids = (batch: Message | Message[]) => (Array.isArray(batch) ? batch.map((m) => m.id) : [batch.id]);

describe("stdio: a served batch is written once every request that will be answered has been", () => {
  let conn: Awaited<ReturnType<typeof stdioConnection>>;
  afterEach(() => conn?.close());

  it("the blind check: [call 20, cancel 20, ping 21] is answered [21] at once, and a later ping 20 alone", async () => {
    conn = await stdioConnection();
    conn.send([slowCall(20, -1), cancel(20), rpc(21, "ping")]);
    await conn.until(() => conn.out.length >= 1);
    expect(conn.out).toEqual([[{ jsonrpc: "2.0", id: 21, result: {} }]]);
    conn.send(rpc(20, "ping"));
    await conn.until(() => conn.out.length >= 2);
    await wait(100);
    // Never folded into the old batch: its own line, an object.
    expect(conn.out).toEqual([[{ jsonrpc: "2.0", id: 21, result: {} }], { jsonrpc: "2.0", id: 20, result: {} }]);
  });

  it("a cancel in a later message drops its request from the open batch; the cancelled request gets no answer", async () => {
    conn = await stdioConnection();
    conn.send([slowCall(20, -1), rpc(21, "ping")]);
    await wait(150);
    expect(conn.out).toEqual([]); // 21 answered, the batch waits for 20
    const cancelledAt = Date.now();
    conn.send(cancel(20));
    await conn.until(() => conn.out.length >= 1);
    expect(Date.now() - cancelledAt).toBeLessThan(CANCEL_SETTLE_MS + 1000);
    await wait(200);
    expect(conn.out).toEqual([[{ jsonrpc: "2.0", id: 21, result: {} }]]);
  });

  it("the same cancel inside a later batch: the open batch is written, the cancel-only batch writes nothing", async () => {
    conn = await stdioConnection();
    conn.send([slowCall(30, -1), rpc(31, "ping")]);
    await wait(100);
    conn.send([cancel(30)]);
    await conn.until(() => conn.out.length >= 1);
    conn.send([cancel(99), cancel(98)]);
    await wait(300);
    expect(conn.out).toEqual([[{ jsonrpc: "2.0", id: 31, result: {} }]]);
  });

  it("a request and its cancel alone write nothing, and a cancel before its request cancels nothing", async () => {
    conn = await stdioConnection();
    conn.send([slowCall(40, -1), cancel(40)]);
    conn.send([cancel(41), slowCall(41, 250)]);
    await conn.until(() => conn.out.length >= 1);
    await wait(200);
    expect(conn.out).toEqual([[{ jsonrpc: "2.0", id: 41, result: { content: [{ type: "text", text: "slept 250" }] } }]]);
  });

  it("an id reused while an open batch waits for it is answered alone, and never folded into that batch", async () => {
    conn = await stdioConnection();
    conn.send([slowCall(50, 300), rpc(51, "ping")]);
    await wait(50);
    conn.send(rpc(50, "ping")); // a client error (MCP: ids are not reused), answered as well as it can be
    await conn.until(() => conn.out.length >= 3, 3000);
    const arrays = conn.out.filter(Array.isArray);
    expect(arrays).toEqual([[{ jsonrpc: "2.0", id: 51, result: {} }]]);
    const singles = conn.out.filter((m): m is Message => !Array.isArray(m));
    expect(singles.map((m) => m.id)).toEqual([50, 50]);
    // The same in a later batch: the earlier batch stops waiting for the id.
    conn.out.length = 0;
    conn.send([slowCall(60, -1), rpc(61, "ping")]);
    await wait(50);
    conn.send([rpc(60, "ping"), rpc(62, "ping")]);
    await conn.until(() => conn.out.length >= 2);
    expect(conn.out.map(ids)).toEqual([[61], [60, 62]]);
  });

  it("a repeated id inside one batch: the first request runs, the repeat is refused, all in one array", async () => {
    conn = await stdioConnection();
    conn.send([rpc(5, "ping"), rpc(5, "tools/list"), rpc(6, "ping")]);
    await conn.until(() => conn.out.length >= 1);
    const [batch] = conn.out as Message[][];
    expect(batch).toHaveLength(3);
    expect(batch).toContainEqual({ jsonrpc: "2.0", id: 5, result: {} });
    expect(batch).toContainEqual({ jsonrpc: "2.0", id: 5, error: { code: -32600, message: expect.stringContaining("repeated in this batch") } });
    expect(batch).toContainEqual({ jsonrpc: "2.0", id: 6, result: {} });
    // The first of the two cancelled: only the repeat's refusal is left to give.
    conn.out.length = 0;
    conn.send([slowCall(7, -1), rpc(7, "ping"), cancel(7)]);
    await conn.until(() => conn.out.length >= 1);
    expect(conn.out).toEqual([[{ jsonrpc: "2.0", id: 7, error: { code: -32600, message: expect.stringContaining("repeated in this batch") } }]]);
  });

  it("a batch mixing a notification with requests answers the requests, and an invalid member with -32600", async () => {
    conn = await stdioConnection();
    conn.send([note, rpc(8, "ping"), { jsonrpc: "1.0", id: 9, method: "ping" }, rpc(10, "tools/list")]);
    await conn.until(() => conn.out.length >= 1);
    const [batch] = conn.out as Message[][];
    expect(batch.map((m) => m.id).sort()).toEqual([10, 8, 9]);
    expect(batch.find((m) => m.id === 9)?.error?.code).toBe(-32600);
  });

  it("no batch waits forever: at its deadline it is written with what has answered", async () => {
    conn = await stdioConnection(300);
    conn.send([slowCall(70, -1), rpc(71, "ping")]);
    await wait(150);
    expect(conn.out).toEqual([]);
    await conn.until(() => conn.out.length >= 1, 2000);
    expect(conn.out).toEqual([[{ jsonrpc: "2.0", id: 71, result: {} }]]);
    // A batch none of whose requests answered by then writes nothing (never an empty array).
    conn.out.length = 0;
    conn.send([slowCall(72, -1)]);
    await wait(600);
    expect(conn.out).toEqual([]);
  });

  it("a single request is untouched by all of this", async () => {
    conn = await stdioConnection();
    conn.send(rpc(80, "ping"));
    conn.send(slowCall(81, -1));
    conn.send(cancel(81));
    await conn.until(() => conn.out.length >= 1);
    await wait(150);
    expect(conn.out).toEqual([{ jsonrpc: "2.0", id: 80, result: {} }]);
  });
});

describe("batchCancellation, the rule both transports read a batch by", () => {
  it("drops a request its own batch cancels and that cancel; refuses a repeated id; keeps the rest in order", () => {
    const plan = batchCancellation([rpc(1, "ping"), cancel(1), cancel(2), rpc(2, "ping"), rpc(2, "ping"), note], () => null);
    expect(plan.passed).toEqual([cancel(2), rpc(2, "ping"), note]);
    expect(plan.answers).toEqual([{ jsonrpc: "2.0", id: 2, error: { code: -32600, message: expect.stringContaining("repeated") } }]);
  });

  it('a cancel names its request by exact id: 20 is not "20"', () => {
    expect(batchCancellation([rpc(20, "ping"), cancel("20")], () => null).passed).toHaveLength(2);
  });
});

// HTTP --------------------------------------------------------------------------------------------
interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  text: string;
  ended: boolean;
}

function events(text: string): Message[] {
  return text
    .split("\n\n")
    .map((e) => e.split("\n").find((l) => l.startsWith("data: ")))
    .filter((l): l is string => Boolean(l))
    .map((l) => JSON.parse(l.slice(6)) as Message);
}

describe("HTTP (stateless, no session id): a served batch's response always ends", () => {
  let handle: HttpServerHandle;
  let port: number;
  const realError = console.error;
  beforeEach(async () => {
    console.error = () => undefined;
    handle = await startHttpServer(slowServer, { port: 0, host: "127.0.0.1", handleSignals: false });
    port = (handle.server.address() as AddressInfo).port;
  });
  afterEach(async () => {
    await handle.close();
    console.error = realError;
  });

  const post = (body: unknown, headers: Record<string, string> = {}, timeoutMs = 3000) =>
    new Promise<Reply>((resolve, reject) => {
      const data = JSON.stringify(body);
      const req = httpRequest(
        { host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { host: `127.0.0.1:${port}`, "content-type": "application/json", accept: "application/json, text/event-stream", "content-length": Buffer.byteLength(data), ...headers } },
        (res) => {
          let text = "";
          const timer = setTimeout(() => {
            req.destroy();
            resolve({ status: res.statusCode ?? 0, headers: res.headers, text, ended: false });
          }, timeoutMs);
          res.on("data", (d) => (text += d));
          res.on("end", () => {
            clearTimeout(timer);
            resolve({ status: res.statusCode ?? 0, headers: res.headers, text, ended: true });
          });
        },
      );
      req.on("error", reject);
      req.end(data);
    });
  const v0326 = { "mcp-protocol-version": "2025-03-26" };

  it("the blind check: after a session-less initialize, [call 20, cancel 20, ping 21] ends with the answer to 21", async () => {
    const init = await post(rpc(1, "initialize", initParams("2025-03-26")));
    expect(init.status).toBe(200);
    expect(init.headers["mcp-session-id"]).toBeUndefined();
    for (const headers of [v0326, {}]) {
      const reply = await post([slowCall(20, -1), cancel(20), rpc(21, "ping")], headers);
      expect(reply.ended).toBe(true); // it never ended before
      expect(reply.status).toBe(200);
      expect(events(reply.text)).toEqual([{ jsonrpc: "2.0", id: 21, result: {} }]);
    }
  });

  it("a batch of notifications only, or of a request and its cancel, is 202 with no body", async () => {
    for (const batch of [[cancel(5), note], [slowCall(6, -1), cancel(6)], [slowCall(7, -1), cancel(7), note]]) {
      const reply = await post(batch, v0326);
      expect(reply, JSON.stringify(batch)).toMatchObject({ status: 202, text: "", ended: true });
    }
  });

  it("a batch mixing a notification with requests answers each request", async () => {
    const reply = await post([note, rpc(1, "ping"), rpc(2, "tools/list")], v0326);
    expect(reply.ended).toBe(true);
    expect(events(reply.text)).toEqual([
      { jsonrpc: "2.0", id: 1, result: {} },
      { jsonrpc: "2.0", id: 2, result: { tools: [] } },
    ]);
  });

  it("a repeated id: the first request runs and is answered, the repeat is refused (one of the two answers was lost)", async () => {
    const reply = await post([slowCall(5, 200), rpc(5, "ping"), rpc(6, "ping")], v0326);
    expect(reply.ended).toBe(true);
    const got = events(reply.text);
    expect(got).toHaveLength(3);
    expect(got).toContainEqual({ jsonrpc: "2.0", id: 5, error: { code: -32600, message: expect.stringContaining("repeated in this batch") } });
    expect(got).toContainEqual({ jsonrpc: "2.0", id: 5, result: { content: [{ type: "text", text: "slept 200" }] } });
    expect(got).toContainEqual({ jsonrpc: "2.0", id: 6, result: {} });
    // Nothing left to run but a refusal to give: that refusal, as JSON.
    const alone = await post([slowCall(8, -1), rpc(8, "ping"), cancel(8)], v0326);
    expect(alone).toMatchObject({ status: 200, ended: true });
    expect(JSON.parse(alone.text)).toEqual([{ jsonrpc: "2.0", id: 8, error: { code: -32600, message: expect.stringContaining("repeated in this batch") } }]);
  });

  it("a cancel in a later POST has nothing to reach (stateless), and the first batch ends with both answers", async () => {
    const first = post([slowCall(20, 300), rpc(21, "ping")], v0326);
    await wait(50);
    expect(await post(cancel(20), v0326)).toMatchObject({ status: 202, ended: true });
    const reply = await first;
    expect(reply.ended).toBe(true);
    expect(events(reply.text).map((m) => m.id).sort()).toEqual([20, 21]);
  });

  it("a batch on a 2025-06-18 session is refused whole: 400, -32600, id null, nothing run", async () => {
    for (const headers of [{ "mcp-protocol-version": "2025-06-18" }, { "mcp-protocol-version": "2025-11-25" }]) {
      const reply = await post([slowCall(20, -1), cancel(20), rpc(21, "ping")], headers);
      expect(reply.status).toBe(400);
      expect(JSON.parse(reply.text)).toEqual({ jsonrpc: "2.0", id: null, error: { code: -32600, message: expect.stringContaining("since protocol revision 2025-06-18") } });
    }
  });

  it("a single request is untouched", async () => {
    const reply = await post(rpc(3, "ping"), v0326);
    expect(reply).toMatchObject({ status: 200, ended: true });
    expect(reply.text).toContain('"id":3');
  });
});
