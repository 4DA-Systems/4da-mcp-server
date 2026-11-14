// SPDX-License-Identifier: Apache-2.0
/**
 * The stdio input, checked line by line before the MCP SDK reads it (pre-publish audit
 * 2026-11-13, protocol nits):
 *
 * - A line that is not JSON gets a JSON-RPC `-32700 Parse error` response (id null), as JSON-RPC
 *   2.0 requires. The SDK's own reader reported it out of band and answered nothing, so a client
 *   waited for a reply that never came.
 * - A 2025-era connection must open with `initialize` (MCP lifecycle): a request other than
 *   `initialize` or `ping` before it is refused with `-32600`, instead of being run. A 2026-07-28
 *   request carries its protocol version in `_meta` and needs no handshake; it passes, as does
 *   `server/discover`.
 *
 * Everything else passes through unchanged, one line each.
 */

import { Transform, type TransformCallback } from "node:stream";

const PROTOCOL_CLAIM = "io.modelcontextprotocol/protocolVersion";
/** One line's limit, as the SDK's reader: past it the line is refused as unparseable. */
const MAX_LINE = 10 * 1024 * 1024;

type Reply = (message: Record<string, unknown>) => void;

export class StdioGate extends Transform {
  private buffer = "";
  private opened = false;

  constructor(private readonly reply: Reply) {
    super();
  }

  override _transform(chunk: Buffer | string, _encoding: BufferEncoding, done: TransformCallback): void {
    this.buffer += chunk.toString();
    let at: number;
    while ((at = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, at).replace(/\r$/, "");
      this.buffer = this.buffer.slice(at + 1);
      this.line(line);
    }
    if (this.buffer.length > MAX_LINE) {
      this.buffer = "";
      this.reply(parseError("the line is longer than the 10 MB limit"));
    }
    done();
  }

  override _flush(done: TransformCallback): void {
    if (this.buffer.trim()) this.line(this.buffer);
    this.buffer = "";
    done();
  }

  private line(line: string): void {
    if (!line.trim()) return;
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch (error) {
      this.reply(parseError(error instanceof Error ? error.message : String(error)));
      return;
    }
    // A JSON-RPC batch (an array), or JSON that is no message at all: MCP has not carried batches
    // since 2025-06-18, and the SDK dropped such a line without a word, so a client waited for a
    // reply that never came (blind audit 2026-11-14).
    if (!isObject(message)) {
      this.reply({
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32600,
          message: Array.isArray(message) ? batchRefusedMessage("stdio") : "Invalid Request: a message must be a JSON object.",
        },
      });
      return;
    }
    // A message that is not JSON-RPC 2.0, or a request whose id is null (MCP: "MUST NOT be null"):
    // the SDK dropped both without a word (blind audit round 3).
    // A request whose id is an object, an array or a boolean was dropped the same way (blind audit
    // round 4): JSON-RPC allows only a string or a number, and the answer carries id null since the
    // id cannot be echoed.
    // A numeric id that is not an integer (1.5) or not a safe one (12345678901234567890), and a
    // "method" that is not a string, were dropped by the SDK's schema with a Zod error on stderr
    // and no reply (blind audit round 5): MCP request ids are strings or integers, and its integer
    // schema takes only safe integers. Each now gets -32600, echoing the id when it is a number.
    const hasMethod = "method" in message && message.method !== undefined;
    const isMethod = typeof message.method === "string";
    const hasId = "id" in message && message.id !== undefined;
    const badId = (isMethod || hasMethod) && hasId && !isRequestId(message.id);
    // A message with no "method" that is not a response either (`{"jsonrpc":"2.0"}`,
    // `{"jsonrpc":"2.0","id":77}`) was dropped by the SDK's schema with a Zod dump on stderr and
    // no reply (pre-publish round 7): -32600, under its id when it has a usable one, else null.
    const isResponse = "result" in message || "error" in message;
    const invalid =
      message.jsonrpc !== "2.0"
        ? `Invalid Request: "jsonrpc" must be "2.0" (got ${JSON.stringify(message.jsonrpc ?? null).slice(0, 40)}).`
        : !hasMethod && !isResponse
          ? 'Invalid Request: a message needs a "method" (a request or a notification), or a "result" or an "error" (a response).'
          : hasMethod && !isMethod
          ? `Invalid Request: "method" must be a string (got ${message.method === null ? "null" : Array.isArray(message.method) ? "an array" : `a ${typeof message.method === "object" ? "JSON object" : typeof message.method}`}).`
          : badId && message.id === null
            ? "Invalid Request: a request id must be a string or a number, never null (MCP); omit id only for a notification."
            : badId && typeof message.id === "number"
              ? `Invalid Request: a request id must be a string or an integer (MCP), and a number id a safe integer (got ${String(message.id).slice(0, 40)}).`
              : badId
                ? `Invalid Request: a request id must be a string or a number (got ${Array.isArray(message.id) ? "an array" : `a ${typeof message.id === "object" ? "JSON object" : typeof message.id}`}).`
                : null;
    if (invalid) {
      const id = typeof message.id === "string" || typeof message.id === "number" ? message.id : null;
      this.reply({ jsonrpc: "2.0", id, error: { code: -32600, message: invalid } });
      return;
    }
    // A request with "params": null (or a string, a number, an array) got no answer either (blind
    // audit round 4): MCP params are an object, or left out.
    const isRequest = isMethod && (typeof message.id === "string" || typeof message.id === "number");
    if (isRequest && "params" in message && message.params !== undefined && !isObject(message.params)) {
      const got = message.params === null ? "null" : Array.isArray(message.params) ? "an array" : `a ${typeof message.params}`;
      this.reply({
        jsonrpc: "2.0",
        id: message.id as string | number,
        error: { code: -32602, message: `Invalid params: MCP params must be a JSON object, or left out (got ${got}).` },
      });
      return;
    }
    if (!this.opened && typeof message.method === "string") {
      const method = message.method;
      const claimed = isObject(message.params) && isObject(message.params._meta) && typeof message.params._meta[PROTOCOL_CLAIM] === "string";
      const isRequest = "id" in message && message.id !== null && message.id !== undefined;
      if (method === "initialize" || method === "server/discover" || claimed) {
        this.opened = true;
      } else if (isRequest && method !== "ping") {
        this.reply({
          jsonrpc: "2.0",
          id: message.id as string | number,
          error: { code: -32600, message: `Server not initialized: send initialize before ${method} (MCP lifecycle).` },
        });
        return;
      }
    }
    this.push(`${line}\n`);
  }
}

/** The refusal of a JSON-RPC batch, the same on stdio and HTTP (http-transport.ts). */
export function batchRefusedMessage(transport: "stdio" | "http"): string {
  return `Invalid Request: JSON-RPC batches are not supported by MCP since protocol revision 2025-06-18; send each request ${transport === "stdio" ? "on its own line" : "in its own HTTP request"}.`;
}

function parseError(detail: string): Record<string, unknown> {
  return { jsonrpc: "2.0", id: null, error: { code: -32700, message: `Parse error: ${detail.slice(0, 200)}` } };
}

/** An MCP request id: a string, or an integer JSON-RPC can carry exactly (a safe integer). */
function isRequestId(value: unknown): value is string | number {
  return typeof value === "string" || (typeof value === "number" && Number.isSafeInteger(value));
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
