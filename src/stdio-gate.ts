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
          message: Array.isArray(message)
            ? "Invalid Request: JSON-RPC batches are not supported by MCP; send each request on its own line."
            : "Invalid Request: a message must be a JSON object.",
        },
      });
      return;
    }
    if (!this.opened && isObject(message) && typeof message.method === "string") {
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

function parseError(detail: string): Record<string, unknown> {
  return { jsonrpc: "2.0", id: null, error: { code: -32700, message: `Parse error: ${detail.slice(0, 200)}` } };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
