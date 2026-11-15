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
 * - A line longer than 10 MB is discarded whole, up to its newline, and answered once. Until 6.3.0
 *   the gate dropped the first 10 MB and read the rest as a line of its own, so a request placed
 *   after the limit ran (blind audit of e3aba98: it stored a decision).
 * - A JSON-RPC batch is served when the connection negotiated protocol 2025-03-26, which requires
 *   a server to accept one, and refused (-32600, id null) from 2025-06-18 on, which removed them:
 *   the same policy as the HTTP transport (http-transport.ts). Each message of a served batch goes
 *   to the SDK on its own line, and the answers come back as one JSON array (`StdioGate.output`).
 * - A served batch is written once every request in it that will be answered has been (pre-publish
 *   round 10, W1). The SDK never answers a cancelled request, and the gate used to wait for every
 *   id, so `[tools/call 20, notifications/cancelled 20, ping 21]` was never written, and a later
 *   single `ping 20` was folded into it as `[{id:21},{id:20}]`. Now (`batchCancellation`):
 *   a request cancelled by a later member of its own batch never runs and is left out; a cancel in
 *   a later message drops its request from the open batch once the SDK has read the cancel; an id
 *   sent again while an open batch waits for it is dropped from that batch, so its answer is never
 *   folded into it; and every open batch is written, with what has answered, at a deadline past
 *   the tool-call budget (call-budget.ts). A batch with no answer to give writes nothing.
 *
 * Everything else passes through unchanged, one line each.
 */

import { StringDecoder } from "node:string_decoder";
import { Transform, Writable, type TransformCallback } from "node:stream";
import { pushAll } from "./array-utils.js";
import { callBudgetMs } from "./call-budget.js";

const PROTOCOL_CLAIM = "io.modelcontextprotocol/protocolVersion";
/** One line's limit, as the SDK's reader: past it the line is refused and discarded whole. */
export const MAX_LINE = 10 * 1024 * 1024;
/** The first protocol revision without JSON-RPC batches (2025-03-26 required them). */
export const FIRST_REVISION_WITHOUT_BATCHES = "2025-06-18";

/**
 * How long after a cancel is passed on the gate still takes its request's answer for the open batch.
 * The SDK reads the cancel within microtasks of it being passed on and from then on answers nothing
 * for that request; an answer it had already sent in that moment is kept (pre-publish round 10, W1).
 */
export const CANCEL_SETTLE_MS = 50;
/** How far past the tool-call budget an open batch waits before it is written with what answered. */
export const BATCH_DEADLINE_GRACE_MS = 10_000;

type Reply = (message: Record<string, unknown>) => void;
type RequestId = string | number;

export interface StdioGateOptions {
  /** How long a served batch may wait for its answers; left out, the tool-call budget plus BATCH_DEADLINE_GRACE_MS. */
  batchDeadlineMs?: number;
}

/** A served batch: the answers it still waits for, and those it has. */
interface OpenBatch {
  waiting: Set<RequestId>;
  answers: Array<Record<string, unknown>>;
  timer: ReturnType<typeof setTimeout> | null;
  done: boolean;
}

export class StdioGate extends Transform {
  private buffer = "";
  /** True while the rest of an over-long line is read and thrown away, up to its newline. */
  private discarding = false;
  private readonly decoder = new StringDecoder("utf8");
  private opened = false;
  /** The id of the `initialize` request, until its answer names the negotiated version. */
  private initializeId: RequestId | null = null;
  /** The protocol revision the connection's `initialize` negotiated, once answered. */
  private negotiated: string | null = null;
  /** The open batch each unanswered batch request id belongs to: one batch per id at a time. */
  private readonly waitedBy = new Map<RequestId, OpenBatch>();
  /** Where answers are written once `output` is in use; until then the gate's replies go to `reply`. */
  private sink: ((text: string) => void) | null = null;

  constructor(
    private readonly reply: Reply,
    private readonly options: StdioGateOptions = {},
  ) {
    super();
  }

  /** One of the gate's own answers: never held for a batch. */
  private send(message: Record<string, unknown>): void {
    if (this.sink) this.sink(`${JSON.stringify(message)}\n`);
    else this.reply(message);
  }

  /** The protocol revision this connection negotiated, or null before (or without) `initialize`. */
  get protocolVersion(): string | null {
    return this.negotiated;
  }

  /**
   * The stream the SDK writes its answers to. It notes the version `initialize` negotiated, and
   * holds back the answers to a served batch until all of them are in, then writes them as one
   * array. Every other answer goes straight to `sink`; so do the gate's own replies from then on.
   */
  output(sink: (text: string) => void): Writable {
    this.sink = sink;
    return new Writable({
      decodeStrings: false,
      write: (chunk: Buffer | string, _encoding, done) => {
        for (const text of chunk.toString().split("\n")) {
          if (!text.trim()) continue;
          let message: unknown;
          try {
            message = JSON.parse(text);
          } catch {
            sink(`${text}\n`);
            continue;
          }
          if (!isObject(message)) {
            sink(`${text}\n`);
            continue;
          }
          this.observe(message);
          if (!this.collect(message)) sink(`${text}\n`);
        }
        done();
      },
    });
  }

  override _transform(chunk: Buffer | string, _encoding: BufferEncoding, done: TransformCallback): void {
    this.consume(typeof chunk === "string" ? chunk : this.decoder.write(chunk));
    done();
  }

  override _flush(done: TransformCallback): void {
    this.consume(this.decoder.end());
    if (!this.discarding && this.buffer.trim()) this.line(this.buffer);
    this.buffer = "";
    this.discarding = false;
    done();
  }

  private consume(text: string): void {
    let rest = text;
    while (rest.length > 0) {
      const at = rest.indexOf("\n");
      if (this.discarding) {
        // The tail of an over-long line: nothing of it is read, up to and with its newline.
        if (at < 0) return;
        this.discarding = false;
        rest = rest.slice(at + 1);
        continue;
      }
      if (at < 0) {
        this.buffer += rest;
        if (this.buffer.length > MAX_LINE) this.refuseLong(this.buffer, true);
        return;
      }
      const line = this.buffer + rest.slice(0, at);
      this.buffer = "";
      rest = rest.slice(at + 1);
      if (line.length > MAX_LINE) this.refuseLong(line, false);
      else this.line(line.replace(/\r$/, ""));
    }
  }

  /** An over-long line: answered once, under its id when its opening names one, and never run. */
  private refuseLong(start: string, more: boolean): void {
    this.buffer = "";
    this.discarding = more;
    const id = leadingId(start);
    this.send(
      id === null
        ? parseError("the line is longer than the 10 MB limit; it was discarded up to its newline and nothing in it was run")
        : { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request: the line is longer than the 10 MB limit; it was discarded up to its newline and not run." } },
    );
  }

  private line(line: string): void {
    if (!line.trim()) return;
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch (error) {
      this.send(parseError(error instanceof Error ? error.message : String(error)));
      return;
    }
    if (Array.isArray(message)) {
      this.batch(message);
      return;
    }
    const refusal = this.check(message);
    if (refusal) {
      this.send(refusal);
      return;
    }
    const m = message as Record<string, unknown>;
    // A single request that reuses an id an open batch waits for: its answer is its own, never the
    // batch's (pre-publish round 10, W1).
    if (isRequestId(m.id) && typeof m.method === "string") this.release(m.id);
    this.push(`${line}\n`);
    const cancelled = cancelledId(m);
    if (cancelled !== null) this.settleCancel(cancelled, this.waitedBy.get(cancelled));
  }

  /**
   * A JSON-RPC batch. Served only on a connection that negotiated a revision that requires
   * batches (2025-03-26 and earlier); refused, as one -32600 with id null, otherwise. A served
   * batch is checked message by message, exactly as single lines are, and answered as one array
   * of every answer it calls for (none, for a batch of notifications only).
   */
  private batch(messages: unknown[]): void {
    const allowed = this.negotiated !== null && this.negotiated < FIRST_REVISION_WITHOUT_BATCHES;
    if (!allowed || messages.length === 0) {
      this.send({
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32600,
          message: messages.length === 0 && allowed ? "Invalid Request: an empty batch." : batchRefusedMessage("stdio", this.negotiated),
        },
      });
      return;
    }
    const open: OpenBatch = { waiting: new Set(), answers: [], timer: null, done: false };
    const plan = batchCancellation(messages, (message) =>
      isObject(message) && message.method === "initialize"
        ? { jsonrpc: "2.0", id: isRequestId(message.id) ? message.id : null, error: { code: -32600, message: "Invalid Request: initialize must not be part of a JSON-RPC batch (MCP 2025-03-26)." } }
        : this.check(message),
    );
    pushAll(open.answers, plan.answers);
    // A cancel names the batch that waits for its id at its own place in the batch: in
    // `[cancel 41, call 41]` it cancels an earlier 41, never this batch's own.
    const cancels: Array<[RequestId, OpenBatch | undefined]> = [];
    for (const m of plan.passed) {
      const cancelled = cancelledId(m);
      if (cancelled !== null) cancels.push([cancelled, this.waitedBy.get(cancelled)]);
      if (isRequestId(m.id) && typeof m.method === "string") {
        // The id was waited for by an earlier open batch: from now on its answer is this batch's.
        this.release(m.id);
        open.waiting.add(m.id);
        this.waitedBy.set(m.id, open);
      }
    }
    if (open.waiting.size === 0) {
      open.done = true;
      if (open.answers.length > 0) this.emitBatch(open);
    } else {
      // No batch waits forever: a request the SDK never answers (dropped, or cancelled from
      // elsewhere) would otherwise hold every other answer in it back (pre-publish round 10, W1).
      const deadline = this.options.batchDeadlineMs ?? callBudgetMs() + BATCH_DEADLINE_GRACE_MS;
      open.timer = setTimeout(() => this.expire(open), deadline);
      open.timer.unref?.();
    }
    for (const m of plan.passed) this.push(`${JSON.stringify(m)}\n`);
    for (const [id, target] of cancels) this.settleCancel(id, target);
  }

  /**
   * A cancel was passed on for `id`. If an open batch waits for it, the SDK will not answer it once
   * it has read the cancel, so the batch stops waiting for it then: an answer already on its way in
   * that moment still counts.
   */
  private settleCancel(id: RequestId, open: OpenBatch | undefined): void {
    if (!open) return;
    const timer = setTimeout(() => {
      if (this.waitedBy.get(id) === open) this.release(id);
    }, CANCEL_SETTLE_MS);
    timer.unref?.();
  }

  /** The open batch waiting for `id` (if one is) stops waiting for it; any later answer goes out alone. */
  private release(id: RequestId): void {
    const open = this.waitedBy.get(id);
    if (!open) return;
    this.waitedBy.delete(id);
    open.waiting.delete(id);
    this.settle(open);
  }

  /** The batch's deadline: it is written with what has answered, and stops waiting for the rest. */
  private expire(open: OpenBatch): void {
    for (const id of open.waiting) if (this.waitedBy.get(id) === open) this.waitedBy.delete(id);
    open.waiting.clear();
    this.settle(open);
  }

  /** Writes a batch that waits for nothing more: its answers as one array, or nothing when it has none. */
  private settle(open: OpenBatch): void {
    if (open.done || open.waiting.size > 0) return;
    open.done = true;
    if (open.timer) clearTimeout(open.timer);
    // JSON-RPC: a batch with no response to give is answered with nothing, never an empty array.
    if (open.answers.length > 0) this.emitBatch(open);
  }

  /** The refusal for one message, or null when it may pass. Single lines and batch members alike. */
  private check(message: unknown): Record<string, unknown> | null {
    // JSON that is no message at all: the SDK dropped such a line without a word, so a client
    // waited for a reply that never came (blind audit 2026-11-14).
    if (!isObject(message)) {
      return { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request: a message must be a JSON object." } };
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
      return { jsonrpc: "2.0", id, error: { code: -32600, message: invalid } };
    }
    // A request with "params": null (or a string, a number, an array) got no answer either (blind
    // audit round 4): MCP params are an object, or left out.
    const isRequest = isMethod && (typeof message.id === "string" || typeof message.id === "number");
    if (isRequest && "params" in message && message.params !== undefined && !isObject(message.params)) {
      const got = message.params === null ? "null" : Array.isArray(message.params) ? "an array" : `a ${typeof message.params}`;
      return { jsonrpc: "2.0", id: message.id as RequestId, error: { code: -32602, message: `Invalid params: MCP params must be a JSON object, or left out (got ${got}).` } };
    }
    if (!this.opened && typeof message.method === "string") {
      const method = message.method;
      const claimed = isObject(message.params) && isObject(message.params._meta) && typeof message.params._meta[PROTOCOL_CLAIM] === "string";
      if (method === "initialize" || method === "server/discover" || claimed) {
        this.opened = true;
        if (method === "initialize" && isRequest) this.initializeId = message.id as RequestId;
      } else if (isRequest && method !== "ping") {
        return { jsonrpc: "2.0", id: message.id as RequestId, error: { code: -32600, message: `Server not initialized: send initialize before ${method} (MCP lifecycle).` } };
      }
    }
    return null;
  }

  /** Notes the protocol version the answer to `initialize` names. */
  private observe(message: Record<string, unknown>): void {
    if (this.initializeId === null || message.id !== this.initializeId) return;
    this.initializeId = null;
    const result = message.result;
    if (isObject(result) && typeof result.protocolVersion === "string") this.negotiated = result.protocolVersion;
  }

  /** Files an answer under the open batch that waits for it; true when it was taken. */
  private collect(message: Record<string, unknown>): boolean {
    const id = message.id;
    if (!isRequestId(id) || !("result" in message || "error" in message)) return false;
    const open = this.waitedBy.get(id);
    if (!open) return false;
    this.waitedBy.delete(id);
    open.waiting.delete(id);
    open.answers.push(message);
    this.settle(open);
    return true;
  }

  private emitBatch(open: OpenBatch): void {
    this.sink?.(`${JSON.stringify(open.answers)}\n`);
  }
}

/** The refusal of a JSON-RPC batch, the same on stdio and HTTP (http-transport.ts). */
export function batchRefusedMessage(transport: "stdio" | "http", negotiated: string | null = null): string {
  const where = transport === "stdio" ? "on its own line" : "in its own HTTP request";
  const note = transport === "stdio" && negotiated === null ? " (a connection whose initialize negotiates 2025-03-26 may send them after it)" : "";
  return `Invalid Request: JSON-RPC batches are not supported by MCP since protocol revision 2025-06-18; send each request ${where}${note}.`;
}

/** The request id a `notifications/cancelled` names, or null for any other message. */
export function cancelledId(message: unknown): RequestId | null {
  if (!isObject(message) || message.method !== "notifications/cancelled" || "id" in message) return null;
  return isObject(message.params) && isRequestId(message.params.requestId) ? message.params.requestId : null;
}

/**
 * What of a served batch goes on to the SDK, and what the gate answers itself. The same on stdio and
 * HTTP (http-transport.ts), read in the batch's order (pre-publish round 10, W1):
 *
 * - a member `refuse` returns a refusal for is answered with it and not passed on;
 * - a request whose id an earlier request of the batch already used is refused (-32600): the two
 *   answers could not be told apart, and on HTTP the SDK lost one of them;
 * - a request a later member of the same batch cancels never runs and is not answered (MCP: a
 *   cancelled request gets no response), and that cancel, having done its work, is not passed on;
 * - everything else is passed on, a cancel of anything outside the batch included.
 */
export function batchCancellation(
  messages: unknown[],
  refuse: (message: unknown) => Record<string, unknown> | null,
): { passed: Array<Record<string, unknown>>; answers: Array<Record<string, unknown>> } {
  const answers: Array<Record<string, unknown>> = [];
  const kept: Array<Record<string, unknown> | null> = [];
  const used = new Set<RequestId>();
  const running = new Map<RequestId, number>();
  for (const message of messages) {
    const refusal = refuse(message);
    if (refusal) {
      answers.push(refusal);
      continue;
    }
    const m = message as Record<string, unknown>;
    if (isRequestId(m.id) && typeof m.method === "string") {
      if (used.has(m.id)) {
        answers.push({ jsonrpc: "2.0", id: m.id, error: { code: -32600, message: "Invalid Request: a request id is repeated in this batch; only its first request was run." } });
        continue;
      }
      used.add(m.id);
      running.set(m.id, kept.length);
      kept.push(m);
      continue;
    }
    const cancelled = cancelledId(m);
    const at = cancelled === null ? undefined : running.get(cancelled);
    if (cancelled !== null && at !== undefined) {
      kept[at] = null;
      running.delete(cancelled);
      continue;
    }
    kept.push(m);
  }
  return { passed: kept.filter((m): m is Record<string, unknown> => m !== null), answers };
}

function parseError(detail: string): Record<string, unknown> {
  return { jsonrpc: "2.0", id: null, error: { code: -32700, message: `Parse error: ${detail.slice(0, 200)}` } };
}

/**
 * The id an over-long line names at its very start (`{"jsonrpc":"2.0","id":7,...` or
 * `{"id":"a",...`), so its refusal can carry it; null when the opening names none.
 */
function leadingId(start: string): RequestId | null {
  const match = /^\s*\{\s*(?:"jsonrpc"\s*:\s*"2\.0"\s*,\s*)?"id"\s*:\s*("(?:[^"\\]|\\.){0,200}"|-?\d{1,16})\s*[,}]/.exec(start.slice(0, 512));
  if (!match) return null;
  try {
    const id = JSON.parse(match[1]) as unknown;
    return isRequestId(id) ? id : null;
  } catch {
    return null;
  }
}

/** An MCP request id: a string, or an integer JSON-RPC can carry exactly (a safe integer). */
function isRequestId(value: unknown): value is string | number {
  return typeof value === "string" || (typeof value === "number" && Number.isSafeInteger(value));
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
