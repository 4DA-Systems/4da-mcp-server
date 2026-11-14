// SPDX-License-Identifier: Apache-2.0
/**
 * The SDK's `Server`, with invalid params answered as Invalid Params.
 *
 * The SDK checks each request's params against the protocol schema before a handler runs. For
 * `tools/call` a failure is a `-32602 Invalid params` error; for every other method it throws a
 * plain `Error`, which goes out as `-32603 Internal error` (pre-publish round 7: `initialize`
 * with no `protocolVersion`, `resources/read` with no `uri`, `prompts/get` with no `name`). JSON-RPC
 * says invalid method parameters are -32602, and an internal error tells a client to retry.
 *
 * The rule: this server's own handlers never throw an error without a JSON-RPC code
 * (`ownHandler` gives any such error -32603 where it is thrown), so an error with no code reaching
 * `_wrapHandler` can only come from the SDK's schema check, and is answered -32602 with the
 * SDK's message.
 */
import { ProtocolError, ProtocolErrorCode, Server, type JSONRPCRequest, type Result, type ServerContext } from "@modelcontextprotocol/server";

type RequestHandler = (request: JSONRPCRequest, ctx: ServerContext) => Promise<Result>;

type Handler<Req, Ctx, Res> = (request: Req, ctx: Ctx) => Res | Promise<Res>;

/** True for an error that carries a JSON-RPC code of its own. */
function hasCode(error: unknown): boolean {
  return typeof error === "object" && error !== null && Number.isSafeInteger((error as { code?: unknown }).code);
}

/**
 * A handler of this server's own: whatever it throws without a JSON-RPC code is an internal error
 * (-32603), as the SDK would have answered it, and is never mistaken for a params failure.
 */
export function ownHandler<Req, Ctx, Res>(handler: Handler<Req, Ctx, Res>): (request: Req, ctx: Ctx) => Promise<Res> {
  return async (request, ctx) => {
    try {
      return await handler(request, ctx);
    } catch (error) {
      if (hasCode(error)) throw error;
      throw new ProtocolError(ProtocolErrorCode.InternalError, error instanceof Error ? error.message : String(error));
    }
  };
}

export class FourDAServer extends Server {
  protected override _wrapHandler(method: string, handler: RequestHandler): RequestHandler {
    const wrapped = super._wrapHandler(method, handler);
    return async (request, ctx) => {
      try {
        return await wrapped(request, ctx);
      } catch (error) {
        if (hasCode(error) || !(error instanceof Error)) throw error;
        throw new ProtocolError(ProtocolErrorCode.InvalidParams, `Invalid params for ${method}: ${error.message}`);
      }
    };
  }
}
