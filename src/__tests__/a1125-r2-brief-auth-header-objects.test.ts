// SPDX-License-Identifier: Apache-2.0
/**
 * A token header whose `alg` or `typ` is not a string is refused, never thrown on (re-check of the
 * 2026-11-25 audit fixes): `{"alg":{"toString":1}}` made verifyToken call String() on the object,
 * which threw, and the HTTP transport answered 500 where a refusal (401) belongs.
 */
import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { verifyToken } from "../auth.js";

const SECRET = "relay-shared-secret-for-tests";
const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const payload = { team_id: "team-alpha", client_id: "client-1", role: "member", exp: 9999999999 };
function sign(header: unknown): string {
  const input = `${b64url(header)}.${b64url(payload)}`;
  return `${input}.${createHmac("sha256", SECRET).update(input).digest("base64url")}`;
}

let warn: ReturnType<typeof vi.spyOn>;
let priorSecret: string | undefined;
beforeEach(() => {
  priorSecret = process.env.MCP_AUTH_SECRET;
  process.env.MCP_AUTH_SECRET = SECRET;
  warn = vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => {
  warn.mockRestore();
  if (priorSecret === undefined) delete process.env.MCP_AUTH_SECRET;
  else process.env.MCP_AUTH_SECRET = priorSecret;
});

describe("a header value that is not a string", () => {
  it.each([
    ["alg as an object with toString", { alg: { toString: 1 } }],
    ["alg as an object with valueOf", { alg: { valueOf: 1, toString: null } }],
    ["alg as an array", { alg: ["HS256"] }],
    ["alg as a number", { alg: 256 }],
    ["typ as an object with toString", { alg: "HS256", typ: { toString: 1 } }],
    ["typ as an array", { alg: "HS256", typ: ["JWT"] }],
    ["alg null", { alg: null }],
  ])("%s is refused without throwing", (_label, header) => {
    expect(() => verifyToken(sign(header))).not.toThrow();
    expect(verifyToken(sign(header))).toBeNull();
  });

  it("a well-formed token still verifies", () => {
    expect(verifyToken(sign({ alg: "HS256", typ: "JWT" }))?.team_id).toBe("team-alpha");
  });
});
