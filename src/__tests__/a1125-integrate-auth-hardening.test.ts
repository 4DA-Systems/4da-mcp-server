// SPDX-License-Identifier: Apache-2.0
/**
 * Hardening found by the lead in the 2026-11-25 audit (L-H1..3):
 * 1. a value from an unverified token header was printed raw to stderr: a newline in `alg` forged a
 *    log line. It is printed quoted and escaped, at most 40 characters.
 * 2. `--host 127.evil.example` counted as a loopback bind (`/^127\./`), so authentication was not
 *    forced on a hostname that resolves anywhere. Only localhost, ::1 and a dotted-quad 127.0.0.0/8
 *    address are loopback.
 * 3. a token segment was decoded leniently: junk appended to a valid signature was accepted. Every
 *    segment must be base64url letters only, and the signature in its canonical spelling.
 */
import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { verifyToken } from "../auth.js";
import { isLoopbackBind } from "../http-transport.js";

const SECRET = "relay-shared-secret-for-tests";
const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const payload = { team_id: "team-alpha", client_id: "client-1", role: "member", exp: 9999999999 };
function sign(header: Record<string, unknown> = { alg: "HS256", typ: "JWT" }): string {
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

const logged = () => warn.mock.calls.map((c: unknown[]) => c.map(String).join(" ")).join("\n");

describe("an unverified header value in the log", () => {
  it.each([
    ["alg", { alg: "none\n[4DA MCP Auth] Token accepted for team admin", typ: "JWT" }],
    ["typ", { alg: "HS256", typ: "x\r\n[4DA MCP Auth] Token accepted" }],
  ])("%s with a newline cannot forge a line", (_field, header) => {
    expect(verifyToken(sign(header))).toBeNull();
    const out = logged();
    expect(out).not.toMatch(/[\r\n]/);
    expect(out).toMatch(/\\[rn]/);
  });

  it("a long value is cut to 40 characters", () => {
    expect(verifyToken(sign({ alg: "A".repeat(500) }))).toBeNull();
    expect(logged()).toContain(JSON.stringify("A".repeat(40)));
    expect(logged()).not.toContain("A".repeat(41));
  });
});

describe("token segments are base64url and nothing else", () => {
  it("a genuine token still verifies", () => {
    expect(verifyToken(sign())).toMatchObject({ team_id: "team-alpha", role: "member" });
  });

  it.each(["!!", " ", "=", "+", "/", "%00", "é"])("junk %j after a valid signature is refused", (junk) => {
    expect(verifyToken(`${sign()}${junk}`)).toBeNull();
  });

  it("junk in the header or payload segment is refused before decoding", () => {
    const [h, p, s] = sign().split(".");
    expect(verifyToken(`${h}!.${p}.${s}`)).toBeNull();
    expect(verifyToken(`${h}.${p} .${s}`)).toBeNull();
  });

  it("a non-canonical spelling of the signature (its last character's unused bits) is refused", () => {
    const token = sign();
    const sig = token.split(".")[2];
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(sig[sig.length - 1]);
    // 32 bytes are 43 characters: the last carries 4 bits, the low 2 are unused.
    const variant = alphabet[last ^ 1];
    expect(Buffer.from(sig.slice(0, -1) + variant, "base64url").equals(Buffer.from(sig, "base64url"))).toBe(true);
    expect(verifyToken(`${token.slice(0, -1)}${variant}`)).toBeNull();
  });
});

describe("loopback binds", () => {
  it.each(["127.0.0.1", "127.255.255.254", "localhost", "LOCALHOST", "::1", "[::1]"])("%s is loopback", (h) => {
    expect(isLoopbackBind(h)).toBe(true);
  });

  it.each(["127.evil.example", "127.0.0.1.nip.io", "127.1", "127.0.0.01", "127.", "0.0.0.0", "::ffff:127.0.0.1", "localhost.evil.example"])("%s is not", (h) => {
    expect(isLoopbackBind(h)).toBe(false);
  });
});
