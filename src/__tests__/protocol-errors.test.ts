// SPDX-License-Identifier: Apache-2.0
/**
 * B-13 / B-14 / B-15 (audit 2026-10-12):
 * - an unknown tool or prompt NAME is a JSON-RPC Invalid Params error
 *   (-32602), as the MCP spec says, not a tool result with isError;
 * - `resources/read` of an unknown URI is a resource-not-found protocol error,
 *   and `4da://schema/__proto__` (or `constructor`, `toString`) reaches no
 *   inherited Object property (it used to throw a TypeError);
 * - `4da://skills` is not advertised: the file behind it never existed.
 *
 * index.ts cannot be imported (it starts the server), so the handlers' logic
 * lives in schema-registry.ts and is tested here, over the SDK's in-memory
 * transport for the wire codes, with index.ts pinned to use it.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { InMemoryTransport, Server } from "@modelcontextprotocol/server";
import {
  getToolSchemaDocument,
  hasToolSchema,
  listResources,
  readResource,
  toolEntry,
  unknownPromptError,
  unknownToolError,
} from "../schema-registry.js";
import { hasDispatchTool } from "../tool-dispatch.js";

const INHERITED = ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"];

describe("own-property lookups only", () => {
  it("no inherited Object property is a tool", () => {
    for (const name of INHERITED) {
      expect(toolEntry(name), name).toBeUndefined();
      expect(hasToolSchema(name), name).toBe(false);
      expect(getToolSchemaDocument(name), name).toBeNull();
      expect(hasDispatchTool(name), name).toBe(false);
    }
    expect(toolEntry("vulnerability_scan")).toBeDefined();
  });

  it("resources/read of 4da://schema/__proto__ is a not-found error, not a TypeError", () => {
    for (const name of INHERITED) {
      let thrown: unknown;
      try {
        readResource(`4da://schema/${name}`);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, name).toBeDefined();
      expect(thrown, name).not.toBeInstanceOf(TypeError);
      expect((thrown as { code?: number }).code, name).toBe(-32602);
    }
  });
});

describe("resources", () => {
  it("4da://skills is neither listed nor readable", () => {
    expect(listResources().map((r) => r.uri)).not.toContain("4da://skills");
    expect(() => readResource("4da://skills")).toThrow();
    expect(listResources().map((r) => r.uri)).toContain("4da://categories");
    expect(readResource("4da://schema/vulnerability_scan").contents[0].text).toContain("vulnerability_scan");
  });
});

/** One request over the SDK's in-memory transport against a server wired like index.ts. */
async function rpc(method: string, params: Record<string, unknown>): Promise<{ result?: unknown; error?: { code: number; message: string } }> {
  const server = new Server({ name: "t", version: "0" }, { capabilities: { tools: {}, resources: {}, prompts: {} } });
  server.setRequestHandler("tools/call", async (request) => {
    if (!toolEntry(request.params.name)) throw unknownToolError(request.params.name);
    return { content: [] };
  });
  server.setRequestHandler("prompts/get", async (request) => {
    throw unknownPromptError(request.params.name);
  });
  server.setRequestHandler("resources/read", async (request) => readResource(request.params.uri));
  const [client, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const replies: Array<Record<string, unknown>> = [];
  client.onmessage = (m) => replies.push(m as Record<string, unknown>);
  await client.start();
  await client.send({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
  });
  await client.send({ jsonrpc: "2.0", method: "notifications/initialized" });
  await client.send({ jsonrpc: "2.0", id: 2, method, params });
  for (let i = 0; i < 50 && !replies.some((r) => r.id === 2); i++) await new Promise((r) => setTimeout(r, 10));
  await server.close();
  return replies.find((r) => r.id === 2) as { result?: unknown; error?: { code: number; message: string } };
}

describe("wire codes", () => {
  it("unknown tool -> JSON-RPC -32602", async () => {
    const reply = await rpc("tools/call", { name: "no_such_tool", arguments: {} });
    expect(reply.error?.code).toBe(-32602);
    expect(reply.error?.message).toContain("no_such_tool");
  });

  it("unknown tool named like an Object property -> -32602", async () => {
    expect((await rpc("tools/call", { name: "constructor", arguments: {} })).error?.code).toBe(-32602);
  });

  it("unknown prompt -> JSON-RPC -32602", async () => {
    expect((await rpc("prompts/get", { name: "nope" })).error?.code).toBe(-32602);
  });

  it("unknown resource -> resource not found (-32602 with data.uri)", async () => {
    const reply = await rpc("resources/read", { uri: "4da://schema/__proto__" });
    expect(reply.error?.code).toBe(-32602);
  });
});

describe("index.ts uses these handlers", () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "index.ts"), "utf8");
  it("wires the protocol errors and the shared resource reader", () => {
    expect(src).toMatch(/unknownToolError\(/);
    expect(src).toMatch(/unknownPromptError\(/);
    expect(src).toMatch(/readResource\(/);
    expect(src).toMatch(/listResources\(/);
    expect(src).not.toContain("4da://skills");
    expect(src).not.toMatch(/TOOL_REGISTRY\[/);
  });
});
