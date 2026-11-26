// SPDX-License-Identifier: Apache-2.0
/**
 * Small items of the 2026-11-25 audit, setup lane:
 * - `--doctor` printed ANSI colour codes when piped into a file or a client's log: colour now only on
 *   a terminal, and never with NO_COLOR set (https://no-color.org);
 * - a UTF-8 byte-order mark before the first stdio message (a client writing "UTF-8 with BOM") made
 *   `initialize` fail to parse (-32700): one leading mark is dropped, nothing else;
 * - `--help` said `--doctor` validates "LLM providers": it checks an embedding provider.
 */
import { describe, expect, it } from "vitest";

import { doctorColors } from "../doctor.js";
import { StdioGate } from "../stdio-gate.js";
import { serverUsage } from "../usage.js";

describe("--doctor colour", () => {
  it("only on a terminal", () => {
    expect(doctorColors(false, {})).toEqual({ colors: { pass: "", warn: "", fail: "" }, reset: "" });
    expect(doctorColors(true, {}).reset).toBe("\x1b[0m");
  });

  it("never with NO_COLOR set to anything, even on a terminal; an empty NO_COLOR does not count", () => {
    for (const value of ["1", "0", "false", "yes"]) expect(doctorColors(true, { NO_COLOR: value }).reset, value).toBe("");
    expect(doctorColors(true, { NO_COLOR: "" }).reset).toBe("\x1b[0m");
  });
});

/** What the gate passes on to the SDK, and what it answers itself, for `chunks` written in order. */
async function feed(chunks: Array<string | Buffer>): Promise<{ passed: string[]; replies: Array<Record<string, unknown>> }> {
  const replies: Array<Record<string, unknown>> = [];
  const gate = new StdioGate((m) => replies.push(m));
  const passed: string[] = [];
  gate.on("data", (d: Buffer | string) => passed.push(...d.toString().split("\n").filter((l) => l.trim())));
  for (const chunk of chunks) gate.write(chunk);
  gate.end();
  await new Promise((resolve) => gate.on("end", resolve));
  return { passed, replies };
}

const INIT = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } });
const PING = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" });

describe("a UTF-8 byte-order mark before the first message", () => {
  it("is dropped, so initialize passes", async () => {
    const { passed, replies } = await feed([Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(`${INIT}\n`)])]);
    expect(replies).toEqual([]);
    expect(JSON.parse(passed[0]).method).toBe("initialize");
  });

  it("also when its three bytes arrive in separate chunks", async () => {
    const { passed, replies } = await feed([Buffer.from([0xef]), Buffer.from([0xbb]), Buffer.from([0xbf]), Buffer.from(`${INIT}\n`)]);
    expect(replies).toEqual([]);
    expect(JSON.parse(passed[0]).method).toBe("initialize");
  });

  it("only one, and only at the start: a second mark, or one before a later message, is still a parse error", async () => {
    const twice = await feed([`﻿﻿${INIT}\n`]);
    expect(twice.replies.map((r) => (r.error as { code: number }).code)).toEqual([-32700]);
    const later = await feed([`${INIT}\n`, `﻿${PING}\n`]);
    expect(later.replies.map((r) => (r.error as { code: number }).code)).toEqual([-32700]);
  });

  it("a stream that starts with no mark is unchanged", async () => {
    const { passed, replies } = await feed([`${INIT}\n`]);
    expect(replies).toEqual([]);
    expect(passed[0]).toBe(INIT);
  });
});

describe("--help on --doctor", () => {
  it("names what it checks, and no LLM provider", () => {
    const usage = serverUsage("1.2.3");
    expect(usage).not.toContain("LLM");
    expect(usage).toContain("the embedding provider");
  });
});
