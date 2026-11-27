// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14b: a value of a credential shape (CREDENTIAL_SHAPES) in an argument is not sent to any host and not stored.
 * Generated: every shape (one sample per alternative of the constant) x every string argument of every tool (from the
 * published schemas), with a recording fetch stub, a temp database and a temp server home (the ledger, the caches):
 * no request URL, header or body, and no stored byte, holds the raw value. Free text a tool stores or sends on
 * purpose (decision_memory, check_decision_alignment, agent_memory) is stored by shape, and the answer says so.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { FourDADatabase } from "../db.js";
import { ledgerWritesSettled } from "../check-ledger.js";
import { dispatchTool } from "../tool-dispatch.js";
import { validateToolArgs } from "../tool-args.js";
import { TOOL_REGISTRY } from "../schema-registry.js";
import { MASKED_TOOLS } from "../argument-screen.js";
import { resultText, serverEntry, stdioSession } from "./helpers/stdio-session.js";
import { SHAPES } from "./helpers/credential-samples.js";

let scratch: string;
let db: FourDADatabase;
const sent: string[] = [];
const saved = new Map<string, string | undefined>();
beforeAll(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a1137b-"));
  for (const [k, v] of Object.entries({ FOURDA_MCP_HOME: path.join(scratch, "home"), FOURDA_OFFLINE: undefined })) {
    saved.set(k, process.env[k]);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  db = new FourDADatabase(path.join(scratch, "standalone.db"));
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const headers = init?.headers ? JSON.stringify(init.headers) : "";
    sent.push(`${String(input)} ${headers} ${init?.body ? String(init.body) : ""}`);
    return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
  });
});
afterAll(() => {
  db.close();
  vi.unstubAllGlobals();
  for (const [k, v] of saved) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows may hold the database a moment: left for the OS temp cleaner.
  }
});
beforeEach(() => {
  sent.length = 0;
});

type Prop = { type?: string; enum?: string[]; items?: Prop; properties?: Record<string, Prop>; required?: string[] };
const sampleValue = (p: Prop): unknown => (p.enum ? p.enum[0] : p.type === "string" ? "zqx-ok" : p.type === "number" || p.type === "integer" ? 1 : p.type === "boolean" ? true : p.type === "array" ? [] : {});
/** Every string position of a tool's schema: [label, args with the token there]. */
function positions(tool: string): Array<[string, (t: string) => Record<string, unknown>]> {
  const schema = TOOL_REGISTRY[tool].definition.inputSchema as Prop;
  const base: Record<string, unknown> = {};
  for (const r of schema.required ?? []) base[r] = sampleValue(schema.properties![r]);
  if (tool === "what_should_i_know") base.packages = [];
  if (tool === "dependency_check") base.items = [{ ecosystem: "npm", package: "zqxok", to: "1.0.0" }];
  if (tool === "decision_memory") Object.assign(base, { action: "record", subject: "zqx", decision: "zqx" });
  if (tool === "agent_memory") Object.assign(base, { action: "store", subject: "zqx", content: "zqx", agent_type: "claude", memory_type: "discovery", session_id: "s1" });
  const out: Array<[string, (t: string) => Record<string, unknown>]> = [];
  for (const [k, p] of Object.entries(schema.properties ?? {})) {
    if (p.type === "string" && !p.enum) out.push([`${tool}.${k}`, (t) => ({ ...base, [k]: t })]);
    if (p.type === "array" && p.items?.type === "string") out.push([`${tool}.${k}[]`, (t) => ({ ...base, [k]: [t] })]);
    if (p.type === "array" && p.items?.properties) {
      for (const [ik, ip] of Object.entries(p.items.properties)) {
        if (ip.type !== "string" || ip.enum) continue;
        const item: Record<string, unknown> = {};
        for (const [jk, jp] of Object.entries(p.items.properties)) if ((p.items.required ?? []).includes(jk)) item[jk] = jp.enum ? jp.enum[0] : jk === "ecosystem" ? "npm" : jk === "public" ? true : jk === "to" ? "1.0.0" : sampleValue(jp);
        out.push([`${tool}.${k}[].${ik}`, (t) => ({ ...base, [k]: [{ ...item, [ik]: t }] })]);
      }
    }
  }
  return out;
}
/** Every stored byte of the run: the database files and every file under the server home. */
function stored(): string {
  const files: string[] = [];
  const walk = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    for (const f of fs.readdirSync(dir)) {
      const p = path.join(dir, f);
      if (fs.statSync(p).isDirectory()) walk(p);
      else files.push(p);
    }
  };
  walk(scratch);
  return files.map((f) => fs.readFileSync(f).toString("latin1")).join("\n");
}

const CASES = Object.keys(TOOL_REGISTRY).flatMap((tool) => positions(tool).flatMap(([where, make], i) => [SHAPES[i % SHAPES.length], SHAPES[(i + 7) % SHAPES.length]].map((tok) => [where, tool, make, tok] as const)));

describe("a credential-shaped argument is not sent to any host and not stored", () => {
  it("one sample per alternative of CREDENTIAL_SHAPES", () => {
    expect(SHAPES.length).toBeGreaterThanOrEqual(15);
  });
  it.each(CASES.map(([where, tool, make, tok]) => [`${where} = ${tok.slice(0, 6)}...`, tool, make, tok] as const))("%s", async (_l, tool, make, tok) => {
    const args = make(tok);
    const problem = validateToolArgs(tool, TOOL_REGISTRY[tool].definition.inputSchema as never, args);
    let answer = "";
    if (!problem) {
      try {
        answer = JSON.stringify(await dispatchTool(tool, db, args));
      } catch (error) {
        answer = String(error);
      }
    }
    await ledgerWritesSettled();
    expect(sent.filter((x) => x.includes(tok)), "a request holds it").toEqual([]);
    expect(stored().includes(tok), "a stored byte holds it").toBe(false);
    if (MASKED_TOOLS.has(tool) && !problem && !/"error"/.test(answer)) expect(answer).toContain("credential_masked");
  }, 120_000);
});

describe("over stdio, behind no network: dependency_check and upgrade_impact refuse a token-shaped name", () => {
  it.skipIf(!fs.existsSync(serverEntry))("nothing is fetched for it, and the answer refuses it", async () => {
    const tok = SHAPES[0];
    const s = await stdioSession(process.cwd(), [
      ["dependency_check", { items: [{ ecosystem: "npm", package: tok, to: "1.0.0" }] }],
      ["upgrade_impact", { package: tok, ecosystem: "npm" }],
    ], {}, { requestTimeoutMs: 120_000 });
    expect(s.fetches.filter((u) => u.includes(tok))).toEqual([]);
    for (const r of s.results) {
      expect(resultText(r)).toContain("credential's shape");
      expect(resultText(r).includes(tok)).toBe(false);
    }
  }, 180_000);
});
