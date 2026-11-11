// SPDX-License-Identifier: Apache-2.0
/**
 * Run the BUILT server over stdio in a directory, make tool calls, and return
 * the results with stderr. The server's working directory matters: started
 * inside a project, it scans that project at startup (readiness audit H3
 * reproduced only in that mode). Hermetic: no app database, temp data dirs,
 * and `fetch` blocked by a preload, so nothing reaches the network.
 *
 * `FOURDA_TEST_SERVER_ENTRY` points the session at another build (a plain
 * release) to show a test failing before its fix.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const serverEntry = process.env.FOURDA_TEST_SERVER_ENTRY ?? path.join(root, "dist", "index.js");

export interface ToolResult {
  isError?: boolean;
  content?: { text?: string }[];
}

export interface Session {
  results: ToolResult[];
  resources: Array<{ uri: string }>;
  tools: string[];
  stderr: string;
  /** How long each request took to be answered, in the order sent. */
  timings: Array<{ method: string; ms: number }>;
}

export interface SessionOptions {
  /** Fail a request that is not answered within this many milliseconds (a blocked event loop answers nothing). */
  requestTimeoutMs?: number;
  /** Send one more `tools/list` after the calls: a server a call left blocked answers the call and then nothing. */
  listAfterCalls?: boolean;
}

export const resultText = (r: ToolResult) => (r.content ?? []).map((c) => c.text ?? "").join("\n");

export async function stdioSession(
  cwd: string,
  calls: Array<[string, Record<string, unknown>]>,
  extraEnv: Record<string, string> = {},
  options: SessionOptions = {},
): Promise<Session> {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-stdio-"));
  const preload = path.join(scratch, "no-network.cjs");
  fs.writeFileSync(preload, 'globalThis.fetch = async (u) => { throw new TypeError("fetch blocked in test: " + u); };\n');
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const k of ["FOURDA_DB_PATH", "FOURDA_SQLITE_DRIVER", "FOURDA_SQL_CORPUS", "NODE_OPTIONS", "FOURDA_OFFLINE", "FOURDA_PROJECT_DIR"]) delete env[k];
  const home = path.join(scratch, "home");
  Object.assign(env, {
    APPDATA: home,
    LOCALAPPDATA: home,
    XDG_DATA_HOME: home,
    HOME: home,
    USERPROFILE: home,
    FOURDA_MCP_HOME: path.join(home, "4da-mcp"),
    FOURDA_DATA_DIR: path.join(home, "no-app"),
    ...extraEnv,
  });
  const child = spawn(process.execPath, ["--require", preload, serverEntry], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  let buffer = "";
  const pending = new Map<number, (m: { result?: unknown; error?: unknown }) => void>();
  child.stderr.on("data", (d) => (stderr += d));
  child.stdout.on("data", (d) => {
    buffer += d;
    let i: number;
    while ((i = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, i).trim();
      buffer = buffer.slice(i + 1);
      if (!line) continue;
      const message = JSON.parse(line) as { id?: number; result?: unknown; error?: unknown };
      if (message.id !== undefined) pending.get(message.id)?.(message);
    }
  });
  const exited = new Promise<never>((_, reject) => child.on("exit", (code) => reject(new Error(`server exited (${code}): ${stderr.slice(-2000)}`))));
  let id = 0;
  const timings: Session["timings"] = [];
  const rpc = async (method: string, params: unknown, label = method) => {
    const started = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<never>((_, reject) => {
      if (options.requestTimeoutMs !== undefined) {
        timer = setTimeout(() => reject(new Error(`no answer to ${label} within ${options.requestTimeoutMs} ms`)), options.requestTimeoutMs);
      }
    });
    try {
      const answer = await Promise.race([
        new Promise<{ result?: unknown; error?: unknown }>((resolve) => {
          pending.set(++id, resolve);
          child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
        }),
        exited,
        late,
      ]);
      timings.push({ method: label, ms: Date.now() - started });
      return answer;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };
  try {
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    const tools = ((await rpc("tools/list", {})).result as { tools: { name: string }[] }).tools.map((t) => t.name);
    const resources = ((await rpc("resources/list", {})).result as { resources: Array<{ uri: string }> }).resources;
    const results: ToolResult[] = [];
    for (const [name, args] of calls) {
      const r = await rpc("tools/call", { name, arguments: args }, `tools/call ${name}`);
      results.push((r.result ?? { isError: true, content: [{ text: JSON.stringify(r.error) }] }) as ToolResult);
    }
    if (options.listAfterCalls) await rpc("tools/list", {}, "tools/list (after the calls)");
    return { results, resources, tools, stderr, timings };
  } finally {
    exited.catch(() => undefined);
    const gone = child.exitCode !== null ? Promise.resolve() : new Promise((resolve) => child.once("exit", resolve));
    child.kill();
    await gone;
    try {
      fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      // Windows can hold a just-exited child's files for a moment; left for the OS temp cleaner.
    }
  }
}
