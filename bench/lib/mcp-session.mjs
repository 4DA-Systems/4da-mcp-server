// SPDX-License-Identifier: Apache-2.0
/**
 * A raw JSON-RPC stdio session with a BUILT server, shared by the harnesses under bench/
 * (plan-exec, env, app-mode). No SDK: what an editor sends, byte for byte.
 *
 * Every session is hermetic about its data: the server's own store (FOURDA_MCP_HOME) and the
 * places it looks for the desktop app's database (APPDATA, HOME, XDG_DATA_HOME, FOURDA_DATA_DIR)
 * all point under the `home` the caller gives, so nothing is read from or written to the
 * operator's real stores. FOURDA_DB_PATH is removed unless the caller names one.
 *
 * `offline: true` makes the session send nothing at all: FOURDA_OFFLINE=1 and a proxy on a port
 * nothing listens on (the server sends every lookup through HTTPS_PROXY when one is set). Use it
 * for every session whose projects carry a made-up name.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

export const DEAD_PROXY = "http://127.0.0.1:9";

/**
 * The server entry point named by `arg`: a file (a dist/index.js), an installed package
 * directory (its package.json names @4da/mcp-server), or a directory with the package under
 * node_modules/@4da/mcp-server.
 */
export function resolveServer(arg) {
  if (!arg) throw new Error("no server given: pass --server <dist/index.js | installed package directory>");
  const p = path.resolve(arg);
  if (!fs.existsSync(p)) throw new Error(`server ${p} does not exist`);
  if (fs.statSync(p).isFile()) return p;
  for (const dir of [p, path.join(p, "node_modules", "@4da", "mcp-server")]) {
    const manifest = path.join(dir, "package.json");
    if (!fs.existsSync(manifest)) continue;
    const pkg = JSON.parse(fs.readFileSync(manifest, "utf8"));
    if (pkg.name !== "@4da/mcp-server") continue;
    const entry = path.join(dir, pkg.main ?? "dist/index.js");
    if (fs.existsSync(entry)) return entry;
    throw new Error(`${dir} is @4da/mcp-server but has no ${pkg.main ?? "dist/index.js"} (build it first)`);
  }
  throw new Error(`${p} is neither a server entry file nor an installed @4da/mcp-server package`);
}

/** The environment for one server process; every data location is under `home`. */
export function hermeticEnv({ home, dbPath = null, offline = false, extra = {} }) {
  const env = { ...process.env };
  for (const k of ["FOURDA_DB_PATH", "FOURDA_PROJECT_DIR", "FOURDA_SQL_CORPUS", "NODE_OPTIONS", "FOURDA_OFFLINE", "FOURDA_TEST_SERVER_ENTRY"]) delete env[k];
  const os = path.join(home, "os-home");
  fs.mkdirSync(os, { recursive: true });
  Object.assign(env, {
    APPDATA: os,
    LOCALAPPDATA: os,
    XDG_DATA_HOME: os,
    HOME: os,
    USERPROFILE: os,
    FOURDA_MCP_HOME: path.join(home, "4da-mcp"),
    FOURDA_DATA_DIR: path.join(home, "no-app"),
  });
  if (dbPath) env.FOURDA_DB_PATH = dbPath;
  if (offline) {
    env.FOURDA_OFFLINE = "1";
    for (const k of ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]) env[k] = DEAD_PROXY;
    for (const k of ["NO_PROXY", "no_proxy"]) delete env[k];
  }
  return { ...env, ...extra };
}

/**
 * Start `server` in `cwd` with `env` (from hermeticEnv) and initialise it.
 * @returns {Promise<Session>} call(name, args) answers { ms, raw, text, json, isError, error }.
 */
export async function openSession({ server, cwd, env, args = [], initTimeoutMs = 60_000 }) {
  const started = Date.now();
  const child = spawn(process.execPath, [server, ...args], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
  const state = { stderr: "", stdoutNoise: [], notifications: [], exited: null };
  const pending = new Map();
  let buffer = "";
  child.stderr.on("data", (d) => (state.stderr += d));
  child.on("exit", (code, signal) => {
    state.exited = { code, signal };
    for (const [, p] of pending) p.reject(new Error(`server exited (${code ?? signal}) before answering`));
    pending.clear();
  });
  child.on("error", (e) => {
    state.exited = { code: null, signal: null, error: e.message };
  });
  child.stdin.on("error", () => undefined);
  child.stdout.on("data", (d) => {
    buffer += d;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        state.stdoutNoise.push(line.slice(0, 300));
        continue;
      }
      if (msg.id !== undefined && msg.id !== null && pending.has(msg.id)) {
        const p = pending.get(msg.id);
        pending.delete(msg.id);
        p.resolve(msg);
      } else state.notifications.push(msg);
    }
  });
  let nextId = 1;
  const rpc = (method, params, { timeoutMs = 900_000 } = {}) => {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      if (state.exited) return reject(new Error(`server already exited (${state.exited.code ?? state.exited.signal})`));
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`no answer to ${method} within ${timeoutMs} ms`));
      }, timeoutMs);
      pending.set(id, {
        resolve: (m) => (clearTimeout(timer), resolve(m)),
        reject: (e) => (clearTimeout(timer), reject(e)),
      });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  };
  const notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "4da-bench", version: "1" } }, { timeoutMs: initTimeoutMs });
  notify("notifications/initialized", {});
  const call = async (name, a = {}, opts) => {
    const t = Date.now();
    const m = await rpc("tools/call", { name, arguments: a }, opts);
    const text = m.result?.content?.map((c) => c.text ?? "").join("\n") ?? "";
    let json = m.result?.structuredContent;
    if (!json) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }
    return { ms: Date.now() - t, raw: m, text, json, isError: Boolean(m.result?.isError) || Boolean(m.error), error: m.error ?? null };
  };
  const tools = async () => ((await rpc("tools/list", {}, { timeoutMs: 60_000 })).result?.tools ?? []).map((t) => t.name);
  const close = () =>
    new Promise((resolve) => {
      if (state.exited) return resolve(state.exited);
      const killer = setTimeout(() => child.kill("SIGKILL"), 10_000);
      child.once("exit", () => (clearTimeout(killer), resolve(state.exited)));
      child.stdin.end();
    });
  const killHard = () =>
    new Promise((resolve) => {
      if (state.exited) return resolve(state.exited);
      child.once("exit", () => resolve(state.exited));
      child.kill("SIGKILL");
    });
  const version = init.result?.serverInfo?.version ?? null;
  return { init, version, initMs: Date.now() - started, rpc, call, tools, notify, close, killHard, state, child, pid: child.pid };
}

/**
 * Remove a directory tree, including files a package manager made read-only (Go's module
 * cache). Returns null when it is gone, or why it is not.
 */
export function rmTree(dir) {
  if (!fs.existsSync(dir)) return null;
  try {
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
    return null;
  } catch {
    const walk = (p) => {
      let st;
      try {
        st = fs.lstatSync(p);
      } catch {
        return;
      }
      try {
        fs.chmodSync(p, st.isDirectory() ? 0o777 : 0o666);
      } catch {
        // Not ours to change: the second rmSync reports it.
      }
      if (st.isDirectory()) for (const e of fs.readdirSync(p)) walk(path.join(p, e));
    };
    walk(dir);
    try {
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : String(e);
    }
  }
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
