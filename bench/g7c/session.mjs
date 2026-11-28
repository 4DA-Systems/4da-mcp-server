// SPDX-License-Identifier: Apache-2.0
// A persistent MCP stdio session with a built server (raw JSON-RPC, no SDK), for the G7c reference scripts.
import { spawn } from 'node:child_process';

export async function openSession({ server, cwd = process.cwd(), env = {}, args = [], keepDb = false } = {}) {
  if (!server) throw new Error('openSession: pass server: <build>/dist/index.js');
  const fullEnv = { ...process.env, ...env };
  if (!keepDb && !('FOURDA_DB_PATH' in env)) delete fullEnv.FOURDA_DB_PATH;
  const t0 = Date.now();
  const child = spawn(process.execPath, [server, ...args], { cwd, env: fullEnv, stdio: ['pipe', 'pipe', 'pipe'] });
  let buf = '';
  const state = { stderr: '', stdoutNoise: [], notifications: [], exited: null };
  const pending = new Map();
  child.stderr.on('data', (d) => { state.stderr += d; });
  child.on('exit', (code, sig) => { state.exited = { code, sig }; for (const [, p] of pending) p.reject(new Error(`server exited (${code}/${sig})`)); pending.clear(); });
  child.stdout.on('data', (d) => {
    buf += d;
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { state.stdoutNoise.push(line.slice(0, 300)); continue; }
      if (msg.id !== undefined && msg.id !== null && pending.has(msg.id)) { const p = pending.get(msg.id); pending.delete(msg.id); p.resolve(msg); }
      else state.notifications.push(msg);
    }
  });
  let nextId = 1;
  const rpc = (method, params, { timeout = 600000, id } = {}) => {
    const useId = id ?? nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(useId); reject(new Error(`timeout ${timeout} ms: ${method}`)); }, timeout);
      pending.set(useId, { resolve: (m) => { clearTimeout(timer); resolve(m); }, reject: (e) => { clearTimeout(timer); reject(e); } });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: useId, method, params }) + '\n');
    });
  };
  const sendRaw = (text) => child.stdin.write(text.endsWith('\n') ? text : text + '\n');
  const notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'g7c-reference', version: '0' } }, { timeout: 30000 });
  const initMs = Date.now() - t0;
  notify('notifications/initialized', {});
  const call = async (name, a = {}, opts) => {
    const t = Date.now();
    const m = await rpc('tools/call', { name, arguments: a }, opts);
    const ms = Date.now() - t;
    const text = m.result?.content?.map((c) => c.text ?? '').join('\n') ?? '';
    let json = m.result?.structuredContent;
    if (!json) { try { json = JSON.parse(text); } catch { /* text answer */ } }
    return { ms, raw: m, text, json, isError: !!m.result?.isError, error: m.error };
  };
  const close = () => new Promise((resolve) => {
    if (state.exited) return resolve(state.exited);
    const killer = setTimeout(() => child.kill(), 5000);
    child.on('exit', () => { clearTimeout(killer); resolve(state.exited); });
    child.stdin.end();
  });
  return { init, initMs, rpc, call, notify, sendRaw, close, state, child, pid: child.pid };
}
