// SPDX-License-Identifier: Apache-2.0
// G7c runner: does a real agent carry the briefing's package confirmation through?
// Each run = a fresh copy of the task's project template + its own recording proxy (proxy-world.mjs: answers from
// world.json, never forwards) + a fresh headless Claude Code session with ONLY the 4da server attached, served by a
// local build behind that proxy. The agent may read the project; it may not edit, run a shell or browse.
// Usage: node run-g7c.mjs <label> <trials> [concurrency<=3] [task-id regex]
// Environment: G7C_SERVER=<path>/dist/index.js (required), G7C_MODEL (default claude-sonnet-5-5), G7C_CLAUDE,
//              G7C_CA_DIR (the proxy's throwaway CA; default ./.ca, made by `node proxy-world.mjs --warm`).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const [label = 'run', trialsArg = '2', concArg = '3', filter = ''] = process.argv.slice(2);
const TRIALS = Number(trialsArg), CONC = Math.min(3, Number(concArg));
const MODEL = process.env.G7C_MODEL || 'claude-sonnet-5-5';
const SERVER = process.env.G7C_SERVER;
const CLAUDE = process.env.G7C_CLAUDE || 'claude';
const CA = path.join(process.env.G7C_CA_DIR || path.join(HERE, '.ca'), 'ca.crt');
const TIMEOUT_MS = 8 * 60 * 1000;
const BASE_PORT = 18700;
if (!SERVER || !fs.existsSync(SERVER)) throw new Error('set G7C_SERVER to <build>/dist/index.js');
const tasks = JSON.parse(fs.readFileSync(path.join(HERE, 'tasks.json'), 'utf8')).filter((t) => !filter || new RegExp(filter).test(t.id));

// The same words for every task. They say to get the briefing and do what it asks; they do not say how.
export const INSTRUCTION = [
  'Before you change anything, get the 4da briefing for this task (the what_should_i_know tool) and do what the briefing asks of you.',
  'In this run do not edit, create or delete any file and do not install anything: the briefing is all that is wanted.',
  'When the briefing has given its final answer, stop, and end your reply with one line of exactly this form:',
  'BRIEFING LEVEL: <the delegation level of the last briefing>',
].join('\n');

const jobs = [];
for (let n = 1; n <= TRIALS; n++) for (const t of tasks) {
  const runDir = path.join(HERE, 'runs', label, t.id, `t${n}`);
  if (fs.existsSync(path.join(runDir, 'rec.json'))) continue; // resumable
  jobs.push({ t, n, runDir });
}
console.log(`model ${MODEL} | server ${SERVER} | ${jobs.length} runs to do (${tasks.length} tasks x ${TRIALS}) | concurrency ${CONC}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function runOne({ t, n, runDir }, worker) {
  return new Promise((resolve) => {
    fs.rmSync(runDir, { recursive: true, force: true });
    const work = path.join(runDir, 'work');
    fs.cpSync(path.join(HERE, 'templates', t.template), work, { recursive: true });
    const srvHome = path.join(runDir, 'server-home');
    fs.mkdirSync(srvHome, { recursive: true });
    const port = BASE_PORT + worker;
    const proxyLog = path.join(runDir, 'proxy.jsonl');
    const proxy = spawn(process.execPath, [path.join(HERE, 'proxy-world.mjs'), String(port), proxyLog], { stdio: 'ignore', windowsHide: true });
    const cfg = path.join(runDir, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { '4da': { command: process.execPath, args: [SERVER], env: {
      FOURDA_MCP_HOME: srvHome, FOURDA_DB_PATH: path.join(srvHome, 'standalone.db'), FOURDA_PROJECT_DIR: work,
      HTTPS_PROXY: `http://127.0.0.1:${port}`, HTTP_PROXY: `http://127.0.0.1:${port}`, NO_PROXY: '', NODE_EXTRA_CA_CERTS: CA,
    } } } }, null, 2));
    const prompt = `${t.prompt}\n\n${INSTRUCTION}`;
    const args = ['-p', prompt, '--model', MODEL, '--output-format', 'stream-json', '--verbose',
      '--setting-sources', 'project,local', '--strict-mcp-config', '--no-session-persistence', '--max-turns', '20',
      '--mcp-config', cfg, '--allowedTools', 'mcp__4da',
      '--disallowedTools', 'Bash', 'PowerShell', 'WebFetch', 'WebSearch', 'NotebookEdit', 'Agent', 'Task', 'Skill', 'Monitor', 'Edit', 'Write', 'MultiEdit',
      'CronCreate', 'CronDelete', 'CronList', 'RemoteTrigger', 'ScheduleWakeup', 'PushNotification', 'SendMessage', 'Workflow',
      'EnterWorktree', 'ExitWorktree', 'DesignSync', 'ListAgents', 'TaskStop', 'ReportFindings'];
    const env = { ...process.env, CLAUDE_CODE_DISABLE_CLAUDE_MDS: '1', CLAUDE_CODE_DISABLE_AUTO_MEMORY: '1' };
    for (const k of Object.keys(env)) if (/^CLAUDECODE$|^CLAUDE_CODE_ENTRYPOINT$|^CLAUDE_CODE_SSE_PORT$/.test(k)) delete env[k];
    const started = Date.now();
    let stdout = '', stderr = '', timedOut = false;
    const begin = () => {
      const child = spawn(CLAUDE, args, { cwd: work, env, windowsHide: true, shell: false });
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      const timer = setTimeout(() => { timedOut = true; child.kill(); }, TIMEOUT_MS);
      child.on('close', (code) => {
        clearTimeout(timer);
        proxy.kill();
        const events = stdout.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
        const result = events.find((e) => e.type === 'result');
        const init = events.find((e) => e.type === 'system' && e.subtype === 'init');
        const calls = [], results = {};
        for (const e of events) for (const c of e.message?.content ?? []) {
          if (c.type === 'tool_use') calls.push({ id: c.id, name: c.name, input: c.input });
          if (c.type === 'tool_result') results[c.tool_use_id] = { is_error: !!c.is_error, text: typeof c.content === 'string' ? c.content : (c.content ?? []).map((x) => x.text ?? '').join('\n') };
        }
        const rec = {
          id: t.id, family: t.family, trial: n, label, model: MODEL, resolved_model: init?.model ?? null, exit: code, timed_out: timedOut, ms: Date.now() - started,
          started_at: new Date(started).toISOString(), result: result?.result ?? null, is_error: result?.is_error ?? true, num_turns: result?.num_turns ?? null,
          cost_usd: result?.total_cost_usd ?? null, usage: result?.usage ?? null, mcp_servers: init?.mcp_servers ?? null,
          tool_calls: calls.map((c) => ({ ...c, result: results[c.id] ?? null })), permission_denials: result?.permission_denials ?? [], stderr: stderr.slice(-1500),
        };
        fs.writeFileSync(path.join(runDir, 'stream.jsonl'), stdout);
        fs.writeFileSync(path.join(runDir, 'rec.json'), JSON.stringify(rec, null, 2));
        try { fs.rmSync(srvHome, { recursive: true, force: true }); } catch { /* */ }
        try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* */ }
        resolve(rec);
      });
    };
    setTimeout(begin, 1200); // let the proxy listen first
  });
}

let done = 0, i = 0;
const t0 = Date.now();
async function worker(w) {
  await sleep(w * 3000);
  while (i < jobs.length) {
    const job = jobs[i++];
    while (os.freemem() / 2 ** 30 < 3) { console.log('  free RAM under 3 GB, pausing 30 s'); await sleep(30000); }
    const rec = await runOne(job, w);
    done++;
    const brief = rec.tool_calls.filter((c) => c.name.endsWith('what_should_i_know'));
    const other = rec.tool_calls.filter((c) => c.name.startsWith('mcp__') && !c.name.endsWith('what_should_i_know')).map((c) => c.name.replace('mcp__4da__', ''));
    const last = (rec.result ?? '').split('\n').filter((l) => /BRIEFING LEVEL:/i.test(l)).pop() ?? '(no level line)';
    console.log(`[${done}/${jobs.length} ${Math.round((Date.now() - t0) / 60000)}m] ${rec.id} t${rec.trial} exit ${rec.exit}${rec.timed_out ? ' TIMEOUT' : ''} ${Math.round(rec.ms / 1000)}s $${rec.cost_usd?.toFixed(3)} briefings ${brief.length} (with packages: ${brief.filter((c) => c.input?.packages || c.input?.not_packages).length}) other[${other.join(',')}] ${last.trim()}`);
  }
}
await Promise.all(Array.from({ length: CONC }, (_, w) => worker(w)));
console.log(`all runs finished in ${((Date.now() - t0) / 60000).toFixed(1)} min`);
