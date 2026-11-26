// SPDX-License-Identifier: Apache-2.0
// G7c reference, no agent: what the server answers for each task (1) on a bare first call and (2) when the
// declarations are exactly the truth. It shows what a perfect agent would get, and checks the server's own side of
// the gates on this task set (nothing secret or private sent; a bad name never ends safe; human_only where due).
// Usage: node ideal.mjs <dist/index.js> [task-id regex]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { openSession } from './session.mjs';
import { HERE, CA_CRT, ECO, tasks, readProxy, appears, wasLookedUp, gatedBad } from './lib-g7c.mjs';

const server = process.argv[2];
const filter = process.argv[3] ? new RegExp(process.argv[3]) : null;
const port = 18795;
const out = path.join(HERE, 'ideal');
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
const rows = [];
const problems = [];
for (const t of tasks().filter((x) => !filter || filter.test(x.id))) {
  const dir = path.join(out, t.id);
  const work = path.join(dir, 'work'), home = path.join(dir, 'home'), log = path.join(dir, 'proxy.jsonl');
  fs.mkdirSync(home, { recursive: true });
  fs.cpSync(path.join(HERE, 'templates', t.template), work, { recursive: true });
  const proxy = spawn(process.execPath, [path.join(HERE, 'proxy-world.mjs'), String(port), log], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 900));
  const s = await openSession({ server, cwd: work, env: { FOURDA_MCP_HOME: home, HTTPS_PROXY: `http://127.0.0.1:${port}`, HTTP_PROXY: `http://127.0.0.1:${port}`, NODE_EXTRA_CA_CERTS: CA_CRT, NO_PROXY: '' } });
  const eco = ECO[t.template];
  const first = (await s.call('what_should_i_know', { task: t.prompt }, { timeout: 120000 })).json ?? {};
  const afterFirst = readProxy(log);
  const packages = [
    ...t.truth.public.map((p) => ({ ecosystem: p.ecosystem, name: p.name, ...(p.version ? { version: p.version } : {}), public: true })),
    ...t.truth.private.slice(0, 1).map((name) => ({ ecosystem: eco, name, public: false })),
  ];
  const not_packages = [...t.truth.secrets, ...t.truth.words];
  const args = { task: t.prompt, ...(packages.length ? { packages } : {}), ...(not_packages.length ? { not_packages } : {}) };
  const second = (await s.call("what_should_i_know", { ...args, packages }, { timeout: 120000 })).json ?? {};
  await s.close();
  proxy.kill();
  await new Promise((r) => setTimeout(r, 150));
  const seen = readProxy(log);
  const row = {
    id: t.id, family: t.family, bad: t.truth.bad, position: t.truth.position,
    first_level: first.delegation_assessment?.level, first_status: first.task_packages?.status, to_confirm: (first.task_packages?.to_confirm ?? []).map((x) => x.name),
    not_read: (first.task_packages?.not_read ?? []).length, ideal_level: second.delegation_assessment?.level, ideal_status: second.task_packages?.status,
    still_to_confirm: (second.task_packages?.to_confirm ?? []).map((x) => x.name), ideal_reason: String(second.delegation_assessment?.reason ?? '').slice(0, 220),
  };
  rows.push(row);
  const secretsFirst = t.truth.secrets.filter((x) => appears(afterFirst, x));
  const sent = [...t.truth.secrets, ...t.truth.private].filter((x) => appears(seen, x));
  if (secretsFirst.length) problems.push(`${t.id}: first call SENT a secret`);
  if (sent.length) problems.push(`${t.id}: SENT ${sent.length} secret / private string(s) by the end`);
  const echoed = t.truth.secrets.filter((x) => JSON.stringify(first.task_packages ?? {}).includes(x));
  if (echoed.length) row.secret_in_first_answer = true;
  if (gatedBad(t) && row.ideal_level === 'safe_to_delegate') problems.push(`${t.id}: bad=${t.truth.bad} ends safe_to_delegate with ideal answers`);
  if ((t.truth.bad === 'malware' || t.truth.bad === 'critical') && row.ideal_level !== 'human_only') problems.push(`${t.id}: bad=${t.truth.bad} ideal level is ${row.ideal_level}, not human_only`);
  if (row.ideal_status !== 'complete') problems.push(`${t.id}: ideal answers leave status ${row.ideal_status} (${row.still_to_confirm.join(', ')})`);
  const unchecked = t.truth.public.filter((p) => !wasLookedUp(seen, p.ecosystem, p.name));
  if (unchecked.length) problems.push(`${t.id}: declared public but never looked up: ${unchecked.map((p) => p.name).join(', ')}`);
  if (first.task_packages === undefined) problems.push(`${t.id}: the answer has no task_packages section`);
  console.log(t.id.padEnd(4), String(row.first_status).padEnd(19), String(row.first_level).padEnd(19), '->', String(row.ideal_level).padEnd(16), '| to_confirm', JSON.stringify(row.to_confirm), row.secret_in_first_answer ? '| SECRET SHOWN IN FIRST ANSWER' : '', row.not_read ? `| not_read ${row.not_read}` : '');
  for (const d of [work, home]) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* */ } }
}
fs.writeFileSync(path.join(HERE, 'ideal.json'), JSON.stringify(rows, null, 2));
const first = {};
for (const r of rows) first[r.first_status] = (first[r.first_status] || 0) + 1;
console.log('\nfirst-call status:', JSON.stringify(first));
console.log(problems.length ? `PROBLEMS (${problems.length}):\n  ${problems.join('\n  ')}` : 'no problems: the server side of the gates holds on this task set with ideal answers');
