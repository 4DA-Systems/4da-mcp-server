// SPDX-License-Identifier: Apache-2.0
// Checks that the canned world gives the verdicts the tasks assume, by asking the server's dependency_check directly.
// Usage: node smoke-world.mjs <dist/index.js>
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openSession } from './session.mjs';
import { CA_CRT } from './lib-g7c.mjs';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const server = process.argv[2];
const port = 18790;
const log = path.join(HERE, 'smoke-proxy.jsonl');
try { fs.unlinkSync(log); } catch { /* */ }
const proxy = spawn(process.execPath, [path.join(HERE, 'proxy-world.mjs'), String(port), log], { stdio: 'ignore' });
await new Promise((r) => setTimeout(r, 1500));
const home = path.join(HERE, 'smoke-home-' + Date.now());
fs.mkdirSync(home, { recursive: true });
const env = { FOURDA_MCP_HOME: home, HTTPS_PROXY: `http://127.0.0.1:${port}`, HTTP_PROXY: `http://127.0.0.1:${port}`, NODE_EXTRA_CA_CERTS: CA_CRT, NO_PROXY: '' };
try {
  for (const tpl of ['npm', 'py', 'rs', 'go']) {
    const s = await openSession({ server, cwd: path.join(HERE, 'templates', tpl), env });
    const items = {
      npm: [['npm', 'ky'], ['npm', 'hono', '4.6.14'], ['npm', 'node-forge', '0.10.0'], ['npm', 'undici', '5.8.0'], ['npm', 'undici', '6.21.0'], ['npm', 'fastifyy'], ['npm', 'valibott'], ['npm', 'helmett', '7.1.0'], ['npm', 'elliptic', '6.5.4']],
      py: [['PyPI', 'litestar'], ['PyPI', 'ormar', '0.12.2'], ['PyPI', 'litestarr'], ['PyPI', 'beaniee', '1.28.1'], ['PyPI', 'hishel', '0.1.1']],
      rs: [['crates.io', 'tokio'], ['crates.io', 'smallvec', '1.6.0'], ['crates.io', 'anyhow']],
      go: [['Go', 'github.com/go-chi/chi/v5'], ['Go', 'golang.org/x/text', 'v0.3.5'], ['Go', 'github.com/rs/zerolog']],
    }[tpl].map(([ecosystem, pkg, to]) => ({ ecosystem, package: pkg, to: to ?? 'latest' }));
    const r = await s.call('dependency_check', { items }, { timeout: 120000 });
    const rows = r.json?.results ?? r.json?.items ?? [];
    for (const it of rows) console.log(tpl.padEnd(3), `${it.package}@${it.to ?? it.requested ?? ''}`.padEnd(34), String(it.verdict).padEnd(8), it.malicious ? 'MALWARE ' : '', String(it.reason ?? '').slice(0, 110));
    if (!rows.length) console.log(tpl, 'NO ROWS', r.text?.slice(0, 400));
    const b = await s.call('what_should_i_know', { task: 'Refactor the entry file.' }, { timeout: 120000 });
    console.log(tpl.padEnd(3), 'briefing with no packages ->', b.json?.delegation_assessment?.level, '|', String(b.json?.delegation_assessment?.reason ?? '').slice(0, 120));
    await s.close();
  }
} finally {
  proxy.kill();
}
const lines = fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((l) => l.kind === 'request');
const hosts = {};
for (const l of lines) hosts[l.host] = (hosts[l.host] || 0) + 1;
console.log('requests by host:', JSON.stringify(hosts), '| answer errors:', fs.readFileSync(log, 'utf8').split('\n').filter((l) => l.includes('answer-error')).length);
