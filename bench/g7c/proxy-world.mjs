// SPDX-License-Identifier: Apache-2.0
// G7c recording proxy. NEVER forwards. It answers CONNECT, terminates TLS with a throwaway CA, logs every
// request (method, host, path, body) and answers from world.json only, shaped like the real services. A name
// that is not in world.json does not exist: 404 from a registry, an empty answer from OSV.dev. So a secret or a
// private name the server tries to look up is RECORDED here and goes nowhere.
// Usage: node proxy-world.mjs <port> <logfile>          serve
//        node proxy-world.mjs --warm                    create the leaf certificates for every host, then exit
// The CA (ca.crt, ca.key, leaf.key) is made on first use in ./.ca with openssl and is never committed.
// Environment: G7C_CA_DIR, G7C_CERT_DIR, G7C_OPENSSL (default: openssl on PATH).
import http from 'node:http';
import tls from 'node:tls';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CA_DIR = process.env.G7C_CA_DIR || path.join(HERE, '.ca');
const CERT_DIR = process.env.G7C_CERT_DIR || path.join(HERE, 'certs');
const OPENSSL = process.env.G7C_OPENSSL || 'openssl';
const CA_CRT = `${CA_DIR}/ca.crt`, CA_KEY = `${CA_DIR}/ca.key`, LEAF_KEY = `${CA_DIR}/leaf.key`;
const WORLD = JSON.parse(fs.readFileSync(path.join(HERE, 'world.json'), 'utf8'));
const HOSTS = ['api.osv.dev', 'registry.npmjs.org', 'api.npmjs.org', 'pypi.org', 'files.pythonhosted.org', 'crates.io', 'index.crates.io',
  'static.crates.io', 'proxy.golang.org', 'sum.golang.org', 'hn.algolia.com', 'api.github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com'];
fs.mkdirSync(CERT_DIR, { recursive: true });
if (!fs.existsSync(CA_CRT) || !fs.existsSync(CA_KEY) || !fs.existsSync(LEAF_KEY)) {
  // A certificate authority for this harness only: its key never leaves this folder and signs nothing but the proxy's leaves.
  fs.mkdirSync(CA_DIR, { recursive: true });
  execFileSync(OPENSSL, ['genrsa', '-out', CA_KEY, '2048'], { stdio: 'ignore' });
  execFileSync(OPENSSL, ['req', '-x509', '-new', '-key', CA_KEY, '-sha256', '-days', '30', '-subj', '/CN=g7c throwaway CA', '-out', CA_CRT], { stdio: 'ignore' });
  execFileSync(OPENSSL, ['genrsa', '-out', LEAF_KEY, '2048'], { stdio: 'ignore' });
}

// ---------------------------------------------------------------- certificates
function certFor(host) {
  const safe = host.replace(/[^A-Za-z0-9.-]/g, '_');
  const crt = path.join(CERT_DIR, `${safe}.crt`);
  if (!fs.existsSync(crt)) {
    const csr = path.join(CERT_DIR, `${safe}.csr`), ext = path.join(CERT_DIR, `${safe}.ext`);
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host);
    fs.writeFileSync(ext, `subjectAltName=${isIp ? 'IP' : 'DNS'}:${host}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n`);
    execFileSync(OPENSSL, ['req', '-new', '-key', LEAF_KEY, '-subj', `/CN=${host}`, '-out', csr], { stdio: 'ignore' });
    execFileSync(OPENSSL, ['x509', '-req', '-in', csr, '-CA', CA_CRT, '-CAkey', CA_KEY, '-CAcreateserial', '-days', '30', '-extfile', ext, '-out', crt], { stdio: 'ignore' });
  }
  return crt;
}
if (process.argv[2] === '--warm') {
  for (const h of HOSTS) certFor(h);
  console.log(`certificates ready for ${HOSTS.length} hosts in ${CERT_DIR}`);
  process.exit(0);
}
const PORT = Number(process.argv[2] || 18700);
const LOG = process.argv[3] || path.join(HERE, 'proxy.jsonl');
let seq = 0;
const log = (o) => fs.appendFileSync(LOG, JSON.stringify({ seq: ++seq, t: new Date().toISOString(), ...o }) + '\n');
const contexts = new Map();
function contextFor(host) {
  if (!contexts.has(host)) contexts.set(host, tls.createSecureContext({ key: fs.readFileSync(LEAF_KEY), cert: fs.readFileSync(certFor(host)) }));
  return contexts.get(host);
}

// ---------------------------------------------------------------- the world
const OLD = '2024-01-01T00:00:00.000Z';
const DAY = 86400000;
const pyNorm = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');
function entry(eco, name) {
  const table = WORLD[eco] || {};
  if (eco === 'PyPI') { const k = Object.keys(table).find((x) => pyNorm(x) === pyNorm(name)); return k ? { name: k, ...table[k] } : null; }
  if (eco === 'npm') return table[name] ? { name, ...table[name] } : null; // npm names are case-sensitive and lower-case
  if (eco === 'crates.io') { const k = Object.keys(table).find((x) => x.replace(/_/g, '-') === name.replace(/_/g, '-')); return k ? { name: k, ...table[k] } : null; }
  return table[name] ? { name, ...table[name] } : null;
}
const parts = (v) => String(v).replace(/^v/, '').split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
function cmp(a, b) {
  const x = parts(a), y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i] ?? 0, q = y[i] ?? 0;
    if (p === q) continue;
    if (typeof p === 'number' && typeof q === 'number') return p < q ? -1 : 1;
    return String(p) < String(q) ? -1 : 1;
  }
  return 0;
}
const affects = (vuln, version) => !version || !vuln.fixed || cmp(version, vuln.fixed) < 0;
const vulnsOf = (eco, name, version) => (entry(eco, name)?.vulns ?? []).filter((v) => affects(v, version));
const ALL_VULNS = new Map();
for (const [eco, table] of Object.entries(WORLD)) {
  if (eco.startsWith('_')) continue;
  for (const [name, e] of Object.entries(table)) for (const v of e.vulns ?? []) ALL_VULNS.set(v.id, { eco, name, e, v });
}
const CVSS = { CRITICAL: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', HIGH: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', MODERATE: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N' };
function vulnRecord(id) {
  const hit = ALL_VULNS.get(id);
  if (!hit) return null;
  const { eco, name, e, v } = hit;
  const semverish = eco !== 'PyPI';
  const events = [{ introduced: '0' }, ...(v.fixed ? [{ fixed: v.fixed }] : [])];
  const rec = {
    id, modified: OLD, published: OLD, schema_version: '1.6.0', summary: v.summary, details: `${v.summary}. Canned for the G7c evaluation.`, aliases: [],
    affected: [{ package: { ecosystem: eco, name }, ranges: [{ type: semverish ? 'SEMVER' : 'ECOSYSTEM', events }], versions: e.versions.filter((x) => affects(v, x)).map((x) => x.replace(/^v/, eco === 'Go' ? '' : 'v').replace(/^v/, '')) }],
  };
  if (v.malware) {
    rec.database_specific = { 'malicious-packages-origins': [{ source: 'g7c-canned', import_time: OLD, modified_time: OLD, sha256: '0'.repeat(64), versions: e.versions }] };
    rec.affected[0].database_specific = { cwes: [{ cweId: 'CWE-506', name: 'Embedded Malicious Code', description: 'canned' }] };
  } else {
    rec.severity = [{ type: 'CVSS_V3', score: CVSS[v.severity] || CVSS.HIGH }];
    rec.database_specific = { severity: v.severity, cwe_ids: [], github_reviewed: true };
  }
  return rec;
}
const repoOf = (name) => `https://github.com/g7c-canned/${name.replace(/^@/, '').replace(/[^A-Za-z0-9-]/g, '-')}`;
function packument(e) {
  const versions = {}, time = { created: OLD, modified: OLD };
  e.versions.forEach((v, i) => {
    versions[v] = { name: e.name, version: v, dependencies: {}, dist: { tarball: `https://registry.npmjs.org/${e.name}/-/${e.name.split('/').pop()}-${v}.tgz`, shasum: '0'.repeat(40), integrity: 'sha512-AAAA' },
      _npmUser: { name: 'g7c', email: 'nobody@example.invalid' }, repository: { type: 'git', url: `git+${repoOf(e.name)}.git` } };
    time[v] = new Date(Date.parse(OLD) + i * DAY * 30).toISOString();
  });
  return { _id: e.name, name: e.name, 'dist-tags': { latest: e.versions[e.versions.length - 1] }, versions, time,
    repository: { type: 'git', url: `git+${repoOf(e.name)}.git` }, maintainers: [{ name: 'g7c', email: 'nobody@example.invalid' }] };
}
function pypiJson(e, version) {
  const releases = {};
  e.versions.forEach((v, i) => {
    releases[v] = [{ filename: `${e.name}-${v}.tar.gz`, packagetype: 'sdist', upload_time_iso_8601: new Date(Date.parse(OLD) + i * DAY * 30).toISOString(),
      url: `https://files.pythonhosted.org/packages/aa/bb/${e.name}-${v}.tar.gz`, yanked: false, requires_python: '>=3.8', digests: { sha256: '0'.repeat(64) } }];
  });
  const v = version || e.versions[e.versions.length - 1];
  if (!releases[v]) return null;
  return { info: { name: e.name, version: v, summary: 'canned', requires_dist: null, requires_python: '>=3.8', yanked: false, project_urls: { Source: repoOf(e.name) }, home_page: '' },
    releases: version ? undefined : releases, urls: releases[v] };
}
function crateApi(e) {
  const last = e.versions[e.versions.length - 1];
  return { crate: { id: e.name, name: e.name, max_version: last, max_stable_version: last, newest_version: last, repository: repoOf(e.name), created_at: OLD, updated_at: OLD },
    versions: [...e.versions].reverse().map((v, i) => ({ id: i + 1, crate: e.name, num: v, created_at: new Date(Date.parse(OLD) + (e.versions.indexOf(v)) * DAY * 30).toISOString(), yanked: false,
      dl_path: `/api/v1/crates/${e.name}/${v}/download`, rust_version: null, published_by: { login: 'g7c' }, features: {} })) };
}
const crateIndex = (e) => e.versions.map((v) => JSON.stringify({ name: e.name, vers: v, deps: [], cksum: '0'.repeat(64), features: {}, yanked: false })).join('\n') + '\n';

// ---------------------------------------------------------------- routing
function answer(req, body, res, scheme) {
  const host = (req.headers.host || '').toLowerCase().replace(/:\d+$/, '');
  const u = new URL(req.url.startsWith('http') ? req.url : `${scheme}://${host}${req.url}`);
  let p; try { p = decodeURIComponent(u.pathname); } catch { p = u.pathname; }
  const json = (code, obj, extra = {}) => { res.writeHead(code, { 'content-type': 'application/json', ...extra }); res.end(JSON.stringify(obj)); };
  const text = (code, s, type = 'text/plain') => { res.writeHead(code, { 'content-type': type }); res.end(s); };

  if (host === 'api.osv.dev') {
    let q = {}; try { q = JSON.parse(body); } catch { /* */ }
    if (p === '/v1/querybatch') {
      return json(200, { results: (q.queries || []).map((one) => {
        const vs = vulnsOf(one.package?.ecosystem, String(one.package?.name ?? ''), one.version);
        return vs.length ? { vulns: vs.map((v) => ({ id: v.id, modified: OLD })) } : {};
      }) });
    }
    if (p === '/v1/query') {
      const vs = vulnsOf(q.package?.ecosystem, String(q.package?.name ?? ''), q.version);
      return json(200, vs.length ? { vulns: vs.map((v) => vulnRecord(v.id)) } : {});
    }
    const m = /^\/v1\/vulns\/(.+)$/.exec(p);
    if (m) { const r = vulnRecord(m[1]); return r ? json(200, r) : json(404, { code: 5, message: 'Bug not found.' }); }
    return json(404, {});
  }
  if (host === 'registry.npmjs.org') {
    if (p === '/-/ping') return json(200, {});
    if (/\/-\/.+\.tgz$/.test(p)) return text(404, 'not here');
    const name = p.slice(1);
    const segs = name.split('/');
    const pkgName = name.startsWith('@') ? segs.slice(0, 2).join('/') : segs[0];
    const ver = name.startsWith('@') ? segs[2] : segs[1];
    const e = entry('npm', pkgName);
    if (!e) return json(404, { error: 'Not found' });
    const doc = packument(e);
    if (ver) return doc.versions[ver] ? json(200, doc.versions[ver]) : json(404, { error: 'version not found' });
    return json(200, doc, { etag: '"g7c"' });
  }
  if (host === 'api.npmjs.org') {
    const m = /^\/downloads\/(point|range)\/([^/]+)\/(.+)$/.exec(p);
    if (!m) return json(404, {});
    const one = (n) => { const e = entry('npm', n); return e ? { downloads: e.downloads ?? 2345678, start: '2026-11-17', end: '2026-11-24', package: n } : null; };
    const names = m[3].split(',');
    if (names.length === 1 && !m[3].includes(',')) { const d = one(names[0]); return d ? json(200, d) : json(404, { error: `package ${names[0]} not found` }); }
    return json(200, Object.fromEntries(names.map((n) => [n, one(n)])));
  }
  if (host === 'pypi.org') {
    const m = /^\/pypi\/([^/]+)(?:\/([^/]+))?\/json$/.exec(p);
    if (m) { const e = entry('PyPI', m[1]); const doc = e && pypiJson(e, m[2]); return doc ? json(200, doc) : json(404, { message: 'Not Found' }); }
    const s = /^\/simple\/([^/]+)\/?$/.exec(p);
    if (s) return entry('PyPI', s[1]) ? text(200, '<html><body></body></html>', 'text/html') : text(404, 'Not Found');
    return json(404, { message: 'Not Found' });
  }
  if (host === 'crates.io') {
    const m = /^\/api\/v1\/crates\/([^/]+)(?:\/(versions)|\/([^/]+)\/dependencies)?$/.exec(p);
    const e = m && entry('crates.io', m[1]);
    if (!e) return json(404, { errors: [{ detail: 'Not Found' }] });
    if (m[2]) return json(200, { versions: crateApi(e).versions, meta: { total: e.versions.length, next_page: null } });
    return m[3] ? json(200, { dependencies: [] }) : json(200, crateApi(e));
  }
  if (host === 'index.crates.io') {
    if (p === '/config.json') return json(200, { dl: 'https://static.crates.io/crates', api: 'https://crates.io' });
    const e = entry('crates.io', p.split('/').pop());
    return e ? text(200, crateIndex(e)) : text(404, 'not found');
  }
  if (host === 'proxy.golang.org' || host === 'sum.golang.org') {
    const m = /^\/(.+?)\/@(v\/list|v\/([^/]+)\.(info|mod|zip)|latest)$/.exec(p);
    if (!m) return text(404, 'not found');
    const mod = m[1].replace(/!([a-z])/g, (_, c) => c.toUpperCase());
    const e = entry('Go', mod);
    if (!e) return text(404, `not found: module ${mod}: no matching versions`);
    const last = e.versions[e.versions.length - 1];
    if (m[2] === 'v/list') return text(200, e.versions.join('\n') + '\n');
    if (m[2] === 'latest') return json(200, { Version: last, Time: OLD });
    if (!e.versions.includes(m[3])) return text(404, 'not found');
    if (m[4] === 'info') return json(200, { Version: m[3], Time: OLD });
    if (m[4] === 'mod') return text(200, `module ${mod}\n\ngo 1.20\n`);
    return text(404, 'not here');
  }
  if (host === 'hn.algolia.com') return json(200, { hits: [] });
  if (host === 'api.github.com') return json(404, { message: 'Not Found' });
  return text(404, `g7c proxy: no such host in this world: ${host}`);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', () => resolve(Buffer.concat(chunks)));
  });
}
async function handle(req, res, scheme, tunnelHost) {
  const raw = await readBody(req);
  let body = raw.toString('utf8');
  if ((req.headers['content-encoding'] || '').includes('gzip')) { try { body = zlib.gunzipSync(raw).toString('utf8'); } catch { /* */ } }
  log({ kind: 'request', scheme, tunnel: tunnelHost || null, method: req.method, host: req.headers.host, url: req.url, body: body.length > 20000 ? body.slice(0, 20000) + `...[${body.length} bytes]` : body });
  try { answer(req, body, res, scheme); } catch (e) { log({ kind: 'answer-error', error: String(e) }); try { res.writeHead(500); res.end(); } catch { /* */ } }
}
const inner = http.createServer((req, res) => handle(req, res, 'https', req.socket.__tunnelHost));
inner.keepAliveTimeout = 5000;
const outer = http.createServer((req, res) => handle(req, res, 'http', null));
outer.on('connect', (req, clientSocket, head) => {
  const [host, port] = req.url.split(':');
  log({ kind: 'CONNECT', target: req.url });
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  let ctx;
  try { ctx = contextFor(host); } catch (e) { log({ kind: 'cert-error', host, error: String(e) }); clientSocket.destroy(); return; }
  const tlsSocket = new tls.TLSSocket(clientSocket, { isServer: true, secureContext: ctx, SNICallback: (sni, cb) => { try { cb(null, contextFor(sni)); } catch (e) { cb(e); } } });
  tlsSocket.__tunnelHost = `${host}:${port}`;
  if (head && head.length) clientSocket.unshift(head);
  tlsSocket.on('error', (e) => log({ kind: 'tls-error', host, error: String(e.message) }));
  inner.emit('connection', tlsSocket);
});
outer.on('clientError', (e, s) => { log({ kind: 'client-error', error: String(e.message) }); s.destroy(); });
outer.listen(PORT, '127.0.0.1', () => { log({ kind: 'listening', port: PORT }); console.log(`g7c proxy on 127.0.0.1:${PORT}, log ${LOG}`); });
