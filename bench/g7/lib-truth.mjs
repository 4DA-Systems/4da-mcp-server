// SPDX-License-Identifier: Apache-2.0
// Ground truth helpers: registry version lists + OSV per-version advisory ids, pinned to disk as JSON.
// Truth never comes from the server under test: registries' own indexes and api.osv.dev only.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const TRUTH_DIR = path.join(HERE, "truth");
const UA = { "User-Agent": "4da-g7-eval (hello@4da.ai)" };

async function getJson(url, opts = {}) {
  for (let attempt = 1; ; attempt++) {
    try {
      const r = await fetch(url, { ...opts, headers: { ...UA, ...(opts.headers ?? {}) } });
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`${r.status} ${url}`);
      return await r.json();
    } catch (e) {
      if (attempt >= 4) throw e;
      await new Promise((res) => setTimeout(res, 1000 * attempt));
    }
  }
}
async function getText(url) {
  for (let attempt = 1; ; attempt++) {
    try {
      const r = await fetch(url, { headers: UA });
      if (r.status === 404 || r.status === 410) return null;
      if (!r.ok) throw new Error(`${r.status} ${url}`);
      return await r.text();
    } catch (e) {
      if (attempt >= 4) throw e;
      await new Promise((res) => setTimeout(res, 1000 * attempt));
    }
  }
}

const goEscape = (m) => m.replace(/[A-Z]/g, (c) => "!" + c.toLowerCase());
const cratePrefix = (n) => (n.length <= 2 ? `${n.length}/${n}` : n.length === 3 ? `3/${n[0]}/${n}` : `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`);

/** Every published version (yanked flagged) + the registry's "latest". */
export async function registryVersions(eco, name) {
  if (eco === "npm") {
    const j = await getJson(`https://registry.npmjs.org/${name.replace("/", "%2F")}`, { headers: { Accept: "application/vnd.npm.install-v1+json" } });
    if (!j) return null;
    return { versions: Object.keys(j.versions ?? {}), yanked: [], latest: j["dist-tags"]?.latest ?? null };
  }
  if (eco === "PyPI") {
    const j = await getJson(`https://pypi.org/pypi/${name}/json`);
    if (!j) return null;
    const versions = Object.keys(j.releases ?? {});
    const yanked = versions.filter((v) => (j.releases[v] ?? []).length > 0 && j.releases[v].every((f) => f.yanked));
    return { versions, yanked, latest: j.info?.version ?? null, canonical: j.info?.name ?? name };
  }
  if (eco === "crates.io") {
    const t = await getText(`https://index.crates.io/${cratePrefix(name.toLowerCase())}`);
    if (!t) return null;
    const rows = t.split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const versions = rows.map((r) => r.vers);
    const yanked = rows.filter((r) => r.yanked).map((r) => r.vers);
    const stable = rows.filter((r) => !r.yanked && !r.vers.includes("-")).map((r) => r.vers);
    return { versions, yanked, latest: stable.at(-1) ?? versions.at(-1) ?? null };
  }
  if (eco === "Go") {
    const list = await getText(`https://proxy.golang.org/${goEscape(name)}/@v/list`);
    const latest = await getJson(`https://proxy.golang.org/${goEscape(name)}/@latest`);
    if (list === null && !latest) return null;
    const versions = (list ?? "").split("\n").map((s) => s.trim()).filter(Boolean);
    if (latest?.Version && !versions.includes(latest.Version)) versions.push(latest.Version);
    return { versions, yanked: [], latest: latest?.Version ?? null };
  }
  throw new Error(`unknown eco ${eco}`);
}

/** OSV ids per version, via querybatch (paged). */
export async function osvIdsPerVersion(eco, name, versions) {
  const out = {};
  for (let i = 0; i < versions.length; i += 500) {
    const chunk = versions.slice(i, i + 500);
    let queries = chunk.map((v) => ({ package: { name, ecosystem: eco }, version: eco === "Go" ? v.replace(/^v/, "") : v }));
    let idx = chunk.map((_, k) => k);
    while (queries.length) {
      const j = await getJson("https://api.osv.dev/v1/querybatch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ queries }) });
      const nextQ = [], nextIdx = [];
      j.results.forEach((r, k) => {
        const v = chunk[idx[k]];
        out[v] = [...(out[v] ?? []), ...(r.vulns ?? []).map((x) => x.id)];
        if (r.next_page_token) { nextQ.push({ ...queries[k], page_token: r.next_page_token }); nextIdx.push(idx[k]); }
      });
      queries = nextQ; idx = nextIdx;
    }
  }
  return out;
}

const vulnCachePath = path.join(TRUTH_DIR, "osv-vulns.json");
let vulnCache = null;
function loadVulnCache() {
  if (!vulnCache) vulnCache = fs.existsSync(vulnCachePath) ? JSON.parse(fs.readFileSync(vulnCachePath, "utf8")) : {};
  return vulnCache;
}
export function saveVulnCache() { if (vulnCache) fs.writeFileSync(vulnCachePath, JSON.stringify(vulnCache, null, 1)); }

/** Minimal OSV record facts: withdrawn, informational (RUSTSEC unmaintained/unsound notices), summary, aliases, severity. */
export async function vulnMeta(ids) {
  const cache = loadVulnCache();
  const todo = [...new Set(ids)].filter((id) => !cache[id]);
  let k = 0;
  async function worker() {
    while (k < todo.length) {
      const id = todo[k++];
      const j = await getJson(`https://api.osv.dev/v1/vulns/${id}`);
      const informational = (j?.affected ?? []).map((a) => a.database_specific?.informational ?? a.ecosystem_specific?.informational).find(Boolean) ?? null;
      cache[id] = {
        id, withdrawn: j?.withdrawn ?? null, informational, summary: (j?.summary ?? j?.details ?? "").slice(0, 160),
        aliases: j?.aliases ?? [], published: j?.published ?? null, modified: j?.modified ?? null,
        severity: j?.database_specific?.severity ?? null,
      };
    }
  }
  await Promise.all(Array.from({ length: 8 }, worker));
  return cache;
}

export const truthFile = (eco, name) => path.join(TRUTH_DIR, eco, name.replace(/[\/:]/g, "__") + ".json");

/** Build (or load the pinned) truth for one package. `scoringTime` marks lookups made after harness build. */
export async function packageTruth(eco, name, { scoringTime = false } = {}) {
  const f = truthFile(eco, name);
  if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, "utf8"));
  const reg = await registryVersions(eco, name);
  let rec;
  if (!reg) rec = { eco, name, exists: false, versions: [], yanked: [], latest: null, vulnsByVersion: {} };
  else {
    const ids = await osvIdsPerVersion(eco, name, reg.versions);
    await vulnMeta(Object.values(ids).flat());
    saveVulnCache();
    rec = { eco, name, exists: true, ...reg, vulnsByVersion: ids };
  }
  rec.fetchedAt = new Date().toISOString();
  rec.scoringTime = scoringTime;
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify(rec));
  return rec;
}

/**
 * Advisories excluded from "vulnerable" by explicit, documented rule (the RUSTSEC-informational analogue):
 * an unmaintained-subpackage notice with no fixed version, which marks every release of the module.
 */
export const EXCLUDED = {
  "GO-2026-5932": "unmaintained notice for the x/crypto/openpgp subpackage; no fix exists; affects every x/crypto release (module-level matching cannot see that the task uses bcrypt)",
};

/** Counted (real) advisories for a version: not withdrawn, not an informational notice, not excluded. */
export function countedVulns(truth, version) {
  const cache = loadVulnCache();
  const ids = truth.vulnsByVersion[version] ?? [];
  return ids.filter((id) => { const m = cache[id]; return m && !m.withdrawn && !m.informational && !EXCLUDED[id]; });
}
