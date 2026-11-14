// SPDX-License-Identifier: Apache-2.0
/**
 * Network sources for `upgrade_impact`: registry version index, the target
 * version's changelog (read from its registry archive) and OSV advisories.
 *
 * Privacy rule (Decision 1, option A): by default the only hosts contacted
 * are the package's own registry (registry.npmjs.org; crates.io +
 * static.crates.io; pypi.org + files.pythonhosted.org; proxy.golang.org) and
 * api.osv.dev. A changelog is read from GitHub only when the user opts in
 * (Decision 1, option B: FOURDA_GITHUB_CHANGELOG, github-releases.ts) and the
 * archive has none for the range; otherwise the report hands the agent a
 * `release_notes_url` built from registry metadata and says how to enable the
 * fallback. Every request goes through `UpgradeNet`, which records the host
 * so `_meta.sources` is a fact, not a claim, and which tests replace with a
 * fake fetch.
 *
 * Request budget per call: index (1) + archive (1) + OSV for from/to (2) = 4,
 * each cached (index 6 h, parsed changelog 7 d, OSV 1 h). The npm packument
 * is large (vite's is ~39 MB, measured 2026-10-02), so only a reduced index
 * is cached — never the raw document.
 */

import { compareVersionPrecedence, parseSemverPrecedence } from "./semver-precedence.js";
import { osvAdvisoryId, quoteThirdParty, thirdPartyUrl, URL_MAX } from "../untrusted-text.js";
import { isMalwareRecord } from "./malware.js";
import { ArchiveError, defaultFetch, fetchArchiveBytes, readRootTextFiles, type FetchFn } from "./package-archive.js";
import { CHANGELOG_PARSER_VERSION, findChangelogFile, isChangelogName, parseChangelog, type ChangelogSection, type VersionOrder } from "./changelog.js";
import { compareVersions, isComparable } from "./version-compare.js";
import { isPrereleaseVersion } from "./osv-ranges.js";
import { looksLikeZip, readZipRootTextFiles } from "./zip-archive.js";
import { loadPypiIndex, normalizePypiName, PYPI_NAME } from "./upgrade-pypi.js";
import { GO_MODULE, goZipUrl, loadGoIndex } from "./upgrade-go.js";

export type UpgradeEcosystem = "npm" | "crates.io" | "PyPI" | "Go";
export const UPGRADE_ECOSYSTEMS: readonly UpgradeEcosystem[] = ["npm", "crates.io", "PyPI", "Go"];

/** Version order for an ecosystem: semver precedence (npm, crates.io, Go without its `v`), PEP 440 (PyPI). Null = unreadable. */
export function versionOrder(ecosystem: UpgradeEcosystem): VersionOrder {
  if (ecosystem === "npm" || ecosystem === "crates.io") return compareVersionPrecedence;
  return (a, b) => (isComparable(a, ecosystem) && isComparable(b, ecosystem) ? compareVersions(a, b, ecosystem) : null);
}

/** Readable as a version in this ecosystem. */
export function isReadableVersion(version: string, ecosystem: UpgradeEcosystem): boolean {
  if (ecosystem === "npm" || ecosystem === "crates.io") return parseSemverPrecedence(version) !== null;
  return version !== "0" && isComparable(version, ecosystem);
}

/** A prerelease in this ecosystem's own terms (PEP 440 `a`/`b`/`rc`/`.dev`; semver `-x`; a Go pseudo-version). */
export function isPrerelease(version: string, ecosystem: UpgradeEcosystem): boolean {
  if (ecosystem === "npm" || ecosystem === "crates.io") return (parseSemverPrecedence(version)?.prerelease.length ?? 0) > 0;
  return isPrereleaseVersion(version, ecosystem);
}

/** Package-name identity: crates.io folds `-`/`_`, PyPI normalises per PEP 503, npm and Go are exact. */
export function sameUpgradeName(a: string, b: string, ecosystem: string): boolean {
  if (ecosystem === "crates.io") return a.replace(/-/g, "_") === b.replace(/-/g, "_");
  if (ecosystem === "PyPI") return normalizePypiName(a) === normalizePypiName(b);
  return a === b;
}

/** crates.io refuses API requests without a descriptive User-Agent. */
export const CRATES_USER_AGENT = "4da-mcp-server (https://4da.ai; upgrade_impact)";

const INDEX_TTL = 6 * 3600;
const CHANGELOG_TTL = 7 * 86_400;
const OSV_TTL = 3600;
const CACHE_SOURCE = "upgrade-impact";
const INDEX_TIMEOUT_MS = 30_000;
const OSV_TIMEOUT_MS = 10_000;

export interface PublishedVersion {
  version: string;
  published: string | null;
  deprecated?: string;
  yanked?: boolean;
  /** Archive URL (npm `dist.tarball`, PyPI sdist); crates and Go archives are derived from name + version. */
  tarball?: string;
}

export interface RegistryIndex {
  /** The registry's canonical spelling (crates.io folds `-`/`_`). */
  name: string;
  ecosystem: UpgradeEcosystem;
  versions: PublishedVersion[];
  repository: string | null;
  /** Links the project itself labels as its changelog (PyPI `project_urls`). */
  changelogLinks?: string[];
  /** npm: releases listed in `time` that the registry no longer serves (unpublished). */
  unpublished?: string[];
}

export interface ChangelogResult {
  found: boolean;
  file?: string;
  sections?: ChangelogSection[];
  reason?: string;
  /** Where the sections came from: the registry archive (default), or the opt-in GitHub fallback. */
  source?: "archive" | "github-releases" | "github-file";
  /** The page or API the GitHub fallback read. */
  url?: string;
}

/** The cache surface used here; `LiveCache` satisfies it. */
export interface UpgradeCache {
  get<T>(key: string): T | null;
  set(key: string, data: unknown, source: string, ttlSeconds: number): void;
}

/** Network + cache seam. `contacted` collects every host actually requested. */
export interface UpgradeNet {
  fetch: FetchFn;
  cache: UpgradeCache | null;
  contacted: Set<string>;
}

export function createUpgradeNet(cache: UpgradeCache | null, fetchFn: FetchFn = defaultFetch): UpgradeNet {
  const contacted = new Set<string>();
  return {
    contacted,
    cache,
    fetch: (url, init, timeoutMs) => {
      contacted.add(new URL(url).host);
      return fetchFn(url, init, timeoutMs);
    },
  };
}

const NPM_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const CRATE_NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

export function isValidPackageName(name: string, ecosystem: UpgradeEcosystem): boolean {
  switch (ecosystem) {
    case "npm":
      return NPM_NAME.test(name) && name.length <= 214;
    case "crates.io":
      return CRATE_NAME.test(name);
    case "PyPI":
      return PYPI_NAME.test(name);
    case "Go":
      return GO_MODULE.test(name) && name.length <= 300 && !name.split("/").some((p) => p === "." || p === "..");
  }
}

async function cached<T>(net: UpgradeNet, key: string, ttl: number, load: () => Promise<T>): Promise<T> {
  const hit = net.cache?.get<T>(key);
  if (hit !== null && hit !== undefined) return hit;
  const value = await load();
  net.cache?.set(key, value, CACHE_SOURCE, ttl);
  return value;
}

interface NpmPackument {
  name?: string;
  versions?: Record<string, { deprecated?: unknown; dist?: { tarball?: string } }>;
  time?: Record<string, string>;
  repository?: unknown;
}

interface CratesCrateResponse {
  crate?: { name?: string; repository?: string | null };
  versions?: Array<{ num?: string; created_at?: string; yanked?: boolean }>;
}

function repositoryUrl(repo: unknown): string | null {
  const raw = typeof repo === "string" ? repo : repo && typeof repo === "object" && typeof (repo as { url?: unknown }).url === "string" ? (repo as { url: string }).url : null;
  if (raw === null) return null;
  // The publisher's words: a repository is a short URL or `owner/repo`, never 5,000 characters or
  // a line break with text after it (r7: both came back whole in release_notes_url and
  // github_fallback.how_to_enable). Anything else names no repository.
  const trimmed = raw.trim();
  // eslint-disable-next-line no-control-regex
  if (trimmed === "" || trimmed.length > URL_MAX || /[\s\u0000-\u001f\u007f-\u009f]/.test(trimmed)) return null;
  return trimmed;
}

async function loadNpmIndex(net: UpgradeNet, name: string): Promise<RegistryIndex | null> {
  const url = `https://registry.npmjs.org/${name.replaceAll("/", "%2F")}`;
  const res = await net.fetch(url, { headers: { Accept: "application/json" } }, INDEX_TIMEOUT_MS);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`npm registry HTTP ${res.status} for ${name}`);
  const doc = (await res.json()) as NpmPackument;
  const versions = Object.entries(doc.versions ?? {}).map(([version, meta]) => {
    const entry: PublishedVersion = { version, published: doc.time?.[version] ?? null };
    if (typeof meta.deprecated === "string" && meta.deprecated) entry.deprecated = quoteThirdParty(meta.deprecated) || "deprecated";
    if (meta.dist?.tarball) entry.tarball = meta.dist.tarball;
    return entry;
  });
  // Releases npm lists in `time` but no longer serves: unpublished (chalk 5.6.1, the September 2025
  // hijack). A refusal to analyse one says so instead of "not published" (r7).
  const served = new Set(Object.keys(doc.versions ?? {}));
  const unpublished = Object.keys(doc.time ?? {}).filter((v) => v !== "created" && v !== "modified" && !served.has(v) && parseSemverPrecedence(v) !== null);
  return { name: doc.name ?? name, ecosystem: "npm", versions, repository: repositoryUrl(doc.repository), ...(unpublished.length > 0 ? { unpublished } : {}) };
}

async function loadCratesIndex(net: UpgradeNet, name: string): Promise<RegistryIndex | null> {
  const url = `https://crates.io/api/v1/crates/${encodeURIComponent(name)}`;
  const headers = { Accept: "application/json", "User-Agent": CRATES_USER_AGENT };
  const res = await net.fetch(url, { headers }, INDEX_TIMEOUT_MS);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`crates.io HTTP ${res.status} for ${name}`);
  const doc = (await res.json()) as CratesCrateResponse;
  const versions = (doc.versions ?? [])
    .filter((v): v is { num: string; created_at?: string; yanked?: boolean } => typeof v.num === "string")
    .map((v) => {
      const entry: PublishedVersion = { version: v.num, published: v.created_at ?? null };
      if (v.yanked) entry.yanked = true;
      return entry;
    });
  return { name: doc.crate?.name ?? name, ecosystem: "crates.io", versions, repository: doc.crate?.repository ?? null };
}

/** Registry index with versions in ascending precedence order (unreadable versions dropped). Null = unknown package. */
export async function getRegistryIndex(
  net: UpgradeNet,
  ecosystem: UpgradeEcosystem,
  name: string,
): Promise<RegistryIndex | null> {
  const keyName =
    ecosystem === "crates.io" ? name.replace(/-/g, "_") : ecosystem === "PyPI" ? normalizePypiName(name) : name;
  // v2 (r7): npm indexes carry `unpublished`, and `repository` is held to a URL's shape and length.
  const key = `upgrade-impact:index:v2:${ecosystem}:${keyName}`;
  const index = await cached(net, key, INDEX_TTL, () => {
    switch (ecosystem) {
      case "npm":
        return loadNpmIndex(net, name);
      case "crates.io":
        return loadCratesIndex(net, name);
      case "PyPI":
        return loadPypiIndex(net, name);
      case "Go":
        return loadGoIndex(net, name);
    }
  });
  if (!index) return null;
  const order = versionOrder(ecosystem);
  const versions = index.versions
    .filter((v) => isReadableVersion(v.version, ecosystem))
    .sort((a, b) => order(a.version, b.version) ?? 0);
  return { ...index, versions };
}

const ARCHIVE_HOSTS = new Set(["registry.npmjs.org", "static.crates.io", "files.pythonhosted.org", "proxy.golang.org"]);

/** The registry archive URL for one version, or null when it is not on the package's own registry. */
export function archiveUrl(index: RegistryIndex, version: PublishedVersion): string | null {
  const url =
    index.ecosystem === "crates.io"
      ? `https://static.crates.io/crates/${index.name}/${index.name}-${version.version}.crate`
      : index.ecosystem === "Go"
        ? goZipUrl(index.name, version.version)
        : version.tarball;
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && ARCHIVE_HOSTS.has(parsed.host) ? url : null;
  } catch {
    return null;
  }
}

/** Cache key of one version's parsed changelog; it carries CHANGELOG_PARSER_VERSION. */
export function changelogCacheKey(ecosystem: string, name: string, version: string): string {
  return `upgrade-impact:changelog:p${CHANGELOG_PARSER_VERSION}:${ecosystem}:${name}:${version}`;
}

/** Parsed changelog shipped inside one version's archive (cached 7 days per version). */
export async function getChangelog(
  net: UpgradeNet,
  index: RegistryIndex,
  version: PublishedVersion,
): Promise<ChangelogResult> {
  const url = archiveUrl(index, version);
  if (!url) {
    return {
      found: false,
      reason:
        index.ecosystem === "PyPI" && !version.tarball
          ? `${version.version} has no source distribution on PyPI (wheels only), so there is no archive changelog to read`
          : "the version's archive is not hosted on the package's own registry",
    };
  }
  // The parser version is in the key: a parser fix must not wait out the 7-day TTL.
  const key = changelogCacheKey(index.ecosystem, index.name, version.version);
  const hit = net.cache?.get<ChangelogResult>(key);
  if (hit) return hit;

  const headers: Record<string, string> = index.ecosystem === "crates.io" ? { "User-Agent": CRATES_USER_AGENT } : {};
  let files: Map<string, string>;
  try {
    const bytes = await fetchArchiveBytes(url, net.fetch, headers);
    // A Go module zip holds its files under `<module>@<version>/`; a zip sdist and every tar one directory deep.
    files = looksLikeZip(bytes)
      ? readZipRootTextFiles(bytes, isChangelogName, index.ecosystem === "Go" ? `${index.name}@${version.version}/` : null)
      : readRootTextFiles(bytes, isChangelogName);
  } catch (err) {
    const result = { found: false, reason: `could not read the ${version.version} archive: ${(err as Error).message}` };
    // A published archive never changes, so a cap or format refusal is permanent;
    // a network failure is not, and must not be remembered for a week.
    if (err instanceof ArchiveError) net.cache?.set(key, result, CACHE_SOURCE, CHANGELOG_TTL);
    return result;
  }
  const file = findChangelogFile(files.keys());
  const sections = file ? parseChangelog(files.get(file) ?? "") : [];
  const result: ChangelogResult = !file
    ? { found: false, reason: `the ${version.version} archive ships no changelog file` }
    : sections.length === 0
      ? { found: false, file, reason: `${file} has no version headings this parser recognises` }
      : { found: true, file, sections, source: "archive" };
  net.cache?.set(key, result, CACHE_SOURCE, CHANGELOG_TTL);
  return result;
}

/** OSV advisory ids affecting one version, or null when OSV could not be reached. */
export async function getOsvAdvisories(
  net: UpgradeNet,
  ecosystem: UpgradeEcosystem,
  name: string,
  version: string,
): Promise<string[] | null> {
  const key = `upgrade-impact:osv:${ecosystem}:${name}:${version}`;
  const hit = net.cache?.get<string[]>(key);
  if (hit) return hit;
  try {
    const res = await net.fetch(
      "https://api.osv.dev/v1/query",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: { name, ecosystem }, version }),
      },
      OSV_TIMEOUT_MS,
    );
    if (!res.ok) return null;
    const body = (await res.json()) as { vulns?: Array<{ id?: string }> };
    // Held to OSV's id shape (blind audit round 5); one that is not an id still counts.
    const ids = [...new Set((body.vulns ?? []).map((v) => osvAdvisoryId(v?.id)))];
    net.cache?.set(key, ids, CACHE_SOURCE, OSV_TTL);
    return ids;
  } catch {
    return null;
  }
}

/**
 * The advisories OSV.dev lists for one exact release, and which of them are malicious-package
 * records (malware.ts isMalwareRecord over the whole record); null when OSV.dev could not be read.
 * Asked only when upgrade_impact refuses a target (not published, or not newer), so the refusal
 * says what is known about it (r7: chalk 5.6.1 came back only "not published on npm").
 */
export async function getOsvRecordFacts(
  net: UpgradeNet,
  ecosystem: UpgradeEcosystem,
  name: string,
  version: string,
): Promise<{ ids: string[]; malware: string[] } | null> {
  try {
    const res = await net.fetch(
      "https://api.osv.dev/v1/query",
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ package: { name, ecosystem }, version }) },
      OSV_TIMEOUT_MS,
    );
    if (!res.ok) return null;
    const body = (await res.json()) as { vulns?: Array<Parameters<typeof isMalwareRecord>[0] | null> };
    const records = (body.vulns ?? []).filter((v): v is NonNullable<typeof v> => v !== null && typeof v === "object");
    const ids = [...new Set(records.map((v) => osvAdvisoryId(v.id)))];
    const malware = [...new Set(records.filter((v) => isMalwareRecord(v)).map((v) => osvAdvisoryId(v.id)))];
    return { ids, malware };
  } catch {
    return null;
  }
}

/**
 * Release-notes page derived from the registry's own `repository` field: a
 * GitHub repo becomes `https://github.com/<owner>/<repo>/releases`; any other
 * https repository URL is returned as-is; anything else is null.
 */
export function releaseNotesUrl(repository: string | null): string | null {
  if (!repository) return null;
  const raw = repository.trim();
  const shorthand = /^(?:github:)?([\w.-]+)\/([\w.-]+)$/.exec(raw);
  const gh = shorthand ?? /github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$/i.exec(raw);
  if (gh) return thirdPartyUrl(`https://github.com/${gh[1]}/${gh[2].replace(/\.git$/, "")}/releases`);
  const https = raw.replace(/^git\+/, "");
  // Held to a URL's shape and length like every third-party URL (r7).
  return /^https:\/\//i.test(https) ? thirdPartyUrl(https.replace(/\.git$/, "")) : null;
}
