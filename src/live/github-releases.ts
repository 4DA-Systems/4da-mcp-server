// SPDX-License-Identifier: Apache-2.0
/**
 * Opt-in changelog fallback for `upgrade_impact`: GitHub releases, and a
 * changelog FILE a PyPI project links from `project_urls` when that file is
 * on GitHub (Decision 1, option B, approved 2026-10-11).
 *
 * Off by default. The default contract stays option A: only the package's own
 * registry and OSV.dev are contacted. A user who wants release notes for the
 * many packages whose archive ships no changelog (vite, zod, cobra, most Go
 * modules) sets FOURDA_GITHUB_CHANGELOG=true; GitHub then learns the
 * repository and the version range, nothing else. GITHUB_TOKEN, when set, is
 * sent as a bearer token (5,000 requests an hour instead of 60).
 *
 * What is parsed is what the project itself published as release notes: the
 * release body (Markdown), read by the same parser and classifier as an
 * archive changelog, one section per release whose tag names a version of
 * this package. A docs page (HTML) is never parsed. Rate limits are reported,
 * not retried: the answer says when the limit resets and how to raise it.
 */

import { CHANGELOG_PARSER_VERSION, isChangelogName, parseChangelog, type ChangelogSection, type VersionOrder } from "./changelog.js";
import { ArchiveError, MAX_FILE_BYTES } from "./package-archive.js";
import type { ChangelogResult, UpgradeNet } from "./upgrade-sources.js";

export const GITHUB_CHANGELOG_ENV = "FOURDA_GITHUB_CHANGELOG";
const CACHE_SOURCE = "upgrade-impact";
/** A range whose target release is published: release notes rarely change after. */
const FOUND_TTL = 24 * 3600;
const MISS_TTL = 3600;
const PER_PAGE = 100;
const MAX_PAGES = 5;
const GITHUB_TIMEOUT_MS = 15_000;
const USER_AGENT = "4da-mcp-server (https://4da.ai; upgrade_impact)";

/** True when the user opted in: FOURDA_GITHUB_CHANGELOG is 1 / true / yes / on. */
export function githubChangelogEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return /^(?:1|true|yes|on)$/i.test(String(env[GITHUB_CHANGELOG_ENV] ?? "").trim());
}

/** `owner/repo` of a GitHub URL (https, git+https, git@, shorthand), or null. */
export function parseGithubRepo(url: string | null | undefined): { owner: string; repo: string } | null {
  if (!url) return null;
  const raw = url.trim();
  const m =
    /^(?:github:)?([\w.-]+)\/([\w.-]+)$/.exec(raw) ??
    /github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$/i.exec(raw);
  if (!m) return null;
  const repo = m[2].replace(/\.git$/, "");
  if (!repo || m[1] === "." || repo === "." || repo === "..") return null;
  return { owner: m[1], repo };
}

interface GithubRelease {
  tag_name?: string;
  name?: string | null;
  body?: string | null;
  draft?: boolean;
  published_at?: string | null;
  created_at?: string | null;
  html_url?: string;
}

export class GithubRateLimitError extends Error {}

function headers(): Record<string, string> {
  const h: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": USER_AGENT,
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

/** A 403/429 that is a rate limit, with when it lifts. */
function rateLimitMessage(res: Response): string | null {
  if (res.status !== 403 && res.status !== 429) return null;
  const remaining = res.headers.get("x-ratelimit-remaining");
  const retryAfter = res.headers.get("retry-after");
  if (remaining !== "0" && !retryAfter && res.status !== 429) return null;
  const reset = Number(res.headers.get("x-ratelimit-reset"));
  const when = Number.isFinite(reset) && reset > 0
    ? `resets at ${new Date(reset * 1000).toISOString()}`
    : retryAfter
      ? `retry after ${retryAfter} s`
      : "try again later";
  const auth = process.env.GITHUB_TOKEN?.trim()
    ? "GITHUB_TOKEN is set; its hourly limit is spent"
    : "set GITHUB_TOKEN to raise the limit from 60 to 5,000 requests an hour";
  return `GitHub API rate limit reached (${when}); ${auth}`;
}

const KNOWN_TAG_PREFIX = /^(?:v|version[-_]?|release[-_]?|rel[-_]?)?$/i;

/**
 * The version a release tag names for this package, or null when the tag is
 * another package's (monorepos) or not a version. `tagPrefix` is a Go
 * module's subdirectory (`service/s3`): its tags are `service/s3/v1.2.3`.
 */
export function versionFromTag(tag: string, pkg: string, tagPrefix: string | null): string | null {
  let rest = tag.trim();
  // Real tags are short; the version regex below is superlinear on long ones (B-10).
  if (rest.length > 256) return null;
  if (tagPrefix) {
    if (!rest.startsWith(`${tagPrefix}/`)) return null;
    rest = rest.slice(tagPrefix.length + 1);
  }
  const m = /^(.*?)(\d+\.\d+(?:\.\d+)*(?:[-.+]?[0-9A-Za-z][0-9A-Za-z.+-]*)?)$/.exec(rest);
  if (!m) return null;
  const prefix = m[1];
  if (KNOWN_TAG_PREFIX.test(prefix)) return m[2];
  // A monorepo tag: `pkg@1.2.3`, `pkg-v1.2.3`, `@scope/pkg@1.2.3`, `pkg/v1.2.3`.
  const fold = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "");
  const bare = prefix.replace(/(?:[@/_-]v?|v)$/i, "");
  const name = pkg.split("/").pop() ?? pkg;
  return fold(bare) === fold(pkg) || fold(bare) === fold(name) ? m[2] : null;
}

/** Release-body lines that are bookkeeping, not changes. */
const NOISE = /made their first contribution|^\W*full changelog\W|^\W*(?:new )?contributors?\W*$/i;

/** One section per release that names a version of this package, entries parsed from its notes. */
export function releasesToSections(releases: GithubRelease[], pkg: string, tagPrefix: string | null): ChangelogSection[] {
  const sections: ChangelogSection[] = [];
  for (const r of releases) {
    if (r.draft || typeof r.tag_name !== "string") continue;
    const version = versionFromTag(r.tag_name, pkg, tagPrefix);
    if (!version) continue;
    const date = (r.published_at ?? r.created_at ?? "").slice(0, 10) || null;
    // A synthetic heading makes the body one release; a body that repeats its own
    // version heading opens the same version again, and those entries are kept too.
    const parsed = parseChangelog(`# ${version}\n\n${(r.body ?? "").slice(0, MAX_FILE_BYTES)}`);
    const entries = parsed
      .filter((s, i) => i === 0 || s.version.replace(/^v/, "") === version.replace(/^v/, ""))
      .flatMap((s) => s.entries)
      .filter((e) => !NOISE.test(e.text) && !(e.under && /^\W*new contributors\W*$/i.test(e.under)));
    sections.push({ version, date, entries });
  }
  return sections;
}

/**
 * Release notes for `pkg` from `owner/repo`, newest first, paging until a
 * release at or below `from` is seen (at most MAX_PAGES pages of 100).
 */
async function fetchReleases(
  net: UpgradeNet,
  repo: { owner: string; repo: string },
  stop: (version: string) => boolean,
  pkg: string,
  tagPrefix: string | null,
): Promise<GithubRelease[]> {
  const out: GithubRelease[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const url = `https://api.github.com/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}/releases?per_page=${PER_PAGE}&page=${page}`;
    const res = await net.fetch(url, { headers: headers() }, GITHUB_TIMEOUT_MS);
    const limited = rateLimitMessage(res);
    if (limited) throw new GithubRateLimitError(limited);
    if (res.status === 404) throw new Error(`github.com/${repo.owner}/${repo.repo} has no public releases API (not found or private)`);
    if (!res.ok) throw new Error(`GitHub API HTTP ${res.status}`);
    const batch = (await res.json()) as GithubRelease[];
    if (!Array.isArray(batch)) throw new Error("GitHub API returned an unexpected releases payload");
    out.push(...batch);
    const reachedFrom = batch.some((r) => {
      const v = typeof r.tag_name === "string" ? versionFromTag(r.tag_name, pkg, tagPrefix) : null;
      return v !== null && stop(v);
    });
    if (batch.length < PER_PAGE || reachedFrom) break;
  }
  return out;
}

export interface GithubFallbackInput {
  pkg: string;
  ecosystem: string;
  repository: string | null;
  /** Changelog links the project published (PyPI `project_urls`). */
  changelogLinks?: string[];
  from: string;
  to: string;
  /** Go: the module's subdirectory in its repository, which prefixes its tags. */
  tagPrefix?: string | null;
  order: VersionOrder;
}

/** `https://github.com/o/r/blob/<ref>/<path>` (or raw.githubusercontent.com) to a raw file URL, when it names a changelog file. */
export function rawChangelogUrl(link: string): string | null {
  let m = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)\/(?:blob|raw)\/([^?#]+)$/i.exec(link.trim());
  let rawUrl: string | null = m ? `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}` : null;
  if (!rawUrl) {
    m = /^https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/[^?#]+$/i.exec(link.trim());
    rawUrl = m ? link.trim() : null;
  }
  if (!rawUrl) return null;
  const base = rawUrl.split("/").pop() ?? "";
  return isChangelogName(base) ? rawUrl : null;
}

async function fetchChangelogFile(net: UpgradeNet, url: string): Promise<ChangelogSection[]> {
  const res = await net.fetch(url, { headers: { "User-Agent": USER_AGENT } }, GITHUB_TIMEOUT_MS);
  const limited = rateLimitMessage(res);
  if (limited) throw new GithubRateLimitError(limited);
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_FILE_BYTES) throw new ArchiveError(`${url} is over ${MAX_FILE_BYTES} bytes`);
  const text = await res.text();
  if (text.length > MAX_FILE_BYTES) throw new ArchiveError(`${url} is over ${MAX_FILE_BYTES} bytes`);
  return parseChangelog(text);
}

function inRangeCount(sections: ChangelogSection[], from: string, to: string, order: VersionOrder): number {
  return sections.filter((s) => (order(s.version, from) ?? 0) > 0 && (order(s.version, to) ?? 1) <= 0).length;
}

export function githubCacheKey(kind: string, where: string, input: GithubFallbackInput): string {
  return `upgrade-impact:github:p${CHANGELOG_PARSER_VERSION}:${kind}:${where}:${input.tagPrefix ?? ""}:${input.ecosystem}:${input.pkg}:${input.from}:${input.to}`;
}

/**
 * The fallback: a GitHub changelog file the project links (PyPI), then the
 * repository's releases. Caller checks the opt-in. Returns a not-found result
 * with the reason (no GitHub repository, rate limit, no matching releases).
 */
export async function getGithubChangelog(net: UpgradeNet, input: GithubFallbackInput): Promise<ChangelogResult> {
  const reasons: string[] = [];

  for (const link of input.changelogLinks ?? []) {
    const raw = rawChangelogUrl(link);
    if (!raw) continue;
    const key = githubCacheKey("file", raw, input);
    const hit = net.cache?.get<ChangelogResult>(key);
    if (hit) return hit;
    try {
      const sections = await fetchChangelogFile(net, raw);
      if (inRangeCount(sections, input.from, input.to, input.order) > 0) {
        const result: ChangelogResult = { found: true, file: raw.split("/").pop(), sections, source: "github-file", url: link };
        net.cache?.set(key, result, CACHE_SOURCE, FOUND_TTL);
        return result;
      }
      reasons.push(`the changelog the project links (${link}) has no section for these releases`);
    } catch (err) {
      if (err instanceof GithubRateLimitError) return { found: false, reason: err.message };
      reasons.push(`the changelog the project links could not be read: ${(err as Error).message}`);
    }
  }

  const repo = parseGithubRepo(input.repository);
  if (!repo) {
    reasons.push("the package names no GitHub repository, so there are no GitHub releases to read");
    return { found: false, reason: reasons.join("; ") };
  }
  const where = `${repo.owner}/${repo.repo}`;
  const key = githubCacheKey("releases", where, input);
  const hit = net.cache?.get<ChangelogResult>(key);
  if (hit) return hit;
  const releasesUrl = `https://github.com/${where}/releases`;
  try {
    const releases = await fetchReleases(net, repo, (v) => (input.order(v, input.from) ?? 1) <= 0, input.pkg, input.tagPrefix ?? null);
    const sections = releasesToSections(releases, input.pkg, input.tagPrefix ?? null);
    const hits = inRangeCount(sections, input.from, input.to, input.order);
    const result: ChangelogResult =
      hits > 0
        ? { found: true, file: "GitHub releases", sections, source: "github-releases", url: releasesUrl }
        : {
            found: false,
            url: releasesUrl,
            reason: [...reasons, `${where} has no GitHub release for ${input.pkg} between ${input.from} and ${input.to}`].join("; "),
          };
    const targetFound = sections.some((s) => input.order(s.version, input.to) === 0);
    net.cache?.set(key, result, CACHE_SOURCE, targetFound ? FOUND_TTL : MISS_TTL);
    return result;
  } catch (err) {
    // A rate limit or network failure is not remembered: the next call may succeed.
    return { found: false, url: releasesUrl, reason: [...reasons, `GitHub releases could not be read: ${(err as Error).message}`].join("; ") };
  }
}
