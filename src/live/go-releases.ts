// SPDX-License-Identifier: Apache-2.0
/**
 * Go module release index for dependency_check, from the module proxy
 * (proxy.golang.org, the host `go get` downloads from):
 *
 * - `/@v/list`: the tagged versions, `+incompatible` ones included (a module
 *   that predates modules and tags v2+ without a `/v2` path).
 * - `/@v/<version>.info`: one release's time. The list carries no dates, so
 *   this is read for the versions being judged only (cached; a published
 *   version never changes). A pseudo-version (`v0.0.0-20240102150405-abcdef123456`)
 *   is not in the list; its `.info` both confirms it exists and dates it.
 * - The latest version's `go.mod`: its `retract` directives withdraw versions
 *   (`go get` skips them), reported like a yank.
 * - An untagged module: `@latest` gives its newest pseudo-version.
 *
 * Major versions 2+ are different module paths (`.../v5`); the proxy lists
 * each path's own versions only.
 *
 * Not applicable to Go and reported so by the signals: publisher identity
 * (integrity is checked against sum.golang.org instead), install hooks (Go
 * runs no package code at download), per-release dependency lists.
 */

import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import { fetchWithTimeout } from "./http-utils.js";
import { compareVersions } from "./version-compare.js";
import { escapeGoPath } from "./upgrade-go.js";
import type { PackageReleaseIndex, RegistryLookup, ReleaseMetadataSource, ReleaseRecord } from "./release-metadata.js";

const GO_PROXY = "https://proxy.golang.org";
const TIMEOUT_MS = 15_000;
const LIST_TTL = 3600;
const INFO_TTL = 30 * 86_400;
/** `.info` reads per getReleases call. */
const MAX_INFO_READS = 6;

export const GO_NOT_APPLICABLE =
  "not applicable to Go modules: the proxy carries no publisher identity (downloads are checked against sum.golang.org)";

/** A Go version: release, prerelease, pseudo-version, optional `+incompatible`. */
export const GO_VERSION = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$/;
const PSEUDO = /(?:^v\d+\.\d+\.\d+-|[.-])(?:0\.)?(\d{14})-[0-9a-f]{12}(?:\+incompatible)?$/;

/** `v`-prefixed spelling of a Go version ("1.2.3" -> "v1.2.3"). */
export function goVersion(raw: string): string {
  const v = raw.trim();
  return /^\d/.test(v) ? `v${v}` : v;
}

/** The commit time a pseudo-version embeds, as ISO, or null when `version` is not one. */
export function pseudoVersionTime(version: string): string | null {
  const m = PSEUDO.exec(version);
  if (!m) return null;
  const t = m[1];
  return `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}T${t.slice(8, 10)}:${t.slice(10, 12)}:${t.slice(12, 14)}Z`;
}

export interface Retraction {
  low: string;
  high: string;
  rationale: string | null;
}

/** `retract` directives of a go.mod: single versions, `[low, high]` intervals, and blocks of either. */
export function parseRetractions(goMod: string): Retraction[] {
  const out: Retraction[] = [];
  const entry = (text: string) => {
    const [body, ...comment] = text.split("//");
    const rationale = comment.join("//").trim() || null;
    const interval = /^\s*\[\s*(v\S+?)\s*,\s*(v\S+?)\s*\]\s*$/.exec(body);
    if (interval) out.push({ low: interval[1], high: interval[2], rationale });
    else {
      const single = /^\s*(v\S+)\s*$/.exec(body);
      if (single) out.push({ low: single[1], high: single[1], rationale });
    }
  };
  const lines = goMod.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*retract\s+(.*)$/.exec(lines[i]);
    if (!m) continue;
    if (m[1].trim().startsWith("(")) {
      for (i++; i < lines.length && !/^\s*\)/.test(lines[i]); i++) entry(lines[i]);
    } else {
      entry(m[1]);
    }
  }
  return out;
}

interface CachedList {
  versions: string[];
  retractions: Retraction[];
  /** Why retractions are unknown, when they are. */
  retractionsNote: string | null;
}

export class GoReleasesReader implements ReleaseMetadataSource {
  constructor(
    private cache: LiveCache,
    private rateLimiter: RateLimiter,
  ) {}

  async getReleases(module: string, wanted: string[]): Promise<RegistryLookup<PackageReleaseIndex>> {
    const list = await this.list(module);
    if (list.status !== "ok") return list;
    const { versions, retractions } = list.data;
    const releases: Record<string, ReleaseRecord> = {};
    for (const version of versions) releases[version] = record(version, null, retractions);

    // Dates (and existence, for a pseudo-version) of the versions being judged.
    const want = [...new Set(wanted.map(goVersion))].filter((v) => GO_VERSION.test(v)).slice(0, MAX_INFO_READS);
    await Promise.all(
      want.map(async (version) => {
        const info = await this.info(module, version);
        // The proxy answers `v20.10.0` with the `v20.10.0+incompatible` release: file it under its own name.
        if (info === null || (info.Version && info.Version !== version)) return;
        const time = info.Time ?? pseudoVersionTime(version);
        releases[version] = { ...(releases[version] ?? record(version, null, retractions)), publishedAt: time ?? null };
      }),
    );
    return { status: "ok", data: { ecosystem: "Go", name: module, createdAt: null, releases } };
  }

  async getCreatedAt(): Promise<RegistryLookup<string | null>> {
    return { status: "ok", data: null };
  }

  private async list(module: string): Promise<RegistryLookup<CachedList>> {
    const key = `go-releases:${module}`;
    const hit = this.cache.get<CachedList>(key);
    if (hit) return { status: "ok", data: hit };
    const base = `${GO_PROXY}/${escapeGoPath(module)}`;
    let versions: string[];
    try {
      const res = await this.get(`${base}/@v/list`);
      // The proxy answers 404 / 410 for a path it cannot resolve.
      if (res.status === 404 || res.status === 410) {
        return { status: "not_found", detail: `"${module}" is not a module the Go proxy can resolve` };
      }
      if (!res.ok) return { status: "unreachable", detail: `Go module proxy answered HTTP ${res.status}` };
      versions = (await res.text()).split("\n").map((v) => v.trim()).filter((v) => GO_VERSION.test(v));
      if (versions.length === 0) {
        // Untagged: the newest pseudo-version.
        const latest = await this.get(`${base}/@latest`);
        if (latest.ok) {
          const info = (await latest.json()) as { Version?: string; Time?: string };
          if (info.Version && GO_VERSION.test(info.Version)) {
            versions = [info.Version];
            if (info.Time) this.cache.set(`go-info:${module}@${info.Version}`, info, "go", INFO_TTL);
          }
        }
      }
    } catch (err) {
      return { status: "unreachable", detail: `Go module proxy: ${err instanceof Error ? err.message : String(err)}` };
    }

    // Retractions live in the newest version's go.mod.
    let retractions: Retraction[] = [];
    let retractionsNote: string | null = null;
    const newest = versions.reduce<string | null>((max, v) => (max === null || compareVersions(v, max, "Go") > 0 ? v : max), null);
    if (newest) {
      try {
        const res = await this.get(`${base}/@v/${escapeGoPath(newest)}.mod`);
        if (res.ok) retractions = parseRetractions(await res.text());
        else retractionsNote = `go.mod of ${newest}: HTTP ${res.status}`;
      } catch (err) {
        retractionsNote = `go.mod of ${newest}: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
    const data: CachedList = { versions, retractions, retractionsNote };
    this.cache.set(key, data, "go", LIST_TTL);
    return { status: "ok", data };
  }

  private async info(module: string, version: string): Promise<{ Version?: string; Time?: string } | null> {
    const key = `go-info:${module}@${version}`;
    const hit = this.cache.get<{ Version?: string; Time?: string }>(key);
    if (hit) return hit;
    try {
      const res = await this.get(`${GO_PROXY}/${escapeGoPath(module)}/@v/${escapeGoPath(version)}.info`);
      if (!res.ok) return null;
      const info = (await res.json()) as { Version?: string; Time?: string };
      this.cache.set(key, info, "go", INFO_TTL);
      return info;
    } catch {
      return null;
    }
  }

  private async get(url: string): Promise<Response> {
    if (!this.rateLimiter.consume("go")) throw new Error("Go module proxy rate limit reached for this minute");
    return fetchWithTimeout(url, {}, TIMEOUT_MS);
  }
}

function record(version: string, publishedAt: string | null, retractions: Retraction[]): ReleaseRecord {
  const hit = retractions.find((r) => compareVersions(version, r.low, "Go") >= 0 && compareVersions(version, r.high, "Go") <= 0);
  return {
    version,
    publishedAt,
    trust: 0,
    trustEvidence: GO_NOT_APPLICABLE,
    installScripts: null,
    deprecated: hit?.rationale ? `retracted: ${hit.rationale}` : null,
    withdrawn: hit ? "retracted" : null,
    dependencies: null,
  };
}
