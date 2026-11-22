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
 * - A judged release's own `go.mod`: its `require` lines, the minimum versions a
 *   project that takes the release gets (getRequirements).
 *
 * Not applicable to Go and reported so by the signals: publisher identity
 * (integrity is checked against sum.golang.org instead), install hooks (Go
 * runs no package code at download), which dependencies a release adds.
 */

import { withinCallBudget } from "../call-budget.js";
import { sanitizeThirdParty } from "../untrusted-text.js";
import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import { fetchWithTimeout } from "./http-utils.js";
import { compareVersions } from "./version-compare.js";
import { escapeGoPath } from "./upgrade-go.js";
import type { PackageReleaseIndex, RegistryLookup, ReleaseMetadataSource, ReleaseRecord, ReleaseRequirement, ReleaseRequirements } from "./release-metadata.js";

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

/** The lines of a go.mod, whatever its line endings (LF, CRLF or bare CR): no line keeps a carriage return. */
export function goModLines(goMod: string): string[] {
  return goMod.split(/\r\n|\r|\n/);
}

/** `retract` directives of a go.mod: single versions, `[low, high]` intervals, and blocks of either. */
export function parseRetractions(goMod: string): Retraction[] {
  const out: Retraction[] = [];
  const entry = (text: string) => {
    const [body, ...comment] = text.split("//");
    const rationale = sanitizeThirdParty(comment.join("//")) || null;
    const interval = /^\s*\[\s*(v\S+?)\s*,\s*(v\S+?)\s*\]\s*$/.exec(body);
    if (interval) out.push({ low: interval[1], high: interval[2], rationale });
    else {
      const single = /^\s*(v\S+)\s*$/.exec(body);
      if (single) out.push({ low: single[1], high: single[1], rationale });
    }
  };
  const lines = goModLines(goMod);
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

/** A module path as go.mod writes one: path elements of letters, digits and `. _ ~ -`, the first with a dot (a host). */
const GO_MODULE_PATH = /^[A-Za-z0-9][A-Za-z0-9._~-]*\.[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*$/;
const GO_MODULE_PATH_MAX = 255;

/**
 * The `require` lines of a go.mod, single and in blocks: each module at the minimum version the
 * release needs (minimal version selection gives a project that takes the release at least these).
 * `replace` and `exclude` are left out: the go command applies them from the main module only. A
 * line whose path or version is not one is counted `unreadable`, never passed on.
 */
export function parseGoRequires(goMod: string): ReleaseRequirements {
  const out = new Map<string, ReleaseRequirement>();
  let unreadable = 0;
  const entry = (text: string) => {
    const [body, ...comment] = text.split("//");
    const parts = body.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return;
    const path = (parts[0] ?? "").replace(/^"(.*)"$/, "$1");
    const version = parts[1] ?? "";
    if (parts.length !== 2 || path.length > GO_MODULE_PATH_MAX || !GO_MODULE_PATH.test(path) || !GO_VERSION.test(version)) {
      unreadable++;
      return;
    }
    const indirect = /^\s*indirect\b/.test(comment.join("//"));
    const seen = out.get(path);
    // One module listed twice: the higher minimum is what selection uses.
    if (!seen || compareVersions(version, seen.spec, "Go") > 0) out.set(path, { name: path, spec: version, ...(indirect ? { indirect: true as const } : {}) });
  };
  const lines = goModLines(goMod);
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*require\b\s*(.*)$/.exec(lines[i]);
    if (!m) continue;
    if (m[1].trim().startsWith("(")) {
      for (i++; i < lines.length && !/^\s*\)/.test(lines[i]); i++) entry(lines[i]);
    } else {
      entry(m[1]);
    }
  }
  return { requirements: [...out.values()], unreadable };
}

/** A module's version list with its retractions, as cached: only a list whose retractions were read. */
interface CachedList {
  versions: string[];
  retractions: Retraction[];
  /** Set on a row that says its retractions were not read: such a row is never an answer. */
  retractionsNote?: string | null;
}

/** How this server's own request limit is named in an answer. */
export const GO_PROXY_NAME = "the Go proxy";
/** The most Go proxy reads one dependency_check item makes (version list, newest go.mod, `.info` of `to` and `from`). */
export const GO_READS_PER_ITEM = 4;
/** The longest one Go proxy read waits in line for this server's own request limit. */
export const GO_QUEUE_MAX_WAIT_MS = 10_000;
/** Kept back from a call's budget when a read waits in line: the item's later reads, its OSV.dev query and the answer. */
const GO_QUEUE_RESERVE_MS = 5_000;

/** A read this server's own request limit did not let through in time: never sent, never the proxy's answer. */
class OwnLimitReached extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super(`this server's own request limit for ${GO_PROXY_NAME} was reached, so the read was not sent (it can be made in ${retryAfterSeconds} s)`);
  }
}

/** A read that failed, as the lookup it makes. */
type Unreachable = Extract<RegistryLookup<never>, { status: "unreachable" }>;

/** One `.info` read: the proxy's answer, a version it does not serve, or a read that failed (with why). */
type InfoRead = { info: { Version?: string; Time?: string } } | { missing: true } | { failed: Unreachable };

export class GoReleasesReader implements ReleaseMetadataSource {
  /** Version-list reads in flight, by module: concurrent items of one module share one read. */
  private listing = new Map<string, Promise<RegistryLookup<CachedList>>>();

  constructor(
    private cache: LiveCache,
    private rateLimiter: RateLimiter,
  ) {}

  /**
   * The release index, retractions applied, with the dates of the versions being judged. Unreachable
   * when the list, the retractions or a judged version's date could not be read: no release is
   * judged on a partial index, and the reason names what was missing (and this server's own request
   * limit, when that is why).
   */
  async getReleases(module: string, wanted: string[]): Promise<RegistryLookup<PackageReleaseIndex>> {
    const list = await this.list(module);
    if (list.status !== "ok") return list;
    const { versions, retractions } = list.data;
    const releases: Record<string, ReleaseRecord> = {};
    for (const version of versions) releases[version] = record(version, null, retractions);

    // Dates (and existence, for a pseudo-version) of the versions being judged.
    const want = [...new Set(wanted.map(goVersion))].filter((v) => GO_VERSION.test(v)).slice(0, MAX_INFO_READS);
    const reads = await Promise.all(want.map(async (version) => ({ version, read: await this.info(module, version) })));
    const failed = reads.find((r) => "failed" in r.read);
    if (failed && "failed" in failed.read) return failed.read.failed;
    for (const { version, read } of reads) {
      if (!("info" in read)) continue;
      const { info } = read;
      // The proxy answers `v20.10.0` with the `v20.10.0+incompatible` release: file it under its own name.
      if (info.Version && info.Version !== version) continue;
      const time = info.Time ?? pseudoVersionTime(version);
      releases[version] = { ...(releases[version] ?? record(version, null, retractions)), publishedAt: time ?? null };
    }
    return { status: "ok", data: { ecosystem: "Go", name: module, createdAt: null, releases } };
  }

  async getCreatedAt(): Promise<RegistryLookup<string | null>> {
    return { status: "ok", data: null };
  }

  /**
   * What one release's own go.mod requires (`/@v/<version>.mod`, the file `go get` reads). A
   * published version's go.mod never changes, so it is kept as long as its `.info`.
   */
  async getRequirements(module: string, version: string): Promise<RegistryLookup<ReleaseRequirements>> {
    const v = goVersion(version);
    if (!GO_VERSION.test(v)) return { status: "not_found", detail: `"${version.slice(0, 40)}" is not a Go version` };
    const key = requiresKey(module, v);
    const hit = this.cache.get<ReleaseRequirements>(key);
    if (hit) return { status: "ok", data: hit };
    try {
      // The registry-CDN bucket (as fix-path lookups): a requirement read never starves the version lists.
      const res = await this.get(`${GO_PROXY}/${escapeGoPath(module)}/@v/${escapeGoPath(v)}.mod`, "fixpath-registry");
      if (res.status === 404 || res.status === 410) return { status: "not_found", detail: `the Go proxy has no go.mod for ${v}` };
      if (!res.ok) return { status: "unreachable", detail: `Go module proxy answered HTTP ${res.status}` };
      const data = parseGoRequires(await res.text());
      this.cache.set(key, data, "go", INFO_TTL);
      return { status: "ok", data };
    } catch (err) {
      return failure(err);
    }
  }

  private async list(module: string): Promise<RegistryLookup<CachedList>> {
    const hit = this.cache.get<CachedList>(listKey(module));
    if (hit && !hit.retractionsNote) return { status: "ok", data: hit };
    const running = this.listing.get(module);
    if (running) return running;
    const read = this.readList(module).finally(() => this.listing.delete(module));
    this.listing.set(module, read);
    return read;
  }

  /**
   * The version list and the retractions in the newest version's go.mod, cached only when both were
   * read (an empty retraction list is a read one). Anything less is unreachable and cached nowhere:
   * a list without its retractions would judge a retracted release as published and clean.
   */
  private async readList(module: string): Promise<RegistryLookup<CachedList>> {
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
        } else if (latest.status !== 404 && latest.status !== 410) {
          return { status: "unreachable", detail: `Go module proxy answered HTTP ${latest.status} for the newest pseudo-version` };
        }
      }
    } catch (err) {
      return failure(err);
    }

    // Retractions live in the newest version's go.mod.
    let retractions: Retraction[] = [];
    const newest = versions.reduce<string | null>((max, v) => (max === null || compareVersions(v, max, "Go") > 0 ? v : max), null);
    if (newest) {
      const where = `the go.mod of ${newest}`;
      try {
        const res = await this.get(`${base}/@v/${escapeGoPath(newest)}.mod`);
        if (!res.ok) return { status: "unreachable", detail: `Go module proxy answered HTTP ${res.status} for ${where}`, withdrawalsUnread: where };
        const goMod = await res.text();
        retractions = parseRetractions(goMod);
        // The same file is what the newest release requires (getRequirements).
        this.cache.set(requiresKey(module, newest), parseGoRequires(goMod), "go", INFO_TTL);
      } catch (err) {
        return { ...failure(err, where), withdrawalsUnread: where };
      }
    }
    const data: CachedList = { versions, retractions };
    this.cache.set(listKey(module), data, "go", LIST_TTL);
    return { status: "ok", data };
  }

  private async info(module: string, version: string): Promise<InfoRead> {
    const key = `go-info:${module}@${version}`;
    const hit = this.cache.get<{ Version?: string; Time?: string }>(key);
    if (hit) return { info: hit };
    try {
      const res = await this.get(`${GO_PROXY}/${escapeGoPath(module)}/@v/${escapeGoPath(version)}.info`);
      // Not served: the version does not exist (a pseudo-version) or carries no date.
      if (res.status === 404 || res.status === 410) return { missing: true };
      if (!res.ok) return { failed: { status: "unreachable", detail: `Go module proxy answered HTTP ${res.status} for the .info of ${version}` } };
      const info = (await res.json()) as { Version?: string; Time?: string };
      this.cache.set(key, info, "go", INFO_TTL);
      return { info };
    } catch (err) {
      return { failed: failure(err, `the .info of ${version}`) };
    }
  }

  /**
   * One proxy request. It waits in line for this server's own request limit as long as the running
   * call can afford (never past GO_QUEUE_MAX_WAIT_MS), and is refused with OwnLimitReached when no
   * token would come in time: the request is then never sent.
   */
  private async get(url: string, bucket: "go" | "fixpath-registry" = "go"): Promise<Response> {
    const deadline = this.rateLimiter.now() + withinCallBudget(GO_QUEUE_MAX_WAIT_MS, GO_QUEUE_RESERVE_MS);
    if (!(await this.rateLimiter.acquire(bucket, deadline))) throw new OwnLimitReached(this.rateLimiter.retryAfterSeconds(bucket));
    return fetchWithTimeout(url, {}, TIMEOUT_MS);
  }
}

const listKey = (module: string) => `go-releases:${module}`;
const requiresKey = (module: string, version: string) => `go-mod-requires:v1:${module}@${version}`;

/** A failed proxy read as a lookup: this server's own limit named as such, anything else as the proxy's failure. */
function failure(err: unknown, what?: string): Unreachable {
  if (err instanceof OwnLimitReached) {
    return {
      status: "unreachable",
      detail: what ? `${what} was not read: ${err.message}` : err.message,
      ownLimit: { registry: GO_PROXY_NAME, retryAfterSeconds: err.retryAfterSeconds },
    };
  }
  const message = err instanceof Error ? err.message : String(err);
  return { status: "unreachable", detail: what ? `Go module proxy: ${what}: ${message}` : `Go module proxy: ${message}` };
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
