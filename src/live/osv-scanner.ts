// SPDX-License-Identifier: Apache-2.0
/**
 * OSV.dev Vulnerability Scanner
 *
 * Batch-queries the Open Source Vulnerability database for known CVEs
 * affecting the user's exact dependency versions. Free, no auth required.
 *
 * Privacy: sends only package names + versions (public manifest data).
 */

import { ADVISORY_SUMMARY_MAX, isOsvAdvisoryId, osvAdvisoryId, quoteThirdParty, thirdPartyId, thirdPartyTimestamp, thirdPartyUrl } from "../untrusted-text.js";
import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import { fetchWithTimeout } from "./http-utils.js";
import { isConcreteVersion } from "./release-version.js";
import { cvssBaseScore } from "./cvss.js";
import { cvss4Score } from "./cvss4.js";
import { compareToLowerBound, compareVersions, isComparable, maxVersion } from "./version-compare.js";
import { collectAffectedSpans } from "./osv-ranges.js";
import { isMaintenanceNotice, isMaintenanceRecord } from "./maintenance.js";
import { gradeAliasGroups } from "./advisory-groups.js";
import { isMalwareRecord } from "./malware.js";
import type {
  AliasSeverityReport,
  ResolvedDependency,
  OsvVulnerability,
  VulnerabilityEntry,
  VulnerabilityScanResult,
} from "./types.js";
import { pushAll } from "../array-utils.js";
import { isOfflineMode } from "../env-flags.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";
const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const OSV_TIMEOUT_MS = 15_000;
/**
 * One `/v1/vulns/{id}` request (a single small record): a hung one held a whole dependency_check
 * past its 20 s call budget at OSV_TIMEOUT_MS x 2 attempts (r7). Two attempts now fit in ~9 s.
 */
const OSV_DETAIL_TIMEOUT_MS = 4_000;
const OSV_CACHE_TTL = 3600; // 1 hour
const OSV_DETAIL_TTL = 86_400; // 24 hours — advisory details change rarely
const MAX_BATCH_SIZE = 1000;
/**
 * Advisory details have no batch endpoint: one GET /v1/vulns/{id} each. They
 * were fetched in rounds of 8, each round waiting for its slowest request, so
 * a project with 900 distinct advisories (superset) made ~113 sequential
 * round trips. Now a pool of HYDRATE_CONCURRENCY workers keeps that many
 * requests in flight (osv-scanner itself hydrates in parallel), a failed or
 * throttled request is retried once, and every result is cached for 24 h.
 */
const HYDRATE_CONCURRENCY = 24;
/** querybatch chunks (1,000 dependencies each) sent at once. */
const BATCH_CONCURRENCY = 4;
/** A query of at most this many dependencies waits COALESCE_MS for others to share its request (OsvHttpSource.query). */
const COALESCE_MAX_DEPS = 50;
const COALESCE_MS = 20;
const DETAIL_RETRY_DELAY_MS = 750;
/** GHSA alias records read per scan to rate records that carry no severity (rateFromAliases). */
export const MAX_ALIAS_LOOKUPS = 50;
/** The whole alias lookup's time budget per scan; past it the records stay unknown, said so. */
export const ALIAS_BUDGET_MS = 5_000;

/**
 * Detail fetches in flight, shared by every scanner in the process. The
 * startup warm-up scan and the first tool call's scan used to run side by
 * side and fetch the same advisories twice, both before either could cache
 * them; a concurrent scan now waits on the request already made.
 */
const detailsInFlight = new Map<string, Promise<OsvVulnerability | null>>();

/** Run `work` over `items` with at most `limit` in flight; results in input order. */
async function pool<T, R>(items: T[], limit: number, work: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await work(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

interface OsvBatchQuery {
  package: { name: string; ecosystem: string };
  version?: string;
  /** Asks for the next page of this query's answer (the `next_page_token` of its previous one). */
  page_token?: string;
}

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVulnerability[]; next_page_token?: string }>;
}

/**
 * Pages read for one querybatch request before the queries still open are
 * left unanswered. OSV pages a long answer (`next_page_token`); the token was
 * ignored, so a dependency with more advisories than one page holds was
 * recorded with the first page only (audit 2026-11-11).
 */
const MAX_RESULT_PAGES = 20;

/** Per-dependency advisory ids, null where there is no answer, and why. */
export interface AdvisoryAnswer {
  ids: Array<string[] | null>;
  failure: string | null;
}

/** How long a scan may wait, in total, for query-budget tokens before the rest of its batches go unanswered. */
const MAX_TOKEN_WAIT_MS = 60_000;
/** A failed querybatch request (network, timeout, 429, 5xx) is retried once after this. */
const BATCH_RETRY_DELAY_MS = 1_000;

/** Why one querybatch request failed, in words a reader can act on. */
function describeFailure(error: unknown): string {
  if (error instanceof OsvHttpError) return `OSV.dev returned HTTP ${error.status}`;
  const name = (error as { name?: string } | null)?.name;
  if (name === "TimeoutError" || name === "AbortError") return `OSV.dev did not answer within ${OSV_TIMEOUT_MS / 1000} s on either of 2 attempts`;
  const message = error instanceof Error ? error.message : String(error);
  return `OSV.dev unreachable (${message.slice(0, 120)})`;
}

class OsvHttpError extends Error {
  constructor(readonly status: number) {
    super(`OSV API error: ${status}`);
  }
}

/**
 * Where advisories come from. The scanner asks which advisory ids affect each
 * exact (ecosystem, name, version), then for the records behind those ids.
 *
 * - OsvHttpSource (the server's): OSV.dev's own evaluator decides membership
 *   (`/v1/querybatch`), records come from `/v1/vulns/{id}`, both cached.
 * - PinnedRecordsSource (pinned-advisories.ts): a fixed set of records on
 *   disk, membership decided locally by osv-ranges.ts. No network. The
 *   conformance harness scores the engine with it against the 4DA corpus.
 */
export interface AdvisorySource {
  /** True when answers come over the network: rate-limited, and cached per dependency. */
  readonly network: boolean;
  /**
   * The advisory ids affecting each dependency, in input order. An entry is
   * null when the source has NO answer for that dependency (unreachable,
   * failed, timed out, out of query budget): never an empty list, which means
   * "checked, nothing found". `failure` says why when any entry is null.
   */
  query(deps: ResolvedDependency[]): Promise<AdvisoryAnswer>;
  /** The full record of each id it can find; a missing id is left out, never fatal. */
  details(ids: string[]): Promise<Map<string, OsvVulnerability>>;
  /**
   * The full records affecting one exact dependency (OSV.dev's `/v1/query` with a version), or
   * null when they cannot be had. Asked only for a dependency whose record fetch failed: the
   * same records carry the severity, the summary and the fix (pre-publish audit 2026-11-14).
   */
  recordsFor?(dep: ResolvedDependency): Promise<OsvVulnerability[] | null>;
}

/** OSV.dev over HTTP: querybatch for membership, per-id hydration for records. */
export class OsvHttpSource implements AdvisorySource {
  readonly network = true;

  constructor(
    private readonly cache: LiveCache,
    private readonly rateLimiter: RateLimiter,
    /** Total wait for query budget per scan (tests shorten it). */
    private readonly tokenWaitMs: number = MAX_TOKEN_WAIT_MS,
  ) {}

  /** Small queries waiting to go out together (coalesce). */
  private waiting: Array<{ deps: ResolvedDependency[]; resolve: (answer: AdvisoryAnswer) => void }> = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * A small query (fix-target and verdict confirmations ask about one or two releases each) waits
   * COALESCE_MS for others and goes out with them in one querybatch request. Sent one by one, a
   * cold scan's ~120 confirmations used the 60-a-minute query budget up, waited a second each for
   * tokens, ran out of time, and were asked again by the next scan (blind audit round 6). A
   * dependency asked about by several callers is asked once. A large query (a scan) goes out as is.
   */
  async query(deps: ResolvedDependency[]): Promise<AdvisoryAnswer> {
    if (deps.length === 0 || deps.length > COALESCE_MAX_DEPS) return this.queryNow(deps);
    return new Promise<AdvisoryAnswer>((resolve) => {
      this.waiting.push({ deps, resolve });
      this.flushTimer ??= setTimeout(() => void this.flush(), COALESCE_MS);
    });
  }

  private async flush(): Promise<void> {
    const group = this.waiting;
    this.waiting = [];
    this.flushTimer = null;
    const keyOf = (d: ResolvedDependency) => `${d.ecosystem}\0${d.name}\0${d.version ?? ""}`;
    const unique = new Map<string, ResolvedDependency>();
    for (const g of group) for (const d of g.deps) if (!unique.has(keyOf(d))) unique.set(keyOf(d), d);
    const all = [...unique.values()];
    let answer: AdvisoryAnswer;
    try {
      answer = await this.queryNow(all);
    } catch (error) {
      answer = { ids: all.map(() => null), failure: describeFailure(error) };
    }
    const idsOf = new Map(all.map((d, i) => [keyOf(d), answer.ids[i] ?? null]));
    for (const g of group) {
      const ids = g.deps.map((d) => idsOf.get(keyOf(d)) ?? null);
      g.resolve({ ids, failure: ids.some((x) => !Array.isArray(x)) ? (answer.failure ?? "OSV.dev gave no answer") : null });
    }
  }

  private async queryNow(deps: ResolvedDependency[]): Promise<AdvisoryAnswer> {
    // querybatch returns only `{ id, modified }`; the rich fields (severity,
    // fixed version, summary, references) come from per-advisory hydration.
    const chunks: ResolvedDependency[][] = [];
    for (let offset = 0; offset < deps.length; offset += MAX_BATCH_SIZE) chunks.push(deps.slice(offset, offset + MAX_BATCH_SIZE));
    // Batches go out as query budget allows, waiting for it to refill (bounded),
    // instead of the whole scan failing when a tree needs more batches than the
    // bucket holds. A batch that gets no budget, or fails twice, is unanswered:
    // its dependencies come back null, and the scan reports them as unchecked.
    const deadline = Date.now() + this.tokenWaitMs;
    let failure: string | null = null;
    // A batch that failed twice means OSV.dev is down or refusing: batches not
    // yet sent are not tried (an outage would otherwise cost a timeout each).
    let outage = false;
    const answered = await pool(chunks, BATCH_CONCURRENCY, async (chunk): Promise<Array<string[] | null>> => {
      if (outage) return chunk.map(() => null);
      if (!(await this.rateLimiter.acquire("osv", deadline))) {
        failure ??= `the OSV.dev query budget (${MAX_BATCH_SIZE.toLocaleString("en-US")} dependencies per request) ran out for ${Math.round(this.tokenWaitMs / 1000)} s`;
        return chunk.map(() => null);
      }
      try {
        const sent = await this.sendBatch(chunk, deadline);
        if (sent.incomplete) failure ??= sent.incomplete;
        return sent.ids;
      } catch (error) {
        failure = describeFailure(error);
        outage = true;
        return chunk.map(() => null);
      }
    });
    return { ids: answered.flat(), failure };
  }

  /**
   * The advisory ids for one chunk, every page of them. A query whose answer
   * OSV cut short carries a `next_page_token`; it is asked again with that
   * token until none comes back. A query whose later pages cannot be had (the
   * request fails, the budget runs out, MAX_RESULT_PAGES pages were not
   * enough) is unanswered, null: a first page alone is not the answer.
   */
  private async sendBatch(chunk: ResolvedDependency[], deadline: number): Promise<{ ids: Array<string[] | null>; incomplete: string | null }> {
    const queries: OsvBatchQuery[] = chunk.map((d) => ({
      package: { name: d.name, ecosystem: d.ecosystem },
      ...(d.version ? { version: d.version } : {}),
    }));
    const first = await this.postBatch(queries);
    // Every id is held to OSV's id shape where it enters (blind audit round 5): untrusted-text.ts osvAdvisoryId.
    const ids: Array<string[] | null> = first.map((r) => [...new Set((r.vulns ?? []).map((v) => osvAdvisoryId(v?.id)))]);
    let open = first.flatMap((r, index) => (r.next_page_token ? [{ index, token: r.next_page_token }] : []));
    let incomplete: string | null = null;
    for (let page = 2; open.length > 0; page++) {
      const abandon = (why: string) => {
        for (const { index } of open) ids[index] = null;
        incomplete = why;
        open = [];
      };
      if (page > MAX_RESULT_PAGES) {
        abandon(`OSV.dev's answer ran past ${MAX_RESULT_PAGES} pages`);
        break;
      }
      if (!(await this.rateLimiter.acquire("osv", deadline))) {
        abandon("the OSV.dev query budget ran out before every page of the answer was read");
        break;
      }
      let more: OsvBatchResponse["results"];
      try {
        more = await this.postBatch(open.map(({ index, token }) => ({ ...queries[index], page_token: token })));
      } catch (error) {
        abandon(`${describeFailure(error)} while reading page ${page} of the answer`);
        break;
      }
      const next: typeof open = [];
      more.forEach((r, k) => {
        const { index } = open[k];
        const seen = new Set(ids[index] ?? []);
        for (const v of r.vulns ?? []) seen.add(osvAdvisoryId(v?.id));
        ids[index] = [...seen];
        if (r.next_page_token) next.push({ index, token: r.next_page_token });
      });
      open = next;
    }
    return { ids, incomplete };
  }

  /** One querybatch request, retried once after a throttle, a server error, a timeout or a network failure. */
  private async postBatch(queries: OsvBatchQuery[]): Promise<OsvBatchResponse["results"]> {
    let lastError: unknown = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, BATCH_RETRY_DELAY_MS));
      try {
        const response = await fetchWithTimeout(OSV_BATCH_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ queries }),
        }, OSV_TIMEOUT_MS);
        if (!response.ok) {
          lastError = new OsvHttpError(response.status);
          // A client error other than a throttle will not change on a retry.
          if (response.status !== 429 && response.status < 500) break;
          continue;
        }
        const data = (await response.json()) as OsvBatchResponse;
        if (!Array.isArray(data?.results) || data.results.length !== queries.length) {
          throw new Error(`OSV.dev answered ${Array.isArray(data?.results) ? data.results.length : "no"} results for ${queries.length} queries`);
        }
        // `{}` is OSV's own "nothing found"; null, a string or a non-array `vulns` is not an answer
        // and was read as clean, then cached for an hour (audit 6.2.5 B-4). A page token that is
        // not a string cannot be followed, so the answer it belongs to is not one either.
        if (
          data.results.some(
            (r) =>
              r === null ||
              typeof r !== "object" ||
              ("vulns" in r && !Array.isArray(r.vulns)) ||
              (r.next_page_token !== undefined && r.next_page_token !== null && typeof r.next_page_token !== "string"),
          )
        ) {
          throw new Error("OSV.dev answered a malformed result");
        }
        return data.results;
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError ?? new Error("OSV.dev querybatch failed");
  }

  /**
   * Hydrate advisory detail for the given IDs. Cache-first (24h), then fetch the
   * misses from `/v1/vulns/{id}` with bounded concurrency. A failed fetch is
   * skipped (not fatal) — the caller falls back to the index-only shape so a
   * real advisory is never silently dropped just because its detail 404'd.
   */
  async details(ids: string[]): Promise<Map<string, OsvVulnerability>> {
    const out = new Map<string, OsvVulnerability>();
    const toFetch: string[] = [];

    for (const id of ids) {
      const cached = this.cache.get<OsvVulnerability>(`osv:detail:${id}`);
      if (cached) out.set(id, cached);
      else toFetch.push(id);
    }

    const fetched: Array<[string, OsvVulnerability]> = [];
    await pool(toFetch, HYDRATE_CONCURRENCY, async (id) => {
      let pending = detailsInFlight.get(id);
      if (!pending) {
        pending = this.fetchDetail(id).finally(() => detailsInFlight.delete(id));
        detailsInFlight.set(id, pending);
      }
      const detail = await pending;
      if (detail) {
        out.set(id, detail);
        fetched.push([`osv:detail:${id}`, detail]);
      }
    });
    this.cache.setMany(fetched, "osv", OSV_DETAIL_TTL);

    return out;
  }

  /**
   * The records affecting one exact dependency, from `/v1/query` with its version: the second route
   * to a record whose `/v1/vulns/{id}` fetch failed. Every page or null; ids held to OSV's shape.
   */
  async recordsFor(dep: ResolvedDependency): Promise<OsvVulnerability[] | null> {
    if (!isConcreteVersion(dep.version) || !this.rateLimiter.consume("osv-package")) return null;
    const out: OsvVulnerability[] = [];
    let token: string | undefined;
    try {
      for (let page = 0; page < MAX_RESULT_PAGES; page++) {
        const res = await fetchWithTimeout(
          OSV_QUERY_URL,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ package: { name: dep.name, ecosystem: dep.ecosystem }, version: dep.version, ...(token ? { page_token: token } : {}) }),
          },
          OSV_TIMEOUT_MS,
        );
        if (!res.ok) return null;
        const body = (await res.json()) as { vulns?: unknown; next_page_token?: unknown } | null;
        if (!body || typeof body !== "object" || (body.vulns !== undefined && !Array.isArray(body.vulns))) return null;
        for (const raw of (body.vulns ?? []) as Array<Partial<OsvVulnerability> | null>) {
          if (!raw || typeof raw !== "object") continue;
          const id = osvAdvisoryId(raw.id);
          if (!isOsvAdvisoryId(id)) continue;
          out.push({ ...raw, id, aliases: (Array.isArray(raw.aliases) ? raw.aliases : []).map(osvAdvisoryId).filter(isOsvAdvisoryId) } as OsvVulnerability);
        }
        token = typeof body.next_page_token === "string" && body.next_page_token ? body.next_page_token : undefined;
        if (!token) return out;
      }
      return null; // more pages than the cap: not the whole answer
    } catch {
      return null;
    }
  }

  /** One advisory's record; retried once after a throttle, a server error or a network failure. Null when it cannot be had. */
  private async fetchDetail(id: string): Promise<OsvVulnerability | null> {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await fetchWithTimeout(`${OSV_VULN_URL}${encodeURIComponent(id)}`, {}, OSV_DETAIL_TIMEOUT_MS);
        if (response.ok) {
          // Only the record asked for is an answer: a 200 `{}` (or any other record) crashed the
          // scan downstream and was cached for 24 h (audit 6.2.5 B-8). Anything else is retried.
          const record = (await response.json()) as OsvVulnerability | null;
          if (record && typeof record === "object" && record.id === id) return record;
          throw new Error(`OSV.dev answered a malformed record for ${id}`);
        }
        // 404 and other client errors are answers, not failures to retry.
        if (response.status !== 429 && response.status < 500) return null;
      } catch {
        // network failure or timeout: retry once
      }
      if (attempt === 0) await new Promise((resolve) => setTimeout(resolve, DETAIL_RETRY_DELAY_MS));
    }
    return null;
  }
}

/**
 * One dependency's cached OSV answer. v5 (blind audit round 4): answers cached before carried
 * line breaks in aliases/references and the old malware reading; an upgrade never reads them.
 */
function osvCacheKey(dep: Pick<ResolvedDependency, "ecosystem" | "name" | "version">): string {
  return `osv:v9:${dep.ecosystem}:${dep.name}:${dep.version}`;
}

/** Dependencies per cache read before the scan yields to the event loop (so the server keeps answering ping). */
const CACHE_READ_BATCH = 2_000;

/** `read` over the dependencies' cache keys, CACHE_READ_BATCH at a time, yielding to the event loop between batches. */
async function readInBatches<V>(deps: readonly ResolvedDependency[], read: (keys: string[]) => Map<string, V>): Promise<Map<string, V>> {
  const out = new Map<string, V>();
  for (let at = 0; at < deps.length; at += CACHE_READ_BATCH) {
    if (at > 0) await new Promise((resolve) => setImmediate(resolve));
    for (const [key, value] of read(deps.slice(at, at + CACHE_READ_BATCH).map(osvCacheKey))) out.set(key, value);
  }
  return out;
}

/** Per cache: a scanner waits only for lookups that fill the cache it reads. */
const IN_FLIGHT = new WeakMap<LiveCache, Map<string, Promise<unknown>>>();

export class OsvScanner {
  private cache: LiveCache;
  private rateLimiter: RateLimiter;
  private source: AdvisorySource;
  /** Dependencies being asked about now, by cache key, by any scanner on this cache: settled when that lookup has written it. */
  private get inFlight(): Map<string, Promise<unknown>> {
    let map = IN_FLIGHT.get(this.cache);
    if (!map) IN_FLIGHT.set(this.cache, (map = new Map()));
    return map;
  }
  private aliasBudgetMs: number;

  constructor(cache: LiveCache, rateLimiter: RateLimiter, source?: AdvisorySource, options: { aliasBudgetMs?: number } = {}) {
    this.aliasBudgetMs = options.aliasBudgetMs ?? ALIAS_BUDGET_MS;
    this.cache = cache;
    this.rateLimiter = rateLimiter;
    this.source = source ?? new OsvHttpSource(cache, rateLimiter);
  }

  /** Drop the cached answers (fresh and expired) for these releases: the next scan asks OSV.dev again. */
  forget(deps: ReadonlyArray<Pick<ResolvedDependency, "ecosystem" | "name" | "version">>): void {
    const keys = [...new Set(deps.filter((d) => d.version !== null).map((d) => osvCacheKey(d)))];
    if (keys.length > 0) this.cache.deleteMany(keys);
  }

  async scan(deps: ResolvedDependency[], projectPath: string): Promise<VulnerabilityScanResult> {
    const start = Date.now();
    const scannable = deps.filter((d) => d.version !== null);
    const ecosystems = [...new Set(scannable.map((d) => d.ecosystem))];
    // Per-dependency caching and the rate limit are for network answers; a
    // pinned source answers locally and must never seed the shared cache.
    const network = this.source.network;

    // Check cache for each dep individually
    const uncached: ResolvedDependency[] = [];
    const cachedVulns: VulnerabilityEntry[] = [];

    // Read in batches, yielding to the event loop between them: one statement per dependency kept a
    // 250,000-entry lockfile's scan from answering `ping` for 7.4 s (blind audit round 4).
    const cachedFor = network ? await readInBatches(scannable, (keys) => this.cache.getMany<VulnerabilityEntry[]>(keys)) : new Map<string, VulnerabilityEntry[]>();
    for (const dep of scannable) {
      const cached = cachedFor.get(osvCacheKey(dep)) ?? null;
      if (cached !== null) {
        pushAll(cachedVulns, cached.map((v) => restampDepContext(v, dep)));
      } else {
        uncached.push(dep);
      }
    }

    // Fetch uncached from OSV. Dependencies it has no answer for fall back to
    // an expired cached answer; with none they are UNCHECKED, counted and
    // reported, and never counted clean.
    const fetchedVulns: VulnerabilityEntry[] = [];
    const unanswered: ResolvedDependency[] = [];
    let failure: string | null = null;

    // A dependency another scan in this process is asking OSV about right now is waited for and read
    // from the cache that scan fills, not asked again: a cold vulnerability_scan's fix-target and
    // verdict checks asked about the same release up to six times at once (blind audit round 6).
    // One that scan got no cacheable answer for is asked here, as before. Waiting never holds this
    // scan's own registrations, so two scans waiting on each other cannot deadlock.
    // A version that is not a release number ("latest" for a package the registry does not have, a
    // tag, a range, "") is never sent to OSV.dev: its dependency is NOT CHECKED (release-version.ts; r7).
    const notRelease = uncached.filter((d) => !isConcreteVersion(d.version));
    let notReleaseWhy: string | null = null;
    if (notRelease.length > 0) {
      pushAll(unanswered, notRelease);
      notReleaseWhy = `"${notRelease[0].version ?? ""}" is not a release number OSV.dev can be asked about, so it was not sent`;
      const releases = uncached.filter((d) => isConcreteVersion(d.version));
      uncached.length = 0;
      pushAll(uncached, releases);
    }
    const theirs = network ? uncached.filter((d) => this.inFlight.has(osvCacheKey(d))) : [];
    const mine = theirs.length > 0 ? uncached.filter((d) => !this.inFlight.has(osvCacheKey(d))) : uncached;
    const ask = async (batch: ResolvedDependency[]) => {
      try {
        return await this.batchQuery(batch);
      } catch (error) {
        // The source layer turns network failures into `outcome.failure`; an
        // exception here is a fault in this server, not an OSV outage, and
        // telling the agent to retry would not help (audit 6.2.5 D-2).
        const detail = error instanceof Error ? error.message.slice(0, 120) : String(error).slice(0, 120);
        return {
          vulns: [] as VulnerabilityEntry[],
          unanswered: batch,
          failure: `an internal error in this server stopped the vulnerability lookup (${detail}); retrying will not help, please report it at https://github.com/4DA-Systems/4da-mcp-server/issues`,
        };
      }
    };
    const own = mine.length === 0 ? null : network ? this.registered(mine, () => ask(mine)) : ask(mine);
    const waited = (async () => {
      if (theirs.length === 0) return [] as ResolvedDependency[];
      await Promise.all([...new Set(theirs.map((d) => this.inFlight.get(osvCacheKey(d))))].map((p) => p?.catch(() => undefined)));
      const filled = this.cache.getMany<VulnerabilityEntry[]>([...new Set(theirs.map(osvCacheKey))]);
      const still: ResolvedDependency[] = [];
      for (const dep of theirs) {
        const hit = filled.get(osvCacheKey(dep));
        if (hit) pushAll(cachedVulns, hit.map((v) => restampDepContext(v, dep)));
        else still.push(dep);
      }
      return still;
    })();
    const [first, still] = await Promise.all([own, waited]);
    const again = still.length > 0 ? await ask(still) : null;
    for (const outcome of [first, again]) {
      if (!outcome) continue;
      pushAll(fetchedVulns, outcome.vulns);
      pushAll(unanswered, outcome.unanswered);
      failure = failure ?? outcome.failure;
    }

    let staleAnswers = 0;
    let staleOldest: string | null = null;
    const unchecked: ResolvedDependency[] = [];
    const staleFor = network
      ? await readInBatches(unanswered, (keys) => this.cache.getStaleMany<VulnerabilityEntry[]>(keys))
      : new Map<string, { data: VulnerabilityEntry[]; fetchedAt: string }>();
    for (const dep of unanswered) {
      const stale = staleFor.get(osvCacheKey(dep)) ?? null;
      if (stale) {
        staleAnswers++;
        if (!staleOldest || stale.fetchedAt < staleOldest) staleOldest = stale.fetchedAt;
        pushAll(cachedVulns, stale.data.map((v) => restampDepContext(v, dep)));
      } else {
        unchecked.push(dep);
      }
    }
    const offline = unchecked.length > 0;

    // npm's security holding packages (`fs@0.0.1-security`) are empty
    // placeholders npm publishes after taking a malicious package down; the
    // malware advisory covering every version does not apply to them (the
    // desktop app's osv::matching::is_npm_security_holding; audit A5).
    const rated = await this.rateFromAliases([...cachedVulns, ...fetchedVulns].filter((v) => !isNpmSecurityHolding(v)));
    // One severity per advisory: every record of an alias group carries the group's most severe grade.
    const allVulns = gradeAliasGroups(rated.vulns);
    const vulnerablePackages = new Set(allVulns.map((v) => v.package));
    const platformInactiveVulnerable = new Set(
      allVulns.filter((v) => !v.platformActive).map((v) => v.package),
    ).size;

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (const v of allVulns) {
      bySeverity[v.severity]++;
    }
    // Advisories matched whose record OSV did not return: known by id only (unhydratedEntry).
    const detailsUnchecked = [...new Set(allVulns.filter((v) => v.detailUnavailable).map((v) => v.vulnId))].sort();

    return {
      scannedAt: new Date().toISOString(),
      projectPath,
      ecosystemsScanned: ecosystems,
      totalScanned: scannable.length,
      totalVulnerable: vulnerablePackages.size,
      platformInactiveVulnerable,
      bySeverity,
      vulnerabilities: allVulns,
      // Answered dependencies with no advisory; an unchecked one is never clean.
      cleanCount: Math.max(0, scannable.length - unchecked.length - vulnerableDependencyCount(allVulns)),
      scanDurationMs: Date.now() - start,
      cached: uncached.length === 0,
      offline,
      unchecked: unchecked.length,
      ...(unchecked.length > 0 ? { uncheckedDependencies: unchecked.map((d) => `${d.ecosystem}\0${d.name}\0${d.version}`) } : {}),
      uncheckedReason: offline ? (failure ?? notReleaseWhy ?? "OSV.dev could not be queried") : null,
      staleAnswers,
      // An expired answer is not a current one: every consumer says so (audit 6.2.5 B-2).
      ...(staleAnswers > 0 ? { staleReason: failure ?? "OSV.dev could not be queried", staleOldestFetchedAt: staleOldest } : {}),
      ...(detailsUnchecked.length > 0 ? { detailsUnchecked } : {}),
      ...(rated.report ? { aliasSeverity: rated.report } : {}),
    };
  }

  /**
   * A severity for records that carry none, from their GHSA alias: one
   * advisory, one grade, in every tool. Go's vulnerability database rates
   * nothing: GO-2024-3333 (golang.org/x/net) has no severity, its alias
   * GHSA-w32m-9786-jp63 is HIGH, and OSV returns only the GO record for the
   * module (the GHSA names golang.org/x/net/html). dependency_check said
   * `avoid` while vulnerability_scan graded the same record unknown (review
   * of 6.2.5 M6, 2026-10-18). The two records name each other, so the
   * alias's rating applies; it is read by the same rule as any record and
   * the entry says where it came from (`severityFrom`).
   *
   * Through this scanner's own source: a pinned source answers from its
   * records, never the network; with live lookups off nothing is fetched.
   * At most MAX_ALIAS_LOOKUPS aliases, within ALIAS_BUDGET_MS in total.
   * Anything not rated stays unknown and is listed as unresolved, with why;
   * unknown is never clean.
   */
  private async rateFromAliases(entries: VulnerabilityEntry[]): Promise<{ vulns: VulnerabilityEntry[]; report: AliasSeverityReport | null }> {
    // A GHSA alias that is itself one of this scan's records is graded already: no fetch.
    const known = new Map<string, VulnerabilityEntry["severity"]>();
    for (const e of entries) if (/^GHSA-/i.test(e.vulnId) && e.severity !== "unknown") known.set(e.vulnId, e.severity);
    const wanted = new Map<string, string[]>(); // record id -> every GHSA alias it names
    for (const e of entries) {
      if (e.severity !== "unknown" || e.severityFrom || wanted.has(e.vulnId) || isMaintenanceNotice(e)) continue;
      const ghsas = [...new Set(e.aliases.filter((a) => /^GHSA-/i.test(a) && a !== e.vulnId))];
      if (ghsas.length > 0) wanted.set(e.vulnId, ghsas);
    }
    if (wanted.size === 0) return { vulns: entries, report: null };

    // The cap and the budget count distinct GHSA ids.
    const toRead = [...new Set([...wanted.values()].flat())].filter((id) => !known.has(id)).sort();
    const asked = toRead.slice(0, MAX_ALIAS_LOOKUPS);
    let records = new Map<string, OsvVulnerability>();
    const reasons: string[] = toRead.length > asked.length ? [`more than ${MAX_ALIAS_LOOKUPS} aliases to read; the rest were not asked for`] : [];
    if (asked.length > 0 && this.source.network && isOfflineMode()) {
      reasons.push("live lookups are disabled (FOURDA_OFFLINE=true)");
    } else if (asked.length > 0) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), this.aliasBudgetMs);
      });
      try {
        // Fetches past the deadline keep running and fill the detail cache for the next call.
        const answer = await Promise.race([this.source.details(asked).catch(() => new Map<string, OsvVulnerability>()), deadline]);
        if (answer === null) reasons.push(`the alias records did not arrive within ${this.aliasBudgetMs / 1000} s`);
        else records = answer;
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    }
    const read = new Map<string, VulnerabilityEntry["severity"]>(known);
    for (const [id, record] of records) read.set(id, deriveSeverity(record).severity);

    const unresolved = new Set<string>();
    const ungraded: string[] = [];
    let ratedCount = 0;
    const vulns = entries.map((e) => {
      const ghsas = wanted.get(e.vulnId);
      if (!ghsas) return e;
      const graded = gradeFromAliases(ghsas, read);
      for (const c of graded.consulted) if (c.grade === "unreadable") unresolved.add(c.id);
      if (graded.severity === "unknown") {
        if (!ungraded.includes(e.vulnId)) ungraded.push(e.vulnId);
        return e;
      }
      ratedCount++;
      return { ...e, severity: graded.severity, severityFrom: graded.from! };
    });
    if (unresolved.size > 0 && reasons.length === 0) reasons.push("an alias record could not be read");
    return {
      vulns,
      report: { rated: ratedCount, unresolved: [...unresolved].sort(), ungraded, reason: unresolved.size > 0 || ungraded.length > 0 ? reasons.join("; ") || "the aliases are unrated themselves" : null },
    };
  }

  /**
   * For each dependency with an advisory whose `/v1/vulns/{id}` record did not arrive: the records
   * OSV.dev's `/v1/query` gives for that exact version. Losing a record turned lodash 4.17.20 and
   * ws 7.5.10 from avoid into review with severity unknown, though the package's advisory list
   * held the full record, severity included (pre-publish audit 2026-11-14). Within the alias
   * budget; what still cannot be read stays an id-only entry (unhydratedEntry), never dropped.
   */
  private async recordsForUnread(
    matches: Array<{ dep: ResolvedDependency; ids: string[] }>,
    detailById: ReadonlyMap<string, OsvVulnerability>,
  ): Promise<Map<ResolvedDependency, OsvVulnerability[]>> {
    const out = new Map<ResolvedDependency, OsvVulnerability[]>();
    const source = this.source;
    if (!source.recordsFor) return out;
    const unread = matches.filter((m) => m.ids.some((id) => isOsvAdvisoryId(id) && !detailById.has(id))).map((m) => m.dep);
    if (unread.length === 0 || (source.network && isOfflineMode())) return out;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, this.aliasBudgetMs);
    });
    try {
      await Promise.race([
        pool(unread.slice(0, MAX_ALIAS_LOOKUPS), HYDRATE_CONCURRENCY, async (dep) => {
          const records = await source.recordsFor!(dep).catch(() => null);
          if (records) out.set(dep, records);
        }),
        deadline,
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
    return new Map(out);
  }

  /** `work` with `deps` registered as in flight until it settles. */
  private async registered<T>(deps: ResolvedDependency[], work: () => Promise<T>): Promise<T> {
    const keys = [...new Set(deps.map(osvCacheKey))];
    const running = work();
    for (const k of keys) this.inFlight.set(k, running);
    try {
      return await running;
    } finally {
      for (const k of keys) if (this.inFlight.get(k) === running) this.inFlight.delete(k);
    }
  }

  private async batchQuery(
    deps: ResolvedDependency[],
  ): Promise<{ vulns: VulnerabilityEntry[]; unanswered: ResolvedDependency[]; failure: string | null }> {
    // Phase 1 — enumerate advisory IDs per dep (OSV: the lightweight batch index).
    const answer = await this.source.query(deps);
    const unanswered = deps.filter((_, i) => !Array.isArray(answer.ids[i]));
    const matches = deps.flatMap((dep, i) => {
      const ids = answer.ids[i];
      return Array.isArray(ids) ? [{ dep, ids }] : [];
    });

    // Phase 2 — the record behind each unique advisory, once.
    const uniqueIds = [...new Set(matches.flatMap((m) => m.ids))];
    // An id that is not one is never looked up: it stays an advisory known by nothing but that.
    const detailById = await this.source.details(uniqueIds.filter(isOsvAdvisoryId));
    // Phase 2b — a record whose fetch failed, from the dependency's own advisory list.
    const recordsByDep = await this.recordsForUnread(matches, detailById);

    // Phase 3 — map to entries and cache per-dep (empty results cached too, so
    // clean deps are not re-queried; network answers only).
    const results: VulnerabilityEntry[] = [];
    const rows: Array<[string, VulnerabilityEntry[]]> = [];
    for (const { dep, ids } of matches) {
      // Drop advisories OSV has withdrawn/retracted — surfacing them is a false
      // positive. Un-hydrated ids (detail fetch failed) are kept: we can't know,
      // and dropping a real advisory is worse than keeping an un-enriched one.
      const inHand = recordsByDep.get(dep);
      const recordOf = (id: string) => detailById.get(id) ?? inHand?.find((r) => r.id === id) ?? inHand?.find((r) => r.aliases?.includes(id));
      const liveIds = ids.filter((id) => !recordOf(id)?.withdrawn);
      const mapped = liveIds.map((id) => {
        const detail = recordOf(id);
        // A record found under an alias describes the same advisory: the id OSV matched is kept.
        return detail ? { ...mapVulnerability(detail, dep), vulnId: id } : unhydratedEntry(id, dep);
      });
      // An id whose record is missing but which a record that WAS read names as its alias is the
      // same advisory, already described: the stub adds nothing.
      const readAliases = new Set(mapped.filter((v) => !v.detailUnavailable).flatMap((v) => v.aliases));
      const depVulns = mapped.filter((v) => !v.detailUnavailable || !readAliases.has(v.vulnId));
      // An advisory whose record did not arrive is known by its id alone: no severity, no fix
      // version. Cached, that stub answered for the next hour, so one failed fetch turned a
      // critical into "unknown, no fix" for every scan in it (audit 2026-11-11, T7). Only a
      // dependency whose every advisory was read is cached; the rest are asked again next time.
      if (depVulns.every((v) => !v.detailUnavailable)) rows.push([`osv:v9:${dep.ecosystem}:${dep.name}:${dep.version}`, depVulns]);
      pushAll(results, depVulns);
    }
    if (this.source.network) this.cache.setMany(rows, "osv", OSV_CACHE_TTL);

    return { vulns: results, unanswered, failure: unanswered.length > 0 ? (answer.failure ?? "OSV.dev gave no answer") : null };
  }
}

/** Distinct (ecosystem, name, version) instances with at least one advisory row. */
function vulnerableDependencyCount(vulns: VulnerabilityEntry[]): number {
  return new Set(vulns.map((v) => `${v.ecosystem}\0${v.package}\0${v.currentVersion}`)).size;
}

/**
 * Overwrite the dep-context fields of a cached advisory entry with the CURRENT
 * resolution's context. The advisory facts (id, severity, summary, fix version)
 * are stable and cacheable; `platformActive`, `target`, `sourceDirs`, and the
 * dev/direct flags are functions of TODAY's dependency resolution, not of the
 * advisory. Serving them from cache bakes yesterday's context into today's
 * scan — observed live 2026-08-30: a pre-platform-filter scan cached `glib`
 * as platform-active and `sandbox` with no source dirs, and every scan for the
 * next hour repeated both errors while the fixed resolver sat idle.
 */
export function restampDepContext(
  cached: VulnerabilityEntry,
  dep: ResolvedDependency,
): VulnerabilityEntry {
  return {
    ...cached,
    package: dep.name,
    currentVersion: dep.version || "unknown",
    ecosystem: dep.ecosystem,
    isDev: dep.isDev,
    isDirect: dep.isDirect,
    devScopeKnown: dep.devScopeKnown,
    target: dep.target,
    platformActive: dep.platformActive,
    sourceDirs: dep.sourceDirs ?? [],
    platformInactiveDirs: dep.platformInactiveDirs,
    // Install drift is today's node_modules state, not an advisory fact:
    // stamped from the current dep, so a cached row never carries it forward.
    installDriftOf: dep.installDriftOf,
    installFix: dep.installFix,
  };
}

function mapVulnerability(
  vuln: Partial<OsvVulnerability> & { id: string },
  dep: ResolvedDependency,
): VulnerabilityEntry {
  const graded = deriveSeverity(vuln);
  // The whole record: summary, details and the OpenSSF origins flag, not the summary alone (blind audit round 4).
  const malware = isMalwareRecord(vuln);
  // An installed malicious copy is critical in every tool, whatever the record grades (the 4DA lead, 2026-10-18).
  const severity = malware ? "critical" : graded.severity;
  const cvssScore = graded.cvssScore;
  const fixedVersion = extractFixedVersion(vuln.affected, dep.name, dep.ecosystem, dep.version);

  return {
    package: dep.name,
    currentVersion: dep.version || "unknown",
    ecosystem: dep.ecosystem,
    isDev: dep.isDev,
    isDirect: dep.isDirect,
    devScopeKnown: dep.devScopeKnown,
    vulnId: vuln.id,
    // Ids and URLs from OSV.dev kept CR/LF (blind audit round 4): only an id's or a URL's shape is kept.
    aliases: [...new Set((vuln.aliases || []).map(thirdPartyId).filter((a): a is string => a !== null))],
    severity,
    cvssScore,
    ...(malware ? { malware: true } : {}),
    maintenance: isMaintenanceRecord(vuln, dep.name, dep.ecosystem),
    // Third-party text: the shared cleaning, one line, no `|`, capped, before any tool reads it
    // (untrusted-text.ts; a 5,135-character summary with a forged `| advisories:` line came back
    // whole in vulnerability_scan, pre-publish audit 2026-11-14).
    summary: quoteThirdParty(vuln.summary || vuln.details || "", ADVISORY_SUMMARY_MAX) || vuln.id,
    fixedVersion,
    published: thirdPartyTimestamp(vuln.published) || thirdPartyTimestamp(vuln.modified),
    references: (vuln.references || [])
      .filter((r) => r.type === "ADVISORY" || r.type === "WEB")
      .map((r) => thirdPartyUrl(r.url))
      .filter((u): u is string => u !== null)
      .slice(0, 3),
    target: dep.target,
    platformActive: dep.platformActive,
    sourceDirs: dep.sourceDirs ?? [],
    ...(dep.platformInactiveDirs ? { platformInactiveDirs: dep.platformInactiveDirs } : {}),
    installDriftOf: dep.installDriftOf,
    installFix: dep.installFix,
  };
}

/**
 * An advisory OSV matched to this dependency whose record could not be
 * fetched: the id is all that is known. Its severity is unknown and it names
 * no fix, and both of those are gaps, not facts: `detailUnavailable` says so,
 * so no filter drops it for being "below" a severity and no advice reads its
 * missing fix as "no fix published". A malicious-package id (MAL-) is still
 * critical on the id alone.
 */
function unhydratedEntry(id: string, dep: ResolvedDependency): VulnerabilityEntry {
  return {
    ...mapVulnerability({ id }, dep),
    detailUnavailable: true,
    summary: `${id}: advisory details NOT CHECKED (OSV.dev did not return the record), so its severity and fix version are unknown`,
  };
}

const GRADE_RANK: Record<string, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * The shared rule for an unrated record (the 4DA app implements it
 * identically): the HIGHEST grade among every GHSA alias that could be read;
 * unknown when none could. `from` names the alias that gave it, the
 * lexicographically smallest id on a tie. An alias that could not be read
 * never lowers the grade; it is reported (`consulted`, grade "unreadable").
 * Umbrella records name several: RUSTSEC-2020-0014 lists 8 GHSAs, so taking
 * the first made the grade depend on alias order.
 */
export function gradeFromAliases(
  ghsas: string[],
  read: ReadonlyMap<string, VulnerabilityEntry["severity"]>,
): { severity: VulnerabilityEntry["severity"]; from: string | null; consulted: Array<{ id: string; grade: VulnerabilityEntry["severity"] | "unreadable" }> } {
  const consulted = [...new Set(ghsas)].sort().map((id) => ({ id, grade: read.get(id) ?? ("unreadable" as const) }));
  let best: { id: string; grade: VulnerabilityEntry["severity"] } | null = null;
  for (const c of consulted) {
    if (c.grade === "unreadable" || c.grade === "unknown") continue;
    if (!best || GRADE_RANK[c.grade] > GRADE_RANK[best.grade]) best = { id: c.id, grade: c.grade };
  }
  return { severity: best?.grade ?? "unknown", from: best?.id ?? null, consulted };
}

/**
 * Derive a severity bucket honestly: a CVSS base score (numeric or computed
 * from a vector) wins; otherwise the GitHub-advisory label; otherwise unknown.
 * Never fabricates a default bucket — an advisory with no severity signal is
 * reported as `unknown`, not silently labeled "medium".
 */
export function deriveSeverity(vuln: Partial<OsvVulnerability>): {
  severity: VulnerabilityEntry["severity"];
  cvssScore: number | null;
} {
  // The curated label first, the CVSS band second (the rule shared with the 4DA app, 2026-10-18,
  // severity vectors sv-015..sv-017): on the pinned corpus 123 of 3,923 records disagree, all GHSA,
  // 113 beside a CVSS v4 vector, where the label follows. A CVSS 0.0 goes by its label. A record with no
  // label is graded by its v3.x vector, else its v4.0 one (cvss4.ts).
  const cvssScore = extractCvssScore(vuln.severity);
  const label = labelToSeverity(vuln.database_specific?.severity);
  if (label !== "unknown") return { severity: label, cvssScore };
  if (cvssScore !== null) return { severity: cvssToSeverity(cvssScore), cvssScore };
  return { severity: "unknown", cvssScore: null };
}

function labelToSeverity(label: string | undefined): VulnerabilityEntry["severity"] {
  switch ((label || "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "unknown";
  }
}

export function extractCvssScore(severity: Array<{ type: string; score: string }> | undefined): number | null {
  if (!severity || severity.length === 0) return null;

  // Prefer an explicit numeric base score when present.
  for (const s of severity) {
    const raw = s.score.trim();
    if (/^\d+(?:\.\d+)?$/.test(raw)) {
      const num = Number(raw);
      if (!isNaN(num) && num >= 0 && num <= 10) return num;
    }
  }

  // OSV most often gives a CVSS *vector* string — compute its base score.
  for (const s of severity) {
    if (s.score.includes("AV:")) {
      const score = cvssBaseScore(s.score);
      if (score !== null) return score;
    }
  }
  // A v4.0 vector only when no v3.x one scored: RustSec records now often carry v4.0 alone
  // (RUSTSEC-2026-0459 was graded unknown), and v3 keeps its place where both are given.
  for (const s of severity) {
    if (/^\s*CVSS:4\.0\//i.test(s.score)) {
      const score = cvss4Score(s.score);
      if (score !== null) return score;
    }
  }
  return null;
}

function cvssToSeverity(score: number): "critical" | "high" | "medium" | "low" | "unknown" {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "unknown";
}

/**
 * Pick the fix version for the OSV range that actually CONTAINS the installed
 * version — never another release line's fix. The old code returned the first
 * range's first `fixed` event, so a multi-range advisory (e.g. undici fixed at
 * 6.x on the 6 line and 7.x on the 7 line) recommended a DOWNGRADE to 6.x for
 * an installed 7.x.
 *
 * Selection order:
 * 1. The `fixed` of the interval containing installed (introduced <= installed
 *    < fixed).
 * 2. If that interval has no fix (or none contains installed), the smallest
 *    published fix strictly ABOVE installed across all ranges.
 * 3. If the installed version is unparseable, the highest published fix (it
 *    resolves the advisory regardless of release line).
 * 4. Otherwise null — omitting the recommendation beats emitting a downgrade.
 *
 * Hard guard: the returned version is never below the installed version.
 */
export function extractFixedVersion(
  affected: OsvVulnerability["affected"] | undefined,
  packageName: string,
  ecosystem: string,
  installedVersion: string | null,
): string | null {
  if (!affected) return null;

  const intervals = collectAffectedSpans(affected, packageName, ecosystem);
  const fixes = intervals
    .map((i) => i.fixed)
    .filter((f): f is string => f !== null);
  if (fixes.length === 0) return null;
  // Ordered the ecosystem's way (PEP 440 for PyPI, `v`-less semver for Go).
  const cmp = (a: string, b: string) => compareVersions(a, b, ecosystem);

  if (installedVersion === null || !isComparable(installedVersion, ecosystem)) {
    // Can't place the installed version on a release line — recommend the
    // highest published fix so the upgrade resolves the advisory either way.
    return maxVersion(fixes, ecosystem);
  }

  // The interval whose release line the installed version sits on. An
  // unreadable bound compares as 0, which keeps those intervals eligible on
  // the introduced side only; "0" (since inception) orders below everything.
  const containing = intervals.find(
    (i) =>
      compareToLowerBound(installedVersion, i.introduced, ecosystem) >= 0 &&
      (i.fixed !== null
        ? cmp(installedVersion, i.fixed) < 0
        : i.lastAffected === null || cmp(installedVersion, i.lastAffected) <= 0),
  );
  if (containing?.fixed && cmp(containing.fixed, installedVersion) > 0) {
    return containing.fixed;
  }

  // No fix on the installed line (open interval, or installed already past
  // every containing range): smallest fix strictly above installed, or nothing.
  const above = fixes.filter((f) => cmp(f, installedVersion) > 0);
  if (above.length === 0) return null;
  return above.reduce((min, v) => (cmp(v, min) < 0 ? v : min), above[0]);
}

/**
 * npm's security holding placeholder: after a malicious package is taken down,
 * npm republishes the name as an empty `0.0.<n>-security` release ("security
 * holding package"). It has no code, so NO advisory applies to it, whichever
 * database's id flags the name: crossenv 0.0.2-security under
 * GHSA-c2m4-w5hm-vqjw read as installed malware when only MAL- ids were held
 * (4DA audit L4, 2026-10-16). Only npm's own shape counts: a publisher's
 * `1.0.0-security` prerelease is real code and stays affected. The same rule
 * as the app's `fourda_depengine::matching::is_npm_security_holding`
 * (shared vectors `holding.jsonl`).
 */
export function isSecurityHoldingRelease(ecosystem: string, version: string): boolean {
  return ecosystem.trim().toLowerCase() === "npm" && /^0\.0\.\d+-security$/.test(version.trim());
}

/** A finding on an npm security holding placeholder (any advisory id): not installed code. */
export function isNpmSecurityHolding(v: Pick<VulnerabilityEntry, "ecosystem" | "currentVersion">): boolean {
  return isSecurityHoldingRelease(v.ecosystem, v.currentVersion);
}
