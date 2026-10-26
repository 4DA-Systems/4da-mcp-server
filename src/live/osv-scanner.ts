// SPDX-License-Identifier: Apache-2.0
/**
 * OSV.dev Vulnerability Scanner
 *
 * Batch-queries the Open Source Vulnerability database for known CVEs
 * affecting the user's exact dependency versions. Free, no auth required.
 *
 * Privacy: sends only package names + versions (public manifest data).
 */

import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import { fetchWithTimeout } from "./http-utils.js";
import { cvssBaseScore } from "./cvss.js";
import { compareToLowerBound, compareVersions, isComparable, maxVersion } from "./version-compare.js";
import { collectAffectedSpans } from "./osv-ranges.js";
import { isMaintenanceNotice, isMaintenanceRecord } from "./maintenance.js";
import { gradeAliasGroups } from "./advisory-groups.js";
import { cweIdsOf, isMalware } from "./malware.js";
import type {
  AliasSeverityReport,
  ResolvedDependency,
  OsvVulnerability,
  VulnerabilityEntry,
  VulnerabilityScanResult,
} from "./types.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";
const OSV_TIMEOUT_MS = 15_000;
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
}

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVulnerability[] }>;
}

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
  if (name === "TimeoutError" || name === "AbortError") return `OSV.dev did not answer within ${OSV_TIMEOUT_MS / 1000} s`;
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

  async query(deps: ResolvedDependency[]): Promise<AdvisoryAnswer> {
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
        return await this.sendBatch(chunk);
      } catch (error) {
        failure = describeFailure(error);
        outage = true;
        return chunk.map(() => null);
      }
    });
    return { ids: answered.flat(), failure };
  }

  /** One querybatch request, retried once after a throttle, a server error, a timeout or a network failure. */
  private async sendBatch(chunk: ResolvedDependency[]): Promise<string[][]> {
    const queries: OsvBatchQuery[] = chunk.map((d) => ({
      package: { name: d.name, ecosystem: d.ecosystem },
      ...(d.version ? { version: d.version } : {}),
    }));
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
        if (!Array.isArray(data?.results) || data.results.length !== chunk.length) {
          throw new Error(`OSV.dev answered ${Array.isArray(data?.results) ? data.results.length : "no"} results for ${chunk.length} queries`);
        }
        return chunk.map((_, i) => (data.results[i]?.vulns ?? []).map((v) => v.id));
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

  /** One advisory's record; retried once after a throttle, a server error or a network failure. Null when it cannot be had. */
  private async fetchDetail(id: string): Promise<OsvVulnerability | null> {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await fetchWithTimeout(`${OSV_VULN_URL}${encodeURIComponent(id)}`, {}, OSV_TIMEOUT_MS);
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

export class OsvScanner {
  private cache: LiveCache;
  private rateLimiter: RateLimiter;
  private source: AdvisorySource;
  private aliasBudgetMs: number;

  constructor(cache: LiveCache, rateLimiter: RateLimiter, source?: AdvisorySource, options: { aliasBudgetMs?: number } = {}) {
    this.aliasBudgetMs = options.aliasBudgetMs ?? ALIAS_BUDGET_MS;
    this.cache = cache;
    this.rateLimiter = rateLimiter;
    this.source = source ?? new OsvHttpSource(cache, rateLimiter);
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

    for (const dep of scannable) {
      const cacheKey = `osv:v3:${dep.ecosystem}:${dep.name}:${dep.version}`;
      const cached = network ? this.cache.get<VulnerabilityEntry[]>(cacheKey) : null;
      if (cached !== null) {
        cachedVulns.push(...cached.map((v) => restampDepContext(v, dep)));
      } else {
        uncached.push(dep);
      }
    }

    // Fetch uncached from OSV. Dependencies it has no answer for fall back to
    // an expired cached answer; with none they are UNCHECKED, counted and
    // reported, and never counted clean.
    let fetchedVulns: VulnerabilityEntry[] = [];
    let unanswered: ResolvedDependency[] = [];
    let failure: string | null = null;

    if (uncached.length > 0) {
      try {
        const outcome = await this.batchQuery(uncached);
        fetchedVulns = outcome.vulns;
        unanswered = outcome.unanswered;
        failure = outcome.failure;
      } catch (error) {
        // The source layer turns network failures into `outcome.failure`; an
        // exception here is a fault in this server, not an OSV outage, and
        // telling the agent to retry would not help (audit 6.2.5 D-2).
        unanswered = uncached;
        const detail = error instanceof Error ? error.message.slice(0, 120) : String(error).slice(0, 120);
        failure = `an internal error in this server stopped the vulnerability lookup (${detail}); retrying will not help, please report it at https://github.com/4DA-Systems/4da-mcp-server/issues`;
      }
    }

    let staleAnswers = 0;
    let staleOldest: string | null = null;
    const unchecked: ResolvedDependency[] = [];
    for (const dep of unanswered) {
      const stale = network ? this.cache.getStale<VulnerabilityEntry[]>(`osv:v3:${dep.ecosystem}:${dep.name}:${dep.version}`) : null;
      if (stale) {
        staleAnswers++;
        if (!staleOldest || stale.fetchedAt < staleOldest) staleOldest = stale.fetchedAt;
        cachedVulns.push(...stale.data.map((v) => restampDepContext(v, dep)));
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
      uncheckedReason: offline ? (failure ?? "OSV.dev could not be queried") : null,
      staleAnswers,
      // An expired answer is not a current one: every consumer says so (audit 6.2.5 B-2).
      ...(staleAnswers > 0 ? { staleReason: failure ?? "OSV.dev could not be queried", staleOldestFetchedAt: staleOldest } : {}),
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
    if (asked.length > 0 && this.source.network && process.env.FOURDA_OFFLINE === "true") {
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
    const detailById = await this.source.details(uniqueIds);

    // Phase 3 — map to entries and cache per-dep (empty results cached too, so
    // clean deps are not re-queried; network answers only).
    const results: VulnerabilityEntry[] = [];
    const rows: Array<[string, VulnerabilityEntry[]]> = [];
    for (const { dep, ids } of matches) {
      // Drop advisories OSV has withdrawn/retracted — surfacing them is a false
      // positive. Un-hydrated ids (detail fetch failed) are kept: we can't know,
      // and dropping a real advisory is worse than keeping an un-enriched one.
      const liveIds = ids.filter((id) => !detailById.get(id)?.withdrawn);
      const depVulns = liveIds.map((id) => mapVulnerability(detailById.get(id) ?? { id }, dep));
      rows.push([`osv:v3:${dep.ecosystem}:${dep.name}:${dep.version}`, depVulns]);
      results.push(...depVulns);
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
  const malware = isMalware(vuln.id, vuln.aliases || [], cweIdsOf(vuln), vuln.summary ?? "");
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
    aliases: vuln.aliases || [],
    severity,
    cvssScore,
    ...(malware ? { malware: true } : {}),
    maintenance: isMaintenanceRecord(vuln, dep.name, dep.ecosystem),
    summary: vuln.summary || vuln.details?.slice(0, 200) || vuln.id,
    fixedVersion,
    published: vuln.published || vuln.modified || "",
    references: (vuln.references || [])
      .filter((r) => r.type === "ADVISORY" || r.type === "WEB")
      .map((r) => r.url)
      .slice(0, 3),
    target: dep.target,
    platformActive: dep.platformActive,
    sourceDirs: dep.sourceDirs ?? [],
    installDriftOf: dep.installDriftOf,
    installFix: dep.installFix,
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
  // 113 beside a CVSS v4 vector neither engine scores and the label follows. A CVSS 0.0 goes by its label.
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
