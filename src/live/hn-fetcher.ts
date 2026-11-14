// SPDX-License-Identifier: Apache-2.0
/**
 * Hacker News Headline Fetcher
 *
 * Queries HN Algolia API for headlines relevant to the user's tech stack.
 * Free, no auth. Generates search queries from detected technologies.
 *
 * Privacy: sends generic tech keywords (e.g. "react", "rust") — not personal data.
 */

import { HEADLINE_MAX, quoteThirdParty, thirdPartyId, thirdPartyTimestamp, thirdPartyUrl } from "../untrusted-text.js";
import { fetchWithTimeout } from "./http-utils.js";
import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import type { LiveHeadline } from "./types.js";

const HN_ALGOLIA_URL = "https://hn.algolia.com/api/v1/search";
const HN_TIMEOUT_MS = 8_000;
const HN_CACHE_TTL = 1800; // 30 minutes
const MAX_QUERIES = 8;
const RESULTS_PER_QUERY = 10;
const MIN_POINTS = 10;

interface HNHit {
  objectID: string;
  title: string;
  url: string | null;
  points: number;
  num_comments: number;
  created_at: string;
  author: string;
}

interface HNResponse {
  hits: HNHit[];
}

export class HNFetcher {
  private cache: LiveCache;
  private rateLimiter: RateLimiter;

  constructor(cache: LiveCache, rateLimiter: RateLimiter) {
    this.cache = cache;
    this.rateLimiter = rateLimiter;
  }

  async fetch(techStack: string[]): Promise<LiveHeadline[]> {
    const cacheKey = `hn:${techStack.slice(0, MAX_QUERIES).sort().join(",")}`;
    const cached = this.cache.get<LiveHeadline[]>(cacheKey);
    if (cached !== null) return cached;

    if (!this.rateLimiter.canProceed("hn")) {
      const stale = this.cache.getStale<LiveHeadline[]>(cacheKey);
      if (stale) return stale.data;
      throw new Error("the Hacker News request budget for this minute is spent");
    }

    const queries = buildQueries(techStack);
    if (queries.length === 0) return [];
    const allHits: HNHit[] = [];
    const seen = new Set<string>();
    let answered = 0;
    let failure = "";

    for (const query of queries) {
      if (!this.rateLimiter.consume("hn")) {
        failure ||= "the Hacker News request budget for this minute is spent";
        break;
      }

      try {
        const hits = await this.searchHN(query);
        answered++;
        for (const hit of hits) {
          if (!seen.has(hit.objectID)) {
            seen.add(hit.objectID);
            allHits.push(hit);
          }
        }
      } catch (err) {
        // One query failed: the others may still answer.
        failure = err instanceof Error ? err.message : String(err);
      }
    }
    // Not one query answered: that is "not read", never "no relevant headlines" (blind audit round 3).
    if (answered === 0) throw new Error(`Hacker News did not answer${failure ? ` (${failure.slice(0, 120)})` : ""}`);

    const headlines = scoreAndMap(allHits, techStack);
    this.cache.set(cacheKey, headlines, "hn", HN_CACHE_TTL);
    return headlines;
  }

  private async searchHN(query: string): Promise<HNHit[]> {
    // "Pulse" means current: without a recency floor Algolia's point-sorted
    // results are dominated by multi-year-old all-time hits (e.g. the Tauri
    // 1.0 launch), which is archaeology, not ecosystem news.
    const fourteenDaysAgo = Math.floor(Date.now() / 1000) - 14 * 24 * 60 * 60;
    const params = new URLSearchParams({
      query,
      tags: "story",
      numericFilters: `points>${MIN_POINTS},created_at_i>${fourteenDaysAgo}`,
      hitsPerPage: String(RESULTS_PER_QUERY),
    });

    const url = `${HN_ALGOLIA_URL}?${params}`;
    // Through the shared layer like every lookup: the private-name guard and the proxy (http-utils.ts).
    const response = await fetchWithTimeout(url, {}, HN_TIMEOUT_MS);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = (await response.json()) as HNResponse;
    return data.hits || [];
  }
}

function buildQueries(techStack: string[]): string[] {
  // Take top technologies, prioritize frameworks over languages
  const prioritized = [...techStack]
    .filter((t) => t.length >= 2 && !SKIP_TERMS.has(t))
    .slice(0, MAX_QUERIES);

  return prioritized;
}

function wordBoundaryMatch(text: string, term: string): boolean {
  // Check EVERY occurrence — indexOf-only missed "react" in a title whose
  // first hit was inside "reactor".
  let idx = -1;
  while ((idx = text.indexOf(term, idx + 1)) !== -1) {
    const before = idx === 0 || !/[a-zA-Z0-9]/.test(text[idx - 1]);
    const after = idx + term.length >= text.length || !/[a-zA-Z0-9]/.test(text[idx + term.length]);
    if (before && after) return true;
  }
  return false;
}

function scoreAndMap(hits: HNHit[], techStack: string[]): LiveHeadline[] {
  const techLower = techStack.map((t) => t.toLowerCase());

  return hits
    // A story with no id in an id's shape has no discussion link to give.
    .filter((hit) => thirdPartyId(hit.objectID) !== null)
    .map((hit) => {
      const titleLower = hit.title.toLowerCase();
      const matchedTech = techLower.filter((t) => wordBoundaryMatch(titleLower, t));
      return { hit, matchedTech };
    })
    // The tool's contract is "filtered by detected technologies" — a hit whose
    // title matches none of the user's stack is Algolia query noise (nuclear
    // "reactors" and weather stories arrived this way), not ecosystem news.
    .filter(({ matchedTech }) => matchedTech.length > 0)
    .map(({ hit, matchedTech }) => {
      // A headline naming a dependency outranks language-level news.
      const named = matchedTech.filter((t) => !LANGUAGE_TERMS.has(t));
      const techBoost = named.length > 0 ? Math.min(0.3 + named.length * 0.1, 0.5) : 0.1;
      const pointsBoost = Math.min(hit.points / 500, 0.3);
      const commentsBoost = Math.min(hit.num_comments / 200, 0.2);
      const score = Math.min(0.1 + techBoost + pointsBoost + commentsBoost, 1.0);

      return {
        // The id, URL and timestamp kept CR/LF into ecosystem_pulse (blind audit round 4): only their shapes are kept.
        id: thirdPartyId(hit.objectID)!,
        title: quoteThirdParty(hit.title ?? "", HEADLINE_MAX),
        url: thirdPartyUrl(hit.url),
        source: "hacker_news" as const,
        points: hit.points,
        comments: hit.num_comments,
        published: thirdPartyTimestamp(hit.created_at),
        relevanceScore: Math.round(score * 100) / 100,
        relevanceReason: named.length > 0
          ? `Names ${named.join(", ")} (used in your projects)`
          : `Language-level news: ${matchedTech.join(", ")}`,
      };
    })
    .sort((a, b) => b.relevanceScore - a.relevanceScore)
    .slice(0, 15);
}

/** Search terms that name a language rather than a dependency. */
const LANGUAGE_TERMS = new Set(["rust", "python", "zig", "kotlin", "swift", "ruby", "elixir"]);

const SKIP_TERMS = new Set([
  "javascript", "typescript", // too generic, floods results
  "docker", // too broad
]);
