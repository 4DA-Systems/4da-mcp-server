// SPDX-License-Identifier: Apache-2.0
/**
 * Blind audit round 3: with Hacker News unreachable, ecosystem_pulse answered "No relevant
 * headlines found for your tech stack", a clean-sounding result for a source it never read.
 * A fetch in which not one query answered now fails, is not cached, and the pulse says NOT CHECKED.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { HNFetcher } from "../live/hn-fetcher.js";
import { LiveCache } from "../live/cache.js";
import { RateLimiter } from "../live/rate-limiter.js";

afterEach(() => vi.unstubAllGlobals());

const fetcher = () => new HNFetcher(new LiveCache(null), new RateLimiter({ hn: { maxPerMinute: 30 } }));
const story = { objectID: "1", title: "React 20 released", url: "https://example.com", points: 200, num_comments: 40, created_at: new Date().toISOString() };

describe("Hacker News unreachable", () => {
  it("fails a fetch in which no query answered, and caches nothing", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("getaddrinfo ENOTFOUND hn.algolia.com"); }));
    const hn = fetcher();
    await expect(hn.fetch(["react", "typescript"])).rejects.toThrow(/Hacker News did not answer \(.*ENOTFOUND/);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ hits: [story] }), { status: 200 })));
    expect((await hn.fetch(["react", "typescript"])).length).toBeGreaterThan(0);
  });

  it("an HTTP error is a failed query, not an empty one", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("down", { status: 503 })));
    await expect(fetcher().fetch(["react"])).rejects.toThrow(/HTTP 503/);
  });

  it("an answer with no hits is still an answer", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ hits: [] }), { status: 200 })));
    expect(await fetcher().fetch(["react"])).toEqual([]);
  });

  it("ecosystem_pulse says NOT CHECKED, never 'No relevant headlines', when the fetch failed", async () => {
    const { executeEcosystemPulse } = await import("../tools/ecosystem-pulse.js");
    const live = {
      getHeadlines: () => [],
      isEnabled: () => true,
      fetchHeadlines: async () => [],
      getHeadlineError: () => "Hacker News did not answer (HTTP 503)",
    };
    const db = { isStandalone: true, getRawDb: () => ({ prepare: () => ({ all: () => [{ name: "react" }], get: () => undefined }) }) };
    const result = await executeEcosystemPulse(db as never, {}, live as never);
    expect(result.headlines).toEqual([]);
    expect(result.note).toMatch(/^NOT CHECKED: Hacker News did not answer \(HTTP 503\)/);
  });
});
