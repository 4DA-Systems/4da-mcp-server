// SPDX-License-Identifier: Apache-2.0
/**
 * What a warm scan no longer redoes, and how a large tree's dependency query is split.
 *
 * - OSV.dev's 404 for an advisory id is an answer, kept as long as a dependency's own answer (1 h):
 *   every warm scan of a tree with Go advisories asked again for 16 GHSA aliases OSV.dev does not
 *   hold, up to three times a call (2026-11-19). A refresh asks again.
 * - querybatch: a tree is sent as up to 8 chunks at once (at most 1,000 dependencies each); one
 *   1,000-dependency request took 2.3 to 2.9 s where a few hundred take under one.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { batchSize, OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import { RecordQueue } from "../live/record-queue.js";
import type { ResolvedDependency } from "../live/types.js";

const dep = (name: string, version = "1.0.0", ecosystem: ResolvedDependency["ecosystem"] = "npm"): ResolvedDependency => ({
  name, version, ecosystem, isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [],
});

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function scanner(db = new Database(":memory:")) {
  const cache = new LiveCache(db);
  const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
  return { db, scanner: new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter, undefined, { background: new RecordQueue({ signal: new AbortController().signal }) }), { aliasBudgetMs: 2_000 }) };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OSV.dev's 404 for a record is kept", () => {
  /** A Go module whose GO record has no severity and names a GHSA alias OSV.dev does not hold. */
  function stubGo() {
    const asked = new Map<string, number>();
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
        return json({ results: queries.map((q) => (q.package.name === "golang.org/x/net" ? { vulns: [{ id: "GO-2024-0001" }, { id: "GHSA-gone-gone-gone" }] } : {})) });
      }
      if (url.includes("/v1/vulns/")) {
        const id = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
        asked.set(id, (asked.get(id) ?? 0) + 1);
        if (id === "GO-2024-0001") return json({ id, summary: "x/net advisory", aliases: ["GHSA-alia-sgon-e404"] });
        return json({ code: 5, message: "Bug not found." }, 404);
      }
      return json({}, 503);
    });
    return asked;
  }

  it("a matched id OSV.dev holds no record for, and an alias it does not hold, are asked for once, not on every scan", async () => {
    const asked = stubGo();
    const { scanner: s } = scanner();
    const deps = [dep("golang.org/x/net", "v0.17.0", "Go")];
    const first = await s.scan(deps, "/proj");
    expect(asked.get("GHSA-gone-gone-gone")).toBe(1);
    expect(asked.get("GHSA-alia-sgon-e404")).toBe(1);
    // Still not clean: the matched id with no record is an id-only advisory, and the GO record stays unknown.
    expect(first.detailsUnchecked).toEqual(["GHSA-gone-gone-gone"]);
    expect(first.vulnerabilities.find((v) => v.vulnId === "GO-2024-0001")?.severity).toBe("unknown");
    expect(first.aliasSeverity?.unresolved).toEqual(["GHSA-alia-sgon-e404"]);

    const second = await s.scan(deps, "/proj");
    expect(asked.get("GHSA-gone-gone-gone")).toBe(1);
    expect(asked.get("GHSA-alia-sgon-e404")).toBe(1);
    expect(asked.get("GO-2024-0001")).toBe(1);
    // The same answer, from the cache.
    expect(second.detailsUnchecked).toEqual(["GHSA-gone-gone-gone"]);
    expect(second.aliasSeverity?.unresolved).toEqual(["GHSA-alia-sgon-e404"]);
  });

  it("the kept 404 lasts as long as a dependency's answer (1 h), and a refresh asks again", async () => {
    const asked = stubGo();
    const { db, scanner: s } = scanner();
    const deps = [dep("golang.org/x/net", "v0.17.0", "Go")];
    await s.scan(deps, "/proj");
    const row = db.prepare("SELECT (julianday(expires_at) - julianday(fetched_at)) * 86400 AS ttl FROM live_cache WHERE cache_key = 'osv:absent:GHSA-gone-gone-gone'").get() as { ttl: number };
    expect(Math.round(row.ttl)).toBe(3600);
    await s.scan(deps, "/proj", { refresh: true });
    expect(asked.get("GHSA-gone-gone-gone")).toBe(2);
  });

  it("a record request that fails (not a 404) is not kept: the next scan asks again", async () => {
    let calls = 0;
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
        return json({ results: queries.map(() => ({ vulns: [{ id: "GHSA-flak-yyyy-zzzz" }] })) });
      }
      if (url.includes("/v1/vulns/")) {
        calls++;
        return json({}, 503);
      }
      return json({}, 503);
    });
    const { scanner: s } = scanner();
    await s.scan([dep("left-pad")], "/proj");
    const first = calls;
    await s.scan([dep("left-pad")], "/proj");
    expect(calls).toBeGreaterThan(first);
  });
});

describe("querybatch chunks", () => {
  it("a 2,084-dependency tree goes out as 8 requests at once, none over 1,000", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const sizes: number[] = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
        sizes.push(queries.length);
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((resolve) => setTimeout(resolve, 10));
        inFlight--;
        return json({ results: queries.map(() => ({})) });
      }
      return json({}, 503);
    });
    const deps = Array.from({ length: 2_084 }, (_, i) => dep(`pkg-${i}`));
    const result = await scanner().scanner.scan(deps, "/proj");
    expect(result.unchecked).toBe(0);
    expect(result.cleanCount).toBe(2_084);
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(2_084);
    expect(sizes).toHaveLength(8);
    expect(Math.max(...sizes)).toBe(batchSize(2_084));
    expect(maxInFlight).toBe(8);
  });

  it("chunk sizes: small trees one request, large trees capped at 1,000", () => {
    expect(batchSize(50)).toBe(200);
    expect(batchSize(1_600)).toBe(200);
    expect(batchSize(2_084)).toBe(261);
    expect(batchSize(8_000)).toBe(1_000);
    expect(batchSize(250_000)).toBe(1_000);
  });
});
