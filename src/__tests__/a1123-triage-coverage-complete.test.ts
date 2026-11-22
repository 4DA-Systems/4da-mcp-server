// SPDX-License-Identifier: Apache-2.0
/**
 * vulnerability_scan always carries a `coverage` object, in both formats: a scan that left
 * nothing out says `complete: true` with how many lockfiles it read, instead of leaving the
 * field out (which a reader cannot tell from a field that was dropped).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import type { ResolvedDependency } from "../live/types.js";
import { conciseScanResult } from "../tools/vulnerability-scan-concise.js";
import { formatScanResult } from "../tools/vulnerability-scan-format.js";

const dep = (name: string, version: string): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: ["/app"],
});

const resolution = (kinds: Array<"lockfile" | "manifest">) => ({
  resolvedAt: "2026-11-23T00:00:00.000Z",
  sources: kinds.map((kind, i) => ({ path: `/app/${kind}-${i}`, kind, mtimeMs: 0 })),
});

function scanner(): OsvScanner {
  const cache = new LiveCache(new Database(":memory:"));
  const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter));
}

function osvAnswers(ok: boolean) {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (ok && url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
      return new Response(JSON.stringify({ results: queries.map(() => ({})) }), { status: 200 });
    }
    throw new TypeError(`fetch failed (${url})`);
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("vulnerability_scan coverage is always an object", () => {
  it("a complete scan says complete: true with the lockfiles read, detailed and concise", async () => {
    osvAnswers(true);
    const result = await scanner().scan([dep("minimist", "1.2.8"), dep("lodash", "4.17.21")], "/app");
    const ctx = { resolution: resolution(["lockfile", "lockfile", "manifest"]), reResolvedThisCall: false, drift: [], includeDev: true } as never;
    const full = formatScanResult(result, undefined, ctx) as Record<string, any>;
    expect(full.coverage).toMatchObject({ complete: true, lockfiles_read: 2, lockfiles_not_scanned: 0 });
    expect(typeof full.coverage.note).toBe("string");
    expect(full.total_vulnerable_packages).toBe(0);
    const concise = conciseScanResult(full as never) as Record<string, any>;
    expect(concise.coverage).toMatchObject({ complete: true, lockfiles_read: 2, lockfiles_not_scanned: 0 });
  });

  it("an incomplete scan still says complete: false", async () => {
    osvAnswers(false);
    const result = await scanner().scan([dep("minimist", "1.2.8")], "/app");
    const ctx = { resolution: resolution(["lockfile"]), reResolvedThisCall: false, drift: [], includeDev: true } as never;
    const full = formatScanResult(result, undefined, ctx) as Record<string, any>;
    expect(full.coverage.complete).toBe(false);
    expect((conciseScanResult(full as never) as Record<string, any>).coverage.complete).toBe(false);
  });
});
