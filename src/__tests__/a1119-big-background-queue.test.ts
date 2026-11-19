// SPDX-License-Identifier: Apache-2.0
/**
 * The background queue (record-queue.ts) finishes the advisory records a call ran out of time for.
 * It is bounded: a fixed number of reads at once, a fixed ceiling on what waits, ids only in
 * memory, nothing new once the server shuts down, and every read under the private-name rules of
 * the project that queued it. A hostile OSV.dev answer naming thousands of ids cannot use it to
 * send more requests than the per-scan limit.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { AsyncLocalStorage } from "node:async_hooks";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { MAX_DETAIL_FETCHES, OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import { BACKGROUND_CONCURRENCY, BACKGROUND_MAX_QUEUED, RecordQueue } from "../live/record-queue.js";
import { refusePrivateRequest, withPrivateContext, type PrivateNameSource } from "../live/private-guard.js";
import type { ResolvedDependency } from "../live/types.js";

const dep = (name: string, version = "1.0.0"): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [],
});
const id = (n: number) => `GHSA-${String(n).padStart(4, "0")}-aaaa-bbbb`;

/** Reads the test settles by hand, counted. */
function heldReads() {
  const started: string[] = [];
  const settle = new Map<string, () => void>();
  let running = 0;
  let maxRunning = 0;
  const read = (rid: string) =>
    new Promise<void>((resolve) => {
      started.push(rid);
      running++;
      maxRunning = Math.max(maxRunning, running);
      settle.set(rid, () => {
        running--;
        resolve();
      });
    });
  const finish = async (n = Infinity) => {
    for (const [rid, done] of [...settle].slice(0, n)) {
      settle.delete(rid);
      done();
    }
    for (let i = 0; i < 5; i++) await Promise.resolve();
  };
  return { started, read, finish, stats: () => ({ running, maxRunning }) };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("RecordQueue", () => {
  it("runs a fixed number of reads at once, whatever is queued", async () => {
    expect(BACKGROUND_CONCURRENCY).toBe(16);
    const r = heldReads();
    const q = new RecordQueue({ signal: new AbortController().signal });
    q.enqueue(Array.from({ length: 100 }, (_, i) => id(i)), r.read);
    expect(r.started).toHaveLength(BACKGROUND_CONCURRENCY);
    while (q.size > 0) await r.finish();
    expect(r.started).toHaveLength(100);
    expect(r.stats().maxRunning).toBe(BACKGROUND_CONCURRENCY);
    await q.drained();
  });

  it("refuses what is past its ceiling, says which, and queues an id only once", () => {
    expect(BACKGROUND_MAX_QUEUED).toBe(2_000);
    const r = heldReads();
    const q = new RecordQueue({ concurrency: 1, maxQueued: 5, signal: new AbortController().signal });
    const first = q.enqueue([id(0), id(1), id(2)], r.read);
    expect(first).toEqual({ taken: [id(0), id(1), id(2)], refused: [] });
    // id(0) is running, id(1) and id(2) wait: offering them again takes them without a second entry,
    // and three more fill the five places.
    const second = q.enqueue([id(1), id(2), id(3), id(4), id(5), id(6), id(7)], r.read);
    expect(second.taken).toEqual([id(1), id(2), id(3), id(4), id(5)]);
    expect(second.refused).toEqual([id(6), id(7)]);
    expect(q.size).toBe(1 + 5);
  });

  it("starts nothing once shut down: the waiting reads are dropped and new ones refused", async () => {
    const r = heldReads();
    const stop = new AbortController();
    const q = new RecordQueue({ concurrency: 2, signal: stop.signal });
    q.enqueue([id(0), id(1), id(2), id(3)], r.read);
    expect(r.started).toEqual([id(0), id(1)]);
    stop.abort();
    expect(q.enqueue([id(9)], r.read)).toEqual({ taken: [], refused: [id(9)] });
    await r.finish();
    expect(r.started).toEqual([id(0), id(1)]);
    expect(q.size).toBe(0);
    await q.drained();
  });

  it("waits while canStart says no, and starts when it says yes", async () => {
    vi.useFakeTimers();
    try {
      let open = false;
      const r = heldReads();
      const q = new RecordQueue({ signal: new AbortController().signal, canStart: () => open });
      q.enqueue([id(0), id(1)], r.read);
      expect(r.started).toEqual([]);
      open = true;
      await vi.advanceTimersByTimeAsync(150);
      expect(r.started).toEqual([id(0), id(1)]);
      await r.finish();
      await q.drained();
    } finally {
      vi.useRealTimers();
    }
  });

  it("a read runs outside the tool call that queued it, under that call's project's private-name rules", async () => {
    const call = new AsyncLocalStorage<string>();
    const project: PrivateNameSource = { privateReason: (_eco: string, name: string) => (name === "acme-internal" ? "named in FOURDA_PRIVATE_PACKAGES" : null) };
    const seen: Array<{ call: string | undefined; refused: boolean }> = [];
    const q = new RecordQueue({ signal: new AbortController().signal });
    await call.run("call-1", () =>
      withPrivateContext(project, async () => {
        q.enqueue([id(1)], async () => {
          let refused = false;
          try {
            refusePrivateRequest("https://registry.npmjs.org/acme-internal");
          } catch {
            refused = true;
          }
          seen.push({ call: call.getStore(), refused });
        });
      }),
    );
    await q.drained();
    expect(seen).toEqual([{ call: undefined, refused: true }]);
  });
});

/** OSV stub: `idsFor(name)` are a dependency's advisory ids; record requests are counted and answered after `recordMs`. */
function stubOsv(idsFor: (name: string) => string[], recordMs = 0) {
  const stats = { records: 0, urls: [] as string[] };
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      return new Response(JSON.stringify({ results: queries.map((q) => ({ vulns: idsFor(q.package.name).map((v) => ({ id: v })) })) }), { status: 200 });
    }
    if (url.includes("/v1/vulns/")) {
      stats.records++;
      stats.urls.push(url);
      if (recordMs > 0) await new Promise((resolve) => setTimeout(resolve, recordMs));
      const asked = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
      return new Response(JSON.stringify({ id: asked, summary: `advisory ${asked}`, database_specific: { severity: "HIGH" } }), { status: 200 });
    }
    return new Response("{}", { status: 503 });
  });
  return stats;
}

describe("a hostile answer and the background queue", () => {
  it("a scan cut short by its deadline hands on only what its per-scan limit allows: 22,973 ids cost at most MAX_DETAIL_FETCHES requests", async () => {
    const flood = Array.from({ length: 22_973 }, (_, i) => id(i));
    // 23 dependencies with 999 advisories each (under the per-dependency limit), all distinct.
    const idsFor = (name: string) => flood.slice(Number(name.split("-")[1]) * 999, Number(name.split("-")[1]) * 999 + 999);
    const deps = Array.from({ length: 23 }, (_, i) => dep(`pkg-${i}`));
    const stats = stubOsv(idsFor, 5);
    const stop = new AbortController();
    const queue = new RecordQueue({ signal: stop.signal });
    const cache = new LiveCache(new Database(":memory:"));
    const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
    const scanner = new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter, undefined, { background: queue }), { aliasBudgetMs: 50 });

    // Records stop 1.5 s before the deadline (POST_RECORDS_MS): a deadline that has passed starts
    // none in the scan itself, and the queue starts at most its own concurrency at once.
    const result = await scanner.scan(deps, "/proj", { deadline: Date.now() });
    expect(stats.records).toBeLessThanOrEqual(BACKGROUND_CONCURRENCY);
    // Not clean, not complete: every advisory is NOT CHECKED, and the queue reads on within the limit.
    expect(result.cleanCount).toBe(0);
    expect(result.detailsUnchecked?.length).toBe(22_973);
    expect(result.detailsInBackground).toBe(MAX_DETAIL_FETCHES);
    expect(queue.size).toBeLessThanOrEqual(MAX_DETAIL_FETCHES);
    await queue.drained();
    expect(stats.records).toBe(MAX_DETAIL_FETCHES);
    // Every request the queue made was a record request for an id OSV.dev named.
    expect(stats.urls.every((u) => /^https:\/\/api\.osv\.dev\/v1\/vulns\/GHSA-\d{4,5}-aaaa-bbbb$/.test(u))).toBe(true);
    // Nothing more goes out once the queue is empty.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(stats.records).toBe(MAX_DETAIL_FETCHES);
    stop.abort();
  });

  it("the queue's ceiling holds across scans: what does not fit is refused and said to be", async () => {
    const stats = stubOsv((name) => Array.from({ length: 30 }, (_, i) => id(Number(name.split("-")[1]) * 30 + i)));
    const stop = new AbortController();
    // A queue that never starts a read (held back) and holds at most 40 ids.
    const queue = new RecordQueue({ maxQueued: 40, signal: stop.signal, canStart: () => false });
    const cache = new LiveCache(new Database(":memory:"));
    const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
    const scanner = new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter, undefined, { background: queue }), { aliasBudgetMs: 50 });
    const first = await scanner.scan([dep("pkg-0")], "/proj", { deadline: Date.now() });
    const second = await scanner.scan([dep("pkg-1")], "/proj", { deadline: Date.now() });
    expect(first.detailsInBackground).toBe(30);
    expect(second.detailsInBackground).toBe(10);
    expect(second.detailsNotQueued).toBe(20);
    expect(queue.size).toBe(40);
    expect(stats.records).toBe(0);
    stop.abort();
    expect(queue.size).toBe(0);
  });
});
