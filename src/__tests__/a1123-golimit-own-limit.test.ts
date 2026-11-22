// SPDX-License-Identifier: Apache-2.0
/**
 * This server's own request limit for the Go proxy is this server's doing, never the proxy's: when
 * it holds a read back, the item is unknown with that said in those words and `retry_after_seconds`,
 * never "registry could not be reached" or "the registry gives no publish time" (healthy modules
 * came back unknown with both, and a retry did not help for about a minute). A read the limit can
 * let through within the call's time waits in line instead of being dropped.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import { RateLimiter } from "../live/rate-limiter.js";
import { GO_QUEUE_MAX_WAIT_MS } from "../live/go-releases.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";
import { ManualClock, goCacheKeys, liveWithGoLimiter, newDb } from "./helpers/a1123-golimit-clock.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-23T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const TESTIFY = "example.com/testify";
const item = { ecosystem: "Go", package: TESTIFY, from: "v1.11.1", to: "v1.12.1" };
const FALSE_BLAME = /could not be reached|gives no publish time|Registry/;

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  net.go[TESTIFY] = { info: { "v1.11.1": daysAgo(400), "v1.12.1": daysAgo(90) }, mods: { "*": `module ${TESTIFY}\n\ngo 1.21\n` } };
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

/** `left` of four reads a minute still free (the next one 15 s away, longer than a read waits in line). */
function limiterWith(clock: ManualClock, left: number): RateLimiter {
  const limiter = new RateLimiter({ go: { maxPerMinute: 4 } }, clock);
  for (let i = 0; i < 4 - left; i++) limiter.consume("go");
  return limiter;
}

const proxyRequests = () => net.requests.filter((r) => r.includes("proxy.golang.org"));

describe("this server's own Go request limit", () => {
  it("holding back the version list: unknown in those words, retry_after_seconds, nothing sent", async () => {
    expect(GO_QUEUE_MAX_WAIT_MS).toBeLessThan(15_000);
    const live = liveWithGoLimiter(newDb(), limiterWith(new ManualClock(), 0));
    const r = (await executeDependencyCheck(noDb, { items: [item] }, live, { now: NOW })).results[0];
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toContain("this server's own request limit for the Go proxy was reached");
    expect(r.reason).toContain("the Go proxy was not asked and is not at fault");
    expect(r.reason).not.toMatch(FALSE_BLAME);
    expect(r.retry_after_seconds).toBe(15);
    // The reads the limit governs were never sent (the module-path check reads `to`'s go.mod first, outside it).
    expect(proxyRequests().filter((u) => /\/@v\/list$|\.info$/.test(u))).toEqual([]);
  });

  it("holding back a judged version's .info: the same, never 'the registry gives no publish time', and its date is not cached as missing", async () => {
    const db = newDb();
    const clock = new ManualClock();
    // The list and the newest go.mod are read; neither .info is.
    const live = liveWithGoLimiter(db, limiterWith(clock, 2));
    const r = (await executeDependencyCheck(noDb, { items: [item] }, live, { now: NOW })).results[0];
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toContain("this server's own request limit for the Go proxy was reached");
    expect(r.reason).not.toMatch(FALSE_BLAME);
    expect(r.signals.find((s) => s.id === "release_age")).toBeUndefined();
    expect(r.retry_after_seconds).toBe(15);
    expect(goCacheKeys(db, "go-info:")).toEqual([]);
    // The list itself was read whole and is kept.
    expect(goCacheKeys(db, "go-releases:")).toEqual([`go-releases:${TESTIFY}`]);

    // Asked again once the limit allows it: the cached list and two new reads give the real answer.
    clock.advance(60_000);
    const again = (await executeDependencyCheck(noDb, { items: [item] }, live, { now: NOW })).results[0];
    expect(again.verdict).toBe("proceed");
    expect(again).not.toHaveProperty("retry_after_seconds");
    expect(again.signals.find((s) => s.id === "release_age")).toMatchObject({ effect: "proceed", value: { published_at: daysAgo(90) } });
  });

  it("holding back a release's own go.mod (what it requires): unknown, and the proxy is not blamed", async () => {
    const limiter = new RateLimiter({ go: { maxPerMinute: 60 }, "fixpath-registry": { maxPerMinute: 4 } }, new ManualClock());
    while (limiter.consume("fixpath-registry"));
    const live = liveWithGoLimiter(newDb(), limiter);
    // v1.11.1 is not the newest release, so its go.mod is read on its own (the newest one's comes with the retractions).
    const r = (await executeDependencyCheck(noDb, { items: [{ ecosystem: "Go", package: TESTIFY, to: "v1.11.1" }] }, live, { now: NOW })).results[0];
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toContain("its requirement list was not read: this server's own request limit for the Go proxy was reached");
    expect(r.reason).not.toMatch(/could not be read from the Go module proxy/);
  });

  it("an empty bucket that refills within the wait: the reads wait in line and the item is answered", async () => {
    const clock = new ManualClock();
    const limiter = new RateLimiter({ go: { maxPerMinute: 60 } }, clock);
    while (limiter.consume("go"));
    const live = liveWithGoLimiter(newDb(), limiter);
    const r = (await executeDependencyCheck(noDb, { items: [item] }, live, { now: NOW })).results[0];
    expect(r.verdict).toBe("proceed");
    expect(r).not.toHaveProperty("retry_after_seconds");
    // Four reads (version list, newest go.mod, two .info), each waiting its turn for a token (one a second), none dropped.
    expect(clock.slept.length).toBe(4);
    expect(proxyRequests().filter((u) => /\/@v\/list$|\.info$/.test(u))).toHaveLength(3);
  });

  it("waiters are served in the order they asked: none, and no caller that does not wait, takes a token an earlier one waits for", async () => {
    const clock = new SteppedClock();
    const limiter = new RateLimiter({ go: { maxPerMinute: 60 } }, clock);
    while (limiter.consume("go"));
    const served: string[] = [];
    const waiters = ["a", "b", "c"].map((id) => limiter.acquire("go", clock.now() + 10_000).then((ok) => ok && served.push(id)));
    // Each reserved the next token to refill: the waits grow by one refill (1 s) each.
    expect(clock.waits).toEqual([1000, 2000, 3000]);
    // One that cannot wait long enough is refused at once, and takes nothing from the line.
    expect(await limiter.acquire("go", clock.now() + 500)).toBe(false);
    await clock.advance(1000);
    expect(served).toEqual(["a"]);
    // A caller that does not wait finds no free token while others wait for theirs.
    expect(limiter.consume("go")).toBe(false);
    await clock.advance(2000);
    await Promise.all(waiters);
    expect(served).toEqual(["a", "b", "c"]);
    expect(limiter.retryAfterSeconds("go")).toBe(1);
  });
});

/** A clock whose sleeps end only when the test moves time past them. */
class SteppedClock {
  private t = 0;
  readonly waits: number[] = [];
  private timers: Array<{ at: number; done: () => void }> = [];
  now(): number {
    return this.t;
  }
  sleep(ms: number): Promise<void> {
    this.waits.push(ms);
    return new Promise((done) => this.timers.push({ at: this.t + ms, done }));
  }
  async advance(ms: number): Promise<void> {
    this.t += ms;
    const due = this.timers.filter((x) => x.at <= this.t).sort((x, y) => x.at - y.at);
    this.timers = this.timers.filter((x) => x.at > this.t);
    for (const x of due) x.done();
    await new Promise((resolve) => setImmediate(resolve));
  }
}
