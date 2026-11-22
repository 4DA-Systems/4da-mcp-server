// SPDX-License-Identifier: Apache-2.0
/**
 * One 25-item batch of Go modules must be answerable in one call. One item costs up to
 * GO_READS_PER_ITEM reads behind this server's own Go request limit (the version list, the newest
 * go.mod for its retractions, the `.info` of `to` and `from`), so a batch is about 100; a limit of
 * 60 a minute left a third of a batch unknown and a retry did not help for a minute. The default
 * limit now holds a whole batch without waiting; past it, reads wait in line within the call's time,
 * and an item the line cannot reach in time is NOT CHECKED with the limit named and the retry time.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import { DEFAULT_RATE_LIMITS, RateLimiter, type LimiterClock } from "../live/rate-limiter.js";
import { GO_READS_PER_ITEM } from "../live/go-releases.js";
import { runWithCallBudget } from "../call-budget.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";
import { ManualClock, liveWithGoLimiter, newDb } from "./helpers/a1123-golimit-clock.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-23T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const MODULES = Array.from({ length: 25 }, (_, i) => `example.com/mod${i}`);
const items = MODULES.map((m) => ({ ecosystem: "Go", package: m, from: "v1.0.0", to: "v1.1.0" }));

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  for (const m of MODULES) net.go[m] = { info: { "v1.0.0": daysAgo(400), "v1.1.0": daysAgo(90) }, mods: { "*": `module ${m}\n\ngo 1.21\n` } };
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

const inCall = <T>(work: () => Promise<T>) => runWithCallBudget(Date.now(), work);

describe("a 25-item Go batch and this server's own Go request limit", () => {
  it("one item costs at most GO_READS_PER_ITEM limited reads, and the default limit holds a whole batch", async () => {
    const limiter = new RateLimiter({ go: { maxPerMinute: 10_000 } }, new ManualClock());
    const acquire = vi.spyOn(limiter, "acquire");
    const out = await inCall(() => executeDependencyCheck(noDb, { items }, liveWithGoLimiter(newDb(), limiter), { now: NOW }));
    expect(out.results.map((r) => r.verdict)).toEqual(items.map(() => "proceed"));
    const goReads = acquire.mock.calls.filter(([source]) => source === "go").length;
    expect(goReads).toBeLessThanOrEqual(GO_READS_PER_ITEM * items.length);
    expect(DEFAULT_RATE_LIMITS.go.maxPerMinute).toBeGreaterThanOrEqual(GO_READS_PER_ITEM * items.length);
  });

  it("with the default limit a fresh 25-item batch is answered whole, no read waiting and none refused", async () => {
    const clock = new ManualClock();
    const live = liveWithGoLimiter(newDb(), new RateLimiter(DEFAULT_RATE_LIMITS, clock));
    const out = await inCall(() => executeDependencyCheck(noDb, { items }, live, { now: NOW }));
    expect(out.results.filter((r) => r.verdict !== "proceed").map((r) => `${r.package}: ${r.reason}`)).toEqual([]);
    expect(clock.slept).toEqual([]);
    expect(out.summary).not.toMatch(/NOT CHECKED/);
  });

  it("a bucket already spent: reads wait in line, and the items the line cannot reach in time say the limit and when to ask again", async () => {
    const clock = new TickingClock();
    const limiter = new RateLimiter(DEFAULT_RATE_LIMITS, clock);
    while (limiter.consume("go"));
    const live = liveWithGoLimiter(newDb(), limiter);
    const out = await clock.runUntil(inCall(() => executeDependencyCheck(noDb, { items }, live, { now: NOW })));
    const answered = out.results.filter((r) => r.verdict === "proceed");
    const held = out.results.filter((r) => r.verdict !== "proceed");
    // Some reads waited their turn and were answered; the rest were held back, never guessed.
    expect(clock.waits.length).toBeGreaterThan(0);
    expect(answered.length).toBeGreaterThan(0);
    expect(held.length).toBeGreaterThan(0);
    for (const r of held) {
      expect(r.verdict).toBe("unknown");
      expect(r.reason).toContain("this server's own request limit for the Go proxy was reached");
      expect(r.reason).not.toMatch(/could not be reached|gives no publish time|time budget/);
      expect(r.retry_after_seconds).toBeGreaterThanOrEqual(1);
    }
    expect(out.summary).toMatch(new RegExp(`^NOT CHECKED: ${held.length} of 25 items could not be checked: this server's own request limit for the Go proxy was reached`));
  });
});

/** A clock whose sleeps end only as the test moves time on (runUntil ticks it while the work runs). */
class TickingClock implements LimiterClock {
  private t = Date.parse("2026-11-23T00:00:00Z");
  readonly waits: number[] = [];
  private timers: Array<{ at: number; done: () => void }> = [];
  now(): number {
    return this.t;
  }
  sleep(ms: number): Promise<void> {
    this.waits.push(ms);
    return new Promise((done) => this.timers.push({ at: this.t + ms, done }));
  }
  /** Advance 100 ms at a time, letting the work run between ticks, until it settles. */
  async runUntil<T>(work: Promise<T>): Promise<T> {
    let settled = false;
    const done = work.finally(() => {
      settled = true;
    });
    while (!settled) {
      await new Promise((resolve) => setImmediate(resolve));
      this.t += 100;
      const due = this.timers.filter((x) => x.at <= this.t);
      this.timers = this.timers.filter((x) => x.at > this.t);
      for (const x of due) x.done();
    }
    return done;
  }
}
