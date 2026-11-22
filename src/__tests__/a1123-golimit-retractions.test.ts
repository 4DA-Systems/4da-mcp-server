// SPDX-License-Identifier: Apache-2.0
/**
 * A Go module's retractions are listed in the go.mod of its newest version. When that file could
 * not be read (the server's own Go request limit refused the read, the proxy answered an error,
 * the request failed), the version list was kept with no retractions and cached for an hour, so a
 * retracted release came back `proceed` ("No advisory or age concern found") in every session on
 * that home. Now an unread retraction list makes the item `unknown`, saying the retractions were
 * not checked, and nothing is cached for the module; only a list actually read (an empty one
 * included) is cached.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import { GoReleasesReader } from "../live/go-releases.js";
import { LiveCache } from "../live/cache.js";
import { RateLimiter } from "../live/rate-limiter.js";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck, runDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";
import { ManualClock, goCacheKeys, liveWithGoLimiter, newDb } from "./helpers/a1123-golimit-clock.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-23T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const LZ4 = "example.com/lz4/v4";
const NEWEST_MOD = `module ${LZ4}\n\ngo 1.21\n\nretract v4.1.26 // Writer.ReadFrom leaves the frame unfinished\n`;

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  net.go[LZ4] = {
    info: { "v4.1.25": daysAgo(500), "v4.1.26": daysAgo(400), "v4.1.34": daysAgo(60) },
    mods: { "v4.1.34": NEWEST_MOD, "*": `module ${LZ4}\n\ngo 1.21\n` },
  };
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

const item = { ecosystem: "Go", package: LZ4, to: "v4.1.26" };

/** Four Go reads a minute (one every 15 s), three of them already spent. */
function drained(clock: ManualClock): RateLimiter {
  const limiter = new RateLimiter({ go: { maxPerMinute: 4 } }, clock);
  for (let i = 0; i < 3; i++) limiter.consume("go");
  return limiter;
}
const check = (live: LiveIntelligence, items: unknown[] = [item]) => executeDependencyCheck(noDb, { items }, live, { now: NOW });

describe("Go retractions that could not be read", () => {
  it("the proxy answering an error for the newest go.mod: unknown, nothing cached, and the next call reads it and says avoid", async () => {
    const db = newDb();
    net.failing = ["/@v/v4.1.34.mod"];
    const first = (await check(new LiveIntelligence(db))).results[0];
    expect(first.verdict).toBe("unknown");
    expect(first.reason).toMatch(/whether v4\.1\.26 is retracted was not checked/i);
    expect(first.reason).toContain("HTTP 503");
    expect(first.reason).not.toMatch(/concern found/);
    expect(first).not.toHaveProperty("retry_after_seconds");
    expect(goCacheKeys(db, "go-releases:")).toEqual([]);

    // The proxy answers again: a new live layer on the same home reads the retraction.
    net.failing = [];
    const second = (await check(new LiveIntelligence(db))).results[0];
    expect(second.verdict).toBe("avoid");
    expect(second.signals.find((s) => s.id === "yanked_or_deprecated")).toMatchObject({ value: { retracted: true }, effect: "avoid" });
    expect(goCacheKeys(db, "go-releases:")).toEqual([`go-releases:${LZ4}`]);
  });

  it("this server's own Go request limit refusing the read: unknown in those words with retry_after_seconds, never cached, never proceed", async () => {
    const db = newDb();
    const clock = new ManualClock();
    // One read left, the next one 15 s away (longer than a read waits in line): the version list
    // takes it, and the go.mod of v4.1.34 is not read.
    const limiter = drained(clock);
    const live = liveWithGoLimiter(db, limiter);
    const first = (await check(live)).results[0];
    expect(first.verdict).toBe("unknown");
    expect(first.reason).toMatch(/whether v4\.1\.26 is retracted was not checked/i);
    expect(first.reason).toContain("this server's own request limit for the Go proxy");
    expect(first.reason).not.toMatch(/could not be reached|gives no publish time|concern found/);
    expect(first.retry_after_seconds).toBe(15);
    expect(net.requests.filter((r) => r.endsWith("/@v/v4.1.34.mod"))).toEqual([]);
    expect(goCacheKeys(db, "go-releases:")).toEqual([]);

    // A minute later every read is made: the retraction is found.
    clock.advance(10 * 60_000);
    const second = (await check(live)).results[0];
    expect(second.verdict).toBe("avoid");
    expect(second).not.toHaveProperty("retry_after_seconds");
  });

  it("the concise answer carries retry_after_seconds and the summary says to call again for that item", async () => {
    const live = liveWithGoLimiter(newDb(), drained(new ManualClock()));
    const out = (await runDependencyCheck(noDb, { items: [item] }, live)) as { summary: string; results: Array<Record<string, unknown>> };
    expect(out.results[0]).toMatchObject({ verdict: "unknown", retry_after_seconds: 15 });
    expect(out.summary).toMatch(/^NOT CHECKED: 1 of 1 item could not be checked: this server's own request limit for the Go proxy was reached/);
    expect(out.summary).toContain("Call dependency_check again for it in 15 s (retry_after_seconds)");
  });
});

describe("GoReleasesReader.getReleases", () => {
  it("caches only a retraction list it read; an empty one counts as read", async () => {
    const db = newDb();
    const reader = new GoReleasesReader(new LiveCache(db), new RateLimiter({ go: { maxPerMinute: 60 } }, new ManualClock()));
    net.failing = ["/@v/v4.1.34.mod"];
    const failed = await reader.getReleases(LZ4, ["v4.1.26"]);
    expect(failed).toMatchObject({ status: "unreachable", withdrawalsUnread: "the go.mod of v4.1.34" });
    expect(goCacheKeys(db, "go-releases:")).toEqual([]);

    net.failing = [];
    net.go[LZ4].mods!["v4.1.34"] = `module ${LZ4}\n\ngo 1.21\n`;
    const read = await reader.getReleases(LZ4, ["v4.1.26"]);
    expect(read.status).toBe("ok");
    expect(read.status === "ok" && read.data.releases["v4.1.26"].withdrawn).toBeNull();
    expect(goCacheKeys(db, "go-releases:")).toEqual([`go-releases:${LZ4}`]);
  });

  it("a request that throws for the newest go.mod is not a read either", async () => {
    const db = newDb();
    const reader = new GoReleasesReader(new LiveCache(db), new RateLimiter({ go: { maxPerMinute: 60 } }, new ManualClock()));
    const realFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith("/@v/v4.1.34.mod")) throw new TypeError("fetch failed (simulated reset)");
      return realFetch(url, init);
    }));
    const failed = await reader.getReleases(LZ4, ["v4.1.26"]);
    expect(failed).toMatchObject({ status: "unreachable", withdrawalsUnread: "the go.mod of v4.1.34" });
    expect(failed.status === "unreachable" && failed.detail).toContain("fetch failed");
    expect(goCacheKeys(db, "go-releases:")).toEqual([]);
  });
});
