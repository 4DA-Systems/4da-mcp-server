// SPDX-License-Identifier: Apache-2.0
/**
 * A limiter clock for the a1123-golimit tests: time moves only when a waiter sleeps or the test
 * advances it, so a test that waits for the Go limiter's tokens never waits in real time.
 */

import Database from "better-sqlite3";
import { LiveIntelligence } from "../../live/index.js";
import type { LiveCache } from "../../live/cache.js";
import { GoReleasesReader } from "../../live/go-releases.js";
import { RateLimiter, type LimiterClock } from "../../live/rate-limiter.js";

export class ManualClock implements LimiterClock {
  /** Every wait a limiter slept, in ms. */
  readonly slept: number[] = [];
  constructor(private t = Date.parse("2026-11-23T00:00:00Z")) {}
  now(): number {
    return this.t;
  }
  sleep(ms: number): Promise<void> {
    this.slept.push(ms);
    this.t += ms;
    return Promise.resolve();
  }
  advance(ms: number): void {
    this.t += ms;
  }
}

/** A live layer over `db` whose Go proxy reader uses `limiter` (the live layer's own cache kept). */
export function liveWithGoLimiter(db: Database.Database, limiter: RateLimiter): LiveIntelligence {
  const live = new LiveIntelligence(db);
  const inner = live as unknown as { cache: LiveCache; goReleases: GoReleasesReader };
  inner.goReleases = new GoReleasesReader(inner.cache, limiter);
  return live;
}

/** The Go proxy cache keys `db` holds now, by prefix. */
export function goCacheKeys(db: Database.Database, prefix: string): string[] {
  return (db.prepare("SELECT cache_key FROM live_cache WHERE cache_key LIKE ? ORDER BY cache_key").all(`${prefix}%`) as Array<{ cache_key: string }>).map((r) => r.cache_key);
}

export function newDb(): Database.Database {
  return new Database(":memory:");
}
