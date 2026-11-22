// SPDX-License-Identifier: Apache-2.0

interface Bucket {
  /** Below zero while waiters hold reservations on tokens that have not refilled yet (acquire). */
  tokens: number;
  maxTokens: number;
  refillRate: number; // tokens per second
  lastRefill: number; // timestamp ms
}

/** The time a limiter reads and the wait it sleeps; tests pass one that needs no real waiting. */
export interface LimiterClock {
  now(): number;
  sleep(ms: number): Promise<void>;
}

const SYSTEM_CLOCK: LimiterClock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms).unref()),
};

export class RateLimiter {
  private buckets: Map<string, Bucket> = new Map();

  constructor(
    config: Record<string, { maxPerMinute: number }>,
    private readonly clock: LimiterClock = SYSTEM_CLOCK,
  ) {
    for (const [source, { maxPerMinute }] of Object.entries(config)) {
      this.buckets.set(source, {
        tokens: maxPerMinute,
        maxTokens: maxPerMinute,
        refillRate: maxPerMinute / 60,
        lastRefill: clock.now(),
      });
    }
  }

  /** The limiter's own time (epoch ms): the clock a deadline passed to acquire is read against. */
  now(): number {
    return this.clock.now();
  }

  canProceed(source: string): boolean {
    const bucket = this.buckets.get(source);
    if (!bucket) return true;
    this.refill(bucket);
    return bucket.tokens >= 1;
  }

  consume(source: string): boolean {
    const bucket = this.buckets.get(source);
    if (!bucket) return true;
    this.refill(bucket);
    if (bucket.tokens < 1) return false;
    bucket.tokens -= 1;
    return true;
  }

  /**
   * Take a token, waiting for one to refill when the bucket is empty, as long
   * as it arrives by `deadline` (epoch ms, on this limiter's clock). False
   * when it would not: the caller then has no answer for that request and
   * must say so, never treat it as an empty one. Waiters are served in the
   * order they asked: each reserves the next token to refill, so a later
   * caller never takes the token an earlier one is waiting for.
   */
  async acquire(source: string, deadline: number): Promise<boolean> {
    const bucket = this.buckets.get(source);
    if (!bucket) return true;
    this.refill(bucket);
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return true;
    }
    const wait = Math.max(1, Math.ceil(((1 - bucket.tokens) / bucket.refillRate) * 1000));
    if (this.clock.now() + wait > deadline) return false;
    bucket.tokens -= 1;
    await this.clock.sleep(wait);
    return true;
  }

  /** Milliseconds until the next token no waiter has reserved refills (0 when one is free now). */
  waitTimeMs(source: string): number {
    const bucket = this.buckets.get(source);
    if (!bucket) return 0;
    this.refill(bucket);
    if (bucket.tokens >= 1) return 0;
    const deficit = 1 - bucket.tokens;
    return Math.ceil((deficit / bucket.refillRate) * 1000);
  }

  /** Whole seconds until a request this limiter refuses now could be made (at least 1). */
  retryAfterSeconds(source: string): number {
    return Math.max(1, Math.ceil(this.waitTimeMs(source) / 1000));
  }

  private refill(bucket: Bucket): void {
    const now = this.clock.now();
    const elapsed = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + elapsed * bucket.refillRate);
    bucket.lastRefill = now;
  }
}

export const DEFAULT_RATE_LIMITS = {
  // querybatch requests (1,000 dependencies each). OSV.dev publishes no
  // per-client limit for it and osv-scanner sends a tree's batches back to
  // back; 10 a minute made any tree over 10,000 dependencies fail outright
  // (D:\4DA\src-tauri, 10,568, reported 0 vulnerable on 2026-10-12). A burst
  // of 60 covers 60,000 dependencies; past that a scan waits for tokens.
  osv: { maxPerMinute: 60 },
  // Per-package advisory lists for fix-path checks (/v1/query), one request per vulnerable package.
  "osv-package": { maxPerMinute: 300 },
  // Fix-path lookups on registry CDNs (crates.io sparse index, abbreviated npm
  // documents): separate from the API buckets so a plan never starves health checks.
  "fixpath-registry": { maxPerMinute: 600 },
  hn: { maxPerMinute: 30 },
  npm: { maxPerMinute: 120 },
  crates: { maxPerMinute: 50 },
  pypi: { maxPerMinute: 60 },
  go: { maxPerMinute: 60 },
};
