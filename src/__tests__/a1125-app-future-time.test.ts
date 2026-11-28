// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, G-5 (db.ts side): a feed whose last fetch time is in the future read as
 * fetched this minute ("fresh") forever: the age was clamped to 0. A timestamp more than a few
 * minutes ahead of this clock now reads as stale, with the reason, and no age.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FourDADatabase, FUTURE_SKEW_MINUTES, futureTimestamp, minutesSince } from "../db.js";

const sqlUtc = (ms: number) => new Date(ms).toISOString().slice(0, 19).replace("T", " ");

let dir: string;
beforeAll(() => {
  dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-future-")));
});
afterAll(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));

function freshnessWithLastFetch(ts: string, name: string) {
  const db = new FourDADatabase(path.join(dir, `${name}.db`));
  try {
    db.getRawDb().prepare("INSERT INTO sources (source_type, name, last_fetch) VALUES ('hn', 'HN', ?)").run(ts);
    return db.getFreshness();
  } finally {
    db.close();
  }
}

describe("G-5: a last fetch in the future is not fresh", () => {
  it("minutesSince keeps the sign; only beyond the skew is a timestamp in the future", () => {
    const now = Date.UTC(2026, 10, 25, 12, 0, 0);
    expect(minutesSince("2026-11-25 11:30:00", now)).toBe(30);
    expect(minutesSince("2026-11-25 13:00:00", now)).toBe(-60);
    expect(futureTimestamp(-60)).toBe(true);
    expect(futureTimestamp(-FUTURE_SKEW_MINUTES)).toBe(false);
    expect(futureTimestamp(0)).toBe(false);
    expect(futureTimestamp(null)).toBe(false);
  });

  it("a last fetch a year ahead is stale, with no age, and the note says why", () => {
    const f = freshnessWithLastFetch(sqlUtc(Date.now() + 365 * 86_400_000), "year-ahead");
    expect(f.is_stale).toBe(true);
    expect(f.age_minutes).toBeNull();
    expect(f.note).toMatch(/in the future/);
    expect(f.note).not.toMatch(/\(fresh\)/);
  });

  it("a last fetch a minute ahead (clock skew) still reads as fresh, age 0", () => {
    const f = freshnessWithLastFetch(sqlUtc(Date.now() + 60_000), "skew");
    expect(f.is_stale).toBe(false);
    expect(f.age_minutes).toBe(0);
  });

  it("a last fetch ten minutes ago is fresh, age 10", () => {
    const f = freshnessWithLastFetch(sqlUtc(Date.now() - 10 * 60_000), "recent");
    expect(f.is_stale).toBe(false);
    expect(f.age_minutes).toBe(10);
  });
});
