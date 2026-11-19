// SPDX-License-Identifier: Apache-2.0
/**
 * readRecords (record-reader.ts): a fixed number of record requests out at once, duplicates
 * included; nothing starts after the stop time; the read answers by its deadline with what has
 * arrived and hands later answers on; a slow request gets at most one duplicate, within a cap.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readRecords, type RecordReadOptions } from "../live/record-reader.js";

/** A request the test answers by hand. */
interface Pending {
  id: string;
  duplicate: boolean;
  answer: (value: string | null) => void;
}

function controlled() {
  const out: Pending[] = [];
  let inFlight = 0;
  let maxInFlight = 0;
  const fetchOne = (id: string, duplicate: boolean) =>
    new Promise<string | null>((resolve) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      out.push({
        id,
        duplicate,
        answer: (value) => {
          inFlight--;
          resolve(value);
        },
      });
    });
  return { out, fetchOne, stats: () => ({ inFlight, maxInFlight }) };
}

const opts = (over: Partial<RecordReadOptions> = {}): RecordReadOptions => ({
  concurrency: 4,
  stopStartingAt: Number.POSITIVE_INFINITY,
  stopWaitingAt: Number.POSITIVE_INFINITY,
  hedgeAfterMs: 1_000,
  maxHedges: 2,
  ...over,
});

const ids = (n: number) => Array.from({ length: n }, (_, i) => `GHSA-${String(i).padStart(4, "0")}-aaaa-bbbb`);

/** Let the read's promise callbacks run (fake timers do not run microtasks by themselves). */
const flush = async () => {
  for (let i = 0; i < 5; i++) await Promise.resolve();
};

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("readRecords", () => {
  it("keeps at most `concurrency` requests out and reads every id once", async () => {
    const c = controlled();
    const reading = readRecords(ids(10), c.fetchOne, opts());
    for (let round = 0; round < 10 && c.out.some((p) => p); round++) {
      const open = c.out.splice(0);
      for (const p of open) p.answer(`record ${p.id}`);
      await flush();
    }
    const result = await reading;
    expect(c.stats().maxInFlight).toBe(4);
    expect(result.got.size).toBe(10);
    expect([...result.got.values()].every((v) => v.startsWith("record "))).toBe(true);
    expect(result.notStarted).toEqual([]);
    expect(result.pending).toEqual([]);
    expect(result.hedges).toBe(0);
  });

  it("starts nothing at or after stopStartingAt; what was started is still waited for", async () => {
    const c = controlled();
    const stopAt = Date.now() + 500;
    const reading = readRecords(ids(10), c.fetchOne, opts({ stopStartingAt: stopAt }));
    expect(c.out).toHaveLength(4);
    await vi.advanceTimersByTimeAsync(600);
    for (const p of c.out.splice(0)) p.answer("r");
    await flush();
    const result = await reading;
    expect(result.got.size).toBe(4);
    expect(result.notStarted).toHaveLength(6);
    expect(result.pending).toEqual([]);
  });

  it("answers at stopWaitingAt with what arrived; later answers go to onLate, and nothing new starts", async () => {
    const c = controlled();
    const late: string[] = [];
    const deadline = Date.now() + 500;
    const reading = readRecords(ids(10), c.fetchOne, opts({ stopStartingAt: deadline, stopWaitingAt: deadline }), (id) => late.push(id));
    // Two answer before the deadline; the other two and the two that took their slots are still out at it.
    c.out[0].answer("a");
    c.out[1].answer("b");
    await flush();
    expect(c.out).toHaveLength(6); // two more started in the freed slots
    await vi.advanceTimersByTimeAsync(600);
    const result = await reading;
    expect(result.got.size).toBe(2);
    expect(result.pending).toHaveLength(4);
    expect(result.notStarted).toHaveLength(4);
    const started = c.out.length;
    // The ones still out answer after the read answered: handed on, and no new request follows.
    for (const p of c.out.slice(2)) p.answer("late");
    await flush();
    expect(late.sort()).toEqual(result.pending.sort());
    expect(c.out).toHaveLength(started);
  });

  it("a request still out after hedgeAfterMs gets one duplicate once every id has a request; the first answer counts", async () => {
    const c = controlled();
    const reading = readRecords(ids(2), c.fetchOne, opts({ hedgeAfterMs: 1_000, maxHedges: 5 }));
    expect(c.out.map((p) => p.duplicate)).toEqual([false, false]);
    c.out[0].answer("fast");
    await flush();
    await vi.advanceTimersByTimeAsync(1_100);
    // One duplicate for the slow one, never a second.
    expect(c.out.filter((p) => p.duplicate).map((p) => p.id)).toEqual([ids(2)[1]]);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(c.out.filter((p) => p.duplicate)).toHaveLength(1);
    c.out[2].answer("from the duplicate");
    await flush();
    const result = await reading;
    expect(result.got.get(ids(2)[1])).toBe("from the duplicate");
    expect(result.hedges).toBe(1);
    // The original's late answer changes nothing.
    c.out[1].answer("original");
    await flush();
    expect(result.got.get(ids(2)[1])).toBe("from the duplicate");
  });

  it("sends at most maxHedges duplicates, and never more requests than `concurrency` at once", async () => {
    const c = controlled();
    const reading = readRecords(ids(6), c.fetchOne, opts({ concurrency: 8, hedgeAfterMs: 100, maxHedges: 2 }));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(c.out.filter((p) => p.duplicate)).toHaveLength(2);
    expect(c.stats().maxInFlight).toBeLessThanOrEqual(8);
    for (const p of c.out.splice(0)) p.answer("r");
    await flush();
    expect((await reading).got.size).toBe(6);
  });

  it("no duplicate is sent while ids still wait for a slot", async () => {
    const c = controlled();
    void readRecords(ids(10), c.fetchOne, opts({ concurrency: 2, hedgeAfterMs: 10, maxHedges: 5 }));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(c.out.every((p) => !p.duplicate)).toBe(true);
    expect(c.out).toHaveLength(2);
  });

  it("a failed request whose duplicate is still out waits for the duplicate; both failing is a failure", async () => {
    const c = controlled();
    const reading = readRecords(ids(2), c.fetchOne, opts({ hedgeAfterMs: 100 }));
    await vi.advanceTimersByTimeAsync(200);
    expect(c.out.filter((p) => p.duplicate)).toHaveLength(2);
    const [a, b, dupA, dupB] = c.out;
    a.answer(null);
    await flush();
    dupA.answer("rescued");
    b.answer(null);
    dupB.answer(null);
    await flush();
    const result = await reading;
    expect(result.got.get(ids(2)[0])).toBe("rescued");
    expect([...result.failed]).toEqual([ids(2)[1]]);
  });

  it("a request that throws is a failure, not a crash", async () => {
    const result = readRecords(["GHSA-aaaa-bbbb-cccc"], () => Promise.reject(new Error("boom")), opts());
    await flush();
    expect([...(await result).failed]).toEqual(["GHSA-aaaa-bbbb-cccc"]);
  });

  it("an empty list answers at once", async () => {
    const result = await readRecords([], () => Promise.resolve("x"), opts());
    expect(result.got.size).toBe(0);
  });
});
