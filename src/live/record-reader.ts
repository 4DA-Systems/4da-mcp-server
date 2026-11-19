// SPDX-License-Identifier: Apache-2.0
/**
 * Reading many advisory records (one request each) with a fixed number in flight.
 *
 * - At most `concurrency` requests are out at any moment, duplicates included.
 * - No request starts at or after `stopStartingAt`; the read stops waiting at `stopWaitingAt`. What
 *   was never started is returned (`notStarted`); what was started and has not answered is
 *   returned too (`pending`), and when it does answer `onLate` is given it.
 * - A request still out after `hedgeAfterMs`, while no other id waits for a slot, is sent once
 *   more (at most `maxHedges` per read) and the first answer counts. One slow response held a
 *   2,084-dependency scan for 2.4 s after every other record had arrived (measured 2026-11-19:
 *   3 of 661 requests took over 1.5 s; the median was 0.37 s).
 */

export interface RecordReadOptions {
  concurrency: number;
  /** Epoch ms; no request starts at or after it. */
  stopStartingAt: number;
  /** Epoch ms; the read answers by then with whatever has arrived (Infinity: when every request has). */
  stopWaitingAt: number;
  hedgeAfterMs: number;
  maxHedges: number;
}

export interface RecordReadOutcome<R> {
  /** Ids answered in time, with their answer. */
  got: Map<string, R>;
  /** Ids whose request (and duplicate, if any) failed. */
  failed: Set<string>;
  /** Ids never asked for: no request started before `stopStartingAt`, or the read stopped waiting first. */
  notStarted: string[];
  /** Ids asked for whose answer had not arrived when the read stopped waiting. */
  pending: string[];
  /** Duplicate requests sent. */
  hedges: number;
}

/**
 * Read `ids` through `fetchOne` (null: the request failed). `fetchOne(id, true)` must make a new
 * request, never wait on one already made.
 */
export function readRecords<R>(
  ids: readonly string[],
  fetchOne: (id: string, duplicate: boolean) => Promise<R | null>,
  options: RecordReadOptions,
  onLate?: (id: string, answer: R) => void,
): Promise<RecordReadOutcome<R>> {
  return new Promise((resolve) => {
    const got = new Map<string, R>();
    const failed = new Set<string>();
    const settled = new Set<string>();
    /** Ids out now, with when their first request started. */
    const out = new Map<string, number>();
    /** Requests out per id (an original and at most one duplicate). */
    const requests = new Map<string, number>();
    const hedged = new Set<string>();
    let next = 0;
    let active = 0;
    let hedges = 0;
    let done = false;
    let waitTimer: ReturnType<typeof setTimeout> | undefined;
    let hedgeTimer: ReturnType<typeof setTimeout> | undefined;

    const finish = () => {
      if (done) return;
      done = true;
      if (waitTimer !== undefined) clearTimeout(waitTimer);
      if (hedgeTimer !== undefined) clearTimeout(hedgeTimer);
      resolve({ got, failed, notStarted: ids.slice(next), pending: [...out.keys()], hedges });
    };

    const settle = (id: string, answer: R | null) => {
      const left = (requests.get(id) ?? 1) - 1;
      requests.set(id, left);
      if (settled.has(id)) return;
      // A failed request whose duplicate is still out waits for that one.
      if (answer === null && left > 0) return;
      settled.add(id);
      out.delete(id);
      if (done) {
        if (answer !== null) onLate?.(id, answer);
        return;
      }
      if (answer !== null) got.set(id, answer);
      else failed.add(id);
      if (settled.size === ids.length) finish();
    };

    const launch = (id: string, duplicate: boolean) => {
      active++;
      requests.set(id, (requests.get(id) ?? 0) + 1);
      let request: Promise<R | null>;
      try {
        request = fetchOne(id, duplicate);
      } catch {
        request = Promise.resolve(null);
      }
      void request
        .catch(() => null)
        .then((answer) => {
          active--;
          settle(id, answer);
          pump();
        });
    };

    const scheduleHedgeCheck = () => {
      if (hedgeTimer !== undefined) clearTimeout(hedgeTimer);
      hedgeTimer = undefined;
      if (done || hedges >= options.maxHedges || next < ids.length) return;
      let oldest = Infinity;
      for (const [id, at] of out) if (!hedged.has(id)) oldest = Math.min(oldest, at);
      if (!Number.isFinite(oldest)) return;
      hedgeTimer = setTimeout(pump, Math.max(1, oldest + options.hedgeAfterMs - Date.now()));
      hedgeTimer.unref?.();
    };

    const pump = () => {
      if (done) return;
      while (active < options.concurrency && next < ids.length && Date.now() < options.stopStartingAt) {
        const id = ids[next++];
        out.set(id, Date.now());
        launch(id, false);
      }
      // Nothing more can start and nothing is out: the read is over.
      if (active === 0 && (next >= ids.length || Date.now() >= options.stopStartingAt)) {
        finish();
        return;
      }
      // Every id has a request: a slow one gets a duplicate while a slot is free.
      if (next >= ids.length && Date.now() < options.stopStartingAt) {
        const now = Date.now();
        for (const [id, at] of out) {
          if (active >= options.concurrency || hedges >= options.maxHedges) break;
          if (hedged.has(id) || now - at < options.hedgeAfterMs) continue;
          hedged.add(id);
          hedges++;
          launch(id, true);
        }
      }
      scheduleHedgeCheck();
    };

    if (Number.isFinite(options.stopWaitingAt)) {
      waitTimer = setTimeout(finish, Math.max(0, options.stopWaitingAt - Date.now()));
      waitTimer.unref?.();
    }
    if (ids.length === 0) finish();
    else pump();
  });
}
