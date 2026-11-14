// SPDX-License-Identifier: Apache-2.0
/**
 * A point where long work gives the event loop back, so the server keeps answering (`ping`, other
 * requests) while a scan or a plan runs.
 *
 * With every answer cached, a scan's lookups resolve as microtasks and never reach the event loop:
 * the whole of a fully cached vulnerability_scan ran as one uninterrupted turn, and `ping` waited
 * for all of it (3.6 s on js-nest-npm3; 20.8 s at 107,000 lockfile entries: blind audit round 6).
 * Loops over findings call `yieldIfDue()`: when more than SLICE_MS has passed since the event loop
 * last had a turn, the caller waits for the next one. Every caller that is due waits on the SAME
 * turn, so a pool of concurrent workers shares one slice per turn instead of taking one each.
 */

const SLICE_MS = 15;
let last = performance.now();
let pending: Promise<void> | null = null;

export function yieldIfDue(): Promise<void> | undefined {
  if (pending) return pending;
  if (performance.now() - last < SLICE_MS) return undefined;
  pending = new Promise<void>((resolve) =>
    setImmediate(() => {
      pending = null;
      last = performance.now();
      resolve();
    }),
  );
  return pending;
}
