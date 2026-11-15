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

/**
 * Work written as a generator that `yield`s at points where it may pause: the same code runs to
 * completion in one turn (`runSteps`, for every synchronous caller) or gives the event loop a turn
 * whenever a slice is due (`runStepsYielding`). One body for both, so the two cannot disagree on a
 * result. The first call's lockfile resolution held the server for 2.3 s on a 150,000-entry
 * pnpm-lock.yaml, and a `ping` sent meanwhile waited for all of it (pre-publish round 10, W11).
 */
export type Steps<T> = Generator<void, T, void>;

/** How many lines or entries a loop handles between two pause points (a power of two, for `& STEP_MASK`). */
export const STEP_MASK = 2047;

/** Run `steps` to completion now, never pausing. */
export function runSteps<T>(steps: Steps<T>): T {
  for (;;) {
    const r = steps.next();
    if (r.done) return r.value;
  }
}

/**
 * Run `steps`, giving the event loop a turn whenever a slice is due (yieldIfDue). `current` is
 * asked after every turn given: false when the work was superseded meanwhile (a caller that could
 * not wait did it synchronously), and the run stops there, returning `superseded`.
 */
export async function runStepsYielding<T, S>(steps: Steps<T>, current: () => boolean, superseded: S): Promise<T | S> {
  for (;;) {
    const r = steps.next();
    // Checked at every step, not only after a pause: a run superseded between two steps that never
    // reached a pause returned its own result, and on a fast machine the caller took it (CI, round 10).
    if (!current()) {
      if (!r.done) steps.return(undefined as unknown as T);
      return superseded;
    }
    if (r.done) return r.value;
    const turn = yieldIfDue();
    if (turn) {
      await turn;
      if (!current()) {
        steps.return(undefined as unknown as T);
        return superseded;
      }
    }
  }
}
