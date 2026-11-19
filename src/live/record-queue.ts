// SPDX-License-Identifier: Apache-2.0
/**
 * One queue per process that finishes reading advisory records a tool call ran out of time for.
 *
 * A cold vulnerability_scan of a large tree can have more records to read than its call has time
 * for. The answer says NOT CHECKED for those, and the records not yet asked for are handed here,
 * so the next call is answered from the cache instead of starting over.
 *
 * Bounded by construction:
 * - `concurrency` reads at most are out at once (BACKGROUND_CONCURRENCY), whatever was queued, and
 *   one starts only while `canStart()` allows (the server's: while fewer than a scan's worth of
 *   record requests are out in the process, so a call's own reads come first);
 * - at most `maxQueued` records wait (BACKGROUND_MAX_QUEUED), across every scan; past that an id
 *   is refused, and the scan that offered it says so;
 * - it holds ids and one reference to the reader per job, never the records it fetched (they go to
 *   the cache), so memory does not grow with what an answer names;
 * - nothing starts once the server is shutting down (shutdown.ts): the waiting jobs are dropped,
 *   and the reads in flight are aborted by the signal every lookup listens to;
 * - a read runs outside any tool call, under the private-name rules of the project that queued it
 *   (private-guard.ts), and goes through the scan's own reader, so through fetchWithTimeout and its
 *   private-name guard.
 */

import { AsyncResource } from "node:async_hooks";
import { shutdownSignal } from "../shutdown.js";
import { bindPrivateContext } from "./private-guard.js";

/** Created at load, outside any tool call: a queued read runs in no call's context, only in its project's. */
const OUTSIDE_ANY_CALL = new AsyncResource("4da-background-records");

/** Reads the background queue keeps out at once. */
export const BACKGROUND_CONCURRENCY = 16;
/** Records waiting in the queue at most (every scan together). */
export const BACKGROUND_MAX_QUEUED = 2_000;
/** How soon a queue held back by `canStart` looks again. */
const RECHECK_MS = 100;

/** One queued read: `read(id)` fetches the record and stores it (or that OSV.dev holds none). */
interface Job {
  read: (id: string) => Promise<void>;
  /** Runs the read as made for the project that queued it (its private-name rules). */
  run: <T>(fn: () => T) => T;
}

export interface RecordQueueOptions {
  concurrency?: number;
  maxQueued?: number;
  signal?: AbortSignal;
  /** Whether a read may start now, besides the queue's own concurrency. */
  canStart?: () => boolean;
}

export class RecordQueue {
  private waiting = new Map<string, Job>();
  private running = new Set<string>();
  private idle: Array<() => void> = [];
  private recheck: ReturnType<typeof setTimeout> | undefined;
  private readonly concurrency: number;
  private readonly maxQueued: number;
  private readonly signal: AbortSignal;
  private readonly canStart: () => boolean;

  constructor(options: RecordQueueOptions = {}) {
    this.concurrency = options.concurrency ?? BACKGROUND_CONCURRENCY;
    this.maxQueued = options.maxQueued ?? BACKGROUND_MAX_QUEUED;
    this.signal = options.signal ?? shutdownSignal;
    this.canStart = options.canStart ?? (() => true);
    this.signal.addEventListener("abort", () => this.stop(), { once: true });
  }

  /**
   * Queue reads of `ids` through `read`. An id already waiting or running is not queued twice.
   * Returns the ids taken (queued now, or already queued or running) and those refused (the queue
   * is full, or the server is shutting down).
   */
  enqueue(ids: readonly string[], read: (id: string) => Promise<void>): { taken: string[]; refused: string[] } {
    if (this.signal.aborted) return { taken: [], refused: [...ids] };
    // The private-name rules of the project that queued them (none: every registered project's).
    const run = bindPrivateContext();
    const taken: string[] = [];
    const refused: string[] = [];
    for (const id of ids) {
      if (this.waiting.has(id) || this.running.has(id)) {
        taken.push(id);
      } else if (this.waiting.size >= this.maxQueued) {
        refused.push(id);
      } else {
        this.waiting.set(id, { read, run });
        taken.push(id);
      }
    }
    this.pump();
    return { taken, refused };
  }

  /** Ids waiting or being read. */
  get size(): number {
    return this.waiting.size + this.running.size;
  }

  /** Settles when nothing is waiting or running (tests; the server never waits for it). */
  drained(): Promise<void> {
    if (this.size === 0) return Promise.resolve();
    return new Promise((resolve) => this.idle.push(resolve));
  }

  private stop(): void {
    this.waiting.clear();
    if (this.recheck !== undefined) clearTimeout(this.recheck);
    this.recheck = undefined;
    this.settleIdle();
  }

  private settleIdle(): void {
    if (this.size === 0) for (const resolve of this.idle.splice(0)) resolve();
  }

  private pump(): void {
    if (this.signal.aborted) {
      this.stop();
      return;
    }
    while (this.running.size < this.concurrency && this.waiting.size > 0 && this.canStart()) {
      const [id, job] = this.waiting.entries().next().value!;
      this.waiting.delete(id);
      this.running.add(id);
      let work: Promise<void>;
      try {
        work = OUTSIDE_ANY_CALL.runInAsyncScope(() => job.run(() => job.read(id)));
      } catch {
        work = Promise.resolve();
      }
      void work
        .catch(() => undefined)
        .then(() => {
          this.running.delete(id);
          this.pump();
        });
    }
    // Held back with nothing of its own running: nothing else would wake it.
    if (this.waiting.size > 0 && this.running.size === 0 && this.recheck === undefined) {
      this.recheck = setTimeout(() => {
        this.recheck = undefined;
        this.pump();
      }, RECHECK_MS);
      this.recheck.unref?.();
    }
    this.settleIdle();
  }
}
