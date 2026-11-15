// SPDX-License-Identifier: Apache-2.0
/**
 * Process shutdown: one signal every network lookup listens to, and one routine that stops the
 * server promptly.
 *
 * Blind audit of e3aba98: after the host closed stdin, the server went on working for up to 60
 * seconds and sent 34 more requests (lookups a timed-out call left running, fix-path work), because
 * nothing listened for stdin to end and the work's timers held the event loop. MCP's stdio
 * shutdown is the client closing stdin and then waiting for the server to exit. Now the end of
 * stdin (and SIGINT / SIGTERM, on either transport) aborts every lookup in flight, refuses new
 * ones, closes the databases and exits.
 */

import { setMaxListeners } from "node:events";

const controller = new AbortController();
// Every lookup in flight listens (a 150,000-entry scan has hundreds at once): no leak warning.
setMaxListeners(0, controller.signal);

/** Aborted once the server is shutting down; every lookup (live/http-utils.ts) listens to it. */
export const shutdownSignal: AbortSignal = controller.signal;

export function isShuttingDown(): boolean {
  return controller.signal.aborted;
}

/** Abort every lookup in flight and refuse new ones. Idempotent. */
export function abortBackgroundWork(reason: string): void {
  if (!controller.signal.aborted) controller.abort(new Error(`4DA MCP server shutting down: ${reason}`));
}

/** The steps a shutdown takes after aborting the work; each runs once, and a failing one never stops the rest. */
export interface ShutdownSteps {
  /** Close databases and other handles. */
  close: Array<() => void | Promise<void>>;
  /** How the process ends (process.exit in the server; a spy in tests). */
  exit: (code: number) => void;
  /** Where to say why (stderr in the server). */
  log?: (line: string) => void;
}

let started = false;

/**
 * Stop the server: abort the work, close each handle, then exit. Never waits on the network:
 * the aborted lookups settle on their own, and the exit does not wait for them.
 */
export function shutdown(reason: string, steps: ShutdownSteps): void {
  if (started) return;
  started = true;
  steps.log?.(`[4DA] ${reason}: shutting down`);
  abortBackgroundWork(reason);
  const closing = steps.close.map(async (close) => {
    try {
      await close();
    } catch {
      // A handle that will not close cleanly must not keep the process alive.
    }
  });
  // A close that never settles cannot hold the exit: one second at most.
  const cap = new Promise<void>((resolve) => setTimeout(resolve, 1000).unref());
  void Promise.race([Promise.all(closing), cap]).then(() => steps.exit(0));
}

/** For tests only: forget that a shutdown ran. The abort signal stays aborted. */
export function resetShutdownForTests(): void {
  started = false;
}
