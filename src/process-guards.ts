// SPDX-License-Identifier: Apache-2.0
/**
 * Process-level guards: an error no request handler caught does not end the server.
 *
 * Each request is already answered when its handler throws (the SDK turns the throw into a
 * JSON-RPC error; the HTTP transport answers 500). What was left is an error thrown outside any
 * request, in a timer or a stream callback, or a promise nobody awaited: Node ends the process on
 * either, and an editor's session lost every tool until it was restarted (pre-publish round 7).
 * Those are logged on stderr and the server keeps serving.
 *
 * Two cases still end it, because there is nothing left to serve: the host closed our stdout (a
 * write fails with EPIPE, or on a destroyed stream), and an out-of-memory error.
 */

type Log = (line: string) => void;

/** Errors that mean the host went away: nothing more can be written, so the process ends. */
const HOST_GONE = new Set(["EPIPE", "ERR_STREAM_DESTROYED", "ERR_STREAM_WRITE_AFTER_END"]);

function describe(error: unknown): string {
  if (error instanceof Error) return `${error.name}: ${error.message}${error.stack ? `\n${error.stack.split("\n").slice(1, 6).join("\n")}` : ""}`;
  return String(error);
}

/** What to do with an error that reached the process: keep serving, or exit (with this code). */
export function processErrorOutcome(error: unknown): { exit: number | null; line: string } {
  const code = typeof error === "object" && error !== null ? (error as { code?: unknown }).code : undefined;
  if (typeof code === "string" && HOST_GONE.has(code)) return { exit: 0, line: `[4DA] The host closed the connection (${code}); exiting.` };
  if (error instanceof RangeError && /allocation failed|out of memory/i.test(error.message)) {
    return { exit: 1, line: `[4DA] Out of memory; exiting. ${describe(error)}` };
  }
  return { exit: null, line: `[4DA] An error no request handled (the server keeps running): ${describe(error)}` };
}

let installed = false;

/** Installs the handlers once per process. `exit` and `log` are injectable for tests. */
export function installProcessGuards(log: Log = (line) => console.error(line), exit: (code: number) => void = (code) => process.exit(code)): void {
  if (installed) return;
  installed = true;
  const handle = (error: unknown) => {
    const outcome = processErrorOutcome(error);
    try {
      log(outcome.line);
    } catch {
      // stderr itself may be gone
    }
    if (outcome.exit !== null) exit(outcome.exit);
  };
  process.on("uncaughtException", handle);
  process.on("unhandledRejection", handle);
}
