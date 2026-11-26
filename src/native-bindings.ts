// SPDX-License-Identifier: Apache-2.0
/**
 * better-sqlite3's native module: a real check, the real cause, and the remedy for the Node.js that
 * runs the server.
 *
 * `import("better-sqlite3")` succeeds even when the compiled module is
 * missing; the failure comes at the first `new Database()`. Measured
 * 2026-10-03 on node:24-bookworm-slim with npm 12.2.0, which blocks
 * dependency install scripts not covered by `allowScripts`: `npm install`
 * (local or -g) left no better_sqlite3.node, `--doctor` still reported the
 * bindings as loaded, and every tool failed with "Could not locate the
 * bindings file" and no hint why.
 *
 * Since 6.1.0 the server uses Node's built-in node:sqlite when the runtime
 * has it (sqlite-driver.ts: Node 22.13 and later, 23.4 and later), so this
 * matters only on Node 22.0-22.12 and 23.0-23.3, where better-sqlite3 is the
 * one driver. npm 12, which blocks install scripts, needs Node 22.22.2 or
 * later, so it is never the cause there.
 *
 * Audit 2026-11-25 (H-5, F m2): the remedy told users to run `npx clear-npx-cache`, a third-party
 * package, unpinned; named npm 12 steps on a Node that npm 12 cannot run on; was printed twice in one
 * message; cut the cause to its first line ("The module '...better_sqlite3.node'", without "was
 * compiled against a different Node.js version"); and told a Node 23.0 user to upgrade to 22.13. It
 * is now one paragraph, said once, with the whole cause, the minimum for that Node line, and no
 * command that runs anyone else's code.
 */

/** The longest cause kept in a message. */
const MAX_CAUSE = 400;

/**
 * The cause of a native-module failure, whole: better-sqlite3 splits it over lines ("The module
 * '...better_sqlite3.node' was compiled against a different Node.js version using NODE_MODULE_VERSION
 * 127. This version of Node.js requires NODE_MODULE_VERSION 115. ..."). A missing module's "Tried:"
 * list of paths is dropped; whitespace is folded and the text capped.
 */
export function nativeBindingCause(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  const text = raw.replace(/\s*Tried:[\s\S]*$/, "").replace(/\s+/g, " ").trim().replace(/\.$/, "");
  return text.length > MAX_CAUSE ? `${text.slice(0, MAX_CAUSE)}...` : text;
}

/** The first Node.js release of `major` that has the built-in node:sqlite, or null when the whole line has it (or none of it does). */
function builtInFrom(major: number): string | null {
  if (major < 22) return "22.13";
  if (major === 22) return "22.13";
  if (major === 23) return "23.4";
  return null;
}

/**
 * What to do when better-sqlite3 cannot be used, for the Node.js that runs the server (`nodeVersion`,
 * default the running one). One paragraph; every step is Node's own or npm's own.
 */
export function nativeBindingRemedy(nodeVersion: string = process.versions.node): string {
  const [major, minor] = nodeVersion.split(".").map((n) => Number.parseInt(n, 10));
  const from = builtInFrom(major);
  const fromMinor = from === null ? null : Number(from.split(".")[1]);
  const reinstall =
    "reinstall @4da/mcp-server with the Node.js that runs it, with install scripts allowed (not --ignore-scripts), " +
    "so better-sqlite3 is built for that Node.js; under npx, delete the _npx folder inside the folder `npm config get cache` prints, then start the server again";
  if (from !== null && (major < 22 || minor < (fromMinor ?? 0))) {
    const also = major === 23 ? " (22.13 and later have it too)" : "";
    return `Node.js ${from} and later${also} have a built-in SQLite driver that needs nothing built: upgrade Node.js (this is ${nodeVersion}), or ${reinstall}.`;
  }
  return `This Node.js (${nodeVersion}) has the built-in SQLite driver: unless FOURDA_SQLITE_DRIVER forces better-sqlite3 (unset it), ${reinstall}.`;
}

/** The remedy for the running Node.js (kept under its old name for the doctor and older callers). */
export const NATIVE_BINDING_FIX = nativeBindingRemedy();

/** Errors that mean the compiled module is absent or built for another Node/platform. */
export function isNativeBindingError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /bindings file|better_sqlite3\.node|NODE_MODULE_VERSION|compiled against a different Node\.js version|invalid ELF header|not a valid Win32 application/i.test(msg);
}

/** Why better-sqlite3 cannot be used, the whole cause, and no remedy (the caller adds it once). */
export function nativeBindingProblem(err: unknown): string {
  return `better-sqlite3's native module is not usable: ${nativeBindingCause(err)}`;
}

/** The cause with the remedy, said once: for a caller that prints this message alone. */
export function nativeBindingMessage(err: unknown): string {
  return `${nativeBindingProblem(err)}. ${NATIVE_BINDING_FIX}`;
}

/** Null when an in-memory database opens; otherwise why not (the cause only: the driver resolution adds the remedy once). */
export function checkNativeBindings(Database: new (file: string) => { close(): unknown }): string | null {
  try {
    new Database(":memory:").close();
    return null;
  } catch (err) {
    return nativeBindingProblem(err);
  }
}
