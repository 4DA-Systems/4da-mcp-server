// SPDX-License-Identifier: Apache-2.0
/**
 * A size cap on the lockfiles and manifests the server reads.
 *
 * They are read whole and synchronously, and a JSON lockfile is parsed in one
 * call, so a file of several hundred megabytes in a scanned repository held
 * the event loop for seconds and could exhaust the heap: the server stopped
 * answering, or died, for every project (audit 2026-11-11, M4). The largest
 * real lockfiles measured are tens of megabytes (a pnpm-lock.yaml of a large
 * monorepo); MAX_LOCKFILE_BYTES leaves room above that.
 *
 * A file over the cap is not read and is REPORTED: the resolution that would
 * have read it returns a lockfile problem, which every tool prints as
 * UNREADABLE with "its dependencies were not checked". It is never a silent
 * skip and never a clean result.
 *
 * FOURDA_MAX_LOCKFILE_BYTES overrides the default (tests).
 */

import * as fs from "node:fs";

const DEFAULT_MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;

export function maxLockfileBytes(): number {
  const raw = Number(process.env.FOURDA_MAX_LOCKFILE_BYTES);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_MAX_LOCKFILE_BYTES;
}

/** "81.2 MB", or kilobytes below one megabyte. */
function sizeText(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

/** The words for a file over the cap, for a lockfile problem. */
export function tooLargeText(bytes: number): string {
  return `is ${sizeText(bytes)}, over the ${sizeText(maxLockfileBytes())} this server reads in one lockfile or manifest, so it was not read`;
}

/** The file's size when it is over the cap; null when it is within it or cannot be stat'ed. */
export function oversize(file: string): number | null {
  try {
    const { size } = fs.statSync(file);
    return size > maxLockfileBytes() ? size : null;
  } catch {
    return null;
  }
}

/** `fs.readFileSync(file, "utf-8")`, refused (thrown) for a file over the cap. */
export function readTextBounded(file: string): string {
  const size = oversize(file);
  if (size !== null) throw new Error(`${file} ${tooLargeText(size)}`);
  return fs.readFileSync(file, "utf-8");
}
