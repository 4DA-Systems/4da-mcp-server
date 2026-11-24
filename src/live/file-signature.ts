// SPDX-License-Identifier: Apache-2.0
/**
 * A cheap identity for a file at one moment, so the live layer can notice a
 * change with stat calls alone: "absent", or mtime + size + inode.
 *
 * The inode matters for node_modules. npm packs every tarball file with one
 * fixed mtime, and pnpm swaps a package version by re-pointing a link at a
 * different store file, so two versions can share an mtime. They cannot share
 * an inode.
 */

import * as fs from "node:fs";
import * as path from "node:path";

export type FileSignature = string;

export const ABSENT: FileSignature = "absent";

export function fileSignature(filePath: string): FileSignature {
  try {
    const s = fs.statSync(filePath);
    return `${s.mtimeMs}:${s.size}:${s.ino}`;
  } catch {
    return ABSENT;
  }
}

/** The modification time a signature recorded, or null for an absent file. */
export function signatureMtime(signature: FileSignature | undefined): number | null {
  if (!signature || signature === ABSENT) return null;
  const mtime = Number(signature.split(":")[0]);
  return Number.isFinite(mtime) ? mtime : null;
}

/**
 * The signature of the directory each absent path of a snapshot is in, taken before the paths
 * themselves. A file cannot appear in a directory without changing the directory's own mtime
 * (creation, rename and deletion all rewrite the directory entry), so while that signature holds,
 * none of the absent paths in it can have appeared, and they need no stat of their own. Most of a
 * project's watched paths are candidates that are not there (five npm lockfile names, a dozen
 * private-rule files per directory): one stat per directory replaces one per candidate.
 */
const absentDirs = new WeakMap<Map<string, FileSignature>, Map<string, FileSignature>>();

/** Signatures for a set of paths, taken now. */
export function signatureMap(paths: Iterable<string>): Map<string, FileSignature> {
  const list = [...paths];
  const dirs = new Map<string, FileSignature>();
  for (const p of list) {
    const dir = path.dirname(p);
    if (!dirs.has(dir)) dirs.set(dir, fileSignature(dir));
  }
  const out = new Map<string, FileSignature>();
  for (const p of list) out.set(p, fileSignature(p));
  absentDirs.set(out, dirs);
  return out;
}

/**
 * True when any recorded file changed, appeared, or disappeared since its signature was taken. An
 * absent file whose directory signature (recorded with the snapshot) still holds is not stat'ed.
 */
export function anySignatureChanged(snapshot: Map<string, FileSignature>): boolean {
  const dirs = absentDirs.get(snapshot);
  const dirHolds = new Map<string, boolean>();
  const unchangedDir = (dir: string): boolean => {
    const recorded = dirs?.get(dir);
    if (recorded === undefined || recorded === ABSENT) return false;
    let holds = dirHolds.get(dir);
    if (holds === undefined) dirHolds.set(dir, (holds = fileSignature(dir) === recorded));
    return holds;
  };
  for (const [p, recorded] of snapshot) {
    if (recorded === ABSENT && unchangedDir(path.dirname(p))) continue;
    if (fileSignature(p) !== recorded) return true;
  }
  return false;
}
