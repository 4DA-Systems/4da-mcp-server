// SPDX-License-Identifier: Apache-2.0
/**
 * Zip archive reader for `upgrade_impact`, Node built-ins only.
 *
 * Go module zips (proxy.golang.org `/@v/<version>.zip`) and the occasional
 * PyPI `.zip` sdist are zip files, not gzip tars. The job is the same as
 * package-archive.ts's: pull a few root-level text files (the changelog) out
 * of a third-party archive without trusting it. Only the central directory
 * is read, so a file's declared sizes come from one place; stored (0) and
 * deflate (8) entries are read, everything else (zip64, encryption, other
 * methods) is skipped rather than guessed at. Each inflate is capped at
 * MAX_FILE_BYTES, so a zip bomb stops at the cap.
 */

import { inflateRawSync } from "node:zlib";
import { ArchiveError, ArchiveTextFiles, MAX_ARCHIVE_TEXT_BYTES, MAX_ARCHIVE_TEXT_FILES, MAX_COMPRESSED_BYTES, MAX_ENTRY_PATH, MAX_FILE_BYTES } from "./package-archive.js";

const EOCD_SIG = 0x06054b50;
const CDH_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;
/** The end-of-central-directory record is 22 bytes plus a comment of at most 65,535. */
const EOCD_SEARCH = 22 + 0xffff;
const MAX_ENTRIES = 200_000;

/** True when the buffer starts like a zip archive (a local file header). */
export function looksLikeZip(buf: Buffer): boolean {
  return buf.length >= 4 && buf.readUInt32LE(0) === LFH_SIG;
}

function findEocd(buf: Buffer): number {
  const stop = Math.max(0, buf.length - EOCD_SEARCH);
  for (let i = buf.length - 22; i >= stop; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  throw new ArchiveError("not a zip archive (no end-of-central-directory record)");
}

/**
 * Text files directly under `root` (a path prefix such as
 * `github.com/foo/bar@v1.2.3/`; "" for every top-level file of a one-directory
 * archive) whose basename `accept` approves. When `root` is null, files one
 * directory deep are read, as the tar reader does. Oversized, binary and
 * unreadable entries are skipped.
 */
export function readZipRootTextFiles(
  buf: Buffer,
  accept: (basename: string) => boolean,
  root: string | null = null,
): ArchiveTextFiles {
  if (buf.length > MAX_COMPRESSED_BYTES) {
    throw new ArchiveError(`archive is ${buf.length} bytes compressed (cap ${MAX_COMPRESSED_BYTES})`);
  }
  if (buf.length < 22) throw new ArchiveError("not a zip archive (too short)");
  const eocd = findEocd(buf);
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (cdOffset === 0xffffffff || count === 0xffff) throw new ArchiveError("zip64 archives are not read");
  if (cdOffset + cdSize > buf.length || count > MAX_ENTRIES) throw new ArchiveError("corrupt zip central directory");

  const files = new ArchiveTextFiles();
  // Local headers already read: a directory may list the same stored bytes under many names.
  const read = new Set<number>();
  let kept = 0;
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CDH_SIG) throw new ArchiveError("corrupt zip central directory entry");
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const compressed = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const nameStart = p + 46;
    p += 46 + nameLen + extraLen + commentLen;
    if (nameLen > MAX_ENTRY_PATH) continue;
    const name = buf.subarray(nameStart, nameStart + nameLen).toString("utf8");

    if (name.endsWith("/") || !isRootFile(name, root) || !accept(name.split("/").pop() ?? "")) continue;
    if (flags & 0x1 || (method !== 0 && method !== 8) || size > MAX_FILE_BYTES) continue;
    // The sizes are the archive's own claims, so each is held to the cap: a stored entry is as
    // long as it says it is, and no accepted file needs more compressed bytes than the cap.
    if (compressed > MAX_FILE_BYTES || (method === 0 && compressed !== size)) continue;
    if (local + 30 > buf.length || buf.readUInt32LE(local) !== LFH_SIG) continue;
    if (read.has(local)) continue;
    read.add(local);
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    if (start + compressed > buf.length) continue;
    const raw = buf.subarray(start, start + compressed);
    let data: Buffer;
    try {
      data = method === 0 ? Buffer.from(raw) : inflateRawSync(raw, { maxOutputLength: MAX_FILE_BYTES });
    } catch {
      continue;
    }
    if (data.includes(0)) continue;
    // A few root-level text files are wanted, so a few are kept: every accepted entry costs up
    // to MAX_FILE_BYTES of memory, and an archive may list hundreds of thousands of them.
    if (files.size >= MAX_ARCHIVE_TEXT_FILES || kept + data.length > MAX_ARCHIVE_TEXT_BYTES) {
      files.stoppedAtLimit = true;
      break;
    }
    kept += data.length;
    files.set(name, data.toString("utf8"));
  }
  return files;
}

function isRootFile(name: string, root: string | null): boolean {
  if (root !== null) return name.startsWith(root) && !name.slice(root.length).includes("/") && name.length > root.length;
  const parts = name.split("/").filter(Boolean);
  return parts.length > 0 && parts.length <= 2;
}
