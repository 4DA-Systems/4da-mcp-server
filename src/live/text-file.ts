// SPDX-License-Identifier: Apache-2.0
/**
 * Lockfiles and manifests as text, whatever encoding they were saved in.
 *
 * Windows PowerShell 5 writes `pip freeze > requirements.txt` as UTF-16LE with
 * a byte-order mark. Read as UTF-8 every other byte is a NUL, no line is a
 * requirement, and the scan answered "0 dependencies, 0 vulnerable" for a file
 * full of pins (audit 2026-11-11, M12). A UTF-8 byte-order mark made
 * `JSON.parse` reject an otherwise valid package-lock.json. Both are decoded
 * here: UTF-8 (with or without a mark), UTF-16LE and UTF-16BE (with a mark, or
 * without one when the NUL pattern is unmistakable).
 */

import * as fs from "node:fs";
import { maxLockfileBytes, oversize, tooLargeText } from "./bounded-read.js";

/** Bytes sampled to recognise UTF-16 that carries no byte-order mark. */
const SNIFF_BYTES = 512;

function swapPairs(bytes: Buffer): Buffer {
  const out = Buffer.allocUnsafe(bytes.length - (bytes.length % 2));
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    out[i] = bytes[i + 1];
    out[i + 1] = bytes[i];
  }
  return out;
}

/**
 * UTF-16 with no mark: ASCII text has a NUL in every second byte, on one side
 * only. Null when the bytes do not look like that.
 */
function unmarkedUtf16(bytes: Buffer): "le" | "be" | null {
  const sample = Math.min(bytes.length - (bytes.length % 2), SNIFF_BYTES);
  if (sample < 8) return null;
  let even = 0;
  let odd = 0;
  for (let i = 0; i < sample; i += 2) {
    if (bytes[i] === 0) even++;
    if (bytes[i + 1] === 0) odd++;
  }
  const pairs = sample / 2;
  if (odd >= pairs * 0.6 && even <= pairs * 0.05) return "le";
  if (even >= pairs * 0.6 && odd <= pairs * 0.05) return "be";
  return null;
}

/** File bytes as text: the byte-order mark decides, else the NUL pattern, else UTF-8. The mark is never part of the text. */
export function decodeText(bytes: Buffer): string {
  let text: string;
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) text = bytes.toString("utf-8", 3);
  else if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) text = bytes.toString("utf16le", 2);
  else if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) text = swapPairs(bytes.subarray(2)).toString("utf16le");
  else {
    const utf16 = unmarkedUtf16(bytes);
    text = utf16 === "le" ? bytes.toString("utf16le") : utf16 === "be" ? swapPairs(bytes).toString("utf16le") : bytes.toString("utf-8");
  }
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/** A line git writes into a file it could not merge: `<<<<<<< ours`, `=======`, `>>>>>>> theirs`. */
const CONFLICT_LINE = /^(?:(<{7})(?=[ \t\r\n]|$)|(={7})(?=\r?$)|(>{7})(?=[ \t\r\n]|$))/gm;

/**
 * Whether `text` holds a git merge conflict: a `<<<<<<<` line, a `=======` line after it and a
 * `>>>>>>>` line after that, each at the start of its line. One marker alone (a reStructuredText
 * underline in a description) is not one. Linear in the text.
 */
export function hasMergeConflict(text: string): boolean {
  if (!text.includes("<<<<<<<")) return false;
  let stage = 0;
  for (const match of text.matchAll(CONFLICT_LINE)) {
    if (match[1] !== undefined) stage = 1;
    else if (match[2] !== undefined) stage = stage === 1 ? 2 : stage;
    else if (stage === 2) return true;
  }
  return false;
}

/** Thrown by readTextFile for a file that holds a merge conflict: neither side is known to be what is installed. */
export class MergeConflictError extends Error {
  constructor(readonly file: string) {
    super(`${file} holds git merge-conflict markers`);
    this.name = "MergeConflictError";
  }
}

export function isMergeConflictError(error: unknown): error is MergeConflictError {
  return error instanceof MergeConflictError;
}

/**
 * `fs.readFileSync(file, "utf-8")` for a lockfile or manifest: throws as it
 * does when the file cannot be read, throws for a file over the size cap
 * (bounded-read.ts) before reading a byte of it, and throws MergeConflictError
 * for a file that holds a merge conflict, so no reader takes one side of it.
 * The one reader for these files, so every caller gets the encoding, the cap
 * and the conflict check.
 */
export function readTextFile(file: string): string {
  const size = oversize(file);
  if (size !== null) throw new Error(`${file} ${tooLargeText(size)}`);
  const text = decodeText(fs.readFileSync(file));
  if (hasMergeConflict(text)) throw new MergeConflictError(file);
  return text;
}

/**
 * What reading one file that decides which package names are private gave: a lockfile, a registry
 * or index configuration, a manifest. `unreadable` is a file that is there and whose text is not
 * known; `reason` completes the sentence "<file> <reason>".
 */
export type RuleFileRead = { state: "absent" } | { state: "read"; text: string } | { state: "unreadable"; reason: string };

/** Error codes that say no file is at the path (a path that cannot name one included). */
const NO_FILE = new Set(["ENOENT", "ENOTDIR", "ENAMETOOLONG", "EINVAL", "ERR_INVALID_ARG_VALUE"]);

const errorCode = (error: unknown): string => {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && code ? code : error instanceof Error ? error.name : "unknown error";
};

/**
 * The one reader for every file the private-name rules are read from, decoded as the lockfile
 * readers decode it (decodeText) under the same size cap. It never answers "empty" for a file it
 * could not read: over the cap, an I/O error, or bytes that decode to no text (NUL characters) is
 * `unreadable`, and the caller treats the names that file could have made private as private.
 * Absent means nothing is at the path (or something that is not a file).
 */
export function readRuleFile(file: string): RuleFileRead {
  let size: number;
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) return { state: "absent" };
    size = stat.size;
  } catch (error) {
    return NO_FILE.has(errorCode(error)) ? { state: "absent" } : { state: "unreadable", reason: `could not be read (${errorCode(error)})` };
  }
  if (size > maxLockfileBytes()) return { state: "unreadable", reason: tooLargeText(size) };
  let text: string;
  try {
    text = decodeText(fs.readFileSync(file));
  } catch (error) {
    // Gone between the stat and the read: absent now, and its signature says so at the next call.
    return errorCode(error) === "ENOENT" ? { state: "absent" } : { state: "unreadable", reason: `could not be read (${errorCode(error)})` };
  }
  if (text.includes("\0")) return { state: "unreadable", reason: "is not text this server can decode (it holds NUL characters)" };
  return { state: "read", text };
}
