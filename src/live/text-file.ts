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

/** `fs.readFileSync(file, "utf-8")` for a lockfile or manifest: throws as it does when the file cannot be read. */
export function readTextFile(file: string): string {
  return decodeText(fs.readFileSync(file));
}
