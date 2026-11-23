// SPDX-License-Identifier: Apache-2.0
/**
 * The check ledger: every final `dependency_check` verdict, appended to a small file in this
 * server's data folder (`check-ledger.jsonl`, db.ts serverDataDir). The Claude Code plugin hook
 * (hooks/manifest-edit.mjs) reads it before an edit or an install command runs, and stops a
 * dependency version that has no recent verdict or whose verdict is `avoid`.
 *
 * What it holds to:
 * - It is local only: nothing in it is sent anywhere, and the server never reads it for its own
 *   answers. A private package's name is stored as the caller gave it, on this machine only.
 * - Writing it never changes or delays a tool's answer: the write starts after the answer is
 *   built, is not awaited by the tool, and any failure is dropped.
 * - It is append-only and bounded: past LEDGER_MAX_BYTES the file is moved to
 *   `check-ledger.1.jsonl` (replacing the one before) and a new one is started, so the two hold
 *   at most about twice that. The hook reads both.
 * - Several servers may write at once: each call's entries go out in one append, and a reader
 *   skips any line that does not parse. A lost or torn line costs a repeated check, never a
 *   wrong allow.
 * - It exists from the server's start (startLedger), empty until the first verdict: the hook
 *   denies only where it finds one, so it never holds an edit beside a server that cannot record.
 */

import { appendFile, mkdir, rename, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import { serverDataDir } from "./db.js";

export const LEDGER_FILE = "check-ledger.jsonl";
export const LEDGER_PREVIOUS_FILE = "check-ledger.1.jsonl";
/** Size at which the ledger is moved aside and a new one started. */
export const LEDGER_MAX_BYTES = 512 * 1024;
/** The longest reason kept per entry. */
const MAX_REASON = 400;
/** The longest name, version or constraint kept (dependency_check bounds its own inputs below this). */
const MAX_FIELD = 300;

/** One line of the ledger. */
export interface LedgerEntry {
  /** When the verdict was given (ISO 8601). */
  t: string;
  ecosystem: string;
  package: string;
  /** The exact version the verdict is for (a constraint's pick, when one was asked). */
  version: string;
  verdict: string;
  /** "latest" or the constraint the caller asked, when `version` is what it resolved to. */
  requested?: string;
  /** The server's one-line reason, single-line and capped. */
  reason?: string;
  /** Why the item was not looked up or did not finish: "private", "time_budget", "module_path". */
  not_checked?: string;
}

/** The fields of a dependency_check result item the ledger keeps. */
export interface CheckedItem {
  ecosystem: string;
  package: string;
  to: string;
  to_requested?: string;
  verdict: string;
  reason?: string;
  not_checked?: string;
}

/** One line of server text: control characters and runs of blanks become one space, capped. */
function oneLine(text: string, max: number): string {
  // eslint-disable-next-line no-control-regex -- replaces control characters on purpose: an entry is one line
  const flat = text.replace(/[\u0000-\u001f\u007f-\u009f\s]+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 3)}...` : flat;
}

/** The ledger lines for one answer's items. Items without a name, version or verdict are left out. */
export function ledgerEntries(items: readonly CheckedItem[], at: Date = new Date()): LedgerEntry[] {
  const t = at.toISOString();
  const out: LedgerEntry[] = [];
  for (const item of items) {
    if (typeof item?.package !== "string" || typeof item.to !== "string" || typeof item.verdict !== "string" || typeof item.ecosystem !== "string") continue;
    const pkg = oneLine(item.package, MAX_FIELD);
    const version = oneLine(item.to, MAX_FIELD);
    if (!pkg || !version) continue;
    out.push({
      t,
      ecosystem: oneLine(item.ecosystem, 40),
      package: pkg,
      version,
      verdict: oneLine(item.verdict, 20),
      ...(typeof item.to_requested === "string" && item.to_requested ? { requested: oneLine(item.to_requested, MAX_FIELD) } : {}),
      ...(typeof item.reason === "string" && item.reason ? { reason: oneLine(item.reason, MAX_REASON) } : {}),
      ...(typeof item.not_checked === "string" ? { not_checked: oneLine(item.not_checked, 40) } : {}),
    });
  }
  return out;
}

/** Append `text` to the ledger in `dir`, moving a full ledger aside first. */
async function append(dir: string, text: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  const file = path.join(dir, LEDGER_FILE);
  let size = 0;
  try {
    size = (await stat(file)).size;
  } catch {
    // No ledger yet: this append starts it.
  }
  if (size > 0 && size + text.length > LEDGER_MAX_BYTES) {
    try {
      await rename(file, path.join(dir, LEDGER_PREVIOUS_FILE));
    } catch {
      // Another writer moved it first, or the move is refused: past twice the bound the file
      // starts over with these entries, so it never grows without limit.
      if (size > 2 * LEDGER_MAX_BYTES) {
        await writeFile(file, text, { encoding: "utf8", mode: 0o600 });
        return;
      }
    }
  }
  await appendFile(file, text, { encoding: "utf8", mode: 0o600 });
}

/** Writes from this process, one after another, so its own entries never interleave. */
let queue: Promise<void> = Promise.resolve();

/**
 * Record each item's final verdict in the ledger of `dir` (the data folder by default). The
 * returned promise never rejects: a ledger that cannot be written is skipped.
 */
export function recordVerdicts(items: readonly CheckedItem[], options: { now?: Date; dir?: string } = {}): Promise<void> {
  let entries: LedgerEntry[];
  let dir: string;
  try {
    entries = ledgerEntries(items, options.now);
    dir = options.dir ?? serverDataDir();
  } catch {
    return queue;
  }
  if (entries.length === 0) return queue;
  // Each append starts on a line of its own, so a line left torn by a crash never swallows it.
  const text = "\n" + entries.map((e) => JSON.stringify(e)).join("\n") + "\n";
  queue = queue.then(() => append(dir, text)).catch(() => undefined);
  return queue;
}

/**
 * Start the ledger in `dir` (the data folder by default) when it has none: an empty file. The
 * hook denies only where a ledger exists, because beside a server that records no verdict (any
 * before 6.5.0) a denied edit could never pass; this file is how it knows one that does has run
 * here. An existing ledger is left as it is. Called once when the server starts serving; like
 * every write here it is not awaited and never rejects.
 */
export function startLedger(options: { dir?: string } = {}): Promise<void> {
  let dir: string;
  try {
    dir = options.dir ?? serverDataDir();
  } catch {
    return queue;
  }
  queue = queue
    .then(async () => {
      await mkdir(dir, { recursive: true });
      // Appending nothing creates the file when it is missing and changes nothing when it is there.
      await appendFile(path.join(dir, LEDGER_FILE), "", { encoding: "utf8", mode: 0o600 });
    })
    .catch(() => undefined);
  return queue;
}

/**
 * Settles once every ledger write started so far has finished (or failed). The server's
 * shutdown waits on it, so an answer the client has already read is never left unrecorded
 * because the host closed stdin right after it. Never rejects.
 */
export function ledgerWritesSettled(): Promise<void> {
  return queue;
}
