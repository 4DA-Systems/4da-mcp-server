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
 * - A name the server withheld is recorded by why: "private" for a private-registry rule (the
 *   rules 6.5.0 had; the hook lets the name through, as 6.5.0 did), "local_source" for a name a
 *   project takes from git, a path, its workspace, an alias, a catalog or another registry, and
 *   "unreadable_lockfile" for one withheld because a lockfile or manifest could not be read (the
 *   hook holds both).
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
/** The longest file path kept; a longer one is left out. */
const MAX_PATH = 1024;

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
  /**
   * Why the item was not looked up or did not finish: "private", "local_source",
   * "unreadable_lockfile" (withheld only because `unreadable_file` could not be read),
   * "time_budget", "module_path", "input".
   */
  not_checked?: string;
  /** For "unreadable_lockfile": the lockfile or manifest that could not be read. */
  unreadable_file?: string;
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
  /** Set when a name was withheld only because this file could not be read (dependency-check-screen.ts privateResult). */
  unreadable_file?: string | null;
}

/** A path kept as it is, or null when it is empty, too long or holds a control character. */
function pathField(value: unknown): string | null {
  // eslint-disable-next-line no-control-regex -- a path with a control character is not kept at all
  return typeof value === "string" && value !== "" && value.length <= MAX_PATH && !/[\u0000-\u001f\u007f-\u009f]/.test(value) ? value : null;
}

/**
 * The reasons that make a name private as 6.5.0 called it: a FOURDA_PRIVATE_PACKAGES pattern, an
 * npm scope mapped to a private registry, a Go GOPRIVATE / GONOPROXY / GONOSUMDB pattern, or a
 * registry, index or proxy that is not public (every such reason ends with the FOURDA_PUBLIC_MIRRORS
 * hint, live/private-packages.ts PUBLIC_MIRRORS_HINT). Read from the answer's reason, which states
 * the rule (dependency-check-screen.ts privateResult).
 */
const PRIVATE_AS_IN_650 = [/FOURDA_PRIVATE_PACKAGES lists /, / is mapped to a private registry in /, /\bGO(?:PRIVATE|NOPROXY|NOSUMDB) \([^)]*\) matches /, /set FOURDA_PUBLIC_MIRRORS to its host if it only mirrors the public registry/];

/**
 * The ledger's word for a name the server withheld as private: "private" only on positive evidence
 * of a rule 6.5.0 also called private; "local_source" for everything else 6.5.1 withholds (a git,
 * path, file:, tarball, link: or workspace source, a patched crate, a reason not recognised here).
 * A 6.5.0 hook lets a "private" name through at any version in every project and holds any other
 * value, so a name 6.5.0 did not withhold must not be recorded as "private" (re-check of 0d30b40,
 * S4: `"lodash": "github:me/lodash"` was held by 6.5.0 and let through by a 6.5.0 hook beside a
 * 6.5.1 server). The 6.5.1 hook holds "local_source" too.
 */
export function withheldKind(reason: unknown): "private" | "local_source" {
  return typeof reason === "string" && PRIVATE_AS_IN_650.some((re) => re.test(reason)) ? "private" : "local_source";
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
    const unread = item.not_checked === "private" ? pathField(item.unreadable_file) : null;
    const withheld = item.not_checked === "private" && !unread ? withheldKind(item.reason) : null;
    out.push({
      t,
      ecosystem: oneLine(item.ecosystem, 40),
      package: pkg,
      version,
      verdict: oneLine(item.verdict, 20),
      ...(typeof item.to_requested === "string" && item.to_requested ? { requested: oneLine(item.to_requested, MAX_FIELD) } : {}),
      ...(typeof item.reason === "string" && item.reason ? { reason: oneLine(item.reason, MAX_REASON) } : {}),
      ...(unread
        ? { not_checked: "unreadable_lockfile", unreadable_file: unread }
        : withheld
          ? { not_checked: withheld }
          : typeof item.not_checked === "string"
            ? { not_checked: oneLine(item.not_checked, 40) }
            : {}),
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
