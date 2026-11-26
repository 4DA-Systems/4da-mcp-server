// SPDX-License-Identifier: Apache-2.0
/**
 * Package confirmation: the briefing's system for the names of a task it has not checked (wave 2,
 * section 1 of the design of 2026-11-27).
 *
 * A free-text task cannot tell a public package name from a private one or from a secret, so the
 * briefing looks a word up on its own only when it can know it is public (a dependency the project
 * already has in that ecosystem; an exact bundled-list name: gateTaskNames). Every other name is
 * listed in `task_packages.to_confirm`, and the AGENT, which knows what the task means, settles each
 * one in its next call: `packages: [{ ecosystem, name, version?, public }]` (public: checked in that
 * call; private: never sent) or `not_packages: [word]` (dropped). Nothing is stored between calls.
 *
 * This module holds the parts that need no network: reading and validating the two arguments,
 * matching a declaration to a name the task gives, and the wording the agent acts on.
 */

import type { CheckEcosystem } from "../live/release-metadata.js";
import { lengthProblem, MAX_NAME_ARG_LENGTH, MAX_VERSION_ARG_LENGTH } from "../tool-args.js";
import { quoteThirdParty } from "../untrusted-text.js";
import { checkableSpec } from "./briefing-names.js";
import { ecosystemKey, NPM_TAG, type TaskWordSeen } from "./briefing-new-packages.js";
import type { UnverifiedWord } from "./briefing-requested-versions.js";
import { nameProblem } from "./dependency-check-screen.js";

/** At most this many `packages` entries and `not_packages` words are read; the rest are refused, said. */
export const MAX_DECLARED = 25;

/** How many names `to_confirm` lists one by one; `to_confirm_total` counts all. */
export const MAX_TO_CONFIRM = 25;

const ECOSYSTEMS: readonly CheckEcosystem[] = ["npm", "PyPI", "crates.io", "Go"];
const DECLARED_FIELDS = new Set(["ecosystem", "name", "version", "public"]);

/** One `packages` entry as the caller wrote it, validated. */
export interface DeclaredPackage {
  ecosystem: CheckEcosystem;
  name: string;
  /** What the task will write: an exact version, a constraint or a dist-tag. Absent: the version the task writes beside the name, else latest. */
  version?: string;
  public: boolean;
  /** Its place in the caller's list. */
  at: number;
}

/** What the screen or the argument check kept from being read: shown without the value, and why. */
export interface NotRead {
  shown: string;
  reason: string;
}

export interface ToConfirm {
  name: string;
  /** The ecosystems the name could belong to (the task names no manager or file that decides one). */
  ecosystems: string[];
  /** The version the task writes beside it, as written. */
  version?: string;
  seen: "operand of an install command" | "entry of a manifest snippet" | "word after an adding verb";
  /** A help for the agent: a near-miss of a popular name. Never a gate. */
  hint?: string;
  /** A help for the agent: the task calls it a key, a secret, a password or a token. Never a gate. */
  caution?: string;
}

export interface CheckedIndex {
  name: string;
  ecosystem: string;
  version: string;
  verdict: string;
  basis: "project dependency" | "well-known name" | "confirmed public by you";
}

export interface PrivateIndex {
  name: string;
  ecosystem: string;
  basis: "marked private by you" | "this project's registry configuration";
}

export interface TaskPackages {
  status: "complete" | "confirmation_needed";
  to_confirm: ToConfirm[];
  /** Every name waiting, when more than to_confirm lists. */
  to_confirm_total?: number;
  checked: CheckedIndex[];
  private: PrivateIndex[];
  not_read: NotRead[];
  dismissed: string[];
  next_step?: string;
}

/**
 * What the agent does when names wait (fixed wording: an agent acts on it). It leads to a statement the
 * agent writes itself; nothing in to_confirm is shaped as the `packages` argument, so it cannot be pasted back.
 */
export const NEXT_STEP =
  "Call what_should_i_know again with the same task and `packages`: one entry for each name in to_confirm that is a package this task adds or changes: `public: true` if it is on the public registry (it is checked in that call), `public: false` if it comes from a private registry, git, a path or the workspace (it is never sent). Put a name that is not a package in `not_packages`. Every name in to_confirm needs one of these three answers: a name left out stays in to_confirm. Nothing about a name is sent until you mark it public. You may add packages the task changes that are not listed.";

/**
 * What the agent does when its call declared no packages and nothing waits (fixed wording). A bare call never
 * ends complete: the reader is a net under the agent's statement, and no promise rests on what it reads.
 */
export const DECLARE_STEP =
  "This call declared no packages. Call what_should_i_know again with the same task and `packages`: one entry for each package the task adds, pins, bumps, downgrades or swaps in, or `packages: []` if it adds or changes none. The level follows from that.";

/** The delegation reason of a bare call with nothing waiting. */
export const DECLARE_REASON = "This call declared no packages: do task_packages.next_step; the level follows from your answer.";

/** What a level reached after a declaration rests on, in one clause. */
export function declaredClause(count: number): string {
  return count === 0 ? "You declared that the task adds or changes no package." : `You declared ${count} package${count === 1 ? "" : "s"}.`;
}

/** The delegation reason while names wait and nothing known already makes the task human_only. */
export function confirmationReason(waiting: number): string {
  return `${waiting} name${waiting === 1 ? "" : "s"} the task may mean as packages ${waiting === 1 ? "waits" : "wait"} for your confirmation (task_packages.to_confirm): do task_packages.next_step; the level follows from the answers.`;
}

/** The summary's sentence while names wait. */
export function confirmationSummary(waiting: number): string {
  return `CONFIRMATION NEEDED: ${waiting} name${waiting === 1 ? "" : "s"} the task may mean as packages ${waiting === 1 ? "was" : "were"} not looked up; task_packages.next_step says how to settle ${waiting === 1 ? "it" : "them"}.`;
}

/**
 * The `packages` argument, entry by entry: an entry with a field this tool does not define, a missing or
 * non-boolean `public`, an unknown ecosystem, a name its registry cannot have or a version no constraint
 * reads is refused in its place and never sent; the others stand. Past MAX_DECLARED entries are refused.
 * A refusal never repeats what the entry held (it may be a secret): it names the entry by its place.
 */
export function readDeclarations(raw: unknown): { entries: DeclaredPackage[]; refused: NotRead[] } {
  const entries: DeclaredPackage[] = [];
  const refused: NotRead[] = [];
  if (raw === undefined || raw === null) return { entries, refused };
  if (!Array.isArray(raw)) return { entries, refused: [{ shown: "packages", reason: "refused: it must be a list of { ecosystem, name, version?, public } entries; nothing in it was read or sent" }] };
  raw.forEach((item, at) => {
    const where = `packages[${at}]`;
    if (at >= MAX_DECLARED) {
      refused.push({ shown: where, reason: `refused: at most ${MAX_DECLARED} entries are read per call; nothing in it was sent` });
      return;
    }
    const problem = declarationProblem(item);
    if (problem) {
      refused.push({ shown: where, reason: `refused: ${problem}; nothing in it was sent` });
      return;
    }
    const o = item as Record<string, unknown>;
    const ecosystem = ECOSYSTEMS.find((e) => e.toLowerCase() === String(o.ecosystem).trim().toLowerCase())!;
    const version = typeof o.version === "string" && o.version.trim() ? o.version.trim() : undefined;
    entries.push({ ecosystem, name: String(o.name).trim(), ...(version ? { version } : {}), public: o.public as boolean, at });
  });
  return { entries, refused };
}

/** Why one `packages` entry is refused, or null. */
function declarationProblem(item: unknown): string | null {
  if (typeof item !== "object" || item === null || Array.isArray(item)) return "an entry must be an object { ecosystem, name, version?, public }";
  const o = item as Record<string, unknown>;
  // A field this tool does not define is never ignored (`registry`, `index_url` say where a package lives,
  // and this tool reads only the public registry): the entry is refused, as dependency_check refuses one.
  const unknown = Object.keys(o).find((k) => !DECLARED_FIELDS.has(k));
  if (unknown !== undefined) return `unknown field ${JSON.stringify(quoteThirdParty(unknown, 40))}: an entry defines only ecosystem, name, version and public`;
  if (typeof o.public !== "boolean") return "`public` must be true (a package on the public registry: it is checked) or false (from a private registry, git, a path or the workspace: never sent)";
  if (typeof o.ecosystem !== "string" || !ECOSYSTEMS.some((e) => e.toLowerCase() === o.ecosystem!.toString().trim().toLowerCase())) return `\`ecosystem\` must be one of ${ECOSYSTEMS.map((e) => `"${e}"`).join(", ")}`;
  if (typeof o.name !== "string" || !o.name.trim()) return "`name` must be a non-empty string";
  if (lengthProblem("name", "package", o.name) || o.name.length > MAX_NAME_ARG_LENGTH) return "`name` is longer than any package name";
  const ecosystem = ECOSYSTEMS.find((e) => e.toLowerCase() === String(o.ecosystem).trim().toLowerCase())!;
  // The ecosystem's own name grammar, the screen dependency_check applies (dependency-check-screen.ts).
  const bad = nameProblem(ecosystem, o.name.trim());
  if (bad) return `\`name\` is no ${ecosystem} package name (${bad})`;
  if (o.version !== undefined && o.version !== null) {
    if (typeof o.version !== "string") return "`version` must be a string";
    const v = o.version.trim();
    if (v.length > MAX_VERSION_ARG_LENGTH) return "`version` is longer than any version or constraint";
    if (v && !versionReadable(ecosystem, v)) return `\`version\` is no ${ecosystem} version, constraint or tag dependency_check reads`;
  }
  return null;
}

/** A version, constraint or tag as dependency_check reads one for `to`. */
export function versionReadable(ecosystem: CheckEcosystem, version: string): boolean {
  if (/^latest$/i.test(version)) return true;
  if (checkableSpec(ecosystem, version) !== null) return true;
  return ecosystem === "npm" && NPM_TAG.test(version);
}

/** The `not_packages` argument: strings, at most MAX_DECLARED, each no longer than a word can be. */
export function readNotPackages(raw: unknown): { words: string[]; refused: NotRead[] } {
  const words: string[] = [];
  const refused: NotRead[] = [];
  if (raw === undefined || raw === null) return { words, refused };
  if (!Array.isArray(raw)) return { words, refused: [{ shown: "not_packages", reason: "refused: it must be a list of words; nothing in it was read" }] };
  raw.forEach((w, at) => {
    if (at >= MAX_DECLARED) refused.push({ shown: `not_packages[${at}]`, reason: `refused: at most ${MAX_DECLARED} words are read per call` });
    else if (typeof w !== "string" || !w.trim() || w.length > 300) refused.push({ shown: `not_packages[${at}]`, reason: "refused: each must be one word of the task" });
    else words.push(w.trim());
  });
  return { words, refused };
}

/** A name compared as its ecosystem compares names (PEP 503, crates' `-`/`_`, npm's case; a Go path as written). */
export function sameName(a: string, b: string, ecosystem: CheckEcosystem): boolean {
  return ecosystemKey(a, ecosystem) === ecosystemKey(b, ecosystem);
}

/** Whether a word the task gives is settled by a `not_packages` word, in any ecosystem it was read for. */
export function dismissedBy(word: string, ecosystems: readonly string[], notPackages: readonly string[]): string | undefined {
  const ecos = (ecosystems.length > 0 ? ecosystems : ECOSYSTEMS).filter((e): e is CheckEcosystem => (ECOSYSTEMS as readonly string[]).includes(e));
  return notPackages.find((n) => n.toLowerCase() === word.toLowerCase() || ecos.some((e) => sameName(n, word, e)));
}

/**
 * The declaration that settles a word the task gives: one whose name is the word under the
 * declaration's own ecosystem's name rule. One declaration settles the word in every ecosystem the
 * reader offered it for (the agent said which registry it is).
 */
export function declarationFor(word: string, declared: readonly DeclaredPackage[]): DeclaredPackage | undefined {
  return declared.find((d) => sameName(d.name, word, d.ecosystem));
}

const SEEN: Record<TaskWordSeen, ToConfirm["seen"]> = {
  command: "operand of an install command",
  manifest: "entry of a manifest snippet",
  prose: "word after an adding verb",
};

/** Words a task uses for a secret: a name beside one of them may be one. */
const SECRET_WORDS = /^(?:keys?|secrets?|passwords?|passwd|pwd|passphrase|tokens?|credentials?|apikey|api[-_]key|otp|salt)$/i;

/**
 * A caution when the task calls the word a key, a secret, a password or a token (within three words of
 * it). Help for the agent, never a gate: a promise never depends on it. Linear: one scan of the task
 * per listed word, at most MAX_TO_CONFIRM words.
 */
export function cautionFor(task: string, word: string): string | undefined {
  const lower = task.toLowerCase();
  const target = word.toLowerCase();
  // At most the first 50 places the word stands: a help, never worth a long scan of a hostile task.
  for (let at = lower.indexOf(target), seen = 0; at >= 0 && seen < 50; at = lower.indexOf(target, at + target.length), seen++) {
    const before = lower.slice(Math.max(0, at - 60), at).split(/[^a-z0-9_-]+/).filter(Boolean).slice(-3);
    const after = lower.slice(at + target.length, at + target.length + 60).split(/[^a-z0-9_-]+/).filter(Boolean).slice(0, 3);
    if ([...before, ...after].some((w) => SECRET_WORDS.test(w))) return "the task calls this a key, a secret, a password or a token: confirm it only if it really is a package";
  }
  return undefined;
}

/** One word waiting for the agent, as to_confirm lists it. */
export function toConfirmEntry(task: string, w: UnverifiedWord & { seen?: TaskWordSeen }): ToConfirm {
  const near = /^one edit from (\S+): /.exec(w.note ?? "")?.[1];
  const caution = cautionFor(task, w.word);
  return {
    name: w.word,
    ecosystems: w.read_as.split(" or "),
    ...(w.version ? { version: w.version } : {}),
    seen: SEEN[w.seen ?? "prose"],
    ...(near ? { hint: `one edit from ${near}: if you mean ${near}, confirm ${near} instead` } : {}),
    ...(caution ? { caution } : {}),
  };
}

/**
 * The embedding provider's copy of the task with the names the caller marked private and its
 * not_packages words blanked as well (P2: neither is sent by any path, the embedding provider included).
 */
export function blankWords(text: string, words: readonly string[]): string {
  let out = text;
  for (const w of words) {
    if (!w) continue;
    const escaped = w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out = out.replace(new RegExp(`(?<![\\w@/.-])${escaped}(?![\\w/-])`, "gi"), (m) => " ".repeat(m.length));
  }
  return out;
}
