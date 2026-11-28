// SPDX-License-Identifier: Apache-2.0
/**
 * Reading `task_packages` (wave 2, package confirmation) in the earlier briefing suites, which were written
 * against `unverified_words` and `withheld_from_task`: the same facts, now one section. `waitingWords`
 * gives each to_confirm entry as { word, read_as, version?, hint?, caution? } (read_as: the ecosystems
 * joined with " or ", as the earlier list said them); `notReadWords` gives not_read. Both are undefined when
 * empty, as the earlier fields were absent then.
 */

interface ToConfirmEntry {
  name: string;
  ecosystems: string[];
  version?: string;
  hint?: string;
  caution?: string;
}

export interface WaitingWord {
  word: string;
  read_as: string;
  version?: string;
  hint?: string;
  caution?: string;
}

const stripHint = (hint: string) =>
  hint
    .split("; ")
    .filter((h) => !/^this project uses .+: declare it in each one you add it to$/.test(h))
    .join("; ");

export function waitingWords(r: unknown): WaitingWord[] | undefined {
  const list = ((r as { task_packages?: { to_confirm?: ToConfirmEntry[] } } | null)?.task_packages?.to_confirm ?? []).map((e) => ({
    word: e.name,
    read_as: e.ecosystems.join(" or "),
    ...(e.version ? { version: e.version } : {}),
    // The ecosystems hint of a prose candidate (round 4, K2) is left out here: a1128-confirm-contract tests it.
    ...(e.hint && stripHint(e.hint) ? { hint: stripHint(e.hint) } : {}),
    ...(e.caution ? { caution: e.caution } : {}),
  }));
  return list.length > 0 ? list : undefined;
}

export function notReadWords(r: unknown): Array<{ shown: string; reason: string }> | undefined {
  const list = (r as { task_packages?: { not_read?: Array<{ shown: string; reason: string }> } } | null)?.task_packages?.not_read ?? [];
  return list.length > 0 ? list : undefined;
}

/** The hint a near-miss of `of` carries in to_confirm. */
export const nearMissHint = (of: string) => `one edit from ${of}: if you mean ${of}, confirm ${of} instead`;
