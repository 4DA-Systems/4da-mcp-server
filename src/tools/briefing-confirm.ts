// SPDX-License-Identifier: Apache-2.0
/**
 * NOTES: how it reads; not part of the contract (what-should-i-know.ts THE CONTRACT).
 *
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

import { CREDENTIAL_REFUSAL } from "../argument-screen.js";
import { hasCredentialShape } from "../output-screen.js";
import type { CheckEcosystem } from "../live/release-metadata.js";
import { credentialShape, looksLikeSecret } from "./briefing-task-screen.js";
import { bareName, foldForNames } from "./briefing-command-check.js";
import { lengthProblem, MAX_NAME_ARG_LENGTH, MAX_VERSION_ARG_LENGTH } from "../tool-args.js";
import { ecosystemKey, type TaskWordSeen } from "./briefing-new-packages.js";
import { validateItem } from "./dependency-check.js";
import type { UnverifiedWord } from "./briefing-requested-versions.js";
import { nameProblem, versionLooksSecret } from "./dependency-check-screen.js";

/** At most this many `packages` entries and `not_packages` words are read; the rest are refused, said. */
export const MAX_DECLARED = 100;

/** How many names `to_confirm` lists one by one; `to_confirm_total` counts all. */
export const MAX_TO_CONFIRM = 25;

const ECOSYSTEMS: readonly CheckEcosystem[] = ["npm", "PyPI", "crates.io", "Go"];
const DECLARED_FIELDS = new Set(["ecosystem", "name", "version", "public"]);

/** One `packages` entry as the caller wrote it, validated. */
export interface DeclaredPackage {
  ecosystem: CheckEcosystem;
  name: string;
  /** What the caller will write: an exact version, a constraint, or "latest" (another dist-tag is refused). Absent: the declaration is incomplete (round 9, E1). */
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
  seen: "operand of an install command" | "operand of a runner command" | "entry of a manifest snippet" | "a name with a version written in the task" | "word after an adding verb" | "a line of the requirements file the task names";
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
  basis: "marked private by you" | "this project's registry configuration" | "your FOURDA_PRIVATE_PACKAGES list" | "the command in the task installs it from its own package index or registry (-i, --index-url, --registry), not the public one" | "the manifest snippet in the task takes it from git, a path, a registry or the workspace, not the public registry";
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
  "Call what_should_i_know again with the same task and `packages`: one entry for each name in to_confirm that is a package this task adds or changes: `public: true` if it is on the public registry (it is checked in that call), `public: false` if it comes from a private registry, git, a path or the workspace (it is never looked up for the task). Put a name that is not a package in `not_packages`. Every name in to_confirm needs one of these three answers: a name left out stays in to_confirm. This briefing sends nothing about a name until you mark it public; this project's own scan still reads its installed dependencies. to_confirm can miss names and ecosystems: declare every package the task adds or changes, in each ecosystem it is added to, whether it is listed here or not.";

/** What a declaration does not change (round 6, item 4a): said wherever an installed dependency is marked private. */
export const SCAN_STILL_READS =
  "A declaration keeps this briefing from looking a name up for the task; it does not change this project's own vulnerability scan, which reads the installed dependencies and sends their names unless the project's configuration marks them private (FOURDA_PRIVATE_PACKAGES, an .npmrc scope or registry, a pip index, GOPRIVATE).";

/** Round 7, C3: why a name the task adds was not looked up when the task names a package source of its own. */
export const SOURCE_HELD = "not looked up: the task names a package source of its own; if it is on the public registry, check it with dependency_check";

/** The last sentence of every safe_to_delegate reason (contract K1). */
/** Round 15, A4: the boundary of what any answer covers, said in every safe reason before its last sentence. */
/**
 * Round 16, C1(a): an installed dependency whose installed version is malware (a MAL- record, or the scan's malware
 * flag) makes every briefing of that project human_only, whatever the task.
 */
export const INSTALLED_MALWARE = (installed: string[]) =>
  `This project has ${installed.length === 1 ? installed[0] : `${installed.slice(0, -1).join(", ")} and ${installed[installed.length - 1]}`} installed, which ${installed.length === 1 ? "is" : "are"} recorded as malware: a person must deal with that before any task is delegated.`;
/** Round 16b: an installed npm security placeholder (`0.0.N-security`) makes every briefing of the project human_only. */
export const INSTALLED_PLACEHOLDER = (installed: string[]) =>
  installed.length === 1
    ? `This project has ${installed[0]} installed, npm's placeholder for a name taken down as malware: a person must remove that dependency before any task is delegated.`
    : `This project has ${installed.slice(0, -1).join(", ")} and ${installed[installed.length - 1]} installed, npm's placeholders for names taken down as malware: a person must remove those dependencies before any task is delegated.`;
/** Round 16, C1(b): the safe reason's opening when project-wide findings are listed (none of them on a package the task touches). */
export const PROJECT_FINDINGS_LISTED = (n: number) =>
  `Vulnerability scan ready; nothing version-confirmed for the packages this task touches; ${n} project-wide finding${n === 1 ? " is" : "s are"} listed below (advisories, scope "project"), no major-version jump and no recorded-decision conflict for this task.`;
/** Round 18b: the error text of a briefing that failed before it finished (index.ts): no level is given. */
export const BRIEFING_FAILED = "what_should_i_know failed before it finished, so nothing about this task was checked: this is no assessment, and the task is not safe to delegate on it.";
/** Round 18, N7: a "ready" scan that did not read every lockfile the walk found says how many it did not read. */
export const NOT_SCANNED_LOCKFILES = (by: number | { ignored: number; depth: number; projectLimit: number; outside: number; unreadable: number }) => {
  const u = typeof by === "number" ? { ignored: by, depth: 0, projectLimit: 0, outside: 0, unreadable: 0 } : by;
  const n = u.ignored + u.depth + u.projectLimit + u.outside + u.unreadable;
  // Ignored, excluded or fixture folders alone: the round 18 sentence, unchanged.
  if (n === u.ignored) return `${n} lockfile${n === 1 ? "" : "s"} under ignored, excluded or test-fixture folders ${n === 1 ? "was" : "were"} not read, so what ${n === 1 ? "it pins" : "they pin"} was not checked (lockfiles_not_scanned).`;
  const parts = [
    u.ignored > 0 ? `${u.ignored} under ignored, excluded or test-fixture folders` : "",
    u.depth > 0 ? `${u.depth} deeper than the scan goes` : "",
    u.projectLimit > 0 ? `${u.projectLimit} past the project limit` : "",
    u.outside > 0 ? `${u.outside} behind a link outside the project` : "",
    u.unreadable > 0 ? `${u.unreadable} in a folder that could not be listed` : "",
  ].filter(Boolean);
  return `${n} lockfile${n === 1 ? " was" : "s were"} found and not read (${parts.join(", ")}), so what ${n === 1 ? "it pins" : "they pin"} was not checked (lockfiles_not_scanned).`;
};
/** Round 19, M5: said in a safe reason whenever the scan withheld installed names the project's configuration makes private. */
export const PRIVATE_INSTALLED = (n: number) => `${n} installed dependenc${n === 1 ? "y is" : "ies are"} private by the project's configuration and ${n === 1 ? "was" : "were"} not checked (vulnerability_scan lists ${n === 1 ? "it" : "them"}).`;
/** Round 19, Q2: a lockfile the scan did not read for a bound or a link (not an ignored or fixture folder): the scan is incomplete. */
export const SCAN_INCOMPLETE = "The scan is incomplete: it found lockfiles it did not read (deeper than it goes, past its project limit, behind a link outside the project, or in a folder it could not list), so it cannot vouch for the project. Pass project_path for the part you need.";
/** Round 16, C3: said only when decisionConflictsFor found no conflict over the declared, the read and the installed names. */
export const NO_DECISION_CONFLICT = "no recorded-decision conflict for this task";
export const OUTSIDE_COVERAGE ="This briefing checks npm, PyPI, crates.io and Go packages: what the task installs through any other manager or tool is outside what this answer covers.";
/** Round 15, A5: the echoed task differs from the caller's in more than blanks (characters folded or removed). */
export const TASK_FOLDED = "the task held characters this briefing folded or removed (full-width or look-alike letters, invisible characters, markup): the echoed task is the reading copy";
export const RESTS_ON_DECLARATION = "This rests on your declaration of what the task adds and on your statement of which words are not packages: a package you did not declare may not have been checked.";
/** Round 11, P1: the task-text reading is best effort. */
export const BEST_EFFORT_READING = "The versions this briefing read in the task's commands and snippets are best effort: a version written in a spelling it does not read was not checked, so declare the version the task writes.";

/** Added to next_step when more names wait than to_confirm shows (fixed wording). */
export const MORE_WAITING =
  "to_confirm shows the first 25 of to_confirm_total names: answer these (keeping your earlier answers in the call), then call again for the next ones; an answer for a waiting name that is not shown is honoured too.";

/**
 * What the agent does when its call declared no packages and nothing waits (fixed wording). A bare call never
 * ends complete: the reader is a net under the agent's statement, and no promise rests on what it reads.
 */
export const DECLARE_STEP =
  "This call declared no packages. Call what_should_i_know again with the same task and `packages`: one entry for each package the task adds, pins, bumps, downgrades or swaps in, or `packages: []` if it adds or changes none. The level follows from that.";

/** The delegation reason of a bare call with nothing waiting. */
export const DECLARE_REASON = "This call declared no packages: do task_packages.next_step; the level follows from your answer.";

/** What a level reached after a declaration rests on, in one clause. */
export function declaredClause(count: number, refused = 0): string {
  // Round 6b, item 1: entries that were refused are no statement that the task changes nothing.
  if (refused > 0 && count === 0) return `None of your ${refused} \`packages\` entr${refused === 1 ? "y" : "ies"} could be read, so nothing you declared was checked.`;
  return count === 0 ? "You declared that the task adds or changes no package." : `You declared ${count} package${count === 1 ? "" : "s"}.`;
}

/** The refused entries by reason class, never their values (round 6b, item 1): "2 with a name its registry cannot have". */
export function refusedClasses(refused: readonly NotRead[]): string {
  const classes: Array<[RegExp, string]> = [
    [/at most \d+ entries/, "past the 100-entry limit"],
    [/unknown field/, "with a field this tool does not define"],
    [/`public` must be/, "without public: true or false"],
    [/`ecosystem` must be/, "with an unknown ecosystem"],
    [/credential.s shape is not a version|`version` looks like a credential/, "with a version shaped like a credential"],
    [/credential.s shape is not an? (?:package name|ecosystem)/, "with a name shaped like a credential"],
    [/`version`/, "with a version dependency_check cannot read"],
    [/`name`/, "with a name its registry cannot have"],
    [/declared public, and private/, "declared both public and private"],
    [/looks like a credential/, "with a name shaped like a credential"],
    [/must be a list|an entry must be an object/, "that are no { ecosystem, name, version?, public } entry"],
    // not_packages (round 9, docs lane 4): the cause by name.
    [/it is not a string/, "in not_packages that are not strings"],
    [/each must be one word of the task/, "in not_packages that are no word of the task"],
    [/at most \d+ words/, "in not_packages past the 100-word limit"],
  ];
  const counts = new Map<string, number>();
  for (const r of refused) {
    const label = classes.find(([re]) => re.test(r.reason))?.[1] ?? "refused for another reason";
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return [...counts].map(([label, n]) => `${n} ${label}`).join(", ");
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
export function readDeclarations(raw: unknown): { entries: DeclaredPackage[]; refused: NotRead[]; forbidOnly: string[] } {
  const entries: DeclaredPackage[] = [];
  const refused: NotRead[] = [];
  /** Round 6, item 4b: a `public: false` entry that is refused still forbids its name (folded by the caller). */
  const forbidOnly: string[] = [];
  if (raw === undefined || raw === null) return { entries, refused, forbidOnly };
  if (!Array.isArray(raw)) return { entries, refused: [{ shown: "packages", reason: "refused: it must be a list of { ecosystem, name, version?, public } entries; nothing in it was read or sent" }], forbidOnly };
  raw.forEach((item, at) => {
    const where = `packages[${at}]`;
    if (at >= MAX_DECLARED) {
      refused.push({ shown: where, reason: `refused: at most ${MAX_DECLARED} entries are read per call; nothing in it was sent. A task that adds more than ${MAX_DECLARED} packages is too large for one briefing: split it into smaller tasks` });
      return;
    }
    const problem = declarationProblem(item);
    if (problem) {
      const credential = /credential.s shape is not an? ([^;]+);/.exec(problem);
      refused.push({ shown: where, reason: credential ? CREDENTIAL_REFUSAL(credential[1]) : `refused: ${problem}; nothing in it was sent` });
      const o = (item ?? {}) as Record<string, unknown>;
      // A refused entry that says private (`false`, or the string "false": round 7, C9c) still forbids its name.
      if (typeof item === "object" && (o.public === false || (typeof o.public === "string" && o.public.trim().toLowerCase() === "false")) && typeof o.name === "string" && o.name.trim() && o.name.length <= MAX_NAME_ARG_LENGTH) forbidOnly.push(goUnescaped(o.name.trim()));
      return;
    }
    const o = item as Record<string, unknown>;
    const ecosystem = ECOSYSTEMS.find((e) => e.toLowerCase() === String(o.ecosystem).trim().toLowerCase())!;
    // As declared (round 7, C6): the item dependency_check would get. A Poetry `^` / `~` is refused for PyPI here as
    // dependency_check refuses it (the smaller change: neither accepts it); a Go `!` path is kept as written.
    const version = typeof o.version === "string" && o.version.trim() ? o.version.trim() : undefined;
    const name = String(o.name).trim();
    entries.push({ ecosystem, name, ...(version ? { version } : {}), public: o.public as boolean, at });
  });
  return { entries, refused, forbidOnly };
}

/** A Go module path in the Go proxy's escaped form (`!z` for `Z`) as the go command writes it. */
export const goUnescaped = (name: string) => name.replace(/!([a-z])/g, (_m, c: string) => c.toUpperCase());

/**
 * A Poetry constraint as the PEP 440 range it means (item 7): `^1.2.3` is `>=1.2.3,<2.0.0` (`^0.2` is `>=0.2,<0.3`),
 * `~1.2` is `>=1.2,<1.3`. Null for anything else.
 */
export function poetrySpec(spec: string): string | null {
  const m = /^([\^~])\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(spec.trim());
  if (!m) return null;
  const [major, minor, patch] = [Number(m[2]), m[3] === undefined ? undefined : Number(m[3]), m[4] === undefined ? undefined : Number(m[4])];
  const floor = [m[2], m[3], m[4]].filter((x) => x !== undefined).join(".");
  let ceil: string;
  if (m[1] === "~") ceil = minor === undefined ? `${major + 1}` : `${major}.${minor + 1}`;
  else if (major > 0 || minor === undefined) ceil = `${major + 1}.0`;
  else if (minor > 0 || patch === undefined) ceil = `0.${minor + 1}`;
  else ceil = `0.0.${patch + 1}`;
  return `>=${floor},<${ceil}`;
}

/** Why one `packages` entry is refused, or null. */
function declarationProblem(item: unknown): string | null {
  if (typeof item !== "object" || item === null || Array.isArray(item)) return "an entry must be an object { ecosystem, name, version?, public }";
  const o = item as Record<string, unknown>;
  // A field this tool does not define is never ignored (`registry`, `index_url` say where a package lives,
  // and this tool reads only the public registry): the entry is refused, as dependency_check refuses one.
  const unknown = Object.keys(o).find((k) => !DECLARED_FIELDS.has(k));
  // Round 14, X1: counted, never named (a key may be a secret).
  if (unknown !== undefined) return `an unknown field (${Object.keys(o).filter((k) => !DECLARED_FIELDS.has(k)).length} unknown): an entry defines only ecosystem, name, version and public`;
  if (typeof o.public !== "boolean") return "`public` must be true (a package on the public registry: it is checked) or false (from a private registry, git, a path or the workspace: never sent)";
  if (typeof o.ecosystem !== "string" || !ECOSYSTEMS.some((e) => e.toLowerCase() === o.ecosystem!.toString().trim().toLowerCase())) return `\`ecosystem\` must be one of ${ECOSYSTEMS.map((e) => `"${e}"`).join(", ")}`;
  if (typeof o.name !== "string" || !o.name.trim()) return "`name` must be a non-empty string";
  if (lengthProblem("name", "package", o.name) || o.name.length > MAX_NAME_ARG_LENGTH) return "`name` is longer than any package name";
  // Round 12, R4: a name of a credential's shape (the task screen's own test) is refused whatever `public` says, and
  // never repeated; a `public: false` one still forbids its name.
  if (credentialShape(o.name.trim()) || looksLikeSecret(o.name.trim())) return CREDENTIAL_REFUSAL("package name").replace(/^refused: /, "");
  // Round 14b: nor an ecosystem (CREDENTIAL_SHAPES, as the output screen); a version is refused below, as dependency_check refuses it.
  if (typeof o.ecosystem === "string" && hasCredentialShape(o.ecosystem)) return CREDENTIAL_REFUSAL("ecosystem").replace(/^refused: /, "");
  const ecosystem = ECOSYSTEMS.find((e) => e.toLowerCase() === String(o.ecosystem).trim().toLowerCase())!;
  // The ecosystem's own name grammar, the screen dependency_check applies (dependency-check-screen.ts), and then
  // dependency_check's own entry rule on the name as written (round 7c, F6): a Go path in the proxy's `!`-escaped
  // form is refused here as dependency_check refuses it, so neither tool looks it up or records it.
  const bad = nameProblem(ecosystem, o.name.trim());
  if (bad) return `\`name\` is no ${ecosystem} package name (${bad})`;
  try {
    validateItem({ ecosystem, package: o.name.trim(), to: "latest" }, 0);
  } catch {
    return `\`name\` is refused as dependency_check refuses it: it is no ${ecosystem} package name as written (a Go path is written unescaped, \`github.com/Org/mod\`, never in the proxy's \`!\` form)`;
  }
  if (o.version !== undefined && o.version !== null) {
    if (typeof o.version !== "string") return "`version` must be a string";
    const v = o.version.trim();
    if (v.length > MAX_VERSION_ARG_LENGTH) return "`version` is longer than any version or constraint";
    // Exactly dependency_check's own validation of the item (a dist-tag other than latest is refused there, so here
    // too): what the check ledger records for a declared entry is what dependency_check would record for it.
    // Item 4c: the credential screen covers the whole entry: a version whose label has a credential shape is refused.
    // The same screen dependency_check applies to `to` (dependency-check-screen.ts versionLooksSecret).
    if (v && versionLooksSecret(v)) return CREDENTIAL_REFUSAL("version").replace(/^refused: /, "");
    if (v) {
      try {
        validateItem({ ecosystem, package: o.name.trim(), to: v }, 0);
      } catch (error) {
        // The refused value is never repeated (round 6b, item 1): dependency_check's message ends "(got <value>)".
        return `\`version\` is refused as dependency_check refuses it: ${(error instanceof Error ? error.message : String(error)).replace(/^items\[0\]\.to /, "").replace(/\s*\(got [\s\S]*\)\s*$/, "")}`;
      }
    }
  }
  return null;
}

/** The `not_packages` argument: strings, at most MAX_DECLARED, each no longer than a word can be. */
export function readNotPackages(raw: unknown): { words: string[]; refused: NotRead[] } {
  const words: string[] = [];
  const refused: NotRead[] = [];
  if (raw === undefined || raw === null) return { words, refused };
  if (!Array.isArray(raw)) return { words, refused: [{ shown: "not_packages", reason: "refused: it must be a list of words; nothing in it was read" }] };
  raw.forEach((w, at) => {
    if (at >= MAX_DECLARED) refused.push({ shown: `not_packages[${at}]`, reason: `refused: at most ${MAX_DECLARED} words are read per call` });
    else if (typeof w !== "string") refused.push({ shown: `not_packages[${at}]`, reason: "refused: it is not a string; each must be one word of the task" });
    else if (!w.trim() || w.length > 300) refused.push({ shown: `not_packages[${at}]`, reason: "refused: each must be one word of the task" });
    else words.push(w.trim());
  });
  return { words, refused };
}

/**
 * The key a forbidden name is held by (invariant I5), folded for every ecosystem's rules at once: case (npm,
 * PyPI, crates.io, an npm scope), PEP 503's runs of `-`, `_` and `.`, crates' `-`/`_`, and a Go path's `!`
 * escape of a capital. Folding more than one ecosystem would is the point: a private name is never sent under
 * another spelling.
 */
export function forbiddenKey(name: string): string {
  // A Go module's major-version suffix names the same private path: example.com/zqx/lib/v2 is example.com/zqx/lib.
  // An npm alias or an ecosystem prefix (`npm:x`) names the same package (fourth check, f-alias2).
  return baseName(name).replace(/!/g, "").replace(/^(.+\/.+)\/v\d+$/, "$1").replace(/[-_.]+/g, "-");
}

/**
 * THE fold of a name (round 14, X3), under every comparison of names: NFKC, default-ignorable code points removed,
 * case folded, the bare name (a version, extras, quotes and a trailing mark off), an ecosystem prefix off. The
 * never-send set and the dismissal compare its union form (forbiddenKey: every ecosystem's separators at once); a
 * declaration and a read name compare it under the declaration's own ecosystem rule (sameName).
 */
export function baseName(name: string): string {
  return bareName(foldForNames(name.trim())).replace(/^(?:npm|jsr|pypi):/, "");
}

/** Whether two names are one edit apart: one character changed, added or dropped, or two neighbours swapped (lodahs, lodash). */
export function oneEditApart(a: string, b: string): boolean {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  if (x === y || Math.abs(x.length - y.length) > 1) return false;
  let i = 0;
  while (i < x.length && i < y.length && x[i] === y[i]) i++;
  if (x.length === y.length) {
    if (x.slice(i + 1) === y.slice(i + 1)) return true;
    return x[i] === y[i + 1] && x[i + 1] === y[i] && x.slice(i + 2) === y.slice(i + 2);
  }
  return x.length > y.length ? x.slice(i + 1) === y.slice(i) : x.slice(i) === y.slice(i + 1);
}

/** A dependency_check answer that the call's time budget cut short (the item was not checked). */
export const BUDGET_MISS = /did not finish in time|time budget|time_budget/i;

/** A name compared as its ecosystem compares names (PEP 503, crates' `-`/`_`, npm's case; a Go path as written). */
export function sameName(a: string, b: string, ecosystem: CheckEcosystem): boolean {
  return ecosystemKey(baseName(a), ecosystem) === ecosystemKey(baseName(b), ecosystem);
}

/** Whether a word the task gives is settled by a `not_packages` word, in any ecosystem it was read for. */
export function dismissedBy(word: string, ecosystems: readonly string[], notPackages: readonly string[]): string | undefined {
  // Round 14, X3: the never-send set's own key (forbiddenKey), so a dismissal and the never-send rule agree on every
  // spelling. `ecosystems` is kept for the callers; the union fold covers each ecosystem's rule.
  void ecosystems;
  const w = forbiddenKey(word);
  return notPackages.find((n) => forbiddenKey(n) === w);
}

/**
 * The declaration that settles a word the task gives: one whose name is the word under the
 * declaration's own ecosystem's name rule. One declaration settles the word in every ecosystem the
 * reader offered it for (the agent said which registry it is).
 */
export function declarationFor(word: string, declared: readonly DeclaredPackage[]): DeclaredPackage | undefined {
  return declared.find((d) => sameName(d.name, word, d.ecosystem));
}

/**
 * Round 14, X2: EVERY seen kind a reader can emit, classified. "read": the briefing read the name itself (an operand
 * of a command it reads, a snippet entry, a version form, a line of a requirements file the task names); a dismissal
 * of it holds review_needed with its DISMISSED_READ text. "caller": a prose candidate, the caller's word to settle.
 * The test a1137-briefing-contract enumerates TaskWordSeen from the source and fails on a kind missing here.
 */
// Round 16, C8: "runner" is not a read kind. Every runner command (npx, pnpm dlx, bunx, uvx, pipx run, npm exec, uv tool
// run) is a command this briefing could not read whole, which holds the answer by unreadableReason; its operand is
// never reported as read, so no dismissal of it is a dismissal of a name the briefing read.
export const SEEN_KINDS: Readonly<Record<TaskWordSeen, "read" | "caller">> = { command: "read", runner: "caller", manifest: "read", form: "read", file: "read", prose: "caller" };
/** Round 18, N5: the reason for a dismissed or private-marked name this briefing would have checked (a well-known name on its bundled list). */
export const DISMISSED_KNOWN = (name: string) => `${name} was not sent because you marked it private or not a package, but this briefing would have checked it (a well-known name): it is unchecked; make sure nothing installs it unchecked`;
/** Round 15, A3: the reason for a dismissed name when the call declared a package one edit from it instead. */
export const DISMISSED_INSTEAD = (word: string, instead: string) => `you said ${word} is not a package and declared ${instead} instead: the task names ${word}; say so to the user, and make sure nothing installs ${word}`;
/** The reason a dismissal of a name the briefing read gives, per read kind (review_needed at least). */
export const DISMISSED_READ: Readonly<Record<Exclude<TaskWordSeen, "prose" | "runner">, (word: string) => string>> = {
  command: (w) => `you said ${w} is not a package; it stands where a package name stands in a command of the task: make sure nothing installs it`,
  manifest: (w) => `you said ${w} is not a package; it stands where a package name stands in a manifest entry of the task: make sure nothing installs it`,
  form: (w) => `you said ${w} is not a package; the task writes a version on it: make sure nothing installs it`,
  file: (w) => `you said ${w} is not a package; it stands on a line of the requirements file the task names: make sure nothing installs it`,
};

const SEEN: Record<TaskWordSeen, ToConfirm["seen"]> = {
  command: "operand of an install command",
  runner: "operand of a runner command",
  manifest: "entry of a manifest snippet",
  // Round 9 (docs lane 1): a D1(a) form in prose or a code span ("we pin zqxd2==1.2.3 there").
  form: "a name with a version written in the task",
  prose: "word after an adding verb",
  // Round 12 (#39): a line of a `-r` / `-c` file the task installs from.
  file: "a line of the requirements file the task names",
};

/** Words a task uses for a secret: a name beside one of them may be one. */
const SECRET_WORDS = /^(?:keys?|secrets?|passwords?|passwd|pwd|passphrase|tokens?|credentials?|apikey|api[-_]key|otp|salt)$/i;

/**
 * A caution when the task calls the word a key, a secret, a password or a token (within three words of
 * it). Help for the agent, never a gate: a promise never depends on it. Linear: one scan of the task
 * per listed word, at most MAX_TO_CONFIRM words.
 */
/** Words a task uses for a package of its own (a help for the agent, never a rule the level rests on). */
const PRIVATE_WORDS = new Set(["internal", "private", "company", "company's", "in-house", "inhouse", "proprietary", "corporate", "own"]);

export function cautionFor(task: string, word: string): string | undefined {
  const lower = task.toLowerCase();
  const target = word.toLowerCase();
  // At most the first 50 places the word stands: a help, never worth a long scan of a hostile task.
  for (let at = lower.indexOf(target), seen = 0; at >= 0 && seen < 50; at = lower.indexOf(target, at + target.length), seen++) {
    const before = lower.slice(Math.max(0, at - 60), at).split(/[^a-z0-9_-]+/).filter(Boolean).slice(-3);
    const after = lower.slice(at + target.length, at + target.length + 60).split(/[^a-z0-9_-]+/).filter(Boolean).slice(0, 3);
    if ([...before, ...after].some((w) => SECRET_WORDS.test(w))) return "the task calls this a key, a secret, a password or a token: confirm it only if it really is a package";
    // "our internal zq7-audit-log (company registry)": the task says where it comes from.
    const parenthetical = /^\s*\(/.test(lower.slice(at + target.length, at + target.length + 4));
    if ([...before.slice(-2), ...(parenthetical ? after : [])].some((w) => PRIVATE_WORDS.has(w))) return "the task calls this internal or the company's own: if it comes from a private registry, git or the workspace, declare it public: false (never sent)";
  }
  return undefined;
}

/** One word waiting for the agent, as to_confirm lists it. */
export function toConfirmEntry(task: string, w: UnverifiedWord & { seen?: TaskWordSeen }): ToConfirm {
  const near = /^one edit from (\S+): /.exec(w.note ?? "")?.[1];
  const caution = cautionFor(task, w.word);
  const ecosystems = w.read_as.split(" or ");
  // V4: never offer what the declaration check would refuse: an npm dist-tag is offered as the name, with a note.
  const tag = w.version && ecosystems.includes("npm") && /^[a-z][\w.-]*$/i.test(w.version) && !/^latest$/i.test(w.version) ? w.version : null;
  const hints = [
    ...(near ? [`one edit from ${near}: if you mean ${near}, confirm ${near} instead`] : []),
    ...(tag ? [`the task writes the tag ${tag}: name the version`] : []),
    // K2: a prose candidate is the caller's word: in which of the project's ecosystems it goes is too.
    ...((w.seen ?? "prose") === "prose" && ecosystems.length > 1 ? [`this project uses ${ecosystems.slice(0, -1).join(", ")} and ${ecosystems[ecosystems.length - 1]}: declare it in each one you add it to`] : []),
  ];
  return {
    name: w.word,
    ecosystems,
    ...(w.version && !tag ? { version: w.version } : {}),
    seen: SEEN[w.seen ?? "prose"],
    ...(hints.length > 0 ? { hint: hints.join("; ") } : {}),
    ...(caution ? { caution } : {}),
  };
}

/** Said in wisdom_recall_note when an embedding provider is configured: the briefing never sends it the task (C1). */
export const EMBEDDING_NOT_SENT_NOTE =
  "The task text is not sent for embedding: what_should_i_know ranks your stored decisions and memories on this machine.";
