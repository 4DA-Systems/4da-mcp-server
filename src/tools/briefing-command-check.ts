// SPDX-License-Identifier: Apache-2.0
/**
 * NOTES: how it reads; not part of the contract (what-should-i-know.ts THE CONTRACT).
 *
 * Task-text evidence of the task's packages (contract K2), best effort: the level rests on the caller's declaration,
 * and a version written in a spelling these readers do not read is not checked (round 11, P1). It is:
 * - the operands of a command the grammar reads whole, each a (name as written, ecosystem) pair;
 * - the entries the snippet readers read (manifestPairs: requirements, pyproject, Poetry, Cargo, package.json, go.mod;
 *   not Pipfile or setup.cfg), each a pair in that manifest's ecosystem;
 * - round 8, D1(a): a token that ties a version to a name, for example name@spec, name==spec (and PEP 440's other
 *   operators), `name = "spec"` or `"name": "spec"` anywhere in the task, prose or code span: the
 *   form itself ties the spec to the name written right before it, and to no other. Where the form decides the
 *   ecosystem (PEP 440: PyPI; `"name": "spec"`: npm; a Go module path: Go) it is a pair that waits; otherwise its
 *   spec is checked for every ecosystem a declaration gives that name. These are versions the briefing happens to
 *   read on a package, checked in addition; never a complete reading: the declared `version` is (K1, round 9);
 * A command or snippet the grammar names but cannot read whole is said by its manager and verb (or "a manifest
 * snippet") only (K3); nothing of it is offered, repeated or looked up. What the grammar consumed is consumed by
 * OCCURRENCE (D4): the same word elsewhere in the task is read by the other readers as before.
 */
import * as path from "node:path";
import type { CheckEcosystem } from "../live/release-metadata.js";
import { pushAll } from "../array-utils.js";
import { canonicalCommands, MANAGER_NAMES, wordsOf, type CanonicalCommand } from "./briefing-canonical.js";
import { checkableSpec } from "./briefing-names.js";
import { credentialShape, looksLikeSecret } from "./briefing-task-screen.js";
import { pep508, readSnippets, type SnippetRead } from "./briefing-snippets.js";
import { readingStopped } from "../call-budget.js";
export { pep508 };

export interface InstallCommand {
  /** The command as written, capped: for tests and diagnosis only, never repeated in an answer (K3). */
  text: string;
  /** The ecosystem its manager installs from. */
  ecosystem: CheckEcosystem;
  /** Its operands, as written. */
  operands: string[];
  /** The manager word and the verb, from this module's fixed lists: what an answer may say of the command. */
  manager: string;
  verb: string;
  /** Why it is not read whole, when it is not (K3; fixed wording, never the task's words). */
  unreadable?: string;
  /** It installs from an index the task names that is not the public one (`pip install -i <private> X`). */
  privateIndex?: boolean;
  /** The requirements files it installs from (`pip install -r requirements-extra.txt`), as written (V2). */
  requirementFiles?: string[];
}

/**
 * The task as the readers read it (V3, V4): markup a chat or a document wraps a command in is dropped (HTML
 * tags such as `<code>`, markdown's `**` and `__`), and a line continuation (a trailing backslash, PowerShell's
 * backtick, cmd's caret, each after a blank) is joined to the next line. Linear.
 *
 * Round 17, C4: emphasis is dropped by an exact rule (`MARKUP_RULE`), never inside a path-like or identifier-like
 * word: a `**` pair around text on one line, with no word character or `*` outside either end (`**bold**` is bold);
 * a `__` pair only around text that holds a blank, with no word character or `_` outside (`__two words__`), so
 * `__init__.py`, `__main__`, `__bold__` and `snake__case` stay as written.
 */
export const MARKUP_RULE = "a ** pair around text on one line with no word character or * outside either end; a __ pair only around text holding a blank, with no word character or _ outside";
export function readingText(task: string): string {
  return task
    .replace(/<\/?(?:code|pre|kbd|samp|tt|b|i|u|em|strong|span|p|div|br|li|ul|ol)\b[^<>]{0,100}>/gi, " ")
    .replace(/(?<![\w*])\*\*(?=[^\s*])([^*\n]{0,200}?[^\s*])\*\*(?![\w*])/g, "$1")
    .replace(/(?<![\w_])__(?=[^\s_])([^_\n]{0,200}?\s[^_\n]{0,200}?[^\s_])__(?![\w_])/g, "$1")
    // A lookbehind, not a leading `[ \t]+`: a 100 KB run of blanks was rescanned from every position (quadratic).
    .replace(/(?<=[ \t])[\\`^][ \t]*\r?\n[ \t]*/g, " ");
}

/** The name an operand names, its version or extras aside (`x@1.2`, `@s/x@^1`, `x==1.0`, `x[extra]>=2`). */
export function operandName(operand: string): string {
  const scoped = operand.startsWith("@");
  const at = operand.indexOf("@", scoped ? 1 : 0);
  const head = at > 0 ? operand.slice(0, at) : operand;
  return head.replace(/\[.*$/, "").replace(/(?:===?|~=|>=|<=|!=|>|<|\^|~).*$/, "");
}

/** A spec of release numbers and operators only: no pre-release or build label, no tag (what the detector may send). */
export const plainSpec = (spec: string) => /^[v\d.*x^~<>=!,| ]+$/i.test(spec) && /\d/.test(spec);

/** The version or constraint written ON an operand (V1): `x@4.17.20` 4.17.20, `x<2` <2, `x==1.0` ==1.0, `x[e]>=2` >=2. */
export function operandSpec(operand: string, ecosystem: CheckEcosystem): string | undefined {
  const scoped = operand.startsWith("@");
  const at = operand.indexOf("@", scoped ? 1 : 0);
  if (at > 0) {
    const spec = operand.slice(at + 1);
    return spec && !/^npm:/i.test(spec) ? spec : undefined;
  }
  if (ecosystem !== "PyPI") return undefined;
  const m = /(?:===?|~=|>=|<=|!=|>|<)[^;\s]*$/.exec(operand.replace(/^[^[]*\[[^\]]*\]/, (x) => x.replace(/\[[^\]]*\]$/, "")));
  if (!m) return undefined;
  // `==3.2.0` is the release 3.2.0, as the reader writes it; a range keeps its operators.
  return /^===?[^=<>!~,]+$/.test(m[0]) ? m[0].replace(/^===?/, "") : m[0];
}

/**
 * Every registry name an operand installs: its own, and an alias's target (`lodash@npm:zqxevil` installs
 * zqxevil; deno's `npm:zqxevil@1`). A `jsr:` specifier names a registry this server does not check: it is
 * returned as written, so it is never accounted for.
 */
export function operandNames(operand: string): string[] {
  const alias = operand.search(/(?:^|@)npm:/i);
  if (alias >= 0) {
    const target = operand.slice(operand.toLowerCase().indexOf("npm:", alias) + 4);
    return [...(alias > 0 ? [operandName(operand.slice(0, alias))] : []), operandName(target)].filter(Boolean);
  }
  if (/^jsr:/i.test(operand)) return [operand];
  return [operandName(operand)].filter(Boolean);
}

/**
 * An operand that names no registry package: a path, a URL, a git or file source, a version, a file. A version is
 * a version only by the grammar (V3): `v8-zqxevil` and `1-zqxevil` are names.
 */
export function namesNoPackage(operand: string): boolean {
  const o = operand.toLowerCase();
  if (!o || o === "." || o === ".." || o === "-" || o === "./...") return true;
  if (/^(?:\.{1,2}[\\/]|[\\/~]|[a-z]:[\\/])/.test(o)) return true;
  if (o.includes("://") || /^(?:git\+|git:|github:|file:|link:|workspace:|catalog:|portal:|patch:)/.test(o)) return true;
  if (/^v?\d+(?:\.\d+)*$/.test(o) || /^v?\d+(?:\.\d+)+[-+][0-9a-z.-]+$/.test(o) || /^[\^~<>=*]/.test(o)) return true;
  // A word with a colon inside is a user and password or a host and port, never a name (`user:hunter2`).
  if (o.includes(":") && !/^(?:npm|jsr):|@npm:/.test(o)) return true;
  return /\.(?:txt|toml|json|lock|whl|tgz|tar\.gz|zip|cfg|ini|ya?ml)$/.test(o);
}

const MAX_PAIRS = 200;

/** A strict (name, ecosystem) pair the task's text gives by position (K2), with the spec written on it. */
export interface StrictPair {
  ecosystem: CheckEcosystem;
  name: string;
  version?: string;
  /** From a command that installs from the task's own private index (`-i <url>`): never sent. */
  privateIndex?: boolean;
  /** How the task gives it: an operand of a command, or an entry of a manifest snippet (round 6, item 1). */
  seen?: "command" | "manifest" | "form" | "file";
}

/**
 * The pairs the task's text gives and the commands it notices it does not read whole (round 7, C1/C2), best effort:
 * the operands of the commands the canonical grammar recognises (briefing-canonical.ts) and the entries the snippet
 * readers read (briefing-snippets.ts: requirements lines, pyproject arrays and tables, Poetry and Cargo tables,
 * package.json dependency objects, go.mod require lines; Pipfile and setup.cfg are not read). Read on the task as written
 * (markup dropped, continuations joined): a credential, a substitution or a quote problem among a command's words
 * makes it not read whole, and nothing of it is offered.
 */
/** A version-shaped written spec tied to a name by its form alone (round 8, D1(a)). */
export interface FormPair {
  name: string;
  spec: string;
  /** The ecosystems the form decides, or null: then every ecosystem a declaration gives the name. */
  ecosystems: CheckEcosystem[] | null;
}

export interface StrictEvidence {
  pairs: StrictPair[];
  unreadable: InstallCommand[];
  requirementFiles: string[];
  privateNames: Array<{ ecosystem: CheckEcosystem; name: string }>;
  manifestNotWhole: boolean;
  /** Commands the grammar named (read whole or not). */
  commands: CanonicalCommand[];
  /** Every occurrence of the word stands inside a command (or snippet) the grammar named: no reader offers it. */
  namedHere: (word: string) => boolean;
  /** Every occurrence of the word was consumed by the grammar (D4: by occurrence): no reader offers, looks up or weighs it. */
  consumedHere: (word: string) => boolean;
  /** Whether a command was named at all (its option values are the grammar's to say). */
  anyCommand: boolean;
  /** D1(a): the written specs of the task tied to a name by their form. */
  formPairs: FormPair[];
}

const META_KEYS = new Set(["version", "name", "edition", "description", "license", "authors", "author", "python", "rust-version", "readme", "homepage", "repository", "main", "type", "module", "types", "engines", "packagemanager", "private", "requires-python"]);

function countInto(map: Map<string, number>, words: readonly string[]): void {
  for (const w of words) map.set(w, (map.get(w) ?? 0) + 1);
}

export function strictEvidence(task: string): StrictEvidence {
  const pairs: StrictPair[] = [];
  const unreadable: InstallCommand[] = [];
  const requirementFiles: string[] = [];
  const seen = new Set<string>();
  const text = readingText(task.length > 200_000 ? task.slice(0, 200_000) : task);
  const tokens = text.split(/\s+/).filter(Boolean);
  // Every word occurrence of the task, as the readers see words (D4: consumption is by occurrence).
  const inTask = new Map<string, number>();
  for (const t of tokens) countInto(inTask, wordsOf(t));
  const named = new Map<string, number>();
  const consumed = new Map<string, number>();
  const wordWide = new Set<string>();
  const wordWideNamed = new Set<string>();
  const commands = canonicalCommands(text);
  for (const c of commands) {
    countInto(named, c.words);
    countInto(consumed, c.consumed);
    if (!c.canonical) {
      unreadable.push(asInstallCommand(c));
      continue;
    }
    for (const f of c.requirementFiles) if (!requirementFiles.includes(f)) requirementFiles.push(f);
    for (const o of c.operands) {
      if (pairs.length >= MAX_PAIRS) break;
      const key = `${c.ecosystem}\0${o.name}\0${o.spec ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      pairs.push({ ecosystem: c.ecosystem, name: o.name, ...(o.spec !== undefined ? { version: o.spec } : {}), seen: "command" });
    }
  }
  const manifest = manifestPairs(task);
  const manifestNotWhole = manifest.unreadable.length > 0;
  // Round 7c, F4: a snippet not read whole offers nothing, as a command not read whole: none of its entries is a
  // pair, a private name or a word another reader offers or looks up. F3: a key the grammar read (an alias key
  // `x = { package = "real" }` included) is never a prose candidate, and an alias key is looked up by no reader.
  // A snippet's words are held wherever they stand (a snippet is no command occurrence).
  if (!manifestNotWhole) pushAll(pairs, manifest.pairs);
  pushAll(unreadable, manifest.unreadable);
  for (const w of manifest.entryWords) wordWideNamed.add(w);
  for (const k of manifest.keys) wordWideNamed.add(k);
  // Marker words of a requirement (`; python_version >= "3.8"`) are no packages (round 11, docs lane).
  for (const w of manifest.consumed) wordWide.add(w);
  const pairNames = new Set(pairs.map((p) => p.name.toLowerCase()));
  for (const k of manifest.keys) if (manifestNotWhole || !pairNames.has(k)) wordWide.add(k);
  for (const p of manifest.privateNames) wordWide.add(p.name.toLowerCase());
  if (manifestNotWhole) for (const p of manifest.pairs) wordWide.add(p.name.toLowerCase());
  if (manifestNotWhole) for (const w of manifest.entryWords) wordWide.add(w);
  const operandNames = new Set(commands.flatMap((c) => c.operands.map((o) => o.name.toLowerCase())));
  const requireBlock = /\brequire[ \t]*\(/.test(text);
  // F8, F9 (round 14): nothing of a command not read whole, or of a command of a manager this briefing does not read,
  // is offered or looked up: every word of it is consumed, wherever the readers would find it.
  for (const c of commands) if (!c.canonical) for (const w of c.text.toLowerCase().split(/[^\p{L}\p{N}@._/-]+/u)) if (w) wordWide.add(w.replace(/[.]+$/, ""));
  for (const w of unreadCommands(text).words) wordWide.add(w);
  const allHere = (map: Map<string, number>, w: string) => (map.get(w) ?? 0) > 0 && (map.get(w) ?? 0) >= (inTask.get(w) ?? 0);
  const consumedHere = (word: string) => {
    const w = word.toLowerCase();
    // Round 12 (docs lane): a package manager's own name is never a candidate where it is no operand ("use brew to set it
    // up"), nor is go.mod's `require` before a parenthesis.
    return wordWide.has(w) || (!operandNames.has(w) && (allHere(consumed, w) || MANAGER_SET.has(w) || (w === "require" && requireBlock)));
  };
  const namedHere = (word: string) => {
    const w = word.toLowerCase();
    return wordWideNamed.has(w) || wordWide.has(w) || allHere(named, w);
  };

  // D1(a): written specs tied to a name by their form, anywhere in the task.
  const formPairs: FormPair[] = [];
  // Round 12, R2(d): the deadline is checked before each whole-task pass; a pass not run marks the call (budget text).
  const go = () => !readingStopped();
  const addForm = (name: string, rawSpec: string, ecosystems: CheckEcosystem[] | null) => {
    let spec = rawSpec.trim();
    let e = spec.length;
    while (e > 0 && ".,;:!?)`'\"".includes(spec[e - 1])) e--;
    spec = spec.slice(0, e);
    if (!name || !spec || formPairs.length >= MAX_PAIRS || META_KEYS.has(name.toLowerCase())) return;
    const fits = (ecosystems ?? (["npm", "PyPI", "crates.io", "Go"] as CheckEcosystem[])).filter((eco) => /^latest$/i.test(spec) || checkableSpec(eco, spec) !== null);
    if (fits.length === 0) return;
    if (!formPairs.some((f) => f.name === name && f.spec === spec)) formPairs.push({ name, spec, ecosystems: ecosystems ? fits : null });
  };
  if (go()) for (const m of text.matchAll(/(?<![\w@\/.-])([a-z0-9.-]+\.[a-z]{2,}\/[^\s@`'"]+)@(v[^\s,;`'")\]]+)/gi)) addForm(m[1], m[2], ["Go"]);
  // Forms that tie a version to a name, for example (round 11, P1: best effort, never a complete list): name@spec,
  // the spec bare or quoted (blanks and `||` inside quotes); `alias@npm:name@spec` (tied to name); PEP 440 operators,
  // compact or with blanks; `name = "spec"`; `"name": "spec"`; `"alias": "npm:name@spec"`.
  if (go()) for (const m of text.matchAll(/(?<![\w@\/.-])((?:@[a-z0-9][\w.-]*\/)?[A-Za-z0-9][\w.-]*)@([^\s,;`'")\]@]+)/g)) if (!m[2].startsWith("npm:")) addForm(m[1], m[2], null);
  if (go()) for (const m of text.matchAll(/(?<![\w@\/.-])((?:@[a-z0-9][\w.-]*\/)?[A-Za-z0-9][\w.-]*)@(["'])([^"'\n]{1,60})\2/g)) addForm(m[1], m[3].trim(), null);
  // An alias key is no package of its own: no reader offers it (round 11, docs lane).
  if (go()) for (const m of text.matchAll(/(?<![\w\/.-])((?:@[a-z0-9][\w.-]*\/)?[A-Za-z0-9][\w.-]*)@npm:((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)@([^\s,;`'")\]@]+)/g)) {
    wordWide.add(m[1].toLowerCase());
    addForm(m[2], m[3], ["npm"]);
  }
  if (go()) for (const m of text.matchAll(/"((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)"\s*:\s*"npm:((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)@([^"\n]{1,60})"/g)) {
    wordWide.add(m[1].toLowerCase());
    addForm(m[2], m[3], ["npm"]);
  }
  if (go()) for (const m of text.matchAll(/(?<![\w@\/.-])([A-Za-z0-9][\w.-]*)(?:\[[\w,.-]*\])?((?:===?|~=|!=|>=|<=|<(?=\s*\d)|>(?=\s*\d))\s*[\w.*+!-]+(?:\s*,\s*(?:===?|~=|!=|>=|<=|<|>)\s*[\w.*+!-]+)*)/g)) addForm(m[1], m[2].replace(/\s+/g, ""), ["PyPI"]);
  // Round 11, P2 #34: a blank between the name (or its extras) and the operator, `name[a, b]==1`, and blanks in a
  // comma list. Tied only to a name the caller declares: it waits for nothing on its own ("if count < 2").
  if (go()) for (const m of text.matchAll(/(?<![\w@\/.-])([A-Za-z0-9][\w.-]*)(\s*\[[\w,. -]{0,80}\])?(\s*)((?:===?|~=|!=|>=|<=|<|>)\s*\d[\w.*+!-]*(?:\s*,\s*(?:===?|~=|!=|>=|<=|<|>)\s*\d[\w.*+!-]*)*)/g)) {
    if (m[3] === "" && !/\s/.test(m[2] ?? "") && !/\s/.test(m[4])) continue;
    if (/^\d[\d.]*$/.test(m[1])) continue;
    // A blank-separated range goes on after it (npm's ">=1 <2", "1.x || 2.x"): no PEP 440 spec, no form here.
    if (/^\s+(?:[<>=~^!]|\|\|)/.test(text.slice(m.index! + m[0].length))) continue;
    addForm(m[1], m[4].replace(/\s+/g, ""), null);
  }
  if (go()) for (const m of text.matchAll(/(?<![\w."-])([A-Za-z0-9][\w.-]*)\s*=\s*"([^"\n]{1,60})"/g)) addForm(m[1], m[2], null);
  if (go()) for (const m of text.matchAll(/"((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)"\s*:\s*"([^"\n]{1,60})"/g)) addForm(m[1], m[2], ["npm"]);
  // A form whose ecosystem is decided is a pair that waits, unless the grammar holds every occurrence of its name
  // (a command or snippet not read whole: nothing of it is offered).
  for (const f of formPairs) {
    if (!f.ecosystems || manifestNotWhole || consumedHere(f.name)) continue;
    for (const ecosystem of f.ecosystems) {
      const key = `${ecosystem}\0${f.name}\0${f.spec}`;
      if (seen.has(key) || pairs.some((p) => p.ecosystem === ecosystem && p.name === f.name && p.version === f.spec) || pairs.length >= MAX_PAIRS) continue;
      seen.add(key);
      pairs.push({ ecosystem, name: f.name, version: f.spec, seen: "form" });
    }
  }

  return { pairs, unreadable, requirementFiles, privateNames: manifestNotWhole ? [] : manifest.privateNames, manifestNotWhole, commands, namedHere, consumedHere, anyCommand: commands.length > 0, formPairs };
}

/**
 * The package-manager names of MANAGER_NAMES, found in the raw text: any letter case, full-width letters folded
 * (NFKC), default-ignorable code points removed, as a whole word or as the basename of a path, quoted or not, with a
 * launcher extension.
 */
const MANAGER_SET: ReadonlySet<string> = new Set(MANAGER_NAMES);
const MANAGER_NAME = new RegExp(`(?:^|[^\\p{L}\\p{N}_-])(?:${[...MANAGER_NAMES].sort((a, b) => b.length - a.length).map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")}|pip[\\d.]+)(?:\\.(?:cmd|exe|ps1|bat))?(?=$|[^\\p{L}\\p{N}_-])`, "iu");

/**
 * Round 13, U5 (#45): a command this briefing does not read, in two cases only, each at a COMMAND POSITION (the start
 * of a line, the start of a code span, right after a shell separator `;` `&&` `||` `|`, or after `$ ` / `xargs` and its
 * options): (a) `xargs` followed, options aside, by a name of MANAGER_NAMES; (b) a package manager the grammar does not
 * read, written as a bare word (no punctuation on it), and its own install verb next (switches between). "For the docs
 * bundle, add hono", "a hidden gem: install dayjs" and "Let it brew; install ky" are no command.
 */
const UNREAD_VERBS: ReadonlyMap<string, readonly string[]> = new Map(Object.entries({
  pipenv: ["install"],
  pdm: ["add", "install"],
  rye: ["add", "install"],
  hatch: [],
  conda: ["install", "create"],
  mamba: ["install", "create"],
  micromamba: ["install", "create"],
  pixi: ["add", "install"],
  gem: ["install"],
  bundle: ["add", "install"],
  composer: ["require", "install"],
  dotnet: ["add"],
  nuget: ["install"],
  brew: ["install", "tap"],
  apt: ["install"],
  "apt-get": ["install"],
}));
/** A raw word as a program name: a leading backtick, a directory and a launcher extension off; null with any other mark. */
const programWord = (raw: string): string | null => {
  const w = raw.replace(/^`/, "").replace(/^.*[\\/]/, "").replace(/\.(?:cmd|exe|ps1|bat)$/i, "");
  return /^[a-z0-9][a-z0-9_.-]*$/i.test(w) ? w.toLowerCase() : null;
};
/**
 * The commands of managers this briefing does not read (see above), per COMMAND SEGMENT (round 14, X4: a line is cut
 * at `;` `&&` `||` `|`, so `gem install devise && npm install zod` holds both): their names, and every word of
 * their segments, which no reader offers or looks up (F9).
 */
export function unreadCommands(task: string): { names: string[]; words: Set<string> } {
  const names: string[] = [];
  const words = new Set<string>();
  const take = (segment: readonly string[]) => {
    for (const t of segment) for (const w of t.toLowerCase().split(/[^\p{L}\p{N}@._/-]+/u)) if (w) words.add(w.replace(/[.]+$/, ""));
  };
  for (const raw0 of task.slice(0, 200_000).normalize("NFKC").split(/\r?\n/).slice(0, 20_000)) {
    if (!MANAGER_NAME.test(raw0)) continue;
    // Round 15, A4: a command position is the start of a line after list, quote and prompt markers, the start of a code
    // span or fence line, and right after `;` `&&` `||` `|` `(` `$(` with or without blanks; then the prefixes of
    // PREFIX_WORDS and NAME=value assignments; the manager word may be quoted.
    const line = raw0
      .replace(/^[ \t]*(?:(?:[-*+]|\d{1,3}[.)]|>|PS>|PS [^>\n]{0,80}>|\$|%)[ \t]+)+/, "")
      .replace(/\$\(|&&|\|\||[;|()`]/g, (sep) => ` ${sep} `);
    const raw = line.split(/[ \t]+/).filter(Boolean);
    let atCommand = true;
    for (let k = 0; k < raw.length; k++) {
      const token = raw[k];
      if (SEPARATOR_TOKENS.has(token)) {
        atCommand = true;
        continue;
      }
      const here: boolean = atCommand;
      // "Run gem install x", "run: brew install jq": an imperative "run" introduces a command like a prompt does.
      // A prefix (sudo, env, time ...) or an assignment keeps the position for the word after it.
      atCommand = /^run:?$/i.test(token) || (here && (PREFIX_WORDS.has(token.toLowerCase()) || /^[A-Za-z_][A-Za-z0-9_]*=\S*$/.test(token) || (here && /^-/.test(token) && PREFIX_WORDS.has((raw[k - 1] ?? "").toLowerCase()))));
      if (!here) continue;
      // The segment: from here to the next separator token.
      let e = k;
      while (e < raw.length - 1 && !SEPARATOR_TOKENS.has(raw[e + 1])) e++;
      const segment = raw.slice(k, e + 1);
      const w = programWord(token.replace(/^(["'])(.*)\1$/, "$2"));
      if (w === "xargs") {
        let j = k + 1;
        while (j < raw.length && j - k <= 8 && raw[j].startsWith("-")) j++;
        const m = raw[j] === undefined ? null : programWord(raw[j]);
        if (m !== null && (MANAGER_NAMES.includes(m) || /^pip[\d.]+$/.test(m))) {
          const name = `${m} (through xargs)`;
          if (!names.includes(name)) names.push(name);
          take(segment);
        }
        continue;
      }
      const verbs = w === null ? undefined : UNREAD_VERBS.get(w);
      // Its own verb next, switches (`-y`) aside; no punctuation on the manager word or between.
      let v = k + 1;
      while (v < raw.length && v - k <= 8 && /^-[\w-]+$/.test(raw[v])) v++;
      if (verbs && verbs.includes(raw[v] ?? "")) {
        // A manager the grammar names itself (K3: pipenv, pdm, rye, conda, mamba, micromamba, pixi) is said there.
        if (canonicalCommands(segment.join(" ")).length > 0) continue;
        if (!names.includes(w!)) names.push(w!);
        take(segment);
      }
    }
  }
  return { names, words };
}

/** Separators a command position follows (round 15, A4), each a token of its own once a line is split. */
const SEPARATOR_TOKENS: ReadonlySet<string> = new Set([";", "&&", "||", "|", "(", "$(", ")", "`"]);
/** Words a command may be prefixed with: the word after them is still at the command position. */
const PREFIX_WORDS: ReadonlySet<string> = new Set(["sudo", "env", "time", "nice", "command", "exec", "nohup", "doas"]);

/** The names of the commands a task holds that this briefing does not read (unreadCommands). */
export function unreadCommandLines(task: string): string[] {
  return unreadCommands(task).names;
}

/** A word's bare package name: `@spec`, PEP 440 operators and what follows, extras, quotes and a trailing mark off. */
export function bareName(word: string): string {
  let w = word.trim().replace(/^["'`(]+/, "");
  const at = w.indexOf("@", w.startsWith("@") ? 1 : 0);
  if (at > 0) w = w.slice(0, at);
  w = w.replace(/\[.*$/, "").replace(/(?:===?|~=|!=|>=|<=|[<>^~]).*$/, "").replace(/["'`),.;:!?]+$/, "");
  return w;
}

/**
 * Default-ignorable code points (soft hyphen, zero-width characters, variation selectors, bidi marks, tags): taken out
 * before any name is compared, so "zqx\u00adfoo" is zqxfoo.
 */
const DEFAULT_IGNORABLE = /\p{Default_Ignorable_Code_Point}/gu;
/** A text as names are compared in it: NFKC, case folded, default-ignorables removed. */
export const foldForNames = (text: string) => text.normalize("NFKC").replace(DEFAULT_IGNORABLE, "").toLowerCase();

const asInstallCommand = (c: CanonicalCommand): InstallCommand => ({
  text: c.text,
  ecosystem: c.ecosystem,
  operands: c.operands.map((o) => (o.spec !== undefined ? `${o.name}${c.ecosystem === "PyPI" ? "" : "@"}${o.spec}` : o.name)),
  manager: c.manager,
  verb: c.verb,
  ...(c.canonical ? {} : { unreadable: (c.why ?? "a shape it cannot read") as InstallCommand["unreadable"] }),
  ...(c.requirementFiles.length > 0 ? { requirementFiles: c.requirementFiles } : {}),
});

/** Every named command of the task, as the canonical grammar reads it (tests and the C3 property view). */
export function scanCommands(task: string): InstallCommand[] {
  return canonicalCommands(readingText(task)).map(asInstallCommand);
}

/** What reading a requirements file gave: its text, or why it was not read. */
export type RequirementsRead = string | null | { why: "outside" | "unreadable" };

/**
 * The packages of a requirements file the task installs with `-r` (V2), with the spec each line writes, as the
 * snippet reader reads a requirements line (best effort: briefing-snippets.ts pep508; blanks collapsed, a line over
 * 2,000 characters is a line it cannot read). A `-r` or `-c` file it names is read too, 8 files at most; files left
 * past that are said. The caller reads a file only when its real path is inside the project's real root, and at most
 * 256 KB (round 12, R5). A file outside the project, one that could not be read (missing, too large), and files past the
 * cap each make the reading not whole (review_needed), and the answer says which. A line it cannot read, a direct reference
 * (`name @ url`), or a word of a credential's shape (the task screen's own test, round 12, R4) makes the file not
 * read whole; such a word is never offered, repeated or looked up.
 */
export function requirementsPairs(root: string, files: readonly string[], read: (path: string) => RequirementsRead): StrictPair[] & { notWhole?: boolean; outside?: boolean; unreadable?: boolean; capped?: boolean } {
  const out: StrictPair[] & { notWhole?: boolean; outside?: boolean; unreadable?: boolean; capped?: boolean } = [];
  const queue = [...files];
  const done = new Set<string>();
  while (queue.length > 0 && done.size < 8) {
    const f = queue.shift()!;
    if (done.has(f)) continue;
    done.add(f);
    const got = read(f);
    if (got === null || typeof got !== "string") {
      if (got !== null && got.why === "outside") out.outside = true;
      else out.unreadable = true;
      continue;
    }
    const text = got;
    let line = "";
    for (const raw of text.slice(0, 262_144).split(/\r?\n/).slice(0, 4000)) {
      if (/\\[ \t]*$/.test(raw)) {
        line += `${raw.replace(/\\[ \t]*$/, "")} `;
        continue;
      }
      line += raw;
      const l = line.replace(/(?:^|[ \t])#.*$/, "").trim();
      line = "";
      const nested = /^-(?:r|c|-requirement|-constraint)(?:[ \t]+|=)(\S+)$/.exec(l);
      if (nested) {
        queue.push(path.posix.join(path.posix.dirname(f.replace(/\\/g, "/")), nested[1]));
        continue;
      }
      const d = pep508(l);
      if (d === "skip") continue;
      if (!d || d.url || credentialShape(d.name) || looksLikeSecret(d.name) || (d.spec !== undefined && looksLikeSecret(d.spec))) {
        out.notWhole = true;
        continue;
      }
      out.push({ ecosystem: "PyPI", name: d.name, ...(d.spec ? { version: d.spec } : {}), seen: "file" });
    }
  }
  // Round 13 (#112): files left when the cap is reached are said (the caller holds review_needed).
  if (queue.some((f) => !done.has(f))) out.capped = true;
  return out;
}

/**
 * The manifest snippets of the task (briefing-snippets.ts, round 11): best effort, read in one pass; a line or entry a
 * reader notices it cannot read makes the snippet "not read whole" (review_needed at most).
 */
export function manifestPairs(task: string): SnippetRead {
  return readSnippets(task);
}

/**
 * Round 7, C3: the task's raw text names a package source of its own. The presence of the word is the evidence;
 * which package it applies to is not parsed. Case-insensitive.
 */
/**
 * Round 9, E3: what is true of a command the grammar cannot read whole for its words (a comma, a word that is no
 * plain name, a dismissed word of a command written into a sentence). No remedy is offered: none reached a clean
 * answer (0 of 81 tries in the seventh check).
 */
export const STAYS_REVIEW = "This command, as the task writes it, keeps the answer from safe_to_delegate: it is not an error. Check what the command installs with dependency_check before running it.";

/**
 * Round 8, D2: C3 is a courtesy check on an exact list, not a promise about sources in general. When the task holds
 * one of these spellings, the briefing does not look up the names the task adds and says so; any other way a task
 * names a source is not noticed, and the declaration decides (`public: false` for anything from a private registry,
 * an index of its own, git or a path). Each spelling is matched as its tool matches it: options, settings and
 * manifest tables in their own case; environment variable names in any case (Windows reads them so).
 */
export const SOURCE_SPELLINGS: readonly string[] = [
  "--registry", "--config.registry=", "--userconfig", "registry=", ":registry", "--index-url", "--extra-index-url", "--default-index", "--index", "--find-links", "pip -i <index>", "pip -f <links>",
  "--source", "--git", "--path", "npmRegistryServer", "[[tool.uv.index]]", "[[index]] (uv.toml)", "[tool.uv.sources]", "[[tool.poetry.source]]", "[install.scopes] (bunfig.toml)",
  "[registries]", "[registries.<name>]", "[registry]", "[source.<name>]", "[patch.<name>]", "a go.mod replace directive with =>, single-line or block",
  "npm_config_registry", "NPM_CONFIG_USERCONFIG", "YARN_REGISTRY", "YARN_NPM_REGISTRY_SERVER", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_INDEX", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL",
  "CARGO_REGISTRIES_<NAME>_INDEX", "CARGO_REGISTRY_DEFAULT", "GOPRIVATE", "GOPROXY", "GONOSUMDB", "GONOPROXY",
];
/** The options, settings and tables of SOURCE_SPELLINGS, in their own case. */
const SOURCE_WORDS =
  /--registry\b|--config\.registry=|--userconfig\b|(?:^|[\s"'`])registry\s*=|:registry\b|--index-url\b|--extra-index-url\b|--default-index\b|--index\b|--find-links\b|--source\b|--git\b|--path\b|npmRegistryServer|\[\[tool\.uv\.index\]\]|\[\[index\]\]|\[tool\.uv\.sources\]|\[\[tool\.poetry\.source\]\]|\[install\.scopes\]|\[registries[.\]]|\[registry\]|\[source\.|\[patch\.|\breplace\s+\S+(?:\s+v\S+)?\s+=>|\breplace\s*\(\s*\n[^)]{0,2000}?=>/;
/** The environment variables of SOURCE_SPELLINGS, in any case. */
const SOURCE_ENV =
  /(?<![A-Za-z0-9_])(?:npm_config_registry|npm_config_userconfig|npm_config_@[\w.-]+:registry|yarn_registry|yarn_npm_registry_server|pip_index_url|pip_extra_index_url|pip_find_links|uv_index|uv_index_url|uv_default_index|uv_extra_index_url|cargo_registries_\w+_index|cargo_registry_default|goprivate|goproxy|gonosumdb|gonoproxy)(?![A-Za-z0-9_])/i;
/**
 * The short source options, only where their own manager reads them: pip's (and `uv pip`'s) `-i <index>` and
 * `-f <links>`. Cargo's `-F` (features), npm's `-f` (force) and others are no source.
 */
const PIP_COMMAND = /\b(?:pip[\d.]*|uv\s+pip)(?:\.exe)?\s+(?:install|download|wheel)\b/g;
const SHORT_SOURCE = /\s-[if](?:\s+|=)\S/;

/** pip's `-i` / `-f` inside a pip command, each command read up to its separator or the next command: linear. */
function pipShortSource(text: string): boolean {
  const starts = [...text.matchAll(PIP_COMMAND)].map((m) => m.index! + m[0].length);
  for (let k = 0; k < starts.length; k++) {
    const segment = text.slice(starts[k], k + 1 < starts.length ? starts[k + 1] : text.length);
    const stop = segment.search(/[\n;&|]/);
    if (SHORT_SOURCE.test(stop >= 0 ? segment.slice(0, stop) : segment)) return true;
  }
  return false;
}

/** Whether the task's raw text names a package source of its own (C3). */
export const RAW_SOURCE = { test: (text: string): boolean => SOURCE_WORDS.test(text) || SOURCE_ENV.test(text) || pipShortSource(text) };

/**
 * The first command with an operand the briefing did not account for, or null (the C3 property test's view of the
 * strict evidence: such an operand waits in to_confirm). `accounted(ecosystem, name)` says whether the briefing
 * checked that pair, the caller declared it, or the project already depends on it.
 */
export function unreadCommand(task: string, accounted: (ecosystem: CheckEcosystem, name: string) => boolean): InstallCommand | null {
  for (const c of scanCommands(task)) {
    // A command not read whole is never accounted for (round 7, C2).
    if (c.unreadable) return c;
    for (const o of c.operands) {
      if (namesNoPackage(o)) continue;
      for (const name of operandNames(o)) if (!namesNoPackage(name) && !accounted(c.ecosystem, name)) return c;
    }
  }
  return null;
}

/** The review reason for a command whose shape could not be read (K3): its manager and verb only, never its words. */
export const unreadableReason = (c: InstallCommand) =>
  c.manager === "a line"
    ? `This task holds ${c.unreadable}: it was not read; check what it adds with dependency_check.`
    : c.manager === "a manifest"
    ? `This task holds a manifest snippet this briefing could not read whole (${c.unreadable}): check what it adds with dependency_check.`
    : `This task holds a command (${[c.manager, c.verb].filter(Boolean).join(" ")}) this briefing could not read whole (${c.unreadable}): check what it installs with dependency_check.${c.unreadable === "a comma in its list of packages" || (c.unreadable ?? "").startsWith("a word that is not a plain package name") || c.unreadable === "a redirection among its words" ? ` ${STAYS_REVIEW}` : ""}`;
