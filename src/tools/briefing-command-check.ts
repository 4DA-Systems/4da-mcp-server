// SPDX-License-Identifier: Apache-2.0
/**
 * Strict evidence of the task's packages (contract K2), on the canonical command grammar (briefing-canonical.ts):
 * - the operands of a command the grammar reads whole, each a (name as written, ecosystem) pair;
 * - the entries of a manifest snippet it reads whole (manifestPairs), each a pair in that manifest's ecosystem;
 * - round 8, D1(a): a token of the form name@spec, name==spec (and PEP 440's other operators, the bare `<`, `>`,
 *   `!=`, `~=`, `===` included), `name = "spec"` or `"name": "spec"` anywhere in the task, prose or code span: the
 *   form itself ties the spec to the name written right before it, and to no other. Where the form decides the
 *   ecosystem (PEP 440: PyPI; `"name": "spec"`: npm; a Go module path: Go) it is a pair that waits; otherwise its
 *   spec is checked for every ecosystem a declaration gives that name. These are versions the briefing happens to
 *   read on a package, checked in addition; never a complete reading: the declared `version` is (K1, round 9);
 * A command or snippet the grammar names but cannot read whole is said by its manager and verb (or "a manifest
 * snippet") only (K3); nothing of it is offered, repeated or looked up. What the grammar consumed is consumed by
 * OCCURRENCE (D4): the same word elsewhere in the task is read by the other readers as before.
 */
import type { CheckEcosystem } from "../live/release-metadata.js";
import { pushAll } from "../array-utils.js";
import { canonicalCommands, wordsOf, type CanonicalCommand } from "./briefing-canonical.js";
import { checkableSpec } from "./briefing-names.js";
import { credentialShape, looksLikeSecret } from "./briefing-task-screen.js";

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
 */
export function readingText(task: string): string {
  return task
    .replace(/<\/?(?:code|pre|kbd|samp|tt|b|i|u|em|strong|span|p|div|br|li|ul|ol)\b[^<>]{0,100}>/gi, " ")
    .replace(/(?<=\s|^)(?:\*\*|__)|(?:\*\*|__)(?=\s|$|[.,;:!?])/g, "")
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
  seen?: "command" | "manifest" | "form";
}

/**
 * The strict pairs of the task and the commands it does not read whole (round 7, C1/C2): the operands of every
 * canonical command (briefing-canonical.ts) and the entries of every manifest snippet. Read on the task as written
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
  const pairNames = new Set(pairs.map((p) => p.name.toLowerCase()));
  for (const k of manifest.keys) if (manifestNotWhole || !pairNames.has(k)) wordWide.add(k);
  for (const p of manifest.privateNames) wordWide.add(p.name.toLowerCase());
  if (manifestNotWhole) for (const p of manifest.pairs) wordWide.add(p.name.toLowerCase());
  if (manifestNotWhole) for (const w of manifest.entryWords) wordWide.add(w);
  const operandNames = new Set(commands.flatMap((c) => c.operands.map((o) => o.name.toLowerCase())));
  const allHere = (map: Map<string, number>, w: string) => (map.get(w) ?? 0) > 0 && (map.get(w) ?? 0) >= (inTask.get(w) ?? 0);
  const consumedHere = (word: string) => {
    const w = word.toLowerCase();
    return wordWide.has(w) || (!operandNames.has(w) && allHere(consumed, w));
  };
  const namedHere = (word: string) => {
    const w = word.toLowerCase();
    return wordWideNamed.has(w) || wordWide.has(w) || allHere(named, w);
  };

  // D1(a): written specs tied to a name by their form, anywhere in the task.
  const formPairs: FormPair[] = [];
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
  for (const m of text.matchAll(/(?<![\w@\/.-])([a-z0-9.-]+\.[a-z]{2,}\/[^\s@`'"]+)@(v[^\s,;`'")\]]+)/gi)) addForm(m[1], m[2], ["Go"]);
  for (const m of text.matchAll(/(?<![\w@\/.-])((?:@[a-z0-9][\w.-]*\/)?[A-Za-z0-9][\w.-]*)@([^\s,;`'")\]@]+)/g)) if (!m[2].startsWith("npm:")) addForm(m[1], m[2], null);
  for (const m of text.matchAll(/(?<![\w@\/.-])([A-Za-z0-9][\w.-]*)(?:\[[\w,.-]*\])?((?:===?|~=|!=|>=|<=|<(?=\s*\d)|>(?=\s*\d))\s*[\w.*+!-]+(?:\s*,\s*(?:===?|~=|!=|>=|<=|<|>)\s*[\w.*+!-]+)*)/g)) addForm(m[1], m[2].replace(/\s+/g, ""), ["PyPI"]);
  for (const m of text.matchAll(/(?<![\w."-])([A-Za-z0-9][\w.-]*)\s*=\s*"([^"\n]{1,60})"/g)) addForm(m[1], m[2], null);
  for (const m of text.matchAll(/"((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)"\s*:\s*"([^"\n]{1,60})"/g)) addForm(m[1], m[2], ["npm"]);
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
 * Round 8, D3: the package-manager names a dismissed word must not share a line, a continued line or a fenced block
 * with. Read on the raw text, whatever the grammar made of it: any letter case, full-width letters folded (NFKC), as a
 * whole word or as the basename of a path, quoted or not, with a launcher extension.
 */
const MANAGER_NAME = /(?:^|[^\p{L}\p{N}_-])(?:npm|pnpm|yarn|bun|pip[\d.]*|pipx|uv|poetry|cargo|go|npx|pnpx|bunx|uvx|pipenv|pdm|corepack)(?:\.(?:cmd|exe|ps1|bat))?(?=$|[^\p{L}\p{N}_-])/iu;

/** The units a word and a manager may share: each fenced block whole, else each line with its continuations joined. */
function shellUnits(task: string): string[] {
  const text = task.normalize("NFKC");
  const units: string[] = [];
  const fences = text.split(/^\s*(?:```|~~~)[^\n]*$/m);
  fences.forEach((part, i) => {
    if (i % 2 === 1) {
      units.push(part);
      return;
    }
    let line = "";
    for (const raw of part.split(/\r?\n/)) {
      const continued = /(?:\s[\\`^])\s*$/.test(raw);
      line += ` ${continued ? raw.replace(/[\\`^]\s*$/, "") : raw}`;
      if (!continued) {
        units.push(line);
        line = "";
      }
    }
    if (line) units.push(line);
  });
  return units;
}

/**
 * The words that stand AFTER a package manager's name in a unit (line, continued line, fenced block) (D3), as a
 * predicate. A command's operands follow its program: "Set NPM_TOKEN in the CI config, then npm install ky" has
 * NPM_TOKEN and CI before npm, where no operand of it stands (G7c d01). One pass over the task, whatever the number of
 * words asked (round 9: 45,000 lines and 100 dismissed words took 3.6 s when each word rescanned the task).
 */
export function wordsAfterManager(task: string): (word: string) => boolean {
  const after = new Set<string>();
  for (const u of shellUnits(task.length > 200_000 ? task.slice(0, 200_000) : task)) {
    const at = u.search(MANAGER_NAME);
    if (at < 0) continue;
    for (const raw of u.slice(at + 1).toLowerCase().split(/[^\p{L}\p{N}_@/.\-]+/u)) {
      let e = raw.length;
      while (e > 0 && raw[e - 1] === ".") e--;
      if (e > 0) after.add(raw.slice(0, e));
    }
  }
  return (word: string) => after.has(word.normalize("NFKC").toLowerCase());
}

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

/**
 * The packages of a requirements file the task installs with `-r` (V2), with the spec each line writes. Only a
 * file inside the project is read, at most 256 KB; `-r`/`-c` lines, options and comments are skipped.
 */
export function requirementsPairs(root: string, files: readonly string[], read: (path: string) => string | null): StrictPair[] {
  const out: StrictPair[] = [];
  for (const f of files.slice(0, 8)) {
    const text = read(f);
    if (text === null) continue;
    for (const line of text.slice(0, 262_144).split(/\r?\n/).slice(0, 2000)) {
      const l = line.replace(/\s+#.*$/, "").trim();
      if (!l || l.startsWith("#") || l.startsWith("-")) continue;
      const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*((?:===?|~=|>=|<=|!=|>|<)[^;\s]*(?:\s*,\s*(?:===?|~=|>=|<=|!=|>|<)[^;\s]*)*)?/.exec(l);
      if (m) out.push({ ecosystem: "PyPI", name: m[1], ...(m[2] ? { version: m[2].replace(/\s+/g, "") } : {}) });
    }
  }
  return out;
}

/**
 * Round 6, item 1: every entry of a manifest snippet is a STRICT pair in that manifest's ecosystem, with the spec it
 * writes: a package.json dependencies object, requirements lines (after a requirements file is named or in a
 * fence), pyproject `dependencies = [...]`, a Poetry table, a Cargo.toml dependencies table, go.mod requires.
 * Bounded: at most 200 entries, each block read to at most 20,000 characters. Linear.
 */
export function manifestPairs(task: string): { pairs: StrictPair[]; unreadable: InstallCommand[]; privateNames: Array<{ ecosystem: CheckEcosystem; name: string }>; entryWords: Set<string>; keys: Set<string> } {
  const text = task.length > 200_000 ? task.slice(0, 200_000) : task;
  const out: StrictPair[] = [];
  const unreadable: InstallCommand[] = [];
  const privateNames: Array<{ ecosystem: CheckEcosystem; name: string }> = [];
  /** The words of an entry not read whole: nothing of them is offered by another reader (C2, C5). */
  const entryWords = new Set<string>();
  /** Every entry key the snippet grammar read, lower case (round 7c, F3). */
  const entryKeys = new Set<string>();
  const notWhole = (ecosystem: CheckEcosystem, why: string, entry = "") => {
    for (const w of entry.toLowerCase().split(/[^a-z0-9@/._-]+/)) if (w) entryWords.add(w);
    if (!unreadable.some((u) => u.unreadable === why && u.ecosystem === ecosystem)) unreadable.push({ text: "", ecosystem, operands: [], manager: "a manifest", verb: "", unreadable: why });
  };
  // As written (round 7, C4/C6): the spec is what dependency_check would be given for this entry.
  const push = (ecosystem: CheckEcosystem, name: string, version?: string) => {
    if (out.length >= 200 || !name) return;
    if (ecosystem === "PyPI" && name.toLowerCase() === "python") return;
    // C5: an entry is read only when its name and its spec are: a spec no checker reads (`password==hunter2`, a tag)
    // or a name of a credential's shape makes the snippet not read whole, and the entry is never offered.
    if (credentialShape(name) || looksLikeSecret(name) || (version !== undefined && !/^(?:latest|\*)$/i.test(version) && checkableSpec(ecosystem, version) === null)) {
      notWhole(ecosystem, "an entry it cannot read", `${name} ${version ?? ""}`);
      return;
    }
    out.push({ ecosystem, name, ...(version ? { version } : {}), seen: "manifest" });
  };
  // package.json: "dependencies": { "x": "1.0.0", ... } (and dev/peer/optional). A value that is no registry spec
  // (git, a path, a URL, `workspace:`) is a source of the task's own for that name (C5).
  // Round 8, m4: a dependencies object this reading cannot take whole (a nested object, no closing brace) is not
  // read whole: nothing of it is offered.
  for (const m of text.matchAll(/"(?:dev|peer|optional)?[dD]ependencies"\s*:\s*\{/g)) {
    const rest = text.slice(m.index! + m[0].length, m.index! + m[0].length + 4000);
    const close = rest.indexOf("}");
    const open = rest.indexOf("{");
    if (close < 0 || (open >= 0 && open < close)) notWhole("npm", "an entry it cannot read", rest.slice(0, close < 0 ? 4000 : rest.indexOf("}", close + 1) > 0 ? rest.indexOf("}", close + 1) : close));
  }
  for (const m of text.matchAll(/"(?:dev|peer|optional)?[dD]ependencies"\s*:\s*\{([^{}]{0,4000})\}/g)) {
    const body = m[1].trim();
    const entries = [...body.matchAll(/"((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)"\s*:\s*"([^"]{0,200})"/gi)];
    if (body && body.replace(/"((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)"\s*:\s*"([^"]{0,200})"\s*,?/gi, "").trim() !== "") notWhole("npm", "an entry it cannot read", body);
    for (const e of entries) {
      entryKeys.add(e[1].toLowerCase());
      // Round 8, m1: `~` followed by a digit is npm's tilde range ("~9.6.0"); a home path is `~/` or `~\`.
      if (/^(?:git|github:|gitlab:|bitbucket:|file:|link:|workspace:|portal:|https?:|\.|\/|~[/\\])/i.test(e[2]) || e[2].includes("://") || e[2].includes("/")) privateNames.push({ ecosystem: "npm", name: e[1] });
      else push("npm", e[1], e[2]);
    }
  }
  // A TOML table: [dependencies] / [dev-dependencies] / [build-dependencies] (Cargo) or [tool.poetry.dependencies]
  // and its groups (Poetry). `package = "real"` names the real crate; git / path / registry / workspace keys are a
  // source of the task's own; any other entry shape is not read whole.
  for (const m of text.matchAll(/\[((?:tool\.poetry\.(?:group\.[\w-]+\.)?)?(?:dev-|build-)?dependencies)\][^\n]*/g)) {
    const ecosystem: CheckEcosystem = m[1].startsWith("tool.poetry") ? "PyPI" : "crates.io";
    // The table's lines, up to the next table header (a line that starts with `[`): an inline array is no header.
    const lines: string[] = [];
    for (const line of text.slice(m.index! + m[0].length, m.index! + m[0].length + 20000).split(/\r?\n/).slice(1, 400)) {
      if (/^\s*\[/.test(line)) break;
      lines.push(line);
    }
    for (const line of lines) {
      const l = line.replace(/\s+#.*$/, "").trim();
      if (!l || l.startsWith("#") || l.startsWith("```")) continue;
      const e = /^([A-Za-z0-9][\w.-]*)\s*=\s*(.{0,400})$/.exec(l);
      if (e) entryKeys.add(e[1].toLowerCase());
      if (!e) {
        notWhole(ecosystem, "an entry it cannot read", l);
        continue;
      }
      const value = e[2].trim();
      const plain = /^"([^"]{0,100})"$/.exec(value);
      if (plain) {
        push(ecosystem, e[1], plain[1]);
        continue;
      }
      const table = /^\{(.*)\}$/.exec(value);
      if (!table) {
        notWhole(ecosystem, "an entry it cannot read", l);
        continue;
      }
      const keys = [...table[1].matchAll(/([\w-]+)\s*=\s*(?:"([^"]*)"|true|false|\[[^\]]*\])/g)];
      if (table[1].replace(/([\w-]+)\s*=\s*(?:"([^"]*)"|true|false|\[[^\]]*\])\s*,?/g, "").trim() !== "") {
        notWhole(ecosystem, "an entry it cannot read", l);
        continue;
      }
      const key = (k: string) => keys.find((x) => x[1] === k);
      const name = key("package")?.[2] ?? e[1];
      if (["git", "path", "registry", "workspace", "url", "source", "develop"].some((k) => key(k))) {
        privateNames.push({ ecosystem, name });
        continue;
      }
      if (keys.some((x) => !["version", "features", "optional", "default-features", "package", "extras", "markers", "python", "allow-prereleases"].includes(x[1]))) {
        notWhole(ecosystem, "an entry it cannot read", l);
        continue;
      }
      push(ecosystem, name, key("version")?.[2]);
    }
  }
  // pyproject (PEP 621): dependencies = ["x>=1", ...] and optional groups.
  for (const m of text.matchAll(/(?:^|\s)dependencies\s*=\s*\[([^\]]{0,4000})\]/g)) {
    for (const e of m[1].matchAll(/["']([^"']{0,300})["']/g)) {
      const d = /^\s*([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*((?:===?|~=|!=|>=|<=|>|<)\s*[\w.*+!-]+(?:\s*,\s*(?:===?|~=|!=|>=|<=|>|<)\s*[\w.*+!-]+)*)?\s*$/.exec(e[1]);
      if (d) push("PyPI", d[1], d[2]?.replace(/\s+/g, ""));
      else if (/@|:\/\//.test(e[1])) privateNames.push({ ecosystem: "PyPI", name: e[1].split(/[\s@[<>=!~]/)[0] });
      else notWhole("PyPI", "an entry it cannot read", e[1]);
    }
  }
  // requirements lines: after a requirements file is named, or inside a ```txt / ```requirements / ```pip fence.
  const reqStart = [...text.matchAll(/requirements[\w.-]*\.(?:txt|in)\b|```(?:txt|text|requirements|pip)\b/gi)].map((m) => m.index! + m[0].length);
  if (reqStart.length > 0) {
    const from = reqStart[0]; // matchAll yields in text order: the first is the smallest
    for (const line of text.slice(from, from + 20000).split(/\r?\n/)) {
      const m = /^\s*([A-Za-z][\w.-]*)(?:\[[^\]]*\])?\s*((?:===?|~=|>=|<=|!=)\s*[\w.*+!-]+(?:\s*,\s*(?:===?|~=|>=|<=|!=|<|>)\s*[\w.*+!-]+)*)\s*(?:#.*)?$/.exec(line);
      if (m) push("PyPI", m[1], m[2].replace(/\s+/g, ""));
    }
    // One line written after the file's name: "Add to requirements.txt: zqxdual==1.0.0".
    for (const m of text.matchAll(/requirements[\w.-]*\.(?:txt|in)\b[^\n:]{0,40}:\s*([A-Za-z][\w.-]*)\s*((?:===?|~=|>=|<=|!=)\s*[\w.*+!-]+)/gi)) push("PyPI", m[1], m[2].replace(/\s+/g, ""));
  }
  // go.mod: require x v1.2.3 / require ( x v1 ... ).
  for (const m of text.matchAll(/\brequire\s*\(([^)]{0,4000})\)|\brequire\s+([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+)\s+(v[\w.+-]+)/gi)) {
    if (m[2]) push("Go", m[2], m[3]);
    else for (const e of m[1].matchAll(/([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+)\s+(v[\w.+-]+)/gi)) push("Go", e[1], e[2]);
  }
  const seen = new Set<string>();
  const pairs = out.filter((p) => {
    const key = `${p.ecosystem}\0${p.name}\0${p.version ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { pairs, unreadable, privateNames, entryWords, keys: entryKeys };
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
export const STAYS_REVIEW = "This stays review_needed for the command as the task writes it: it is not an error. Check what the command installs with dependency_check before running it.";

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
  c.manager === "a manifest"
    ? `This task holds a manifest snippet this briefing could not read whole (${c.unreadable}): check what it adds with dependency_check.`
    : `This task holds a command (${[c.manager, c.verb].filter(Boolean).join(" ")}) this briefing could not read whole (${c.unreadable}): check what it installs with dependency_check.${c.unreadable === "a comma in its list of packages" || (c.unreadable ?? "").startsWith("a word that is not a plain package name") || c.unreadable === "a redirection among its words" ? ` ${STAYS_REVIEW}` : ""}`;
