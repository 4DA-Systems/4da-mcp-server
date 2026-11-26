// SPDX-License-Identifier: Apache-2.0
/**
 * Strict positional evidence of the task's packages (contract K2). A detector over the task text finds every
 * command that can add or run a package, by its SHAPE, never by co-occurrence (round 4, F1):
 * (a) a manager or runner word (npm, pnpm, yarn, bun, bunx, npx, pnpx, pip, pip3, pipx, uv, uvx, poetry, cargo, go,
 *     deno, `python -m pip`; with `.exe`, `.cmd`, `.ps1` or `.bat`) followed by its verb with only options between
 *     them (`npm install`, `pnpm -w add`, `go get`, `uv tool run`, `uv run --with`); a runner word is its own verb;
 * (b) the prose form "install / add <names> with | using | via | from <manager>", and "install the package with
 *     npm: <names>";
 * (c) a name tied by the sentence to a named manifest file ("add X to package.json and to requirements.txt": two
 *     pairs) or to an ecosystem label right after it ("install papaparse (npm)").
 * "Add chi (github.com/go-chi/chi/v5) to a Go project" names a manager word and a verb in one sentence: no command.
 * A command's operands are the contiguous run after the verb (F2). It ends at the first token that cannot be an
 * operand or option: an opening parenthesis (unless it is a label or version right after an operand), a comma,
 * semicolon or closing mark, a sentence or line end, a plain connective. Words after the run are prose for the
 * ordinary reader (F3). Each operand is a strict (name, ecosystem) pair: what-should-i-know.ts makes every pair
 * that is not checked, declared or a dependency WAIT in to_confirm. A command whose shape cannot be read (an
 * unclosed quote, a substitution among its words) is said by its manager and verb only (K3): no task text that
 * has not gone through the task screen is ever repeated.
 */
import type { CheckEcosystem } from "../live/release-metadata.js";
import { pushAll } from "../array-utils.js";
import { canonicalCommands, type CanonicalCommand } from "./briefing-canonical.js";
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
  seen?: "command" | "manifest";
}

/**
 * The strict pairs of the task and the commands it does not read whole (round 7, C1/C2): the operands of every
 * canonical command (briefing-canonical.ts) and the entries of every manifest snippet. Read on the task as written
 * (markup dropped, continuations joined): a credential, a substitution or a quote problem among a command's words
 * makes it not read whole, and nothing of it is offered.
 */
export function strictEvidence(task: string): { pairs: StrictPair[]; unreadable: InstallCommand[]; requirementFiles: string[]; privateNames: Array<{ ecosystem: CheckEcosystem; name: string }>; namedWords: Set<string>; manifestNotWhole: boolean; consumed: Set<string> } {
  const pairs: StrictPair[] = [];
  const unreadable: InstallCommand[] = [];
  const requirementFiles: string[] = [];
  const seen = new Set<string>();
  /** Every word of every command the grammar named, read whole or not (lower case, quotes and marks set aside). */
  const namedWords = new Set<string>();
  const commands = canonicalCommands(readingText(task));
  // Round 7c, F1: what the grammar consumed as program, verb, switch, option or value, unless it is also an operand.
  const operandNames = new Set(commands.flatMap((c) => c.operands.map((o) => o.name.toLowerCase())));
  const consumed = new Set(commands.flatMap((c) => c.consumed).filter((w) => !operandNames.has(w)));
  for (const c of commands) {
    for (const w of c.text.split(/\s+/)) {
      const word = w.replace(/^[`"'(]+|[`"'),.;:!?]+$/g, "").toLowerCase();
      namedWords.add(word);
      // Its name, a spec aside (`qzws@7.4.5`, `x==1.0`, `x[extra]>=2`), and every piece of a word a comma, `=`, `:`
      // or `@` joins (`a,b`, `x=1`, `x@npm:y`): no word of a command is offered by another reader (C2).
      for (const piece of [word, ...word.split(/[,=:@]+/)]) if (piece) namedWords.add(operandName(piece.replace(/^npm:/, "")) || piece);
    }
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
  if (!manifestNotWhole) pushAll(pairs, manifest.pairs);
  pushAll(unreadable, manifest.unreadable);
  for (const w of manifest.entryWords) namedWords.add(w);
  for (const k of manifest.keys) namedWords.add(k);
  const pairNames = new Set(pairs.map((p) => p.name.toLowerCase()));
  for (const k of manifest.keys) if (manifestNotWhole || !pairNames.has(k)) consumed.add(k);
  for (const p of manifest.privateNames) consumed.add(p.name.toLowerCase());
  if (manifestNotWhole) for (const p of manifest.pairs) consumed.add(p.name.toLowerCase());
  return { pairs, unreadable, requirementFiles, privateNames: manifestNotWhole ? [] : manifest.privateNames, namedWords, manifestNotWhole, consumed };
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
  for (const m of text.matchAll(/"(?:dev|peer|optional)?[dD]ependencies"\s*:\s*\{([^{}]{0,4000})\}/g)) {
    const body = m[1].trim();
    const entries = [...body.matchAll(/"((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)"\s*:\s*"([^"]{0,200})"/gi)];
    if (body && body.replace(/"((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)"\s*:\s*"([^"]{0,200})"\s*,?/gi, "").trim() !== "") notWhole("npm", "an entry it cannot read", body);
    for (const e of entries) {
      entryKeys.add(e[1].toLowerCase());
      if (/^(?:git|github:|file:|link:|workspace:|https?:|\.|\/|~)/i.test(e[2]) || e[2].includes("://") || e[2].includes("/")) privateNames.push({ ecosystem: "npm", name: e[1] });
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
/** How an agent gets a clean answer for a command written into a sentence (round 7b, item 3). */
export const CLEAN_COMMAND = "For a clean answer, write the command on its own line or in a code span (`npm install x y`) with only package names after the verb, and call again.";

/**
 * C3's source words, matched in their own case (round 7c, F5: case-insensitive matching read Cargo's `-F derive` as
 * pip's `-f <url>`). Long options, settings, environment variables and manifest tables are each written as their tool
 * writes them; npm's environment form is matched in both cases it is used in.
 */
const SOURCE_WORDS =
  /--registry\b|(?:^|[\s"'`])registry\s*=|[A-Z_]*REGISTRY=|:registry\b|--index-url\b|--extra-index-url\b|--default-index\b|--index\b|--find-links\b|--source\b|--git\b|--path\b|npm_config_registry|NPM_CONFIG_REGISTRY|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX|UV_DEFAULT_INDEX|UV_EXTRA_INDEX_URL|GOPRIVATE|GOPROXY|GONOSUMDB|GONOPROXY|npmRegistryServer|\[\[tool\.uv\.index\]\]|\[\[tool\.poetry\.source\]\]|\[registries[.\]]|\[registry\]|\[source\.|\[patch\.|\breplace\s+\S+(?:\s+v\S+)?\s+=>/;
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
export const RAW_SOURCE = { test: (text: string): boolean => SOURCE_WORDS.test(text) || pipShortSource(text) };

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
    : `This task holds a command (${[c.manager, c.verb].filter(Boolean).join(" ")}) this briefing could not read whole (${c.unreadable}): check what it installs with dependency_check.${/comma|not a plain package name/.test(c.unreadable ?? "") ? ` ${CLEAN_COMMAND}` : ""}`;
