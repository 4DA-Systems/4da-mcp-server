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

const MANAGERS: ReadonlyMap<string, CheckEcosystem> = new Map([
  ...["npm", "pnpm", "yarn", "bun", "bunx", "npx", "pnpx"].map((m) => [m, "npm"] as const),
  ...["pip", "pip3", "pipx", "uv", "uvx", "poetry"].map((m) => [m, "PyPI"] as const),
  ["cargo", "crates.io"] as const,
  ["go", "Go"] as const,
  // Deno installs npm packages by their `npm:` specifier; its other operands are files and URLs.
  ["deno", "npm"] as const,
]);
/** Options whose value IS a package (the runner's package, uv's `--with`): never a script. */
const PACKAGE_OPTIONS = new Set(["--with", "--with-editable", "--spec", "--from", "--package", "-p"]);
/** pip's index options: a value that is not the public index makes the command's operands private. */
const INDEX_OPTIONS = new Set(["-i", "--index-url", "--extra-index-url", "--index", "--default-index", "--registry"]);
/** A script or program file a runner runs (`uv run --with X s.py`): not a package when no option carries it. */
const SCRIPT = /\.(?:py|pyw|sh|ps1|ts|tsx|js|mjs|cjs)$/i;
/** Runner words: the word is its own verb, the next non-option word the package. */
const RUNNERS = new Set(["npx", "pnpx", "bunx", "uvx"]);
const VERBS = new Set([
  "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "it", "install-test", "add", "x", "exec", "dlx", "create",
  "init", "up", "upgrade", "update", "get", "inject", "binstall",
]);
/** Words that end a command's operands in a sentence: function words, clause verbs and the nouns "the deps" uses. */
const STOPS = new Set([
  "to", "for", "with", "so", "because", "the", "a", "an", "in", "on", "at", "from", "into", "then", "if", "when", "it", "them", "this", "that", "which",
  "as", "by", "via", "after", "before", "using", "use", "but", "also", "please", "first", "now", "here", "there", "we", "our", "my", "your", "its", "their",
  "is", "are", "be", "was", "will", "should", "must", "can", "need", "needs", "make", "move", "keep", "run", "build", "test", "fix", "update", "wire",
  "expose", "point", "store", "add", "remove", "set", "configure", "check", "write", "rename", "refactor", "deploy", "commit", "push", "open", "start",
  "deps", "dependencies", "dependency", "packages", "package", "modules", "module", "crates", "crate", "everything", "all", "again", "locally", "globally",
  "work", "works", "working", "properly", "correctly", "fine", "succeed", "succeeds", "pass", "passes",
]);
/** Long options whose value never names a registry package (a directory, a feature, a source to fetch from). */
const VALUE_OPTIONS = new Set([
  "--features", "--timeout", "--loglevel", "--log-level", "--network-timeout", "--prefix", "--cwd", "--dir", "--filter", "--target", "--registry",
  "--index-url", "--extra-index-url", "--index", "--default-index", "-i", "--rev", "--branch", "--tag", "--python", "--root", "--manifest-path", "--profile",
  "--cache-dir", "--config", "--userconfig", "--requirement", "-r", "--constraint", "-e", "--editable",
]);
const MAX_SEGMENT_WORDS = 400;
const MAX_TEXT = 120;
/** No package name is longer (briefing-task-screen.ts MAX_TASK_WORD is of the same order). */
const MAX_WORD = 302;
/** Plain English connectives: the first one ends a command's operand run (F2); later words are prose. */
const CONNECTIVES = new Set(["and", "or", "then", "in", "into", "to", "for", "so", "with", "on", "from", "plus", "but", "&", "+", "after", "before", "because", "if", "when", "while", "using", "via"]);
/** The prose form's link words: "install X with|using|via|from <manager>" (F1 b). */
const PROSE_LINKS = new Set(["with", "using", "via", "from"]);
/** Words between the verb and the link of "install the package with npm: X". */
const PACKAGE_NOUNS = new Set(["the", "a", "an", "package", "packages", "dependency", "dependencies", "module", "modules", "crate", "crates", "library", "libraries", "lib", "libs"]);
/** An ecosystem label in parentheses after a name. */
const LABEL_ECOSYSTEM: ReadonlyMap<string, CheckEcosystem> = new Map([
  ...["npm", "pnpm", "yarn", "bun", "node", "js", "javascript", "typescript"].map((w) => [w, "npm"] as const),
  ...["pypi", "pip", "uv", "poetry", "python"].map((w) => [w, "PyPI"] as const),
  ...["crates", "crates.io", "cargo", "rust"].map((w) => [w, "crates.io"] as const),
  ...["go", "golang"].map((w) => [w, "Go"] as const),
]);
/** What a parenthetical right after an operand may say and still belong to it: an ecosystem label, latest, a version. */
const LABEL = /^(?:latest|stable|next|v?\d+(?:\.\d+)*(?:[-+.][\w.-]*)?)$/i;
/** Manifest files a sentence may add a name to, and the ecosystem each one installs from (K2). */
const MANIFESTS: ReadonlyArray<[RegExp, CheckEcosystem]> = [
  [/^package\.json$/i, "npm"],
  [/^(?:requirements[\w.-]*\.(?:txt|in)|pyproject\.toml|pipfile|setup\.py|setup\.cfg)$/i, "PyPI"],
  [/^cargo\.toml$/i, "crates.io"],
  [/^go\.mod$/i, "Go"],
];

export interface InstallCommand {
  /** The command as written, capped: for tests and diagnosis only, never repeated in an answer (K3). */
  text: string;
  /** The ecosystem its manager installs from. */
  ecosystem: CheckEcosystem;
  /** Its operands, as written. */
  operands: string[];
  /** The operands right after an option this module does not know, with that option's flag (they may be its value). */
  maybeValues?: Array<[string, string]>;
  /** The manager word and the verb, from this module's fixed lists: what an answer may say of the command. */
  manager: string;
  verb: string;
  /** Why its shape could not be read, when it could not (K3). */
  unreadable?: "an unclosed quote" | "a command substitution among its words";
  /** It installs from an index the task names that is not the public one (`pip install -i <private> X`). */
  privateIndex?: boolean;
  /** The requirements files it installs from (`pip install -r requirements-extra.txt`), as written (V2). */
  requirementFiles?: string[];
}

const OPEN = new Set(['"', "'", "`", "(", "[", "{", "<", "*", "_"]);
const CLOSE = new Set(['"', "'", "`", ")", "]", "}", ">", ".", ",", ";", ":", "!", "?", "*"]);
/** A word without its quotes, brackets and trailing punctuation: a walk, not a regex (a 150 KB run of dots was quadratic). */
function bare(word: string): string {
  const w = word.length > MAX_WORD ? word.slice(0, MAX_WORD) : word;
  let a = 0;
  let b = w.length;
  while (a < b && OPEN.has(w[a])) a++;
  while (b > a && CLOSE.has(w[b - 1])) b--;
  return w.slice(a, b);
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

/** The task cut into commands and sentences: at a new line, `;`, `&&`, `||`, `|`, and a sentence end. */
function segments(task: string): string[] {
  return task.split(/\r?\n|;|&&|\|\||\||(?<=[.!?])\s+/);
}

/** One whitespace token: its bare word, whether it opens a parenthetical, and whether it ends the run after itself. */
interface Token {
  raw: string;
  word: string;
  opens: boolean;
  /** A trailing comma, semicolon, colon, closing parenthesis or backtick: the run ends after this token. */
  closes: boolean;
}
const tokenOf = (raw: string): Token => {
  const word = bare(raw);
  return { raw, word: word.toLowerCase(), opens: raw.startsWith("("), closes: /[,;:)`]["'`)]*$/.test(raw) && !raw.startsWith("(") };
};
/** The manager a word names, with a Windows launcher's extension (`npm.cmd`, `npx.exe`, `pip.ps1`, `yarn.bat`). */
const managerOf = (word: string) => MANAGERS.get(word.replace(/\.(?:exe|cmd|ps1|bat)$/, ""));
const managerName = (word: string) => word.replace(/\.(?:exe|cmd|ps1|bat)$/, "");

interface Operand {
  text: string;
  /** The value of an option that names a package (`--with X`, `-p X`). */
  ofOption: boolean;
  /** The ecosystem of a label right after it: "papaparse (npm)". */
  label?: CheckEcosystem;
  /** Right after an option this module does not know (its flag): it may be that option's value (a token, a path). */
  afterOption?: string;
}

/** A public package index URL (pip's own default, its JSON mirror name). */
const publicIndex = (url: string) => /^https?:\/\/(?:pypi\.org|pypi\.python\.org|files\.pythonhosted\.org|registry\.npmjs\.org|registry\.yarnpkg\.com)(?:\/|$)/i.test(url);

/**
 * The operand run from `from` (F2): the contiguous words after the verb, ending at the first token that cannot be
 * an operand or option. `end` is the index of the first token after it.
 */
function operandRun(t: Token[], from: number): { operands: Operand[]; end: number; privateIndex: boolean; requirementFiles: string[]; unreadable?: InstallCommand["unreadable"] } {
  const operands: Operand[] = [];
  const requirementFiles: string[] = [];
  let end = from;
  let packageNext = false;
  let maybeValue: string | null = null;
  let privateIndex = false;
  let unreadable: InstallCommand["unreadable"];
  for (; end < t.length; end++) {
    const { word: w, raw } = t[end];
    if (t[end].opens) {
      // "hono (latest)", "litestar (PyPI)", "papaparse (npm)": the label belongs to the operand before it.
      const closed = /\)["'`]*[,;:.]?$/.test(raw);
      const ecosystem = LABEL_ECOSYSTEM.get(w);
      if (operands.length > 0 && closed && (LABEL.test(w) || ecosystem)) {
        if (ecosystem) operands[operands.length - 1].label = ecosystem;
        if (/[,;:]$/.test(raw)) {
          end++;
          break;
        }
        continue;
      }
      break;
    }
    if (!w) continue;
    if (w.startsWith("-")) {
      const flag = w.replace(/=.*$/, "");
      if (VALUE_OPTIONS.has(flag)) {
        const value = w.includes("=") ? w.slice(w.indexOf("=") + 1) : end + 1 < t.length ? t[end + 1].word : "";
        if (INDEX_OPTIONS.has(flag) && value && !publicIndex(value)) privateIndex = true;
        if ((flag === "-r" || flag === "--requirement") && value) requirementFiles.push(w.includes("=") ? bare(t[end].raw).slice(bare(t[end].raw).indexOf("=") + 1) : bare(t[end + 1].raw));
        if (!w.includes("=") && end + 1 < t.length) end++;
      } else if (w.includes("=")) operands.push({ text: bare(raw).replace(/^[^=]*=/, ""), ofOption: true });
      else {
        packageNext = PACKAGE_OPTIONS.has(flag);
        maybeValue = packageNext ? null : flag;
      }
      if (t[end].closes) {
        end++;
        break;
      }
      continue;
    }
    if (CONNECTIVES.has(w) || STOPS.has(w) || managerOf(w)) break;
    // K3: a substitution or an unclosed quote among the command's words: its shape cannot be read.
    if (raw.includes("$(") || raw.includes("${") || (raw.startsWith("`") && !/^`[^`\s]+`[.,;:)]*$/.test(raw))) unreadable = "a command substitution among its words";
    const quote = raw[0] === '"' || raw[0] === "'" ? raw[0] : null;
    if (quote && raw.indexOf(quote, 1) < 0 && !t.slice(end + 1).some((x) => x.raw.includes(quote))) unreadable ??= "an unclosed quote";
    operands.push({ text: bare(raw), ofOption: packageNext, ...(maybeValue ? { afterOption: maybeValue } : {}) });
    packageNext = false;
    maybeValue = null;
    if (t[end].closes) {
      end++;
      break;
    }
  }
  return { operands: operands.filter((o) => o.text !== ""), end, privateIndex, requirementFiles, ...(unreadable ? { unreadable } : {}) };
}

/**
 * The verb of a command that starts at `managerAt` (F1 a): the manager's verb with only options between them
 * (`npm install`, `pnpm -w add`, `uv tool run`, `uv run --with`); a runner is its own verb. -1 when it is no command.
 */
function verbAfter(t: Token[], managerAt: number): number {
  const manager = managerName(t[managerAt].word);
  if (RUNNERS.has(manager)) return managerAt;
  for (let k = managerAt + 1; k < t.length; k++) {
    const w = t[k].word;
    if (w.startsWith("-") && !t[k].opens) {
      if (VALUE_OPTIONS.has(w) && k + 1 < t.length) k++;
      if (t[k].closes) return -1;
      continue;
    }
    if (VERBS.has(w)) return k;
    if (w === "tool" && (t[k + 1]?.word === "run" || t[k + 1]?.word === "install")) return k + 1;
    if (w === "run" && (manager === "deno" || t.slice(k + 1, k + 40).some((x) => /^--(?:with|spec)(?:-editable|-requirements)?(?:=|$)/.test(x.word)))) return k;
    return -1;
  }
  return -1;
}

const manifestEcosystem = (word: string): CheckEcosystem | undefined => MANIFESTS.find(([re]) => re.test(word))?.[1];

/** Every command (and prose install) in the task that can add or run a package. Linear in the task's length. */
/** A word that ends a command's operand run: no operand of a command is ever one (V6: "make pip install -e . work"). */
export const isRunStop = (word: string) => STOPS.has(word.toLowerCase()) || CONNECTIVES.has(word.toLowerCase());

export function scanCommands(task: string): InstallCommand[] {
  const commands: InstallCommand[] = [];
  const text = readingText(task.length > 200_000 ? task.slice(0, 200_000) : task);
  for (const seg of segments(text)) {
    const t = seg.split(/\s+/).filter(Boolean).slice(0, MAX_SEGMENT_WORDS).map(tokenOf);
    for (let m = 0; m < t.length; m++) {
      const w = t[m].word;
      // (a) A command: a manager or runner word (or `python -m pip`) and its verb with only options between.
      const pythonPip = (w === "python" || w === "python3" || w === "py" || w === "python.exe") && t[m + 1]?.word === "-m" && (t[m + 2]?.word === "pip" || t[m + 2]?.word === "pip3");
      const managerAt = pythonPip ? m + 2 : m;
      const ecosystem = managerOf(t[managerAt]?.word ?? "");
      if (ecosystem && !t[managerAt].closes) {
        const v = verbAfter(t, managerAt);
        if (v >= 0) {
          const read = t[v].closes && v !== managerAt ? { operands: [] as Operand[], end: v + 1, privateIndex: false, requirementFiles: [] as string[] } : operandRun(t, v + 1);
          const manager = managerName(t[managerAt].word);
          const deno = manager === "deno";
          const verb = v === managerAt ? manager : t[v].word;
          const runs = deno || verb === "run" || RUNNERS.has(verb) || verb === "x" || verb === "exec" || verb === "dlx";
          // A runner's script file is no package; deno reads only its `npm:` and `jsr:` operands as packages.
          const kept = read.operands
            .filter((o) => !(runs && !o.ofOption && SCRIPT.test(o.text) && !RUNNERS.has(verb)))
            .filter((o) => !deno || /^(?:npm|jsr):/i.test(o.text));
          const operands = kept.map((o) => o.text);
          const maybeValues = kept.filter((o) => o.afterOption).map((o) => [o.text, o.afterOption!] as [string, string]);
          commands.push({
            text: t.slice(m, Math.max(read.end, v + 1)).map((x) => x.raw).join(" ").slice(0, MAX_TEXT),
            ecosystem,
            operands,
            manager,
            verb,
            ...("unreadable" in read && read.unreadable ? { unreadable: read.unreadable } : {}),
            ...(read.privateIndex ? { privateIndex: true } : {}),
            ...(maybeValues.length > 0 ? { maybeValues } : {}),
            ...(read.requirementFiles.length > 0 && ecosystem === "PyPI" ? { requirementFiles: read.requirementFiles } : {}),
          });
          m = Math.max(m, read.end - 1);
          continue;
        }
      }
      if (w !== "install" && w !== "add") continue;
      // (b) "install the package with npm: zqxevil".
      let n = m + 1;
      while (n < t.length && PACKAGE_NOUNS.has(t[n].word) && !t[n].closes) n++;
      if (n > m + 1 && PROSE_LINKS.has(t[n]?.word ?? "") && t[n + 1] && managerOf(t[n + 1].word) && t[n + 1].raw.endsWith(":")) {
        const read = operandRun(t, n + 2);
        if (read.operands.length > 0) {
          commands.push({ text: t.slice(m, read.end).map((x) => x.raw).join(" ").slice(0, MAX_TEXT), ecosystem: managerOf(t[n + 1].word)!, operands: read.operands.map((o) => o.text), manager: managerName(t[n + 1].word), verb: w });
          m = read.end - 1;
          continue;
        }
      }
      // (b) "install / add <names> with|using|via|from <manager>" ("add the ctx package to package.json" too).
      let first = m + 1;
      while (first < t.length && (t[first].word === "the" || t[first].word === "a" || t[first].word === "an") && !t[first].closes) first++;
      const read = operandRun(t, first);
      if (read.operands.length === 0) continue;
      if (PACKAGE_NOUNS.has(t[read.end]?.word ?? "") && !t[read.end].opens && !t[read.end - 1]?.closes) read.end++;
      const link = t[read.end];
      const after = t[read.end + 1]?.word === "the" ? read.end + 2 : read.end + 1;
      const named = link && PROSE_LINKS.has(link.word) && !link.opens ? managerOf(t[after]?.word ?? "") : undefined;
      if (named) {
        commands.push({ text: t.slice(m, after + 1).map((x) => x.raw).join(" ").slice(0, MAX_TEXT), ecosystem: named, operands: read.operands.map((o) => o.text), manager: managerName(t[after].word), verb: w });
        m = after;
        continue;
      }
      // (c) "add X to package.json and to requirements.txt": one pair per manifest file the sentence names.
      const files = new Set<CheckEcosystem>();
      for (let k = read.end; k < t.length && k - read.end < 12; k++) {
        const eco = manifestEcosystem(t[k].word);
        if (eco) files.add(eco);
        else if (!CONNECTIVES.has(t[k].word) && !PACKAGE_NOUNS.has(t[k].word) && t[k].word !== "both" && t[k].word !== "file") break;
      }
      for (const eco of files) commands.push({ text: t.slice(m, read.end).map((x) => x.raw).join(" ").slice(0, MAX_TEXT), ecosystem: eco, operands: read.operands.map((o) => o.text), manager: "a manifest", verb: w });
      // (c) "install papaparse (npm)": a label ties the name before it to that ecosystem.
      for (const o of read.operands) if (o.label && !files.has(o.label)) commands.push({ text: t.slice(m, read.end).map((x) => x.raw).join(" ").slice(0, MAX_TEXT), ecosystem: o.label, operands: [o.text], manager: "a label", verb: w });
    }
  }
  return commands;
}

/** The name an operand names, its version or extras aside (`x@1.2`, `@s/x@^1`, `x==1.0`, `x[extra]>=2`). */
export function operandName(operand: string): string {
  const scoped = operand.startsWith("@");
  const at = operand.indexOf("@", scoped ? 1 : 0);
  const head = at > 0 ? operand.slice(0, at) : operand;
  return head.replace(/\[.*$/, "").replace(/(?:===?|~=|>=|<=|!=|>|<|\^|~).*$/, "");
}

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

/** A strict (name, ecosystem) pair the task's text gives by position (K2), with the spec written on it. */
export interface StrictPair {
  ecosystem: CheckEcosystem;
  name: string;
  version?: string;
  /** From a command that installs from the task's own private index (`-i <url>`): never sent. */
  privateIndex?: boolean;
  /** Right after an option this module does not know (its flag): the word may be that option's value. */
  afterOption?: string;
}

/** The strict pairs of the task, and the commands whose shape could not be read (K2, K3). */
export function strictEvidence(task: string): { pairs: StrictPair[]; unreadable: InstallCommand[]; requirementFiles: string[] } {
  const pairs: StrictPair[] = [];
  const unreadable: InstallCommand[] = [];
  const requirementFiles: string[] = [];
  const seen = new Set<string>();
  for (const c of scanCommands(task)) {
    if (c.unreadable) unreadable.push(c);
    for (const f of c.requirementFiles ?? []) if (!requirementFiles.includes(f)) requirementFiles.push(f);
    // A command whose shape cannot be read gives no pairs (K3). A word that may be an unknown option's value is
    // marked: it is offered by name only where the task screen left it readable (what-should-i-know.ts).
    if (c.unreadable) continue;
    for (const o of c.operands) {
      const maybeValue = c.maybeValues?.find(([text]) => text === o)?.[1];
      if (namesNoPackage(o)) continue;
      const names = operandNames(o);
      for (const name of names) {
        if (namesNoPackage(name) || name.endsWith("/") || !/[a-z0-9]/i.test(name)) continue;
        // npm names are lower case (a scoped one with capitals is no name); a Go module path starts with a domain.
        if (c.ecosystem === "npm" && name.startsWith("@") && /[A-Z]/.test(name)) continue;
        if (c.ecosystem === "Go" && !/^[^/]*\.[^/]+\//.test(name)) continue;
        const own = names.length === 1 || name === names[names.length - 1];
        const version = own ? operandSpec(/^npm:/i.test(o) ? o.slice(4) : o.includes("@npm:") ? o.slice(o.indexOf("@npm:") + 5) : o, c.ecosystem) : undefined;
        const key = `${c.ecosystem}\0${name.toLowerCase()}\0${version ?? ""}`;
        if (seen.has(key)) continue;
        seen.add(key);
        pairs.push({ ecosystem: c.ecosystem, name, ...(version ? { version } : {}), ...(c.privateIndex ? { privateIndex: true } : {}), ...(maybeValue ? { afterOption: maybeValue } : {}) });
      }
    }
  }
  return { pairs, unreadable, requirementFiles };
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
 * The first command with an operand the briefing did not account for, or null (the C3 property test's view of the
 * strict evidence: such an operand waits in to_confirm). `accounted(ecosystem, name)` says whether the briefing
 * checked that pair, the caller declared it, or the project already depends on it.
 */
export function unreadCommand(task: string, accounted: (ecosystem: CheckEcosystem, name: string) => boolean): InstallCommand | null {
  for (const c of scanCommands(task)) {
    for (const o of c.operands) {
      if (namesNoPackage(o)) continue;
      for (const name of operandNames(o)) if (!namesNoPackage(name) && !accounted(c.ecosystem, name)) return c;
    }
  }
  return null;
}

/** The review reason for a command whose shape could not be read (K3): its manager and verb only, never its words. */
export const unreadableReason = (c: InstallCommand) =>
  `This task holds a command${c.manager === "a manifest" || c.manager === "a label" ? "" : ` (${c.manager} ${c.verb})`} this briefing could not read whole (${c.unreadable}): check what it installs with dependency_check.`;
