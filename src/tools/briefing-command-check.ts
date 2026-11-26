// SPDX-License-Identifier: Apache-2.0
/**
 * C3: the reader is not trusted for safe_to_delegate. A detector over the raw task text finds every command that
 * can add or run a package, by its SHAPE, never by co-occurrence (round 4, F1):
 * (a) a manager or runner word (npm, pnpm, yarn, bun, bunx, npx, pnpx, pip, pip3, pipx, uv, uvx, poetry, cargo, go,
 *     deno, `python -m pip`) followed by its verb with only options between them (`npm install`, `pnpm -w add`,
 *     `go get`, `uv tool run`, `uv run --with`); a runner word is its own verb;
 * (b) the prose form "install / add <names> with | using | via | from <manager>".
 * "Add chi (github.com/go-chi/chi/v5) to a Go project" names a manager word and a verb in one sentence: no command.
 * The command's operands are the contiguous run after the verb (F2). It ends at the first token that cannot be an
 * operand or option: an opening parenthesis, a comma, semicolon or closing mark, a sentence or line end, a plain
 * connective (and, then, in, into, to, for, so, with, on, from ...). A parenthetical that is an ecosystem label,
 * "latest" or a version right after an operand belongs to it ("npm install hono (latest)"). Words after the run
 * are prose for the ordinary reader, where a name-shaped word still waits in to_confirm (F3).
 * Every operand of the run must be accounted for (a pair checked, one the caller declared, a project dependency)
 * or name no registry package (a path, a URL, a file, a version); an option's value counts as an operand unless
 * the option's value never names a package. One operand not accounted for keeps the briefing from safe_to_delegate
 * (what-should-i-know.ts). A not_packages word is no account of an operand.
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
]);
/** Long options whose value never names a registry package (a directory, a feature, a source to fetch from). */
const VALUE_OPTIONS = new Set([
  "--features", "--timeout", "--loglevel", "--log-level", "--network-timeout", "--prefix", "--cwd", "--dir", "--filter", "--target", "--registry",
  "--index-url", "--extra-index-url", "--rev", "--branch", "--tag", "--python", "--root", "--manifest-path", "--profile", "--cache-dir", "--config",
  "--userconfig", "--requirement", "--constraint",
]);
const MAX_SEGMENT_WORDS = 400;
const MAX_TEXT = 120;
/** No package name is longer (briefing-task-screen.ts MAX_TASK_WORD is of the same order). */
const MAX_WORD = 302;

export interface InstallCommand {
  /** The command as written, capped. */
  text: string;
  /** The ecosystem its manager installs from. */
  ecosystem: CheckEcosystem;
  /** Its operands, as written. */
  operands: string[];
}

const OPEN = new Set(['"', "'", "`", "(", "[", "{", "<"]);
const CLOSE = new Set(['"', "'", "`", ")", "]", "}", ">", ".", ",", ";", ":", "!", "?"]);
/** A word without its quotes, brackets and trailing punctuation: a walk, not a regex (a 150 KB run of dots was quadratic). */
function bare(word: string): string {
  const w = word.length > MAX_WORD ? word.slice(0, MAX_WORD) : word;
  let a = 0;
  let b = w.length;
  while (a < b && OPEN.has(w[a])) a++;
  while (b > a && CLOSE.has(w[b - 1])) b--;
  return w.slice(a, b);
}

/** The task cut into commands and sentences: at a new line, `;`, `&&`, `||`, `|`, and a sentence end. */
function segments(task: string): string[] {
  return task.split(/\r?\n|;|&&|\|\||\||(?<=[.!?])\s+/);
}

interface Operand {
  text: string;
  /** The value of an option that names a package (`--with X`, `-p X`). */
  ofOption: boolean;
}

/** Plain English connectives: the first one ends a command's operand run (F2); later words are prose. */
const CONNECTIVES = new Set(["and", "or", "then", "in", "into", "to", "for", "so", "with", "on", "from", "plus", "but", "&", "+", "after", "before", "because", "if", "when", "while", "using", "via"]);
/** The prose form's link words: "install X with|using|via|from <manager>" (F1 b). */
const PROSE_LINKS = new Set(["with", "using", "via", "from"]);
/** What a parenthetical right after an operand may say and still belong to it: an ecosystem or manager, latest, a version. */
const LABEL = /^(?:npm|pypi|crates(?:\.io)?|cargo|go|golang|pip|pnpm|yarn|bun|uv|poetry|latest|stable|next|v?\d+(?:\.\d+)*(?:[-+.][\w.-]*)?)$/i;

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

interface Operand {
  text: string;
  /** The value of an option that names a package (`--with X`, `-p X`). */
  ofOption: boolean;
}

/**
 * The operand run from `from` (F2): the contiguous words after the verb, ending at the first token that cannot be
 * an operand or option: an opening parenthesis (unless it is a label right after an operand), a comma, semicolon or
 * closing mark, a connective or another stop word, a manager word. `end` is the index of the first token after it.
 */
function operandRun(t: Token[], from: number): { operands: Operand[]; end: number } {
  const operands: Operand[] = [];
  let end = from;
  let packageNext = false;
  for (; end < t.length; end++) {
    const { word: w, raw } = t[end];
    if (t[end].opens) {
      // "hono (latest)", "litestar (PyPI)": the label belongs to the operand before it.
      if (operands.length > 0 && LABEL.test(w) && /\)["'`]*[,;:.]?$/.test(raw)) {
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
        if (!w.includes("=") && end + 1 < t.length) end++;
      } else if (w.includes("=")) operands.push({ text: bare(raw).replace(/^[^=]*=/, ""), ofOption: true });
      else packageNext = PACKAGE_OPTIONS.has(flag);
      if (t[end].closes) {
        end++;
        break;
      }
      continue;
    }
    if (CONNECTIVES.has(w) || STOPS.has(w) || MANAGERS.has(w)) break;
    operands.push({ text: bare(raw), ofOption: packageNext });
    packageNext = false;
    if (t[end].closes) {
      end++;
      break;
    }
  }
  return { operands: operands.filter((o) => o.text !== ""), end };
}

/**
 * The verb of a command that starts at `managerAt` (F1 a): the manager's verb with only options between them
 * (`npm install`, `pnpm -w add`, `uv tool run`, `uv run --with`); a runner is its own verb. -1 when it is no command.
 */
function verbAfter(t: Token[], managerAt: number): number {
  const manager = t[managerAt].word;
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

/** Every command (and prose install) in the task that can add or run a package. Linear in the task's length. */
export function scanCommands(task: string): InstallCommand[] {
  const commands: InstallCommand[] = [];
  for (const seg of segments(task.length > 200_000 ? task.slice(0, 200_000) : task)) {
    const t = seg.split(/\s+/).filter(Boolean).slice(0, MAX_SEGMENT_WORDS).map(tokenOf);
    for (let m = 0; m < t.length; m++) {
      const w = t[m].word;
      // (a) A command: a manager or runner word (or `python -m pip`) and its verb with only options between.
      const pythonPip = (w === "python" || w === "python3" || w === "py") && t[m + 1]?.word === "-m" && (t[m + 2]?.word === "pip" || t[m + 2]?.word === "pip3");
      const managerAt = pythonPip ? m + 2 : m;
      const ecosystem = MANAGERS.get(t[managerAt]?.word ?? "");
      if (ecosystem && !t[managerAt].closes) {
        const v = verbAfter(t, managerAt);
        if (v >= 0) {
          const read = t[v].closes && v !== managerAt ? { operands: [], end: v + 1 } : operandRun(t, v + 1);
          const deno = t[managerAt].word === "deno";
          const verb = t[v].word;
          const runs = deno || verb === "run" || RUNNERS.has(verb) || verb === "x" || verb === "exec" || verb === "dlx";
          // A runner's script file is no package; deno reads only its `npm:` and `jsr:` operands as packages.
          const operands = read.operands
            .filter((o) => !(runs && !o.ofOption && SCRIPT.test(o.text) && !RUNNERS.has(verb)))
            .filter((o) => !deno || /^(?:npm|jsr):/i.test(o.text))
            .map((o) => o.text);
          commands.push({ text: t.slice(m, Math.max(read.end, v + 1)).map((x) => x.raw).join(" ").slice(0, MAX_TEXT), ecosystem, operands });
          m = Math.max(m, read.end - 1);
          continue;
        }
      }
      // (b) The prose form: "install / add <names> with|using|via|from <manager>".
      if (w === "install" || w === "add") {
        const read = operandRun(t, m + 1);
        const link = t[read.end];
        const after = t[read.end + 1]?.word === "the" ? read.end + 2 : read.end + 1;
        const named = link && PROSE_LINKS.has(link.word) && !link.opens ? MANAGERS.get(t[after]?.word ?? "") : undefined;
        if (named && read.operands.length > 0) {
          commands.push({ text: t.slice(m, after + 1).map((x) => x.raw).join(" ").slice(0, MAX_TEXT), ecosystem: named, operands: read.operands.map((o) => o.text) });
          m = after;
        }
      }
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

/** An operand that names no registry package: a path, a URL, a git or file source, a version, a file. */
export function namesNoPackage(operand: string): boolean {
  const o = operand.toLowerCase();
  if (!o || o === "." || o === ".." || o === "-" || o === "./...") return true;
  if (/^(?:\.{1,2}[\\/]|[\\/~]|[a-z]:[\\/])/.test(o)) return true;
  if (o.includes("://") || /^(?:git\+|git:|github:|file:|link:|workspace:|catalog:|portal:|patch:)/.test(o)) return true;
  if (/^v?\d+(?:\.\d+)*(?:[-+.][\w.-]*)?$/.test(o) || /^[\^~<>=*]/.test(o)) return true;
  return /\.(?:txt|toml|json|lock|whl|tgz|tar\.gz|zip|cfg|ini|ya?ml)$/.test(o);
}

/**
 * The first command with an operand the briefing did not account for, or null. `accounted(ecosystem, name)` says
 * whether the briefing checked that pair, the caller declared it, or the project already depends on it.
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

/** The fixed review reason (C3). */
export const unreadCommandReason = (c: InstallCommand) =>
  `This task holds a command this briefing could not read whole (${c.text}): check what it installs with dependency_check.`;
