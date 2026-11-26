// SPDX-License-Identifier: Apache-2.0
/**
 * C3: the reader is not trusted for safe_to_delegate. A coarse detector over the raw task text finds every
 * command that can add or run a package: a package-manager or runner word (npm, pnpm, yarn, bun, bunx, npx, pnpx,
 * pip, pip3, pipx, uv, uvx, poetry, cargo, go, and `python -m pip`) followed later in the same sentence or line
 * by a verb that adds or runs one (install and npm's aliases, i, add, x, exec, dlx, create, init, up, upgrade,
 * update, get, inject, binstall, `tool run` / `tool install`, `run --with` / `run --spec`), and a sentence that
 * installs with a manager named after the verb ("Install zqxevil with npm."). It does not parse options: every
 * non-option word after the verb, up to the end of the command, is an operand the briefing must account for (a
 * pair it checked, one the caller declared, a project dependency) or a form naming no registry package (a path,
 * a URL, a file, a version). An option's value counts as an operand unless the option is one whose value never
 * names a package: reading too many operands costs a review, reading too few would cost a missed install. One
 * operand not accounted for keeps the briefing from safe_to_delegate (what-should-i-know.ts). The 16 forms the
 * second independent check found (`pnpm add -w X`, `npm i -m X`, `yarn up X`, `npm init X`, `uv run --with X`,
 * `cargo binstall X` ...) fall to it without a list of each manager's options.
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
/** List words between operands: neither operand nor stop. */
const LIST = new Set(["and", "or", "plus", "&", "+"]);
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

/** Operands from `from` to the end of the command; `end` is where it stopped. */
function operandsFrom(raw: string[], words: string[], from: number, upto: number): { operands: Operand[]; end: number } {
  const operands: Operand[] = [];
  let end = from;
  let packageNext = false;
  for (; end < upto; end++) {
    const w = words[end];
    if (!w || LIST.has(w)) continue;
    if (w.startsWith("-")) {
      const flag = w.replace(/=.*$/, "");
      if (VALUE_OPTIONS.has(flag)) {
        if (!w.includes("=") && end + 1 < upto) end++;
      } else if (w.includes("=")) operands.push({ text: bare(raw[end]).replace(/^[^=]*=/, ""), ofOption: true });
      else packageNext = PACKAGE_OPTIONS.has(flag);
      continue;
    }
    if (STOPS.has(w) || MANAGERS.has(w)) break;
    operands.push({ text: bare(raw[end]), ofOption: packageNext });
    packageNext = false;
  }
  return { operands: operands.filter((o) => o.text !== ""), end };
}

/** Every command (and prose install) in the task that can add or run a package. Linear in the task's length. */
export function scanCommands(task: string): InstallCommand[] {
  const commands: InstallCommand[] = [];
  for (const seg of segments(task.length > 200_000 ? task.slice(0, 200_000) : task)) {
    const raw = seg.split(/\s+/).filter(Boolean).slice(0, MAX_SEGMENT_WORDS);
    const words = raw.map((w) => bare(w).toLowerCase());
    let sawCommand = false;
    for (let m = 0; m < words.length; m++) {
      const pythonPip = (words[m] === "python" || words[m] === "python3" || words[m] === "py") && words[m + 1] === "-m" && (words[m + 2] === "pip" || words[m + 2] === "pip3");
      const managerAt = pythonPip ? m + 2 : m;
      const ecosystem = MANAGERS.get(words[managerAt]);
      if (!ecosystem) continue;
      let v = -1;
      if (RUNNERS.has(words[managerAt])) v = managerAt;
      else {
        for (let k = managerAt + 1; k < words.length; k++) {
          if (MANAGERS.has(words[k])) break;
          if (VERBS.has(words[k])) {
            v = k;
            break;
          }
          if (words[k] === "tool" && (words[k + 1] === "run" || words[k + 1] === "install")) {
            v = k + 1;
            break;
          }
          if (words[k] === "run" && (words[managerAt] === "deno" || words.slice(k + 1).some((w) => /^--(?:with|spec)(?:-editable|-requirements)?(?:=|$)/.test(w)))) {
            v = k;
            break;
          }
        }
      }
      if (v < 0) continue;
      const read = operandsFrom(raw, words, v + 1, words.length);
      const end = read.end;
      const deno = words[managerAt] === "deno";
      const runs = deno || words[v] === "run" || RUNNERS.has(words[v]) || words[v] === "x" || words[v] === "exec" || words[v] === "dlx";
      // A runner's script file is no package; deno reads only its `npm:` and `jsr:` operands as packages.
      const operands = read.operands
        .filter((o) => !(runs && !o.ofOption && SCRIPT.test(o.text) && !RUNNERS.has(words[v])))
        .filter((o) => !deno || /^(?:npm|jsr):/i.test(o.text))
        .map((o) => o.text);
      commands.push({ text: raw.slice(m, Math.max(end, v + 1)).join(" ").slice(0, MAX_TEXT), ecosystem, operands });
      sawCommand = true;
      m = Math.max(m, end - 1);
    }
    // A prose install: an installing verb, then a manager named later in the sentence ("Install zqxevil with npm.").
    if (!sawCommand) {
      const verbAt = words.findIndex((w) => w === "install" || w === "add" || w === "use");
      const managerAt = verbAt < 0 ? -1 : words.findIndex((w, k) => k > verbAt && MANAGERS.has(w));
      if (managerAt > verbAt + 1) {
        const operands = raw.slice(verbAt + 1, managerAt).map(bare).filter((w) => w && !STOPS.has(w.toLowerCase()) && !LIST.has(w.toLowerCase()) && !w.startsWith("-"));
        commands.push({ text: raw.slice(verbAt, managerAt + 1).join(" ").slice(0, MAX_TEXT), ecosystem: MANAGERS.get(words[managerAt])!, operands });
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
