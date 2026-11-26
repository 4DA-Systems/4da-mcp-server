// SPDX-License-Identifier: Apache-2.0
/**
 * Round 7, C1: the canonical command grammar. Five independent checks found new holes in a hand-written reader of
 * commands inside free text (launcher names, where options stand, stop words, option arity, lower-casing, prose
 * versions), so a command is either read whole by this small exact grammar or it is NOT READ WHOLE, and the answer
 * can then be at most review_needed (what-should-i-know.ts). There are no stop-word lists and no guessing which word
 * is a value.
 *
 * A command is NAMED when a manager word (its basename: a directory, `.cmd` / `.exe` / `.bat` / `.ps1` and a
 * version suffix such as `pip3.12` set aside; `python -m pip`, `py -m pip`) is followed by one of its verbs with
 * only options between. It is CANONICAL only when it is exactly: program, verb, then tokens each of which is
 *  (a) a switch on that manager's short, case-SENSITIVE allow list (it takes no value), or an option of fixed
 *      arity whose value is consumed and never offered (`-w <ws>`, `--group <g>`, `-F <features>`), or
 *  (b) an operand that is a plain package name, with an optional spec, in that ecosystem's grammar;
 * and it ENDS at a shell separator (`;`, `&&`, `||`, `|`, a new line), the close of its own code span (`...`) or
 * parenthesis ("(npm install pino)"), or the end of its sentence: every word up to there is an option or an operand,
 * so a command inside prose ("npm install msw for tests") holds msw, for and tests. Every operand of a canonical
 * command is a strict (name as written,
 * ecosystem) pair; no word is skipped because it looks like English (`npm i -D test zqxevil` holds test and
 * zqxevil). Anything else is NOT READ WHOLE: an option not on the list (never lower-cased before comparing: `-F`
 * is not `-f`), a registry, index, source, git or path option, a substitution, a quote problem, a comma in the
 * operand list, a word that is not a plain name (a path, a URL, a credential's shape), a runner or scaffold verb
 * (`npx`, `dlx`, `npm create` / `npm init <x>`: they fetch and run a package this briefing does not check).
 */
import type { CheckEcosystem } from "../live/release-metadata.js";
import { checkableSpec } from "./briefing-names.js";
import { credentialShape, looksLikeSecret } from "./briefing-task-screen.js";
import { nameProblem } from "./dependency-check-screen.js";

type Manager = "npm" | "pnpm" | "yarn" | "bun" | "pip" | "uv" | "poetry" | "cargo" | "go" | "pipx";
const ECOSYSTEM: Record<Manager, CheckEcosystem> = { npm: "npm", pnpm: "npm", yarn: "npm", bun: "npm", pip: "PyPI", uv: "PyPI", poetry: "PyPI", cargo: "crates.io", go: "Go", pipx: "PyPI" };

/** The adding verbs of each manager: a verb listed here with its operands is an install the grammar can read. */
const ADDING: Record<Manager, ReadonlySet<string>> = {
  npm: new Set(["install", "i", "in", "add", "update", "up", "upgrade"]),
  pnpm: new Set(["add", "install", "i", "update", "up", "upgrade"]),
  yarn: new Set(["add", "up", "upgrade"]),
  bun: new Set(["add", "install", "i", "update"]),
  pip: new Set(["install"]),
  uv: new Set(["add", "install"]), // `uv pip install`, `uv tool install` (a bare `uv install` is no uv verb: not named)
  poetry: new Set(["add"]),
  cargo: new Set(["add", "install", "binstall"]),
  go: new Set(["get", "install"]),
  pipx: new Set(["install"]),
};
/** Verbs that fetch and run a package (or a scaffold named create-<x>): named, never read whole. */
const RUNNING: Record<Manager, ReadonlySet<string>> = {
  npm: new Set(["x", "exec", "create", "init"]),
  pnpm: new Set(["dlx", "create", "exec"]),
  yarn: new Set(["dlx", "create"]),
  bun: new Set(["x", "create"]),
  pip: new Set(),
  uv: new Set(["run"]),
  poetry: new Set(),
  cargo: new Set(),
  go: new Set(["run"]),
  pipx: new Set(["run", "inject"]),
};
const RUNNER_WORDS = new Set(["npx", "pnpx", "bunx", "uvx", "deno"]);

/** Switches that take no value (case-SENSITIVE). */
const SWITCHES: Record<Manager, ReadonlySet<string>> = {
  npm: new Set(["-D", "--save-dev", "-S", "--save", "-E", "--save-exact", "-g", "--global", "-O", "--save-optional", "-P", "--save-prod", "--no-save", "--save-peer", "-B", "--save-bundle", "--legacy-peer-deps", "--ignore-scripts", "--no-audit", "--no-fund"]),
  pnpm: new Set(["-D", "--save-dev", "-E", "--save-exact", "-O", "--save-optional", "-P", "--save-prod", "-g", "--global", "-w", "--workspace-root", "--save-peer", "--ignore-scripts"]),
  yarn: new Set(["-D", "--dev", "-E", "--exact", "-O", "--optional", "-P", "--peer", "-T", "--tilde", "-W", "--ignore-workspace-root-check"]),
  bun: new Set(["-d", "-D", "--dev", "--development", "-E", "--exact", "--optional", "-g", "--global", "--no-save"]),
  pip: new Set(["-U", "--upgrade", "--user", "--no-deps", "--pre", "-q", "--quiet", "-v", "--verbose", "--force-reinstall", "--no-cache-dir"]),
  uv: new Set(["--dev", "--frozen", "--locked", "--no-sync"]),
  poetry: new Set(["-D", "--dev", "--allow-prereleases", "--dry-run", "--lock"]),
  cargo: new Set(["--dev", "--build", "--no-default-features", "--locked", "--optional"]),
  go: new Set(["-u", "-t", "-v", "-d"]),
  pipx: new Set(["--force"]),
};
/** Options of fixed arity 1 whose value is no package (consumed, never offered). `-r <file>` is read (V2). */
const ARITY: Record<Manager, ReadonlySet<string>> = {
  npm: new Set(["-w", "--workspace"]),
  pnpm: new Set(["--filter"]),
  yarn: new Set(),
  bun: new Set(),
  pip: new Set(["-r", "--requirement", "-c", "--constraint"]),
  uv: new Set(["--group", "--optional"]),
  poetry: new Set(["--group", "-G", "--optional"]),
  cargo: new Set(["-F", "--features", "-p", "--package"]),
  go: new Set(),
  pipx: new Set(),
};

export interface CanonicalCommand {
  manager: string;
  verb: string;
  ecosystem: CheckEcosystem;
  /** Read whole: every token is an allowed option or a plain operand. */
  canonical: boolean;
  /** Why it is not read whole (fixed wording: never the task's words). */
  why?: string;
  /** Its operands, as written (canonical commands only). */
  operands: Array<{ name: string; spec?: string }>;
  /** Requirements files it installs from (`pip install -r <file>`), as written (canonical commands only). */
  requirementFiles: string[];
  /** The command as written, capped: for tests and diagnosis only, never in an answer. */
  text: string;
  /**
   * The words the grammar consumed as program, verb, switch, option or option value (lower case, marks set aside):
   * no other reader may offer, look up or weigh them (round 7c, F1: `npm install ms` looked `install` up).
   */
  consumed: string[];
}

const MAX_TOKENS = 200;

/** The manager a word names, its directory, launcher extension and version suffix set aside. */
export function managerOf(word: string): Manager | null {
  const base = word.replace(/^[`"'(]+/, "").replace(/^.*[\\/]/, "").replace(/\.(?:cmd|exe|bat|ps1)$/i, "").replace(/(?<=^(?:pip|pip3))(?:\.\d+)+$/, "");
  const m = /^(npm|pnpm|yarn|bun|pip3?|uv|poetry|cargo|go|pipx)$/.exec(base);
  if (!m) return null;
  return (m[1] === "pip3" ? "pip" : m[1]) as Manager;
}
const isPython = (word: string) => /^(?:python[\d.]*|py)(?:\.exe)?$/i.test(word.replace(/^[`"'(]+/, "").replace(/^.*[\\/]/, ""));

/** One operand in its ecosystem's grammar: the plain name as written and its optional spec, or null. */
export function plainOperand(ecosystem: CheckEcosystem, raw: string): { name: string; spec?: string } | null {
  let token = raw;
  // A token wrapped whole in one kind of quote is that token ("zqx-vuln-py<2").
  const q = /^(["'])(.*)\1$/.exec(token);
  if (q) token = q[2];
  // Characters a package name with a spec can hold in that ecosystem; anything else (a colon, a quote, a `$`) is no
  // plain operand.
  const charset = ecosystem === "PyPI" ? /^[\w.\-[\],<>=!~*+]+$/ : /^[@\w./~^<>=*!+|-]+$/;
  if (!token || !charset.test(token)) return null;
  let name = token;
  let spec: string | undefined;
  if (ecosystem === "PyPI") {
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9._,-]*\])?((?:===?|~=|!=|>=|<=|>|<)\S+)?$/.exec(token);
    if (!m) return null;
    name = m[1];
    spec = m[2];
  } else {
    const scoped = token.startsWith("@");
    const at = token.indexOf("@", scoped ? 1 : 0);
    if (at > 0) {
      name = token.slice(0, at);
      spec = token.slice(at + 1);
      if (!spec) return null;
    }
  }
  if (nameProblem(ecosystem, name) !== null || credentialShape(name) || looksLikeSecret(name) || looksLikeSecret(name.replace(/^@[^/]+\//, ""))) return null;
  // npm names are lower case (the registry takes no new name with capitals); a Go module path starts with a domain.
  if (ecosystem === "npm" && /[A-Z]/.test(name)) return null;
  if (ecosystem === "Go" && (!/^[^/]*\.[^/]+\//.test(name) || name.endsWith("/") || name.includes("//"))) return null;
  if (spec !== undefined && !(/^latest$/i.test(spec) || checkableSpec(ecosystem, spec) !== null)) return null;
  return { name, ...(spec !== undefined ? { spec } : {}) };
}

/** The task cut into lines and shell commands: a new line, `;`, `&&`, `||`, `|`. Sentences are cut below. */
function pieces(text: string): string[] {
  return text.split(/\r?\n|;|&&|\|\||\|/);
}

/** Every named command of the text, each canonical or not. Linear in the text's length. */
export function canonicalCommands(text: string): CanonicalCommand[] {
  const out: CanonicalCommand[] = [];
  for (const piece of pieces(text.length > 200_000 ? text.slice(0, 200_000) : text)) {
    // Sentences: a sentence end is `.`, `!` or `?` followed by a blank (a version's dots are no sentence end).
    // (a lone "." is a path, and a sentence starts with a capital, a quote, a backtick or a parenthesis).
    for (const sentence of piece.split(/(?<=[\w)\]"'`][.!?])\s+(?=[A-Z`"'(])/)) {
      const tokens = sentence.split(/\s+/).filter(Boolean).slice(0, MAX_TOKENS);
      for (let m = 0; m < tokens.length; m++) {
        const read = readAt(tokens, m);
        if (!read) continue;
        out.push(read.command);
        m = read.end - 1;
      }
    }
  }
  return out;
}

/** A command named at token `m`, read canonically or not; null when no command is named there. */
function readAt(tokens: string[], m: number): { command: CanonicalCommand; end: number } | null {
  const first = tokens[m];
  // A command in a code span of its own ends at its closing backtick; one opened by a parenthesis at its ")".
  const span: Closer = first.startsWith("`") ? "`" : first.startsWith("(") ? ")" : null;
  let k = m;
  let manager: Manager | null = null;
  let runnerWord: string | null = null;
  if (isPython(first) && tokens[m + 1] === "-m" && /^pip3?$/.test(tokens[m + 2] ?? "")) {
    manager = "pip";
    k = m + 2;
  } else {
    manager = managerOf(first);
    const base = first.replace(/^[`"'(]+/, "").replace(/^.*[\\/]/, "").replace(/\.(?:cmd|exe|bat|ps1)$/i, "").replace(/[`"')]+$/, "");
    if (!manager && RUNNER_WORDS.has(base)) runnerWord = base;
    if (!manager && !runnerWord) return null;
  }
  if (runnerWord) {
    const eco: CheckEcosystem = runnerWord === "uvx" ? "PyPI" : "npm";
    const end = endOf(tokens, m, span);
    return { command: notWhole(runnerWord, "", eco, "it fetches and runs a package this briefing does not check", tokens, m, end), end };
  }
  // The verb: options of that manager (allowed ones only) may stand between.
  let v = k + 1;
  let bad: string | null = null;
  for (; v < tokens.length; v++) {
    const t = clean(tokens[v]);
    if (!t.startsWith("-")) break;
    if (SWITCHES[manager!].has(t)) continue;
    if (ARITY[manager!].has(t)) {
      v++;
      continue;
    }
    bad = "an option this briefing does not read";
    // An unknown option may take the next word as its value (`npm --registry <url> install x`): the command is still
    // named when a verb follows that word.
    if (!clean(tokens[v + 1] ?? "-").startsWith("-") && ADDING[manager!].has(clean(tokens[v + 2] ?? ""))) v++;
  }
  let verb = clean(tokens[v] ?? "").replace(/[.!?]+$/, "");
  // `uv pip install`, `uv tool install`, `yarn global add`, `yarn workspace <name> add`.
  if (manager === "uv" && (verb === "pip" || verb === "tool") && clean(tokens[v + 1] ?? "") === "install") {
    verb = `${verb} install`;
    v++;
  } else if (manager === "uv" && verb === "tool" && clean(tokens[v + 1] ?? "") === "run") {
    const end = endOf(tokens, m, span);
    return { command: notWhole("uv", "tool run", "PyPI", "it fetches and runs a package this briefing does not check", tokens, m, end), end };
  } else if (manager === "yarn" && verb === "global" && clean(tokens[v + 1] ?? "") === "add") {
    verb = "global add";
    v++;
  } else if ((manager === "yarn" || manager === "pnpm") && verb === "workspace" && ADDING[manager].has(clean(tokens[v + 2] ?? ""))) {
    verb = `workspace ${clean(tokens[v + 2])}`;
    v += 2;
  }
  const plainVerb = verb.replace(/^(?:workspace|global|pip|tool) /, "");
  if (manager === "cargo" && verb.startsWith("+")) {
    // `cargo +nightly install x`: the toolchain.
    v++;
    verb = clean(tokens[v] ?? "");
  }
  const ecosystem = ECOSYSTEM[manager!];
  const end = endOf(tokens, m, span);
  if (RUNNING[manager!].has(plainVerb) && !(manager === "npm" && plainVerb === "init" && v + 1 >= end)) {
    const why = plainVerb === "create" || plainVerb === "init" ? "it fetches and runs a package named create-<name> (or <scope>/create), which this briefing does not check" : "it fetches and runs a package this briefing does not check";
    return { command: notWhole(manager!, plainVerb, ecosystem, why, tokens, m, end), end };
  }
  if (!ADDING[manager!].has(plainVerb) && !(manager === "cargo" && ADDING.cargo.has(verb))) return null;
  if (manager === "uv" && verb === "install") return null;
  // Where it starts does not matter: it ends at a shell separator, its code span's close or its sentence's end, and
  // every word up to there is an option or an operand (C1: "Use npm install msw for tests" names msw, for, tests).
  if (bad) return { command: notWhole(manager!, verb, ecosystem, bad, tokens, m, end), end };
  const operands: Array<{ name: string; spec?: string }> = [];
  const requirementFiles: string[] = [];
  for (let j = v + 1; j < end; j++) {
    const rawTok = tokens[j];
    const last = j === end - 1;
    let t = span === "`" ? rawTok.replace(/`[.,;:!?)]*$/, "") : span === ")" && j === end - 1 ? rawTok.replace(/\)[.,;:!?]*$/, "") : rawTok;
    if (last) t = t.replace(/[.!?]$/, "");
    if (rawTok.includes("$(") || rawTok.includes("${") || (rawTok.startsWith("`") && j > m)) return { command: notWhole(manager!, verb, ecosystem, "a command substitution among its words", tokens, m, end), end };
    if (/,$/.test(t) || (t.includes(",") && ecosystem !== "PyPI")) return { command: notWhole(manager!, verb, ecosystem, "a comma in its list of packages", tokens, m, end), end };
    if (t.startsWith("-")) {
      const flag = t.replace(/=.*$/, "");
      if (SWITCHES[manager!].has(t)) continue;
      if (ARITY[manager!].has(flag)) {
        const value = t.includes("=") ? t.slice(t.indexOf("=") + 1) : tokens[++j];
        if (value === undefined || j >= end) return { command: notWhole(manager!, verb, ecosystem, "an option without its value", tokens, m, end), end };
        if (flag === "-r" || flag === "--requirement") requirementFiles.push(value.replace(/[`.]$/, ""));
        continue;
      }
      return { command: notWhole(manager!, verb, ecosystem, "an option this briefing does not read", tokens, m, end), end };
    }
    if ((t.startsWith('"') || t.startsWith("'")) && !(t.length > 1 && t.endsWith(t[0]))) return { command: notWhole(manager!, verb, ecosystem, "an unclosed quote", tokens, m, end), end };
    const op = plainOperand(ecosystem, t);
    if (!op) return { command: notWhole(manager!, verb, ecosystem, "a word that is not a plain package name (a path, a URL, a source, a credential's shape)", tokens, m, end), end };
    operands.push(op);
  }
  const operandWords = new Set(operands.map((o) => o.name.toLowerCase()));
  const consumed = consumedWords(tokens, m, end).filter((w) => !operandWords.has(w));
  return { command: { manager: manager!, verb, ecosystem, canonical: true, operands, requirementFiles, text: tokens.slice(m, end).join(" ").slice(0, 120), consumed }, end };
}

type Closer = "`" | ")" | null;

/** Where a command started at `m` ends: the close of its own code span or parenthesis, else the end of its sentence. */
function endOf(tokens: string[], m: number, span: Closer): number {
  const closes = span === "`" ? /`[.,;:!?)]*$/ : /\)[.,;:!?]*$/;
  if (span) {
    if (closes.test(tokens[m].slice(1))) return m + 1;
    for (let j = m + 1; j < tokens.length; j++) if (closes.test(tokens[j])) return j + 1;
  }
  return tokens.length;
}

/** The token without its wrapping marks; walks, never an anchored regex (linear on a long run of marks). */
const clean = (t: string) => {
  let a = 0;
  let b = t.length;
  while (a < b && "`\"'(".includes(t[a])) a++;
  while (b > a && "`\"')".includes(t[b - 1])) b--;
  return t.slice(a, b);
};

function notWhole(manager: string, verb: string, ecosystem: CheckEcosystem, why: string, tokens: string[], m: number, end: number): CanonicalCommand {
  // Of a command not read whole, the grammar consumed its program, verb and options (their values it cannot tell).
  const words = consumedWords(tokens, m, end);
  const lastVerb = verb.split(" ").at(-1)?.toLowerCase() ?? "";
  const upTo = Math.max(0, lastVerb ? words.indexOf(lastVerb) : 0);
  const consumed = words.filter((w, i) => i <= upTo || w.startsWith("-"));
  return { manager, verb, ecosystem, canonical: false, why, operands: [], requirementFiles: [], text: tokens.slice(m, end).join(" ").slice(0, 120), consumed };
}

/** The words of tokens[m, end) as other readers see them: lower case, quotes, ticks and end marks set aside. */
function consumedWords(tokens: string[], m: number, end: number): string[] {
  const out: string[] = [];
  for (const t of tokens.slice(m, end)) {
    // Trailing marks trimmed by a walk: an anchored `[.,;:!?]+$` backtracked over a 150 KB run of dots (31 s of CPU).
    let w = clean(t);
    let e = w.length;
    while (e > 0 && ".,;:!?".includes(w[e - 1])) e--;
    w = w.slice(0, e).toLowerCase();
    if (!w) continue;
    out.push(w);
    // `--group=dev`, `python3 -m pip`: the option's value and the program's own name are consumed too.
    if (w.includes("=")) out.push(w.slice(w.indexOf("=") + 1));
    const base = w.replace(/^.*[\\/]/, "").replace(/\.(?:cmd|exe|bat|ps1)$/, "");
    if (base !== w) out.push(base);
  }
  return out;
}
