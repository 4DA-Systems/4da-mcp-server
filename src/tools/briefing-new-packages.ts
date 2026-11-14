// SPDX-License-Identifier: Apache-2.0
/**
 * The packages a task ADDS, for the what_should_i_know briefing (audit 2026-11-11, M14).
 *
 * `{ task: "add the lodahs package" }` came back safe_to_delegate. The briefing asked only which
 * of the project's own dependencies the task names (briefing-task-scope.ts), and a package about
 * to be added is, by definition, not one of them. `lodahs` is a name npm took down as malware.
 *
 * So the briefing also reads the names a task is about to add, and runs each through
 * dependency_check at `latest`: the same name-level checks an agent gets when it asks before
 * writing the version (a malware name is avoid, a near-miss of a popular package is review or
 * avoid, a name the registry does not have is unknown). Whatever is not `proceed` raises the
 * delegation verdict, and a check that could not run never reads as safe.
 *
 * Reading names out of prose is a heuristic, kept narrow so an ordinary task ("add tests to the
 * auth package", "add error handling") names nothing:
 * - a package-manager command: `npm install a b`, `pnpm add -D a`, `cargo add a`, `pip install a`,
 *   `uv add a`, `poetry add a`, `go get host/path`;
 * - an adding verb, then only articles and package words, then the name: "add the lodahs package",
 *   "install lodahs", "add a dependency on lodahs", "use the left-pad library";
 * - "add X to requirements.txt / package.json / the dependencies", "add X as a dependency": the
 *   destination says X is a package, whatever X looks like;
 * - "replace/swap A with/for B", "switch/migrate (from A) to B": B comes in;
 * - a bare "add X" / "install X" for any plausible name ("add ctx", "add flatmap-stream"; round 5
 *   audits found both safe_to_delegate), unless X is everyday English ("install steps", "add routes
 *   to the app", "add memoization": briefing-names.ts). A bare name nothing else marks as a package
 *   is `weak`: if no registry has it and no malicious-package record covers it, or it comes back
 *   clean, it was prose and is dropped; a malware name, a near-miss or any other finding stands.
 *   A popular npm name or a near-miss of one is always a package, English or not.
 *   dependency_check still judges the name when the agent asks before writing it.
 * - "we need X", "bring in X", "pull in X", "include X" read like "add X";
 * - the task is read clause by clause, and after the verb every item of a list counts: "add a, b and
 *   c", "a & b", "a + b", "a plus b", each item `name [version]` (readTaskItems). A version is bound to
 *   the item before it and the item is checked at that version: "replace request with axios 0.21.0"
 *   checks axios 0.21.0, not latest. Manifest entries written into the task read the same way
 *   (`"dbg": "npm:debug@4.4.2"` is debug 4.4.2; briefing-names.ts normalizeVersionSyntax);
 * - a bare name that is a near-miss of a popular PyPI project, in a project that installs from PyPI,
 *   is a package as a near-miss of a popular npm one is ("add colourama").
 * A name the task gives no ecosystem for (no manager, manifest or ecosystem word) is checked in every
 * ecosystem the project uses, and the worst answer stands: "add ctx" in an npm + Python project is
 * PyPI's malware `ctx`, not npm's clean one. When none of them has the name, the other ecosystems'
 * malware records are read too ("bring in rustdecimal" in an npm project is crates.io's malware).
 * A name the project already depends on is the task-scope module's, not this one's.
 */

import type { LiveIntelligence } from "../live/index.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import type { CheckEcosystem } from "../live/release-metadata.js";
import type { ResolvedDependency } from "../live/types.js";
import { closestPopularPypi, ENGLISH_TASK_WORDS, installedGoModule, isManifestFile, MANIFEST_FIELDS, normalizeVersionSyntax, NOT_A_PACKAGE_ADJECTIVES, PYTHON_STDLIB } from "./briefing-names.js";
import { isNpmPackageName } from "../untrusted-text.js";
import { COMMON_WORDS } from "./briefing-task-scope.js";
import { executeDependencyCheck } from "./dependency-check.js";
import { nearMissOf } from "./dependency-check-nearmiss.js";

export interface NewPackage {
  name: string;
  ecosystem: CheckEcosystem;
  /** The version or range the task writes for it ("axios 0.21.0", `debug@4.4.2`): checked at that, not at `latest`. */
  version?: string;
  /** Other ecosystems the project uses: a name the task gives no ecosystem for is checked in each, and the worst answer stands. */
  alternatives?: CheckEcosystem[];
  /**
   * Read from a bare "add X" with nothing else saying X is a package: when no registry has the name
   * and no malicious-package record covers it, it was prose ("add memoization"), and it is dropped
   * instead of reported as a hallucinated package. Any other answer (malware, a near-miss, a release
   * with advisories, a lookup that could not run) stands.
   */
  weak?: true;
  /** The task gave no ecosystem for it: a name none of the project's ecosystems has is also checked for malware in the others. */
  guessed?: true;
}

/** What the name check found for one package a task adds. */
export interface NewPackageFinding extends NewPackage {
  /** dependency_check's verdict for the package at `latest`; `unknown` when it could not be checked. */
  verdict: "proceed" | "wait" | "review" | "avoid" | "unknown";
  /** The release `latest` resolved to, when one did (null when the task named a version: see `version`). */
  latest: string | null;
  /** dependency_check's reason, in this server's words. */
  reason: string;
  /** The name itself is malware (npm took it down, or a malicious-package record covers it). */
  malicious: boolean;
  /** The popular package the name is a near-miss of, when it is one. */
  did_you_mean: string | null;
  /** What the name check itself said, apart from the release's own signals: avoid, review, or null. */
  name_finding: "avoid" | "review" | null;
  /**
   * The task named no ecosystem, so the name was checked in every one the project uses; this
   * finding is the worst answer, and these are the others (`not_found`: that registry has no such name).
   */
  also_checked?: Array<{ ecosystem: CheckEcosystem; verdict: NewPackageFinding["verdict"] | "not_found"; malicious?: true }>;
}

const POPULAR = new Set(POPULAR_NPM);
/** Enough for any list a task gives ("add a, b, c and d"): every name in it is checked. */
const MAX_NEW_PACKAGES = 8;
/** How long a briefing waits for the name checks. Past it they are unchecked, never clean. */
const NAME_CHECK_BUDGET_MS = 10_000;

/**
 * Verbs that bring a package in. "need" too: "we need electorn for the desktop build" and "we need
 * ctx for the config" came back safe_to_delegate (black-box audit of 60c9edc, 2026-11-14).
 */
const ADD_VERBS = new Set([
  "add", "adding", "adds", "use", "using", "adopt", "adopting", "introduce", "introducing", "import", "importing", "require", "requiring", "try", "trying", "need", "needs",
  "include", "includes",
]);
/** Verbs that bring a package in with "in" after them: "bring in ctx", "pull in left-pad". */
const IN_VERBS = new Set(["bring", "bringing", "brings", "pull", "pulling", "pulls"]);
const INSTALL_VERBS = new Set(["install", "installing", "installs", "reinstall"]);
/** Words that may stand between the verb and the name. */
const FILLERS = new Set(["the", "a", "an", "new", "this", "another", "npm", "pnpm", "yarn", "bun", "node", "nodejs", "pip", "pypi", "python", "cargo", "rust", "go", "golang", "official", "popular", "called", "named", "on", "of"]);
/** Words that say the thing named is a package. */
const PACKAGE_WORDS = new Set(["package", "packages", "library", "libraries", "lib", "crate", "crates", "module", "modules", "dependency", "dependencies", "dep", "deps", "plugin", "sdk"]);
/** Never a package name in prose, whatever stands around it. */
const NOT_A_NAME = new Set([
  "for", "to", "in", "on", "of", "with", "from", "into", "as", "at", "by", "and", "or", "so", "that", "which", "it", "its", "this", "these", "those", "them", "is", "are", "be",
  "missing", "more", "some", "all", "any", "other", "extra", "needed", "required", "optional", "latest", "version", "versions", "support", "tests", "test", "unit", "logging",
  "error", "errors", "handling", "feature", "features", "validation", "types", "typing", "docs", "documentation", "comments", "code", "function", "method", "class", "endpoint",
  "route", "page", "button", "field", "column", "table", "index", "config", "option", "flag", "check", "checks", "new", "dev", "peer", "runtime", "production", "project", "repo",
  "we", "you", "i", "my", "our", "your", "their", "one", "two", "each", "every", "same", "following", "above", "below", "here", "there", "then", "now", "also", "just", "only",
  "again", "first", "locally", "globally", "manually", "properly", "correctly", "successfully", "fails", "failed", "works", "step", "command", "script", "before", "after",
  "when", "if", "because", "but", "not", "no", "yet", "still", "everything", "anything", "nothing", "something", "run", "running", "via", "using", "inside", "without",
]);
/** Verbs that start a new clause after "and": the list of names has ended. */
const CLAUSE_VERBS = new Set([
  "set", "upgrade", "update", "bump", "pin", "change", "remove", "delete", "drop", "fix", "run", "make", "move", "write", "roll", "downgrade", "test", "build",
  "configure", "refactor", "replace", "rename", "check", "verify", "add", "install", "use", "deploy", "release", "publish", "commit", "push", "lock", "revert",
  "parse", "print", "read", "save", "load", "send", "render", "handle", "return", "call", "wire", "connect", "show", "display", "import", "export",
  "rewrite", "clean", "validate", "log", "document", "swap", "switch", "migrate", "start", "stop", "restart", "open", "close", "create", "generate",
]);
/**
 * Verbs that swap one thing for another: "replace lodash with lodahs", "swap express for expres",
 * "switch from moment to dayjs", "migrate to pnpm". The thing after the connector is introduced
 * (both of the first two came back safe_to_delegate with no new package; round 5 audits).
 */
const SWAP_VERBS = new Set(["replace", "replacing", "replaces", "swap", "swapping", "swaps", "switch", "switching", "migrate", "migrating", "move", "moving", "port", "porting"]);
/** The word before what comes in, by verb: "replace A with B", "swap A for B", "switch from A to B". */
const swapConnectors = (verb: string): ReadonlySet<string> => (verb.startsWith("replac") ? new Set(["with", "by"]) : verb.startsWith("swap") ? new Set(["for", "with"]) : new Set(["to"]));
/** Words between a name and the manifest it goes in: "add ctx to requirements.txt", "into the package.json". */
const DESTINATION_PREPOSITIONS = new Set(["to", "into", "in", "inside"]);
const DESTINATION_FILLERS = new Set(["the", "our", "my", "your", "this", "project's", "app's", "dev", "runtime", "a", "an", "its"]);
/** Section names a destination may give instead of a file: "add ctx to the dependencies", "to requirements". */
const DESTINATION_SECTIONS = new Set(["dependencies", "deps", "devdependencies", "dev-dependencies", "requirements", "manifest", "lockfile", "lock", "pyproject", "gemfile"]);
/** English, as briefing-names.ts lists it, less every name on the popular list: those are always checked. */
const ENGLISH = new Set([...ENGLISH_TASK_WORDS].filter((w) => !POPULAR.has(w)));
/** Endings of English nouns and gerunds ("memoization", "caching", "management"): a bare "add X" with one is prose. */
const ENGLISH_ENDING = /^[a-z]{3,}(?:ing|tion|sion|ment|ness|ity|ance|ence|ism|ship|ure|ies)$/;
/** Punctuation and shapes no English word has: a name like this after "add" is a package ("logger-libs", "flatmap-stream"). */
const NAME_SHAPED = /[-_.@/\d]/;
const VERSION_ONLY = /^v?\d+(?:\.(?:\d+|x|\*))*(?:[-+][\w.]+)?$/i;
/** A version or range a task binds to the name before it: 4.17.21, v1.2.3, ^1.2, ~2.0, >=2, ==3.3.6, ~=3.1, 7.x. */
const BINDABLE_VERSION = /^(?:={1,3}|~=|[~^]|[<>]=?)?v?\d+(?:\.(?:\d+|x|\*))*(?:-[\w.-]+)?(?:\+[\w.-]+)?$/i;
/** Words between a name and its version: "event-stream at version 3.3.6". */
const VERSION_LEADS = new Set(["at", "version", "@"]);
/** Words that join items of a list ("a, b and c", "a & b", "a + b", "a plus b"); commas, "&" and "+" are read from the text between words. */
const LIST_WORDS = new Set(["and", "plus", "&", "+"]);

type Manager = { ecosystem: CheckEcosystem; commands: ReadonlySet<string> };
const MANAGERS: Record<string, Manager> = {
  npm: { ecosystem: "npm", commands: new Set(["install", "i", "add"]) },
  pnpm: { ecosystem: "npm", commands: new Set(["install", "i", "add"]) },
  yarn: { ecosystem: "npm", commands: new Set(["add"]) },
  bun: { ecosystem: "npm", commands: new Set(["install", "i", "add"]) },
  cargo: { ecosystem: "crates.io", commands: new Set(["add", "install"]) },
  pip: { ecosystem: "PyPI", commands: new Set(["install"]) },
  pip3: { ecosystem: "PyPI", commands: new Set(["install"]) },
  uv: { ecosystem: "PyPI", commands: new Set(["add"]) },
  poetry: { ecosystem: "PyPI", commands: new Set(["add"]) },
  pipenv: { ecosystem: "PyPI", commands: new Set(["install"]) },
  go: { ecosystem: "Go", commands: new Set(["get"]) },
};

/** A token as a package name of the ecosystem (a trailing `@version` / `==version` dropped), or null. */
export function asName(token: string, ecosystem: CheckEcosystem): string | null {
  let name = token.replace(/[),.;:!?'"]+$/, "");
  const at = name.indexOf("@", 1);
  // `go get mod@v1.2.3` too: the version is not part of the module path (live/go-path.ts).
  if (at > 0) name = name.slice(0, at);
  name = name.replace(/(?:[=~<>!]=?|\^).*$/, "");
  if (name.length < 2 || VERSION_ONLY.test(name) || NOT_A_NAME.has(name.toLowerCase()) || PACKAGE_WORDS.has(name.toLowerCase())) return null;
  switch (ecosystem) {
    case "npm":
      return isNpmPackageName(name) ? name.toLowerCase() : null;
    case "crates.io":
      return /^[a-z][a-z0-9_-]{0,63}$/i.test(name) ? name : null;
    case "PyPI":
      return /^[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$/i.test(name) ? name : null;
    case "Go":
      // A malformed path ("x.com/a//b", a trailing "/") is still the name the task gives: dependency_check
      // says it is not one the go command accepts (live/go-path.ts), never a silent skip.
      return /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\/[\w.~/-]*$/i.test(name) && name.length <= 300 ? name : null;
  }
}

/** The ecosystem prose names ("the crate", "from PyPI"), else the project's most common, else npm. */
export function proseEcosystem(words: string[], deps: readonly ResolvedDependency[]): CheckEcosystem {
  return statedEcosystem(words) ?? projectEcosystems(deps)[0] ?? "npm";
}

/** The ecosystem the task's own words name ("pip", "cargo", "package.json"...), or null. */
export function statedEcosystem(words: string[]): CheckEcosystem | null {
  const has = (...w: string[]) => w.some((x) => words.includes(x));
  if (has("crate", "crates", "cargo", "crates.io", "rust", "cargo.toml", "cargo.lock")) return "crates.io";
  if (has("pip", "pip3", "pypi", "python", "poetry", "uv", "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "pipfile", "setup.py")) return "PyPI";
  if (has("go.mod", "go.sum")) return "Go";
  if (has("npm", "pnpm", "yarn", "bun", "node", "nodejs", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")) return "npm";
  return null;
}

/** The checkable ecosystems the project installs from, most dependencies first. */
export function projectEcosystems(deps: readonly ResolvedDependency[]): CheckEcosystem[] {
  const counts = new Map<CheckEcosystem, number>();
  for (const d of deps) {
    if (d.ecosystem === "npm" || d.ecosystem === "crates.io" || d.ecosystem === "PyPI" || d.ecosystem === "Go") counts.set(d.ecosystem, (counts.get(d.ecosystem) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([e]) => e);
}

/**
 * The packages a task is about to add that the project does not already have (see the module
 * comment for what counts as naming one). At most eight, in the order named.
 */
export function detectNewPackages(task: string, deps: readonly ResolvedDependency[]): NewPackage[] {
  return readTaskItems(normalizeVersionSyntax(task), deps).packages;
}

/** Where in the (normalized) task a version is written. */
export interface TaskSpan {
  start: number;
  end: number;
}

/** A version the task writes right after a name it adds ("axios 0.21.0", "event-stream at version 3.3.6"). */
export interface BoundVersion extends TaskSpan {
  /** The name as written (before any ecosystem's spelling rules). */
  name: string;
  version: string;
}

export interface TaskItems {
  packages: NewPackage[];
  /** Versions tied to the name before them: briefing-requested-versions.ts judges each for that name. */
  bound: BoundVersion[];
  /** Versions of what a swap takes out ("replace request 2.88.0 with axios"): not written by the task. */
  ignored: TaskSpan[];
}

/**
 * The task read clause by clause (pre-publish audit of 5d709ff). A clause ends at a sentence break,
 * ";", "then" or a new verb; in each one the verb (add, install, need, bring in, replace A with,
 * migrate from A to...) is followed by a list of items, each `name [version]`, separated by commas,
 * "and", "&", "+" or "plus". A version is bound to the item just before it: "add lodash 4.17.21 and
 * crossenv" checks both packages (the version used to end the list), "replace request with axios
 * 0.21.0" checks axios at 0.21.0 (the version used to be dropped), and in "upgrade lodash to 4.17.21
 * and add express 4.x" the 4.x is express's.
 *
 * `task` must already be normalized (normalizeVersionSyntax).
 */
export function readTaskItems(task: string, deps: readonly ResolvedDependency[]): TaskItems {
  const quoted = new Set((task.match(/`([^`\s]+)`/g) ?? []).map((q) => q.slice(1, -1).toLowerCase()));
  // Word-ish tokens that keep package punctuation; a leading "-" marks a command flag.
  const tokens = [...task.matchAll(/(?:--?[A-Za-z][\w-]*)|[@A-Za-z0-9][\w./@*=<>~^!-]*/g)];
  const raw = tokens.map((t) => t[0]);
  const starts = tokens.map((t) => t.index ?? 0);
  const words = raw.map((t) => t.replace(/[.,;:)]+$/, "").toLowerCase());
  const fallback = proseEcosystem(words, deps);
  const stated = statedEcosystem(words);
  // A name filed under the project's main ecosystem only because the task names none is a guess:
  // it is checked in every ecosystem the project uses (checkNewPackages takes the worst answer).
  const others = stated ? [] : projectEcosystems(deps).filter((e) => e !== fallback);
  const guessed = new Set<CheckEcosystem>([fallback, ...others]);
  const have = new Set(deps.map((d) => `${d.ecosystem}\0${d.name.toLowerCase()}`));
  const installedName = (name: string) => deps.some((d) => d.name.toLowerCase() === name.toLowerCase()) || installedGoModule(name, deps) !== null;
  const found: NewPackage[] = [];
  const bound: BoundVersion[] = [];
  const ignored: TaskSpan[] = [];
  const add = (name: string | null, ecosystem: CheckEcosystem, guess = false, weak = false, version: string | null = null) => {
    if (!name || have.has(`${ecosystem}\0${name.toLowerCase()}`) || isManifestFile(name)) return false;
    // A guessed name the project already has, in any ecosystem or as a Go module's short name
    // ("install gin" with github.com/gin-gonic/gin in go.mod), is not new (blind audit round 4).
    if (guess && installedName(name)) return false;
    const alternatives = guess ? others.filter((e) => asName(name, e) !== null) : [];
    const at = found.findIndex((f) => f.ecosystem === ecosystem && f.name === name);
    if (at < 0) {
      found.push({
        name,
        ecosystem,
        ...(version ? { version } : {}),
        ...(alternatives.length > 0 ? { alternatives } : {}),
        ...(guess && !stated ? { guessed: true as const } : {}),
        ...(weak ? { weak: true as const } : {}),
      });
    } else {
      if (!weak) delete found[at].weak;
      if (version && !found[at].version) found[at].version = version;
    }
    return true;
  };
  /** The span of token `k` in the task, trailing punctuation aside. */
  const span = (k: number): TaskSpan => ({ start: starts[k], end: starts[k] + raw[k].replace(/[.,;:)]+$/, "").length });
  /** What separates token `k` from the next: a list separator, a clause break, or nothing. */
  const separatorAfter = (k: number): "list" | "clause" | null => {
    const gap = task.slice(span(k).end, k + 1 < raw.length ? starts[k + 1] : task.length);
    if (/[;!?\n]|[.:](?:\s|$)/.test(gap)) return "clause";
    if (/[,&+]/.test(gap)) return "list";
    return null;
  };
  /** The version token `k` carries itself: `axios@0.21.0`, `requests==2.19.0`. */
  const inlineVersion = (k: number): string | null => {
    const token = raw[k].replace(/[.,;:)]+$/, "");
    const at = token.indexOf("@", 1);
    const spec = at > 0 ? token.slice(at + 1) : (/^[A-Za-z0-9][\w.-]*((?:===?|~=|>=|<=|!=|>|<)\S+)$/.exec(token)?.[1] ?? null);
    return spec && BINDABLE_VERSION.test(spec) ? spec.replace(/^==?(?!=)/, "") : null;
  };
  /**
   * The version written after item `k` ("axios 0.21.0", "event-stream at version 3.3.6"), and the
   * token after it. A version with no dot ("ctx 2") is bound only after add and install, where a
   * number after a name is a release; elsewhere it is as often a count.
   */
  const versionAfter = (k: number, bareNumbers: boolean): { version: string; at: number } | null => {
    let v = k + 1;
    if (separatorAfter(k) !== null) return null;
    while (v < words.length && VERSION_LEADS.has(words[v]) && separatorAfter(v) === null) v++;
    if (v >= words.length) return null;
    const token = raw[v].replace(/[.,;:)]+$/, "");
    if (!BINDABLE_VERSION.test(token) || (!bareNumbers && !/\d\.(?:\d|x|\*)/i.test(token))) return null;
    return { version: token.replace(/^==?(?!=)/, ""), at: v };
  };
  /**
   * The words after a name (or a list of names) put it in a manifest or the dependency list:
   * "to requirements.txt", "into the package.json", "to the dependencies", "as a dev dependency".
   */
  const goesInManifest = (from: number): boolean => {
    let j = from;
    // Past the rest of an "a and b" / "a, b" list, and the versions in it.
    while (
      j < words.length &&
      (LIST_WORDS.has(words[j]) || BINDABLE_VERSION.test(words[j]) || VERSION_LEADS.has(words[j]) || (asName(raw[j], fallback) !== null && !DESTINATION_PREPOSITIONS.has(words[j]) && words[j] !== "as"))
    ) {
      if (j - from > 10) return false;
      j++;
    }
    if (words[j] === "as") {
      let m = j + 1;
      while (m < words.length && (DESTINATION_FILLERS.has(words[m]) || words[m] === "new")) m++;
      return PACKAGE_WORDS.has(words[m] ?? "");
    }
    if (!DESTINATION_PREPOSITIONS.has(words[j] ?? "")) return false;
    let m = j + 1;
    while (m < words.length && DESTINATION_FILLERS.has(words[m])) m++;
    const target = words[m] ?? "";
    return isManifestFile(raw[m] ?? "") || DESTINATION_SECTIONS.has(target) || PACKAGE_WORDS.has(target);
  };
  /** Prose that reads as English, not as a package, for a name nothing else marks as one. */
  const english = (name: string, bareAdd: boolean) => {
    const n = name.toLowerCase();
    if (ENGLISH.has(n)) return true;
    if (!bareAdd) return false;
    return COMMON_WORDS.has(n) || PYTHON_STDLIB.has(n) || (!NAME_SHAPED.test(n) && ENGLISH_ENDING.test(n));
  };

  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    // `npm install a b`, `pnpm add -D a`, `go get host/path`: every argument that is a name.
    const manager = Object.hasOwn(MANAGERS, word) ? MANAGERS[word] : undefined;
    let j = i + 1;
    if (manager && word === "uv" && words[j] === "pip") j++;
    if (manager && (manager.commands.has(words[j]) || (word === "uv" && words[j] === "install"))) {
      for (j++; j < words.length; j++) {
        if (words[j].startsWith("-")) continue;
        // The first argument that is not a name ends the command; one the project already has does not.
        const name = asName(raw[j], manager.ecosystem);
        if (!name) break;
        add(name, manager.ecosystem, false, false, inlineVersion(j));
        if (separatorAfter(j) === "clause") break;
      }
      i = j - 1;
      continue;
    }
    const installing = INSTALL_VERBS.has(word);
    // "bring in ctx", "pull in left-pad": the verb is the pair.
    const bringingIn = IN_VERBS.has(word) && (words[i + 1] === "in" || words[i + 1] === "into");
    if (bringingIn) i++;
    // "replace lodash with lodahs", "swap express for expres", "switch to dayjs": what comes in.
    let swapped = false;
    let swappedFromDependency = false;
    if (SWAP_VERBS.has(word)) {
      let c = i + 1;
      if (words[c] === "out" || words[c] === "over") c++;
      if (words[c] === "from") c++;
      // "move" and "port" move code as often as packages: only "move from A to B" swaps one.
      if ((word.startsWith("mov") || word.startsWith("port")) && words[c - 1] !== "from") continue;
      // The thing replaced: up to four words ("the lodash package", "our old date library").
      const connectors = swapConnectors(word);
      let end = c;
      while (end < words.length && end - c < 5 && !connectors.has(words[end])) end++;
      if (!connectors.has(words[end] ?? "")) continue;
      // "switch to B" / "migrate to B" name only what comes in; "replace X with Y" must name X.
      if (end === c && words[end] !== "to") continue;
      // "migrate lodash from 4.17.20 to 4.17.21" moves one package between versions: no swap.
      if (end + 1 < words.length && BINDABLE_VERSION.test(words[end + 1])) continue;
      swappedFromDependency = words.slice(c, end).some((w) => installedName(w) || PACKAGE_WORDS.has(w) || quoted.has(w));
      // The version of what goes out is not one the task writes.
      for (let o = c; o < end; o++) if (BINDABLE_VERSION.test(words[o])) ignored.push(span(o));
      swapped = true;
      i = end;
    } else if (!installing && !bringingIn && !ADD_VERBS.has(word)) continue;
    // A number after a name is a release after add and install; after "use" or "need" it may be a count.
    const bareNumbers = installing || word.startsWith("add");
    // The verb, then only articles and package words, then the list of items.
    let k = i + 1;
    let saidPackage = false;
    let skipped = 0;
    // "install the private @acme scope": an adjective there is no package (blind audit round 4).
    while (k < words.length && (FILLERS.has(words[k]) || PACKAGE_WORDS.has(words[k]) || (NOT_A_PACKAGE_ADJECTIVES.has(words[k]) && !quoted.has(words[k])))) {
      if (PACKAGE_WORDS.has(words[k])) saidPackage = true;
      k++;
      skipped++;
    }
    while (k < words.length) {
      const name = asName(raw[k], fallback);
      if (!name) break;
      const inline = inlineVersion(k);
      const after = inline ? null : versionAfter(k, bareNumbers);
      const version = inline ?? after?.version ?? null;
      let next = after ? after.at + 1 : k + 1;
      const isQuoted = quoted.has(words[k]) || quoted.has(name.toLowerCase());
      // A popular npm name, or a near miss of one, is a package whatever the wording: "add lodahs" came
      // back safe_to_delegate without a packaging word (blind audit round 3, B3). The list is bundled,
      // so an unknown word is never sent anywhere for it.
      // A near-miss of a popular PyPI project too, in a project that installs from PyPI: "add colourama",
      // "add jeIlyfish" and "add python3-dateutil" read as prose (black-box audit of 60c9edc, 2026-11-14).
      const known =
        !COMMON_WORDS.has(name) &&
        !ENGLISH.has(name) &&
        !PYTHON_STDLIB.has(name) &&
        ((guessed.has("npm") && (POPULAR.has(name) || nearMissOf(name) !== null)) || (guessed.has("PyPI") && closestPopularPypi(name) !== null));
      // "add ctx to requirements.txt", "add extrahtml to the dependencies": the destination says it is a package
      // (both came back safe_to_delegate in a Python project; round 5 audits). A manifest's own fields are not.
      const manifest = goesInManifest(next) && !MANIFEST_FIELDS.has(name.toLowerCase());
      // A version written after it says it is a package: "pull in node-ipc 10.1.1".
      const strong = saidPackage || PACKAGE_WORDS.has(words[next] ?? "") || isQuoted || known || manifest || version !== null || (swapped && swappedFromDependency);
      if (!strong) {
        // A bare "add X" (or "install X", "replace A with X") reads X as a package for any plausible
        // name ("add ctx", "add flatmap-stream" came back safe_to_delegate; round 5 audits), unless it
        // is English ("install steps", "add routes"). After an article only a name-shaped word counts
        // ("add a footer" is prose, "add the logger-libs" is not).
        if (english(name, !installing)) break;
        if (!installing && skipped > 0 && !NAME_SHAPED.test(name)) break;
      }
      add(name, fallback, true, !strong && !installing, version);
      if (after) bound.push({ name: raw[k].replace(/[.,;:)]+$/, ""), version: after.version, ...span(after.at) });
      // "the lodahs package, and expres": a package word may close the item.
      if (PACKAGE_WORDS.has(words[next] ?? "") && separatorAfter(next - 1) === null) next++;
      // The next item: after a comma, "and", "&", "+" or "plus"; a clause break or a new verb ends the list
      // ("install omega-flag-beta and set lodash ..." added a package named `set`).
      const separator = separatorAfter(next - 1);
      if (separator === "clause") break;
      if (LIST_WORDS.has(words[next] ?? "")) next++;
      else if (separator !== "list") {
        // "install zqx omega risk": a bare list without separators is one name, unless installing.
        if (!installing) break;
        k = next;
        skipped = 0;
        continue;
      }
      if (words[next] === "also") next++;
      if (next >= words.length || words[next] === "then" || CLAUSE_VERBS.has(words[next]) || IN_VERBS.has(words[next])) break;
      skipped = 0;
      while (next < words.length && (FILLERS.has(words[next]) || (NOT_A_PACKAGE_ADJECTIVES.has(words[next]) && !quoted.has(words[next])))) {
        next++;
        skipped++;
      }
      k = next;
    }
  }
  return { packages: found.slice(0, MAX_NEW_PACKAGES), bound, ignored };
}

export type NameCheckLive = Pick<LiveIntelligence, "isEnabled"> & Partial<Pick<LiveIntelligence, "getReleaseSources" | "getFixPathSources" | "queryAdvisories">>;

/** The popular package a name resembles in its ecosystem's bundled list, when there is one. */
function nearMissName(name: string, ecosystem: CheckEcosystem): string | null {
  if (ecosystem === "npm") return nearMissOf(name)?.of ?? null;
  if (ecosystem === "PyPI") return closestPopularPypi(name);
  return null;
}

function unchecked({ alternatives: _alternatives, weak: _weak, guessed: _guessed, ...pkg }: NewPackage, why: string): NewPackageFinding {
  return {
    ...pkg,
    verdict: "unknown",
    latest: null,
    reason: `${pkg.name}${pkg.version ? ` ${pkg.version}` : ""} could not be checked (${why}). Call dependency_check on it before adding it.`,
    malicious: false,
    did_you_mean: nearMissName(pkg.name, pkg.ecosystem),
    name_finding: null,
  };
}

/** No registry of that ecosystem has the name and no malicious-package record covers it. */
const nameNotFound = (f: NewPackageFinding) => !f.malicious && f.verdict === "unknown" && /a hallucinated package/.test(f.reason);
/** That ecosystem has neither the name nor, for a named version, that release: its answer says nothing about the others. */
const notFound = (f: NewPackageFinding) => nameNotFound(f) || (Boolean(f.version) && !f.malicious && f.verdict === "unknown" && /is not a published version on/.test(f.reason));
/** The checkable ecosystems a bare name can be in (a Go module is a host path, never a bare name). */
const NAME_ECOSYSTEMS: readonly CheckEcosystem[] = ["npm", "crates.io", "PyPI"];

/**
 * How bad one ecosystem's answer for a name is: malware, then a name finding of avoid, then any
 * avoid, then review, then a check that could not run, then wait, then proceed. A name that
 * ecosystem does not have at all ranks below everything: it says nothing about the others.
 */
function badness(f: NewPackageFinding): number {
  if (notFound(f)) return -1;
  if (f.malicious) return 6;
  if (f.name_finding === "avoid") return 5;
  if (f.verdict === "avoid") return 4;
  if (f.verdict === "review" || f.name_finding === "review") return 3;
  if (f.verdict === "unknown") return 2;
  return f.verdict === "wait" ? 1 : 0;
}

/**
 * dependency_check's answer for each package at `latest`, within the briefing's budget. Offline,
 * without the live layer, or past the budget, a package is `unknown`: never read as safe.
 *
 * A name the task gives no ecosystem for is checked in every ecosystem the project uses, all at
 * once, and the worst answer is the finding: "add ctx" in a project with package.json and
 * requirements.txt looked up only npm's `ctx` (clean) and came back safe_to_delegate, while PyPI's
 * `ctx` is malware (PYSEC-2022-199; black-box audit of 60c9edc, 2026-11-14). The other
 * ecosystems' answers are listed in `also_checked`.
 */
export async function checkNewPackages(liveIntel: NameCheckLive | null, packages: NewPackage[], now?: Date): Promise<NewPackageFinding[]> {
  if (packages.length === 0) return [];
  if (!liveIntel || !liveIntel.isEnabled()) return packages.map((p) => unchecked(p, "live lookups are disabled"));
  if (!liveIntel.getReleaseSources || !liveIntel.getFixPathSources || !liveIntel.queryAdvisories) {
    return packages.map((p) => unchecked(p, "the registry lookups are not available in this session"));
  }
  const deadline = Date.now() + NAME_CHECK_BUDGET_MS;
  /** One dependency_check run within what is left of the budget; null past it. */
  const run = async (list: NewPackage[]) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        executeDependencyCheck(null, { items: list.map((p) => ({ ecosystem: p.ecosystem, package: p.name, to: p.version ?? "latest" })) }, liveIntel as LiveIntelligence, now ? { now } : {}),
        new Promise<null>((resolve) => {
          timer = setTimeout(() => resolve(null), Math.max(0, deadline - Date.now()));
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
  type Answer = NonNullable<Awaited<ReturnType<typeof run>>>;
  const finding = (pkg: NewPackage, r: Answer["results"][number] | undefined): NewPackageFinding => {
    const { alternatives: _alternatives, weak: _weak, guessed: _guessed, ...p } = pkg;
    if (!r) return unchecked(p, "no answer");
    const advisories = r.signals.find((s) => s.id === "advisories")?.value as { malicious_package?: { did_you_mean?: string | null } } | null | undefined;
    const nameCheck = r.signals.find((s) => s.id === "name_check");
    const nearMiss = (nameCheck?.value as { near_miss_of?: string } | undefined)?.near_miss_of;
    return {
      ...p,
      verdict: r.verdict,
      latest: !p.version && r.to !== "latest" ? r.to : null,
      reason: r.reason,
      malicious: Boolean(advisories?.malicious_package),
      did_you_mean: advisories?.malicious_package?.did_you_mean ?? nearMiss ?? nearMissName(p.name, p.ecosystem),
      name_finding: nameCheck?.effect === "avoid" || nameCheck?.effect === "review" ? nameCheck.effect : null,
    };
  };
  // Every ecosystem a guessed name may be in, in one run: the lookups go out together, so a
  // second ecosystem costs no more wall time than the first, within the same budget.
  const items = packages.flatMap((p, i) => [p, ...(p.alternatives ?? []).map((ecosystem) => ({ name: p.name, ecosystem, ...(p.version ? { version: p.version } : {}) }))].map((q) => ({ i, q })));
  try {
    const answer = await run(items.map((x) => x.q));
    if (!answer) return packages.map((p) => unchecked(p, "the lookups did not finish in time"));
    const answered = packages.map((_p, i) => items.flatMap((x, k) => (x.i === i ? [finding(x.q, answer.results[k])] : [])));
    // A name the task gives no ecosystem for that none of the project's ecosystems has: the others'
    // malicious-package records are read too. "bring in rustdecimal" in an npm project came back
    // safe_to_delegate: npm has no such name, and crates.io's rustdecimal is malware
    // (GHSA-7pwq-f4pq-78gm; pre-publish audit of 5d709ff). Only a malware answer there is kept.
    const elsewhere = packages.flatMap((p, i) =>
      p.guessed && answered[i].every(nameNotFound)
        ? NAME_ECOSYSTEMS.filter((e) => !answered[i].some((f) => f.ecosystem === e) && asName(p.name, e) !== null).map((ecosystem) => ({ i, q: { name: p.name, ecosystem } as NewPackage }))
        : [],
    );
    if (elsewhere.length > 0) {
      const more = await run(elsewhere.map((x) => x.q)).catch(() => null);
      if (more) {
        elsewhere.forEach((x, k) => {
          const f = finding(x.q, more.results[k]);
          if (f.malicious || f.name_finding === "avoid") answered[x.i].push(f);
        });
      }
    }
    const out = packages.map((p, i) => {
      const answers = answered[i];
      if (answers.length === 1) return answers[0];
      // The worst answer; when no ecosystem has the name, the one that knows what it resembles.
      const worst = answers.reduce((a, b) => (badness(b) > badness(a) ? b : a));
      const pick = notFound(worst) ? (answers.find((f) => f.did_you_mean) ?? worst) : worst;
      const also = answers.filter((f) => f !== pick).map((f) => ({ ecosystem: f.ecosystem, verdict: notFound(f) ? ("not_found" as const) : f.verdict, ...(f.malicious ? { malicious: true as const } : {}) }));
      return { ...pick, also_checked: also };
    });
    /** A weak name no registry has and no malware record covers was prose; a clean one adds nothing to say. */
    const prose = (f: NewPackageFinding, i: number) => packages[i].weak === true && !f.malicious && f.name_finding === null && (f.verdict === "proceed" || notFound(f));
    return out.filter((f, i) => !prose(f, i));
  } catch (error) {
    return packages.map((p) => unchecked(p, `the check failed: ${String(error instanceof Error ? error.message : error).slice(0, 120)}`));
  }
}
