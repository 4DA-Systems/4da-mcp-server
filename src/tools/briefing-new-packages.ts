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
import {
  checkableSpec,
  closestPopularPypi,
  ENGLISH_TASK_WORDS,
  installedGoModule,
  isManifestFile,
  isTomlEntry,
  isVersionSpec,
  MANIFEST_FIELDS,
  normalizePypiName,
  normalizeVersionSyntax,
  NOT_A_PACKAGE_ADJECTIVES,
  PYTHON_STDLIB,
  SPEC_JOINERS,
  specText,
} from "./briefing-names.js";
import { isNpmPackageName } from "../untrusted-text.js";
import { COMMON_WORDS } from "./briefing-task-scope.js";
import { executeDependencyCheck } from "./dependency-check.js";
import { isKnownSwitch, MAX_TASK_WORD, optionTakesValue, pathLikeOperand, screenedOut, screenTask } from "./briefing-task-screen.js";
import { nearMissOf } from "./dependency-check-nearmiss.js";
import { checkNameOnly, type NameOnlyAnswer } from "./briefing-task-name-check.js";

export interface NewPackage {
  name: string;
  ecosystem: CheckEcosystem;
  /** The version or range the task writes for it ("axios 0.21.0", `debug@4.4.2`): checked at that, not at `latest`. */
  version?: string;
  /** The task writes a version for it that is no version, range or tag (`zustand@<uuid>`): never read as latest. */
  versionUnread?: true;
  /** Other ecosystems the project uses: a name the task gives no ecosystem for is checked in each, and the worst answer stands. */
  alternatives?: CheckEcosystem[];
  /**
   * Read from a bare "add X" with nothing else saying X is a package: when no registry has the name
   * and no malicious-package record covers it, it was prose ("add memoization"), and it is dropped
   * instead of reported as a hallucinated package. Any other answer (malware, a near-miss, a release
   * with advisories, a lookup that could not run) stands.
   */
  weak?: true;
  /**
   * Weak, and read after a verb that names a way of working as often as a package ("use blueprints",
   * "try generators"): only a finding about the NAME (malware, a near-miss) stands; a release-level
   * one on a word read that way is prose (r8: "use blueprints" was review_needed on npm's
   * `blueprints` 0.1.3 and its vulnerable `cli` dependency).
   */
  loose?: true;
  /** The task gave no ecosystem for it: a name none of the project's ecosystems has is also checked for malware in the others. */
  guessed?: true;
  /** Ecosystems whose registry, index or proxy for this project is not public: the name is never asked about there (r9, B1). */
  closed?: CheckEcosystem[];
  /**
   * `alternatives` count only when `ecosystem` has no such name or release: a pip-style comparator
   * read as PyPI in a project that uses PyPI is tried on npm only as a fallback (pre-publish round 10, W16).
   */
  fallbackOnly?: true;
  /** On equal answers, report this ecosystem (the project's own), not the comparator's guess (pre-publish round 10, final check). */
  preferOnTie?: CheckEcosystem;
}

/** dependency_check's signals, as far as the briefing reads them. */
type Signals = ReadonlyArray<{ id: string; effect?: string }>;

/**
 * The answer is "review" only because the name is a near-miss of a popular one in that ecosystem:
 * no release-level signal says review or avoid. Such an answer from a namesake must not outrank a
 * real answer from the ecosystem that has the release (pre-publish round 10, W16: "add numpy 2.1" in an
 * npm + PyPI project was review_needed on npm's numpy namesake).
 */
export function nameOnlyReview(verdict: string, signals: Signals): boolean {
  const flagged = signals.filter((s) => s.effect === "review" || s.effect === "avoid");
  return verdict === "review" && flagged.length > 0 && flagged.every((s) => s.id === "name_check");
}

/** The ecosystem knows the name as no near-miss: its answer is about the package being added. */
export function nameClean(signals: Signals): boolean {
  const name = signals.find((s) => s.id === "name_check");
  return !name || (name.effect !== "review" && name.effect !== "avoid");
}

/**
 * dependency_check found no release matching the requested version or constraint, or no such name:
 * that ecosystem's answer is not an answer for the name ("No published, non-withdrawn release of rsa
 * matches 4.7" outranked PyPI's proceed; pre-publish round 10, W16).
 */
export const NO_SUCH_RELEASE = /is not a published version on|a hallucinated package|No published, non-withdrawn release of .+ matches /;

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
/**
 * How many names a briefing checks. Past it the rest are NOT CHECKED, said by name, and the briefing
 * is never safe_to_delegate (what-should-i-know.ts): a long list is never silently cut.
 */
export const MAX_NEW_PACKAGES = 8;
/**
 * How many packages a task is read for. Each is judged against the bundled popular lists (a near-miss
 * check), and a task listing 10,000 names took 28 s of CPU (pre-publish audit 2026-11-25, F-M3): past
 * it the rest of the task is not read, and the briefing says so (NOT CHECKED), never safe_to_delegate.
 */
export const MAX_READ_PACKAGES = 100;
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
/** Adding verbs that name a way of working as often as a package: a bare word after them is `loose`. */
const LOOSE_VERBS = new Set(["use", "using", "adopt", "adopting", "introduce", "introducing", "import", "importing", "require", "requiring", "try", "trying", "need", "needs", "include", "includes"]);
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
/** An npm dist-tag as tasks write one (`next`, `beta`, `canary`, `next-14`): letters, then short dashed parts. */
export const NPM_TAG = /^[a-z]{2,20}(?:-[a-z0-9]{1,10}){0,2}$/i;
const VERSION_ONLY = /^v?\d+(?:\.(?:\d+|x|\*))*(?:[-+][\w.]+)?$/i;
/**
 * Words between a name and its version: "event-stream at version 3.3.6", "add chalk to 5.6.1" (r8: the
 * 5.6.1 was judged avoid in requested_versions while the summary said "Task adds chalk (proceed)").
 */
const VERSION_LEADS = new Set(["at", "version", "v", "@", "to"]);
/** "depend on X", "depends upon X": the verb is the pair (r8: "depend on event-stream 3.3.6" left 3.3.6 unread). */
const ON_VERBS = new Set(["depend", "depends", "depending"]);
/** How far an item the reader passes over (prose, not a name) may run before the list is taken to have ended. */
const MAX_SKIPPED_ITEM = 8;
/** Words that join items of a list ("a, b and c", "a & b", "a + b", "a plus b"); commas, "&" and "+" are read from the text between words. */
const LIST_WORDS = new Set(["and", "plus", "&", "+"]);
/** Articles before a word that, followed by more prose, names a thing ("a retry with backoff"). */
const ARTICLES = new Set(["a", "an", "the", "some"]);

/**
 * A package manager command: the ecosystem it installs from fixes the ecosystem of every argument,
 * for both readers (pre-publish round 10, W14: in an npm project `poetry add pyyaml@5.3` judged npm's
 * `pyyaml` in requested_versions while new_packages judged PyPI's, and PyPI's 5.3 has a critical
 * advisory). `ecosystem: null` is a manager whose registry this server does not read (RubyGems,
 * Packagist, conda channels): its arguments are named NOT CHECKED, never looked up in npm.
 * conda installs from conda channels, whose builds and version numbers are not PyPI's: a PyPI answer
 * would be a guess about another registry, so conda is not read as PyPI.
 */
type Manager = { ecosystem: CheckEcosystem | null; commands: ReadonlySet<string>; registry?: string };
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
  pdm: { ecosystem: "PyPI", commands: new Set(["add"]) },
  pipx: { ecosystem: "PyPI", commands: new Set(["install"]) },
  rye: { ecosystem: "PyPI", commands: new Set(["add"]) },
  go: { ecosystem: "Go", commands: new Set(["get", "install"]) },
  gem: { ecosystem: null, commands: new Set(["install"]), registry: "RubyGems" },
  bundle: { ecosystem: null, commands: new Set(["add"]), registry: "RubyGems" },
  composer: { ecosystem: null, commands: new Set(["require"]), registry: "Packagist" },
  conda: { ecosystem: null, commands: new Set(["install"]), registry: "conda" },
  mamba: { ecosystem: null, commands: new Set(["install"]), registry: "conda" },
  micromamba: { ecosystem: null, commands: new Set(["install"]), registry: "conda" },
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

/**
 * The ecosystem of a manifest entry the task writes in TOML (`name = { version = "..." }`): a
 * Cargo.toml or pyproject entry, never npm. The one the task names, else the one of the two the
 * project installs from most, else crates.io (pre-publish round 10, W3).
 */
export function tomlEcosystem(stated: CheckEcosystem | null, deps: readonly ResolvedDependency[]): CheckEcosystem {
  if (stated === "crates.io" || stated === "PyPI") return stated;
  return projectEcosystems(deps).find((e) => e === "crates.io" || e === "PyPI") ?? "crates.io";
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
  return detectAllNewPackages(task, deps).slice(0, MAX_NEW_PACKAGES);
}

/** Every package the task adds, uncapped: the briefing checks the first MAX_NEW_PACKAGES and names the rest as not checked. */
export function detectAllNewPackages(task: string, deps: readonly ResolvedDependency[]): NewPackage[] {
  // Credentials, URLs, over-long words and whatever the task takes from a private registry, an index,
  // git, a path or a URL are never read (briefing-task-screen.ts; audit 2026-11-25, E1/E2/F-M3).
  // What may then be looked up is decided by gateTaskNames (briefing-requested-versions.ts), after the
  // project's own private rules.
  const screen = screenTask(task, dependencyOf(deps));
  return readTaskItems(normalizeVersionSyntax(screen.text), deps).packages.filter((p) => screenedOut(screen, p.name, [p.ecosystem, ...(p.alternatives ?? [])]) === null);
}

/** A name as an ecosystem compares names: PEP 503 for PyPI, `-`/`_` alike for crates.io, case aside for npm; a Go module path as written. */
function ecosystemKey(name: string, ecosystem: CheckEcosystem): string {
  if (ecosystem === "PyPI") return normalizePypiName(name);
  if (ecosystem === "crates.io") return name.toLowerCase().replace(/_/g, "-");
  if (ecosystem === "npm") return name.toLowerCase();
  return name;
}

/**
 * Whether the project already depends on `name` in `ecosystem` (its own dependency set: nothing is asked
 * to know it). Only inside that ecosystem, with its own name rule, and a Go module only by its full path:
 * a private PyPI `zqx-pyonly` made "npm install zqx_pyonly" look npm up, and a go.mod module
 * `git.x/team/zqx-pay-engine` made "npm install zqx-pay-engine" do the same (third blind check, item 3).
 */
export function installedNames(deps: readonly ResolvedDependency[]): (name: string, ecosystem: CheckEcosystem) => boolean {
  const keys = new Set<string>();
  for (const d of deps) {
    if (d.ecosystem === "npm" || d.ecosystem === "PyPI" || d.ecosystem === "crates.io" || d.ecosystem === "Go") keys.add(`${d.ecosystem}\0${ecosystemKey(d.name, d.ecosystem)}`);
  }
  return (name, ecosystem) => keys.has(`${ecosystem}\0${ecosystemKey(name, ecosystem)}`);
}

/** Whether a word names one of the project's own dependencies, in any ecosystem: never a setting. */
export function dependencyOf(deps: readonly ResolvedDependency[]): (name: string) => boolean {
  const names = new Set(deps.map((d) => d.name.toLowerCase().replace(/[-_.]+/g, "-")));
  return (name) => names.has(name.toLowerCase().replace(/[-_.]+/g, "-"));
}

/** A word the briefing did not look up, as the answer names it. */
export interface HeldWord {
  shown: string;
  reason: string;
}


/** Why an item is not looked up when a withheld span touches it. */
export const NOT_READ_WHOLE =
  "not read whole: part of it, or of the version beside it, looked like a credential, URL or address and was withheld, so it is not looked up at a version the task did not write";

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
  /** Every package the task adds, in the order named (uncapped). */
  packages: NewPackage[];
  /** Versions tied to the name before them: briefing-requested-versions.ts judges each for that name. */
  bound: BoundVersion[];
  /** Versions of what a swap takes out ("replace request 2.88.0 with axios"): not written by the task. */
  ignored: TaskSpan[];
  /**
   * Tokens whose ecosystem the task fixes, by a manager command (`poetry add pyyaml@5.3`) or a
   * PEP 440 specifier (`requests~=2.31`, `flask<2.2.5`): the version reader files them there too, never
   * under the project's guess (pre-publish round 10, W14).
   */
  fixed: Array<TaskSpan & { ecosystem: CheckEcosystem; alternatives?: CheckEcosystem[]; fallbackOnly?: true }>;
  /** Arguments of a manager whose registry this server does not read (`gem install rails`): named NOT CHECKED. */
  foreign: Array<TaskSpan & { name: string; registry: string }>;
  /** The task names more than MAX_READ_PACKAGES packages: the rest was not read (named NOT CHECKED). */
  truncated?: true;
  /** Words of a command that were not read (after an option that may take them as its value). */
  unreadWords: Array<{ shown: string; reason: string }>;
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
/** Word-ish tokens of a (normalized) task: package punctuation kept, a version with its operator, a joined constraint whole. */
const TOKEN = new RegExp(
  String.raw`(?:--?[A-Za-z][\w-]*)|(?:[<>]=?|={1,3}|~=?|\^|!=)v?\d[\w./@*=<>~^!${SPEC_JOINERS}-]*|[@A-Za-z0-9][\w./@*=<>~^!${SPEC_JOINERS}-]*`,
  "g",
);

/**
 * A version token as the package manager reads it: an exact pin's `==` dropped, a joined constraint as
 * text. Cargo's `=1.6.0` keeps its `=`: Cargo reads a bare 1.6.0 as ^1.6.0, so dropping it told the agent a
 * fresh resolve installs 1.16.5, where `=1.6.0` installs only 1.6.0 (pre-publish round 10, W14).
 */
export function taskVersionText(token: string, ecosystem?: CheckEcosystem): string {
  const text = specText(token);
  if (ecosystem === "crates.io" && /^=(?!=)/.test(text)) return text;
  return /^={1,2}(?!=)[^,|\s]+$/.test(text) ? text.replace(/^==?/, "") : text;
}

/** A specifier only PyPI writes right after the name: `requests~=2.31`, `flask<2.2.5`, `x===1.0`, `x==2.*`. */
const PEP440_INLINE = /^[A-Za-z0-9][\w.-]*(?:~=|===|==|!=|>=|<=|<|>)\S/;

/**
 * What ends a command's operands, between two tokens: a shell operator or redirection, a comment, a new
 * line, a comma before a blank, a parenthesis, a brace, a dash between clauses, a backtick, `$(`.
 */
const OPERANDS_END = /[&|;<>#\n(){}–—`]|\/\/|,\s|\$\(|(?:^|\s)-(?:\s|$)/;

/**
 * Whether the blank-delimited word around `at` has a colon followed by more of it (`admin:hunter2`,
 * `user:pass@host`): never a package name. A spec source the screen names (`npm:`, `file:`, `git+ssh:`)
 * is read there, so it is not one of these.
 */
function colonWord(task: string, at: number): boolean {
  let a = at;
  while (a > 0 && !/\s/.test(task[a - 1]) && at - a < MAX_TASK_WORD) a--;
  let b = at;
  while (b < task.length && !/\s/.test(task[b]) && b - at < MAX_TASK_WORD) b++;
  const word = task.slice(a, b);
  return /:[^\s/]/.test(word) && !/^(?:[\w.@/-]*@)?(?:npm|jsr|file|link|portal|workspace|catalog|patch|git(?:\+[a-z]+)?|github|gitlab|bitbucket|https?):/i.test(word);
}

export function readTaskItems(task: string, deps: readonly ResolvedDependency[]): TaskItems {
  const quoted = new Set((task.match(/`([^`\s]+)`/g) ?? []).map((q) => q.slice(1, -1).toLowerCase()));
  // Word-ish tokens that keep package punctuation; a leading "-" marks a command flag; a version may
  // start with its operator (`<1.2.6`, `^4.0.0`: the operator was dropped, and `^4.0.0` read as 4.0.0).
  const tokens = [...task.matchAll(TOKEN)];
  const raw = tokens.map((t) => t[0]);
  const starts = tokens.map((t) => t.index ?? 0);
  const words = raw.map((t) => t.replace(/[.,;:)]+$/, "").toLowerCase());
  const fallback = proseEcosystem(words, deps);
  const stated = statedEcosystem(words);
  // A TOML manifest entry is Cargo's or Poetry's, filed as the version reader files it (round 10, W3).
  const toml = tomlEcosystem(stated, deps);
  // A name filed under the project's main ecosystem only because the task names none is a guess:
  // it is checked in every ecosystem the project uses (checkNewPackages takes the worst answer).
  const others = stated ? [] : projectEcosystems(deps).filter((e) => e !== fallback);
  const guessed = new Set<CheckEcosystem>([fallback, ...others]);
  // A Python standard-library name is English, except one npm's popular list has in a project that does
  // not install from PyPI: "add uuid and electorn" in an npm project ended the list at `uuid` (r8, B1).
  const stdlib = (n: string) => PYTHON_STDLIB.has(n) && (guessed.has("PyPI") || !POPULAR.has(n));
  // Keyed by each ecosystem's own name rule: requirements' `zqx_tools` is the scan's `zqx-tools`, so the
  // project's own dependency was read as new and looked up a second time (fifth blind check, item 1).
  const haveKey = (ecosystem: CheckEcosystem, name: string) => `${ecosystem}\0${ecosystemKey(name, ecosystem)}`;
  const have = new Set(deps.map((d) => haveKey(d.ecosystem as CheckEcosystem, d.name)));
  const installedName = (name: string) => deps.some((d) => d.name.toLowerCase() === name.toLowerCase()) || installedGoModule(name, deps) !== null;
  const found: NewPackage[] = [];
  /** Where each (ecosystem, name) is in `found`: a list of thousands of names was quadratic (F-M3). */
  const foundAt = new Map<string, number>();
  const unreadWords: TaskItems["unreadWords"] = [];
  const bound: BoundVersion[] = [];
  const ignored: TaskSpan[] = [];
  const fixed: TaskItems["fixed"] = [];
  const foreign: TaskItems["foreign"] = [];
  const add =(name: string | null, ecosystem: CheckEcosystem, guess = false, weak = false, version: string | null = null, loose = false): NewPackage | null => {
    if (!name || have.has(haveKey(ecosystem, name)) || isManifestFile(name)) return null;
    // A guessed name the project already has, in any ecosystem or as a Go module's short name
    // ("install gin" with github.com/gin-gonic/gin in go.mod), is not new (blind audit round 4).
    if (guess && installedName(name)) return null;
    const alternatives = guess ? others.filter((e) => asName(name, e) !== null) : [];
    const at = foundAt.get(`${ecosystem}\0${name}`) ?? -1;
    if (at < 0) {
      foundAt.set(`${ecosystem}\0${name}`, found.length);
      found.push({
        name,
        ecosystem,
        ...(version ? { version } : {}),
        ...(alternatives.length > 0 ? { alternatives } : {}),
        ...(guess && !stated ? { guessed: true as const } : {}),
        ...(weak ? { weak: true as const } : {}),
        ...(weak && loose ? { loose: true as const } : {}),
      });
      return found[found.length - 1];
    }
    if (!weak) delete found[at].weak;
    if (!weak || !loose) delete found[at].loose;
    if (version && !found[at].version) found[at].version = version;
    return found[at];
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
  /** The version token `k` carries itself: `axios@0.21.0`, `requests==2.19.0`, `django>=2,<3`. */
  const inlineVersion = (k: number, ecosystem?: CheckEcosystem): string | null => {
    const token = raw[k].replace(/[.,;:)]+$/, "");
    const at = token.indexOf("@", 1);
    const spec = at > 0 ? token.slice(at + 1) : (/^[A-Za-z0-9][\w.-]*((?:===?|~=|>=|<=|!=|>|<)\S+)$/.exec(token)?.[1] ?? null);
    return spec && isVersionSpec(spec) ? taskVersionText(spec, ecosystem) : null;
  };
  /**
   * The version written after item `k` ("axios 0.21.0", "event-stream at version 3.3.6", "chalk to
   * 5.6.1"), and the token it is. A version with no dot ("ctx 2") is bound only after add and install,
   * where a number after a name is a release; elsewhere it is as often a count.
   */
  const versionAfter = (k: number, bareNumbers: boolean, ecosystem?: CheckEcosystem): { version: string; at: number } | null => {
    let v = k + 1;
    if (separatorAfter(k) !== null) return null;
    while (v < words.length && VERSION_LEADS.has(words[v]) && separatorAfter(v) === null) v++;
    if (v >= words.length) return null;
    const token = raw[v].replace(/[.,;:)]+$/, "");
    if (!isVersionSpec(token) || (!bareNumbers && !/\d\.(?:\d|x|\*)|[<>~^!=-]/i.test(token))) return null;
    return { version: taskVersionText(token, ecosystem), at: v };
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
      (LIST_WORDS.has(words[j]) ||
        isVersionSpec(words[j]) ||
        (VERSION_LEADS.has(words[j]) && words[j] !== "to") ||
        (asName(raw[j], fallback) !== null && !DESTINATION_PREPOSITIONS.has(words[j]) && words[j] !== "as"))
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
    return COMMON_WORDS.has(n) || stdlib(n) || (!NAME_SHAPED.test(n) && ENGLISH_ENDING.test(n));
  };
  /** A word that ends a list: a new clause, or another verb. */
  const endsList = (j: number) => j >= words.length || words[j] === "then" || CLAUSE_VERBS.has(words[j]) || IN_VERBS.has(words[j]) || ON_VERBS.has(words[j]);

  let truncated = false;
  for (let i = 0; i < words.length; i++) {
    if (found.length >= MAX_READ_PACKAGES) {
      truncated = true;
      break;
    }
    const word = words[i];
    // `npm install a b`, `pnpm add -D a`, `go get host/path`: every argument that is a name.
    const manager = Object.hasOwn(MANAGERS, word) ? MANAGERS[word] : undefined;
    let j = i + 1;
    if (manager && word === "uv" && words[j] === "pip") j++;
    if (manager && (manager.commands.has(words[j]) || (word === "uv" && words[j] === "install"))) {
      const ecosystem = manager.ecosystem;
      if (ecosystem === null) {
        // A registry this server does not read: every argument to the clause's end is named NOT CHECKED,
        // and none of it (a name, `-v 5.0.0`) is read as an npm package or version (round 10, W14).
        for (j++; j < words.length && !endsList(j); j++) {
          if (foreign.length >= MAX_READ_PACKAGES) {
            truncated = true;
            break;
          }
          foreign.push({ ...span(j), name: "", registry: manager.registry ?? word });
          if (!words[j].startsWith("-") && !isVersionSpec(words[j]) && !LIST_WORDS.has(words[j]) && words[j - 1] !== "-v" && words[j - 1] !== "--version") {
            const name = raw[j].replace(/[),.;:!?'"]+$/, "").replace(/(?:[=~<>!]=?|[:@]).*$/, "");
            if (/^[a-z0-9][\w./-]*$/i.test(name) && !NOT_A_NAME.has(name.toLowerCase())) foreign[foreign.length - 1].name = name;
          }
          if (separatorAfter(j) === "clause") break;
        }
        // The verb that ended the command is the next clause's ("gem install rails and add lodahs").
        i = j < words.length && endsList(j) ? j - 1 : j;
        continue;
      }
      const commandWord = word === "uv" && words[i + 1] === "pip" ? "pip" : word;
      /** The package the command named last: Cargo's `--vers` / `--version` names its version. */
      let lastAdded: NewPackage | null = null;
      for (j++; j < words.length; j++) {
        // At most MAX_READ_PACKAGES names, here too: `npm install p1 ... p30000` returned 30,012 (re-check, item 3).
        if (found.length >= MAX_READ_PACKAGES) {
          truncated = true;
          break;
        }
        // A shell or sentence separator ends the operands (`&& git push origin x` listed git, push, origin;
        // fourth blind check, item 2); a shell variable or expansion (`$X`, `%X%`, `${X}`) is never a name,
        // nor is a word with a colon inside (`--auth admin:hunter2` listed hunter2). A dash standing alone
        // is a dash between clauses (an em dash is folded to one).
        const before = task.slice(span(j - 1).end, starts[j]);
        const expands = /\$\(|\$\{?$/.test(before) || /%$/.test(before);
        if (expands) unreadWords.push({ shown: `${before.trim().slice(-2)}${raw[j].slice(0, 20)}`, reason: "not read: a shell expansion, whose value the task does not give" });
        if (/\$\(/.test(before) || (!before.startsWith("|") && OPERANDS_END.test(before)) || (raw[j] === "-" && /\s$/.test(before))) break;
        if (expands) continue;
        // The blank-delimited word this token is in: a word that starts with `-` is an option whatever follows
        // (`--_authToken`, `-_auth`, `--@scope:_authToken`, `--token:`; fifth blind check, item 2).
        let ws = starts[j];
        while (ws > 0 && !/\s/.test(task[ws - 1]) && starts[j] - ws < MAX_TASK_WORD) ws--;
        let we = starts[j];
        while (we < task.length && !/\s/.test(task[we]) && we - starts[j] < MAX_TASK_WORD) we++;
        if (task[ws] === "-") {
          // An option's value (`--tag next`, `-w packages/api`, `--prefix ./x`) is never a package (E2).
          // `--opt=value` is a value. After `--opt`, the next word is read as an operand only when the
          // option is known to take no value (`-D`, `-U`); after any other option it may be that option's
          // value, so it is not read, and is named as not read unless the option is known to take one
          // (re-check of the 2026-11-25 fixes, item 2). A long blank is a value the screen withheld.
          const flag = task.slice(ws, we).replace(/[.,;:)]+$/, "");
          // Past every token of the option's own word.
          while (j + 1 < raw.length && starts[j + 1] < we) j++;
          const gap = j + 1 < raw.length ? task.slice(we, starts[j + 1]) : "";
          // `cargo add hyper --vers 0.14.9`: the version of the crate before it, never a crate called "vers"
          // (third blind check, item 5).
          if (ecosystem === "crates.io" && (flag === "--vers" || flag === "--version") && lastAdded && j + 1 < raw.length && /^[ \t]{1,3}$/.test(gap) && isVersionSpec(raw[j + 1].replace(/[.,;:)]+$/, ""))) {
            const version = taskVersionText(raw[j + 1].replace(/[.,;:)]+$/, ""), ecosystem);
            lastAdded.version = version;
            bound.push({ name: lastAdded.name, version, ...span(j + 1) });
            j++;
            continue;
          }
          const glued = /^--?(?:vers|version)=/.test(flag) ? flag.slice(flag.indexOf("=") + 1) : null;
          if (ecosystem === "crates.io" && glued && lastAdded && isVersionSpec(glued.replace(/^=(?!=)/, ""))) {
            const version = taskVersionText(glued.replace(/^=(?!=)/, ""), ecosystem);
            lastAdded.version = version;
            bound.push({ name: lastAdded.name, version, start: we - glued.length, end: we });
            continue;
          }
          // The value may start with characters no token holds (`--prefix ./x`): the gap then ends inside its word.
          if (!flag.includes("=") && /^[ \t]{1,3}\S*$/.test(gap) && !isKnownSwitch(commandWord, flag) && task[we + gap.length - gap.trimStart().length] !== "-") {
            if (!optionTakesValue(commandWord, flag)) unreadWords.push({ shown: `the word after ${flag.slice(0, 40)}`, reason: "not read: that option may take it as its value (a value is never repeated: it may be a secret)" });
            let ve = starts[j + 1];
            while (ve < task.length && !/\s/.test(task[ve]) && ve - starts[j + 1] < MAX_TASK_WORD) ve++;
            while (j + 1 < raw.length && starts[j + 1] < ve) j++;
          }
          continue;
        }
        if (colonWord(task, starts[j])) {
          unreadWords.push({ shown: "a word with a colon inside", reason: "not read: a user and password or a host and port is no package name (it is never repeated: it may be a secret)" });
          continue;
        }
        // A path, a URL or a GitHub shorthand is never a registry name (the screen names it).
        // The rest of a constraint (`x@^4.0.0||<text>`) is no operand: what follows `|` belongs to the spec before it.
        if (/\|\s*$/.test(task.slice(span(j - 1).end, starts[j]))) continue;
        // Judged on its whole blank-delimited word: a token may start after a `./` or `~/` no token holds.
        let wordStart = starts[j];
        while (wordStart > 0 && !/\s/.test(task[wordStart - 1]) && starts[j] - wordStart < 8) wordStart--;
        if (pathLikeOperand(task.slice(wordStart, span(j).end), ecosystem)) {
          if (separatorAfter(j) === "clause") break;
          continue;
        }
        // A scoped npm name is lower case by npm's rule: one with capitals (`@x/aB3dE9fG`) is no package name,
        // and is never lower-cased into one (third blind check).
        if (ecosystem === "npm" && raw[j].startsWith("@") && /[A-Z]/.test(raw[j].replace(/(?<=.)@.*$/, ""))) {
          unreadWords.push({ shown: `${raw[j].slice(0, 4)}...`, reason: "not read: npm package names are lower case, so this is no package name" });
          if (separatorAfter(j) === "clause") break;
          continue;
        }
        // The first argument that is not a name ends the command; one the project already has does not.
        const name = asName(raw[j], ecosystem);
        if (!name) break;
        // The command fixes the ecosystem for the version reader too (round 10, W14).
        fixed.push({ ...span(j), ecosystem });
        // After `@`: a version or range; for npm a dist-tag kept as written (`zustand@next`); anything else
        // (`zustand@<uuid>`) is a version that could not be read, never replaced by latest (third blind check, item 5).
        const after = raw[j].indexOf("@", 1) > 0 ? raw[j].replace(/[.,;:)]+$/, "").slice(raw[j].indexOf("@", 1) + 1) : "";
        const inline = inlineVersion(j, ecosystem);
        const tag = !inline && ecosystem === "npm" && NPM_TAG.test(after) && !/^[a-f\d]{7,}$/i.test(after) ? after : null;
        const pkg = add(name, ecosystem, false, false, inline ?? tag);
        if (pkg && after && !inline && !tag && !/^(?:latest|\*)$/i.test(after)) pkg.versionUnread = true;
        lastAdded = pkg;
        if (separatorAfter(j) === "clause") break;
      }
      i = j - 1;
      continue;
    }
    const installing = INSTALL_VERBS.has(word);
    // "bring in ctx", "pull in left-pad", "depend on event-stream": the verb is the pair.
    const bringingIn =
      (IN_VERBS.has(word) && (words[i + 1] === "in" || words[i + 1] === "into")) || (ON_VERBS.has(word) && (words[i + 1] === "on" || words[i + 1] === "upon"));
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
      if (end + 1 < words.length && isVersionSpec(words[end + 1])) continue;
      swappedFromDependency = words.slice(c, end).some((w) => installedName(w) || PACKAGE_WORDS.has(w) || quoted.has(w));
      // The version of what goes out is not one the task writes.
      for (let o = c; o < end; o++) if (isVersionSpec(words[o])) ignored.push(span(o));
      swapped = true;
      i = end;
    } else if (!installing && !bringingIn && !ADD_VERBS.has(word)) continue;
    // A number after a name is a release after add and install; after "use" or "need" it may be a count.
    const bareNumbers = installing || word.startsWith("add") || ON_VERBS.has(word);
    /** Past the articles and adjectives before an item: where its first word is, or null when the list ended. */
    const itemStart = (from: number): { at: number; skipped: number; saidPackage: boolean } | null => {
      let n = from;
      if (words[n] === "also") n++;
      if (endsList(n)) return null;
      let skipped = 0;
      let saidPackage = false;
      // "install the private @acme scope": an adjective there is no package (blind audit round 4).
      while (n < words.length && (FILLERS.has(words[n]) || PACKAGE_WORDS.has(words[n]) || (NOT_A_PACKAGE_ADJECTIVES.has(words[n]) && !quoted.has(words[n])))) {
        if (PACKAGE_WORDS.has(words[n])) saidPackage = true;
        n++;
        skipped++;
      }
      return n < words.length ? { at: n, skipped, saidPackage } : null;
    };
    /**
     * Where the item after the one at `from` starts, when a list separator follows within the clause:
     * a list item that is prose ("add uuid and electorn", "add a logger, lodahs", "add json and ctx")
     * is passed over and the list goes on (r8, B1: it ended the list, and electorn, lodahs and ctx were
     * never checked). Null when the clause ends first.
     */
    const nextItem = (from: number, word: boolean): number | null => {
      for (let n = from; n < words.length && n - from < MAX_SKIPPED_ITEM; n++) {
        if (n > from && LIST_WORDS.has(words[n])) return n + 1;
        if (n > from && endsList(n)) return null;
        const sep = separatorAfter(n);
        if (sep === "clause") return null;
        if (sep === "list") return LIST_WORDS.has(words[n + 1] ?? "") ? n + 2 : n + 1;
        // `install a b c` lists without separators: after an English word, the next word is the next item
        // (what is not a name at all ends the command, as it always did).
        if (installing) return word ? n + 1 : null;
      }
      return null;
    };
    // The verb, then only articles and package words, then the list of items.
    let start = itemStart(i + 1);
    let afterSeparator = false;
    let proseSeen = false;
    /** This list's packages, and whether anything marked each as one. */
    const listed: Array<{ pkg: NewPackage; strong: boolean }> = [];
    let listedStrong = false;
    while (start) {
      if (found.length >= MAX_READ_PACKAGES) {
        truncated = true;
        break;
      }
      const k: number = start.at;
      const skipped = start.skipped;
      const tomlEntry = isTomlEntry(task, starts[k]);
      // A comparator glued to the name (`requests~=2.31`, `flask<2.2.5`) is pip's syntax: npm writes
      // `name@range` and Cargo `name = "range"`. Read as PyPI, not as the project's guess, by both readers:
      // in an npm project "add requests~=2.31" offered npm's deprecated `request` as the fix, and "add
      // flask<2.2.5" listed npm's flask proceed beside PyPI's avoid (round 10, W14). A name the project
      // already has in another ecosystem, and no PyPI copy, stays that one's.
      const pepEcosystem = (): CheckEcosystem | null => {
        if (tomlEntry || raw[k].includes("@") || !PEP440_INLINE.test(raw[k])) return null;
        if (stated) return stated;
        const bare = raw[k].replace(/(?:[=~<>!]=?).*$/, "").toLowerCase();
        const other = deps.find((d) => d.name.toLowerCase() === bare && d.ecosystem !== "PyPI");
        return other && !have.has(haveKey("PyPI", bare)) ? null : "PyPI";
      };
      const pep = pepEcosystem();
      const itemEcosystem: CheckEcosystem = tomlEntry ? toml : (pep ?? fallback);
      const name = asName(raw[k], itemEcosystem);
      const skip = (word = true) => {
        const n = nextItem(k, word);
        start = n === null ? null : itemStart(n);
        afterSeparator = true;
      };
      if (!name) {
        proseSeen = true;
        skip(false);
        continue;
      }
      const inline = inlineVersion(k, itemEcosystem);
      const after = inline ? null : versionAfter(k, bareNumbers, itemEcosystem);
      const version = inline ?? after?.version ?? null;
      let next = after ? after.at + 1 : k + 1;
      const isQuoted = quoted.has(words[k]) || quoted.has(name.toLowerCase());
      // A popular npm name, or a near miss of one, is a package whatever the wording: "add lodahs" came
      // back safe_to_delegate without a packaging word (blind audit round 3, B3). The list is bundled,
      // so an unknown word is never sent anywhere for it.
      // A near-miss of a popular PyPI project too, in a project that installs from PyPI: "add colourama",
      // "add jeIlyfish" and "add python3-dateutil" read as prose (black-box audit of 60c9edc, 2026-11-14).
      // After a prose item, a popular name that is also an everyday word is prose too: "add logging and
      // retry around the upload" is no npm `retry`.
      // A popular name that is also an everyday word ("debug", "ms") is a package where the list shape
      // says so: leading an add list, closed by a comma ("add debug, then wire it into the logger"), or
      // a whole item of a list that already names a package for certain ("add debug, chalk and ms": only
      // chalk was read; pre-publish round 10, W3). Followed by more words ("add debug output") it is prose.
      const itemEnds = separatorAfter(k) !== null || endsList(k + 1) || LIST_WORDS.has(words[k + 1] ?? "");
      // Leading, only when what follows the comma is no English list: the clause ends ("then ..."), a
      // pronoun goes on about it ("it is tiny"), or a package follows ("chalk"); "add open, close and
      // save buttons" names no package.
      const afterComma = (() => {
        let n = k + 1;
        if (LIST_WORDS.has(words[n] ?? "")) n++;
        const w = words[n];
        if (w === undefined || endsList(n) || NOT_A_NAME.has(w)) return true;
        return (POPULAR.has(w) && !COMMON_WORDS.has(w) && !ENGLISH.has(w)) || nearMissOf(w) !== null || NAME_SHAPED.test(w);
      })();
      const leadsList = skipped === 0 && !afterSeparator && !proseSeen && listed.length === 0 && separatorAfter(k) === "list" && afterComma;
      const inPackageList = afterSeparator && !proseSeen && listedStrong && itemEnds;
      const commonPackage = !ENGLISH_TASK_WORDS.has(name) && (leadsList || inPackageList);
      const known =
        !(proseSeen && ENGLISH_TASK_WORDS.has(name)) &&
        (!COMMON_WORDS.has(name) || commonPackage) &&
        !ENGLISH.has(name) &&
        !stdlib(name) &&
        ((guessed.has("npm") && (POPULAR.has(name) || nearMissOf(name) !== null)) || (guessed.has("PyPI") && closestPopularPypi(name) !== null));
      // "add ctx to requirements.txt", "add extrahtml to the dependencies": the destination says it is a package
      // (both came back safe_to_delegate in a Python project; round 5 audits). A manifest's own fields are not.
      const manifest = goesInManifest(next) && !MANIFEST_FIELDS.has(name.toLowerCase());
      // A version written after it says it is a package: "pull in node-ipc 10.1.1".
      const strong = start.saidPackage || PACKAGE_WORDS.has(words[next] ?? "") || isQuoted || known || manifest || version !== null || (swapped && swappedFromDependency);
      // After an article, a popular name followed by more prose names a thing, not a package: "add a retry
      // with backoff to the client" checked npm's `retry`, "add a progress bar" `progress` (round 10, W14).
      // A version, a manifest, backticks, a packaging word or a near-miss of a popular name still say it is one.
      const articleProse =
        ARTICLES.has(words[k - 1] ?? "") &&
        !afterSeparator &&
        version === null &&
        !isQuoted &&
        !manifest &&
        !start.saidPackage &&
        !NAME_SHAPED.test(name) &&
        separatorAfter(k) === null &&
        k + 1 < words.length &&
        !endsList(k + 1) &&
        !LIST_WORDS.has(words[k + 1]) &&
        !PACKAGE_WORDS.has(words[k + 1]) &&
        nearMissOf(name) === null &&
        !(guessed.has("PyPI") && closestPopularPypi(name) !== null);
      if (articleProse) {
        proseSeen = true;
        skip();
        continue;
      }
      if (!strong) {
        // A bare "add X" (or "install X", "replace A with X") reads X as a package for any plausible
        // name ("add ctx", "add flatmap-stream" came back safe_to_delegate; round 5 audits), unless it
        // is English ("install steps", "add routes"). After an article only a name-shaped word counts
        // ("add a footer" is prose, "add the logger-libs" is not), unless a list separator came before
        // it: an item of a list is always a candidate (r8, B1).
        // A word before an English noun, after an article, names the thing, not a package: "install the
        // git hooks" judged npm's `git` (avoid) (r8).
        const modifier = skipped > 0 && separatorAfter(k) === null && ENGLISH.has(words[k + 1] ?? "") && !PACKAGE_WORDS.has(words[k + 1] ?? "");
        const prose = english(name, !installing) || (proseSeen && ENGLISH_TASK_WORDS.has(name)) || modifier || (!installing && !afterSeparator && skipped > 0 && !NAME_SHAPED.test(name));
        if (prose) {
          proseSeen = true;
          skip();
          continue;
        }
      }
      // A comparator the task did not tie to PyPI by name or command is a guess, not a fixed ecosystem:
      // "add event-stream==3.3.6" in an npm project was judged on PyPI alone (no such name: unknown),
      // hiding npm's malware. npm is judged too with the same constraint, and the worst answer stands; in a
      // project that uses PyPI, only when PyPI has no such name or release (pre-publish round 10, W16).
      const pepAlternatives: CheckEcosystem[] = pep === "PyPI" && !stated && asName(raw[k].replace(/(?:[=~<>!]=?).*$/, ""), "npm") !== null ? ["npm"] : [];
      const pepFallbackOnly = pepAlternatives.length > 0 && projectEcosystems(deps).includes("PyPI");
      if (pep) fixed.push({ ...span(k), ecosystem: pep, ...(pepAlternatives.length > 0 ? { alternatives: pepAlternatives } : {}), ...(pepFallbackOnly ? { fallbackOnly: true as const } : {}) });
      const pkg = tomlEntry || pep ? add(name, itemEcosystem, false, false, version) : add(name, fallback, true, !strong && !installing, version, LOOSE_VERBS.has(word));
      if (pkg && pep && pepAlternatives.length > 0) {
        pkg.alternatives = [...new Set([...(pkg.alternatives ?? []), ...pepAlternatives])];
        if (pepFallbackOnly) pkg.fallbackOnly = true;
        else pkg.preferOnTie = "npm";
      }
      if (pkg) listed.push({ pkg, strong });
      if (pkg && strong) listedStrong = true;
      if (after) bound.push({ name: raw[k].replace(/[.,;:)]+$/, ""), version: after.version, ...span(after.at) });
      // "the lodahs package, and expres": a package word may close the item.
      if (PACKAGE_WORDS.has(words[next] ?? "") && separatorAfter(next - 1) === null) next++;
      // The next item: after a comma, "and", "&", "+" or "plus"; a clause break or a new verb ends the list
      // ("install omega-flag-beta and set lodash ..." added a package named `set`).
      const separator = separatorAfter(next - 1);
      if (separator === "clause") break;
      const joined = LIST_WORDS.has(words[next] ?? "");
      if (joined) next++;
      else if (separator !== "list" && !installing) break; // "add zqx omega risk": one name, unless installing.
      start = itemStart(next);
      afterSeparator = joined || separator === "list";
    }
    // A list that names a package for certain names packages: its other items are not prose to drop
    // when they come back clean ("add zod, valibot, superstruct, io-ts and is-even" listed only zod and
    // the other popular names; r8).
    if (listed.length > 1 && listed.some((l) => l.strong)) {
      for (const l of listed) {
        delete l.pkg.weak;
        delete l.pkg.loose;
      }
    }
  }
  return { packages: found, bound, ignored, fixed, foreign, unreadWords, ...(truncated ? { truncated: true as const } : {}) };
}

export type NameCheckLive = Pick<LiveIntelligence, "isEnabled"> &
  Partial<Pick<LiveIntelligence, "getReleaseSources" | "getFixPathSources" | "queryAdvisories" | "lookupPrivateReason" | "privateReason">>;

/** The popular package a name resembles in its ecosystem's bundled list, when there is one. */
function nearMissName(name: string, ecosystem: CheckEcosystem): string | null {
  if (ecosystem === "npm") return nearMissOf(name)?.of ?? null;
  if (ecosystem === "PyPI") return closestPopularPypi(name);
  return null;
}

function unchecked({ alternatives: _alternatives, weak: _weak, guessed: _guessed, loose: _loose, closed: _closed, fallbackOnly: _fallbackOnly, preferOnTie: _preferOnTie, versionUnread: _versionUnread, ...pkg }: NewPackage, why: string): NewPackageFinding {
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
const notFound = (f: NewPackageFinding) => nameNotFound(f) || (Boolean(f.version) && !f.malicious && f.verdict === "unknown" && NO_SUCH_RELEASE.test(f.reason));
/** Findings whose "review" is only a near-miss of the name in that ecosystem, and those whose name check is clean (nameOnlyReview, nameClean). */
const NAME_ONLY = new WeakSet<NewPackageFinding>();
const NAME_CLEAN = new WeakSet<NewPackageFinding>();

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
  /** Work within what is left of the budget; null past it. */
  const inBudget = async <T>(work: Promise<T>): Promise<T | null> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        work,
        new Promise<null>((resolve) => {
          timer = setTimeout(() => resolve(null), Math.max(0, deadline - Date.now()));
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
  /**
   * One dependency_check run within the budget. A constraint goes in the form dependency_check reads
   * for that ecosystem: npm's `>=1.2.0 <1.2.6` for the task's `>= 1.2.0, < 1.2.6` (checkableSpec; round 10, W3).
   */
  const run = (list: NewPackage[]) =>
    inBudget(
      executeDependencyCheck(
        null,
        { items: list.map((p) => ({ ecosystem: p.ecosystem, package: p.name, to: p.version ? (checkableSpec(p.ecosystem, p.version) ?? p.version) : "latest" })) },
        liveIntel as LiveIntelligence,
        now ? { now } : {},
      ),
    );
  type Answer = NonNullable<Awaited<ReturnType<typeof run>>>;
  const finding = (pkg: NewPackage, r: Answer["results"][number] | undefined): NewPackageFinding => {
    const { alternatives: _alternatives, weak: _weak, guessed: _guessed, loose: _loose, closed: _closed, fallbackOnly: _fallbackOnly, preferOnTie: _preferOnTie, versionUnread: _versionUnread, ...p } = pkg;
    if (!r) return unchecked(p, "no answer");
    const advisories = r.signals.find((s) => s.id === "advisories")?.value as { malicious_package?: { did_you_mean?: string | null } } | null | undefined;
    const nameCheck = r.signals.find((s) => s.id === "name_check");
    const nearMiss = (nameCheck?.value as { near_miss_of?: string } | undefined)?.near_miss_of;
    const out: NewPackageFinding = {
      ...p,
      verdict: r.verdict,
      latest: !p.version && r.to !== "latest" ? r.to : null,
      reason: r.reason,
      malicious: Boolean(advisories?.malicious_package),
      did_you_mean: advisories?.malicious_package?.did_you_mean ?? nearMiss ?? nearMissName(p.name, p.ecosystem),
      name_finding: nameCheck?.effect === "avoid" || nameCheck?.effect === "review" ? nameCheck.effect : null,
    };
    if (nameOnlyReview(r.verdict, r.signals)) NAME_ONLY.add(out);
    if (nameClean(r.signals)) NAME_CLEAN.add(out);
    return out;
  };
  /** A loose word's name-level answer (briefing-task-name-check.ts) as a finding. */
  const nameFinding = (q: NewPackage, a: NameOnlyAnswer | undefined): NewPackageFinding => {
    if (!a) return unchecked(q, "no answer");
    if (a.kind === "unchecked") return unchecked(q, a.why);
    const base = { ...q, latest: null, reason: a.reason, name_finding: null };
    if (a.kind === "malware") return { ...base, verdict: "avoid", malicious: true, did_you_mean: a.found.didYouMean ?? nearMissName(q.name, q.ecosystem) };
    return { ...base, verdict: a.kind === "clean" ? "proceed" : "unknown", malicious: false, did_you_mean: nearMissName(q.name, q.ecosystem) };
  };
  // Every ecosystem a guessed name may be in, in one run: the lookups go out together, so a
  // second ecosystem costs no more wall time than the first, within the same budget. Not one that
  // cannot read the constraint the task writes: dependency_check refuses the whole run over it, and
  // "add lodash-es 1.2.3 - 1.4.0 and ctx" lost ctx's malware to PyPI's refusal (round 10, W3).
  const items = packages.flatMap((p, i) =>
    [p.ecosystem, ...(p.alternatives ?? [])]
      .filter((ecosystem) => !p.version || checkableSpec(ecosystem, p.version) !== null)
      .map((ecosystem) => ({ i, q: { name: p.name, ecosystem, ...(p.version ? { version: p.version } : {}) } as NewPackage })),
  );
  // A loose word ("use blueprints") is checked by its name alone, one advisory-list read: the full
  // run also judged its newest release, a second OSV.dev lookup of the name whose answer is dropped
  // for a loose word anyway (round 10, W3). A near-miss of a popular name gets the full run (name_check).
  const byName = (x: { i: number; q: NewPackage }) => packages[x.i].loose === true && nearMissName(x.q.name, x.q.ecosystem) === null;
  const full = items.filter((x) => !byName(x));
  const named = items.filter(byName);
  try {
    const [answer, names] = await Promise.all([
      full.length > 0 ? run(full.map((x) => x.q)) : Promise.resolve({ results: [] as Answer["results"] }),
      named.length > 0 ? inBudget(Promise.all(named.map((x) => checkNameOnly(liveIntel, x.q.ecosystem, x.q.name)))) : Promise.resolve([] as NameOnlyAnswer[]),
    ]);
    if (!answer) return packages.map((p) => unchecked(p, "the lookups did not finish in time"));
    const answerFor = (x: { i: number; q: NewPackage }) =>
      byName(x) ? (names ? nameFinding(x.q, names[named.indexOf(x)]) : unchecked(x.q, "the lookups did not finish in time")) : finding(x.q, answer.results[full.indexOf(x)]);
    const answered = packages.map((_p, i) => items.filter((x) => x.i === i).map(answerFor));
    // No lookup outside the gate: the "rustdecimal fallback" looked a name its own registry did not have up in
    // every other ecosystem, which is exactly what a private dependency gets (fifth blind check, item 1).
    const out = packages.map((p, i) => {
      let answers = answered[i];
      // A fallback ecosystem counts only when the task's own one has no such name or release (W16).
      const own = p.fallbackOnly ? answers.find((f) => f.ecosystem === p.ecosystem) : undefined;
      if (own && !notFound(own)) answers = [own];
      // A namesake's near-miss "review" does not outrank a real answer from an ecosystem that has the
      // release and knows the name; malware or avoid from any ecosystem that has it still wins (W16).
      if (answers.some((f) => !notFound(f) && !NAME_ONLY.has(f) && NAME_CLEAN.has(f) && f.verdict !== "unknown")) {
        const kept = answers.filter((f) => !NAME_ONLY.has(f));
        if (kept.length > 0) answers = kept;
      }
      if (answers.length === 0) return unchecked(p, `dependency_check reads no ${p.ecosystem} version or constraint in "${p.version ?? ""}"`);
      if (answers.length === 1) return answers[0];
      // The worst answer; when no ecosystem has the name, the one that knows what it resembles.
      // On a tie the project's own ecosystem is reported: "add event-stream<=3.3.6" in an npm-only project
      // named PyPI's namesake release 1.6.3, which npm does not have (pre-publish round 10, final check).
      const worst = answers.reduce((a, b) => (badness(b) > badness(a) || (badness(b) === badness(a) && p.preferOnTie !== undefined && b.ecosystem === p.preferOnTie) ? b : a));
      const pick = notFound(worst) ? (answers.find((f) => f.did_you_mean) ?? worst) : worst;
      const also = answers.filter((f) => f !== pick).map((f) => ({ ecosystem: f.ecosystem, verdict: notFound(f) ? ("not_found" as const) : f.verdict, ...(f.malicious ? { malicious: true as const } : {}) }));
      return { ...pick, also_checked: also };
    });
    /**
     * A weak name no registry has and no malware record covers was prose; a clean one adds nothing to
     * say; a loose one ("use blueprints") stands only on a finding about the name, or a check that
     * could not run.
     */
    const prose = (f: NewPackageFinding, i: number) =>
      packages[i].weak === true && !f.malicious && f.name_finding === null && (f.verdict === "proceed" || notFound(f) || (packages[i].loose === true && f.verdict !== "unknown"));
    return out.filter((f, i) => !prose(f, i));
  } catch (error) {
    return packages.map((p) => unchecked(p, `the check failed: ${String(error instanceof Error ? error.message : error).slice(0, 120)}`));
  }
}
