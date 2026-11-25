// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know and the version a task names (black-box re-run of 96c16d2, 2026-11-14):
 * "add lodash 4.17.20 to package.json" came back safe_to_delegate, with lodash judged at `latest`
 * (4.18.1) instead of the 4.17.20 the task writes, which four advisories affect; "pin axios to
 * 0.21.1" did not see axios at all. The versions a task names are read here in every common form
 * and judged by dependency_check itself (the same engine), at that exact version or constraint:
 *
 *   name@1.2.3 / name@^1.2 (npm, Go `module@v1.2.3`), name==1.2.3 / name~=3.1 / name>=2,<3 (PyPI),
 *   "name to 1.2.3", "name from 1.0 to 1.2", "pin name 1.2.3", "add name 4.17.20",
 *   "pull in name 1.2.3", "replace A with name 1.2.3", "add a 1.0, b 2.0 & c" (each version bound to
 *   the name before it by the clause reader, briefing-new-packages.ts readTaskItems), and manifest
 *   entries (`"name": "^1.2"`, `"alias": "npm:name@1.2.3"`, `name = "1.2"`, `name==1.2`).
 *
 * A named version that is not `proceed` keeps the briefing from safe_to_delegate.
 */

import type { LiveIntelligence } from "../live/index.js";
import type { CheckEcosystem } from "../live/release-metadata.js";
import type { ResolvedDependency } from "../live/types.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import { POPULAR_PYPI } from "../live/popular-pypi.js";
import { asName, MAX_READ_PACKAGES, nameClean, nameOnlyReview, NO_SUCH_RELEASE, projectEcosystems, proseEcosystem, readTaskItems, statedEcosystem, taskVersionText, tomlEcosystem, type NameCheckLive } from "./briefing-new-packages.js";
import {
  checkableSpec,
  ENGLISH_TASK_WORDS,
  installedGoModule,
  isManifestFile,
  isTomlEntry,
  isVersionSpec,
  normalizePypiName,
  normalizeVersionSyntax,
  NOT_A_PACKAGE_ADJECTIVES,
  SPEC_JOINERS,
  specText,
} from "./briefing-names.js";
import { COMMON_WORDS } from "./briefing-task-scope.js";
import { boundWords, screenedOut, screenTask } from "./briefing-task-screen.js";
import { executeDependencyCheck } from "./dependency-check.js";

export interface RequestedVersion {
  name: string;
  ecosystem: CheckEcosystem;
  /** The version or constraint the task names, as written. */
  to: string;
  /** The installed version, when the project has exactly one copy of it. */
  from?: string;
  /** Other ecosystems the project uses, tried when the guessed one has no such release. */
  alternatives?: CheckEcosystem[];
  /** `alternatives` count only when `ecosystem` has no such name or release (a pip-style comparator in a project that uses PyPI; pre-publish round 10, W16). */
  fallbackOnly?: true;
  /** On equal answers, report this ecosystem (the project's own), not the comparator's guess. */
  preferOnTie?: CheckEcosystem;
}

export interface RequestedVersionFinding extends RequestedVersion {
  /** dependency_check's verdict for exactly `to`. */
  verdict: "proceed" | "wait" | "review" | "avoid" | "unknown";
  /** The release a constraint resolved to (equal to `to` for an exact version). */
  resolved: string | null;
  reason: string;
  /** The safe releases dependency_check names, when it names any. */
  safe?: { smallest: string | null; newest: string | null };
  malicious: boolean;
  /** Critical advisories that affect exactly this release (event-stream 3.3.6: GHSA-mh6f-8j2x-4483). */
  critical?: string[];
}

/** How many named versions a briefing checks; past it the rest are NOT CHECKED, by name (what-should-i-know.ts). */
export const MAX_REQUESTED = 8;
const CHECK_BUDGET_MS = 10_000;
/**
 * A version or constraint as tasks write them: 4.17.20, v1.2.3, ^1.2, ~2.0.1, >=2, 7.x, 1.2.*,
 * ==3.3.6, prereleases with dashes (1.4.44-liberty-2) and Go pseudo-versions
 * (v0.0.0-20210226172049-e18ecbb05110).
 */
const VERSIONISH = { test: (token: string) => isVersionSpec(token) };
/** A dotted version (or a pseudo-version): a token the briefing must tie to a package or say it could not. */
const DOTTED = /^(?:={1,3}|[~^]|[<>]=?)?v?\d+\.(?:\d+|x|\*)/i;
/** Words that come before a package name and are never one. */
const VERBS = new Set([
  "add", "adding", "install", "installing", "pin", "pinning", "bump", "bumping", "upgrade", "upgrading", "update", "updating", "downgrade", "downgrading",
  "move", "moving", "set", "setting", "use", "using", "change", "changing", "lock", "require", "version", "release", "it", "them", "everything", "all",
  "dependency", "package", "roll", "revert", "restore", "write", "put", "get", "and", "or", "with", "then", "also", "depend", "depends", "depending",
]);
/**
 * Words a version is never tied past: another verb or a list word starts another item ("add nanoid and
 * bump x to 1.2"). Other words that are no package ("by one patch to 0.7.29") are passed over (r8:
 * the 0.7.29 was judged as a package called `patch`).
 */
const TIE_BOUNDARIES = new Set([
  "add", "adding", "install", "installing", "pin", "pinning", "bump", "bumping", "upgrade", "upgrading", "update", "updating", "downgrade", "downgrading",
  "move", "moving", "set", "setting", "use", "using", "change", "changing", "lock", "require", "roll", "revert", "restore", "write", "put", "get",
  "and", "or", "with", "then", "also", "plus", "&", "+", "replace", "swap", "remove", "drop", "fix", "need", "depend", "depends",
]);
/** Words between a package and its version: "lodash to 4.17.20", "event-stream at version 3.3.6", "lodash: 4.18.1 -> 4.17.20". */
const CONNECTORS = new Set([
  "to", "at", "version", "versions", "v", "=", "==", "===", ":", "->", "=>", ">", "→", "is", "be", "back", "down", "up", "from", "of", "on", "into",
  "the", "a", "an", "its", "package", "packages", "dependency", "dependencies", "dep", "crate", "module", "library", "lib", "release", "pinned", "exactly",
]);
/** Runtimes and toolchains a task gives a version to ("node 20", "python 3.12", "go 1.22"): not packages to judge. */
const RUNTIMES = new Set([
  "node", "nodejs", "node.js", "python", "python3", "py", "go", "golang", "rust", "rustc", "cargo", "npm", "pnpm", "yarn", "bun", "deno", "java", "jdk",
  "typescript", "ts", "ubuntu", "debian", "alpine", "macos", "windows", "ios", "android", "es", "ecmascript", "pip", "msrv", "edition", "toolchain",
  "rust-version", "requires-python", "engines",
]);
/** Verbs that change a dependency: a task with one is about dependencies. */
const DEPENDENCY_VERBS = new Set([
  "add", "adding", "install", "installing", "pin", "pinning", "bump", "bumping", "upgrade", "upgrading", "update", "updating", "downgrade", "downgrading",
  "set", "setting", "change", "changing", "roll", "revert", "require", "lock", "use", "using", "depend", "depends", "depending",
]);
/**
 * A manifest, lockfile or packaging word: the task is about dependencies. It once held literal
 * backspace characters for its word boundaries and so matched no task: "lodash in package.json to
 * 4.17.20" left 4.17.20 unread when lodash was not installed (round 5 audits).
 */
const DEPENDENCY_TASK = /\b(?:package(?:-lock)?\.json|cargo\.(?:toml|lock)|requirements(?:-[\w-]+)?\.txt|pyproject\.toml|poetry\.lock|uv\.lock|pipfile|go\.(?:mod|sum)|pnpm-lock\.yaml|yarn\.lock|dependenc(?:y|ies)|packages?|librar(?:y|ies)|crates?|npm|pnpm|yarn|pip|pypi|cargo)\b/i;
const PYPI_SPEC = /^([A-Za-z0-9][A-Za-z0-9._-]*)((?:===?|~=|>=|<=|!=|>|<)[^\s]+)$/;
/**
 * Verbs that only ever mean a dependency change. "set", "change" and "use" also set config values
 * ("Set the request timeout to 30" was judged as `timeout@30`; blind audit round 4), so a bare
 * number after a name nobody installs is a version only in a task with one of these, or a
 * manifest or packaging word.
 */
const PACKAGE_VERBS = new Set([
  "add", "adding", "install", "installing", "pin", "pinning", "bump", "bumping", "upgrade", "upgrading", "update", "updating", "downgrade", "downgrading",
  "depend", "depends", "depending",
]);
/** A version with no dot (30, v2, ^5): in prose it is as often a setting as a release. */
const BARE_NUMBER = /^(?:={1,3}|[~^]|[<>]=?)?v?\d+$/i;
/**
 * Setting nouns a task gives a number to ("timeout to 30", "port 8080", "retries to 5"): in prose
 * they are never a package nobody installs. A package really called that is named as `timeout@1.0`,
 * quoted, or installed.
 */
const SETTING_NOUNS = new Set([
  "timeout", "timeouts", "ttl", "port", "ports", "limit", "limits", "retry", "retries", "attempts", "count", "size", "max", "min", "maximum", "minimum",
  "interval", "delay", "threshold", "concurrency", "workers", "threads", "width", "height", "depth", "level", "ratio", "rate", "percent", "percentage",
  "seconds", "secs", "milliseconds", "minutes", "mins", "hours", "days", "kb", "mb", "gb", "memory", "buffer", "batch", "pool", "capacity", "quota",
  "budget", "offset", "page", "pagesize", "backoff", "duration", "precision", "scale", "weight", "priority", "verbosity", "loglevel", "value", "number",
  "length", "default", "replicas", "instances", "connections", "deadline", "expiry", "lifetime", "maxage", "age", "temperature", "tokens",
]);
/** A bare npm scope with no package after its slash: "@acme". */
const BARE_SCOPE = /^@[a-z0-9~][\w.~-]*$/i;
/** Words after a bare scope that name the group of its packages ("the @acme scope", "@acme packages"). */
const GROUP_NOUNS = new Set(["scope", "scopes", "org", "orgs", "organisation", "organization", "namespace", "packages", "package", "libraries", "libs", "modules", "family", "workspace", "monorepo"]);
/** Words that put a manifest after a package ("lodash in package.json to 4.17.20"). */
const FILE_PREPOSITIONS = new Set(["in", "inside", "within", "into", "of", "from"]);

const GO_HOST_PATH = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\//i;
/** The part after `@` in an email address ("ping ops@example.com"): not a version. */
const EMAIL_DOMAIN = /^[a-z][\w-]*(?:\.[\w-]+)*\.[a-z]{2,}$/i;

/** A token as a name: quotes, brackets, trailing punctuation and a possessive `'s` removed. */
function cleanToken(t: string): string {
  // `"node":` loses its colon and both quotes: a manifest key read as `node"` was taken for a package.
  return t
    .replace(/[`'"),.;:]+$/, "")
    .replace(/^[`'"(]+/, "")
    .replace(/'s$/i, "");
}

function nameFor(
  token: string,
  deps: readonly ResolvedDependency[],
  fallback: CheckEcosystem,
  explicit = false,
  stated: CheckEcosystem | null = null,
): { name: string; ecosystem: CheckEcosystem; guessed?: true } | null {
  const bare = cleanToken(token).replace(/[!?]+$/, "");
  const lower = bare.toLowerCase();
  if (VERBS.has(lower) || CONNECTORS.has(lower) || RUNTIMES.has(lower) || isManifestFile(bare)) return null;
  const norm = (s: string) => s.toLowerCase().replace(/[-_.]+/g, "-");
  const checkable = (d: ResolvedDependency) => d.ecosystem === "npm" || d.ecosystem === "crates.io" || d.ecosystem === "PyPI" || d.ecosystem === "Go";
  const same = deps.filter((d) => checkable(d) && (d.name.toLowerCase() === lower || (d.ecosystem === "PyPI" && norm(d.name) === norm(bare))));
  // An installed dependency of any ecosystem beats a guess; the one the task names, when it names one.
  const installed = same.find((d) => d.ecosystem === stated) ?? same[0];
  if (installed) return { name: installed.name, ecosystem: installed.ecosystem as CheckEcosystem };
  // A short name for an installed Go module ("gin"), unless the task names another ecosystem.
  if (!stated || stated === "Go") {
    const go = installedGoModule(bare, deps);
    if (go) return { name: go, ecosystem: "Go" };
  }
  // A host-led path ("github.com/...") is a Go module whatever the project mostly holds, and a
  // malformed one ("github.com/gin-gonic/gin/") is passed on as written: dependency_check says it is
  // not a path the go command accepts, never a clean answer (pre-publish audit B1).
  if (GO_HOST_PATH.test(bare)) {
    const go = asName(bare, "Go");
    if (go) return { name: go, ecosystem: "Go" };
  }
  // An English word is no package in prose; written as `colors@1.4.44` or `name==1.0` it is one.
  if (!explicit && (COMMON_WORDS.has(lower) || NOT_A_PACKAGE_ADJECTIVES.has(lower))) return null;
  const name = asName(bare, fallback);
  return name ? { name, ecosystem: fallback, guessed: true } : null;
}

/** What the briefing read from a task: the (package, version) pairs, and dotted versions it could tie to nothing. */
export interface TaskVersions {
  requested: RequestedVersion[];
  /** Versions the task writes that no package (or runtime) could be read for: never safe to delegate on. */
  unread: string[];
  /** Packages a manager this server does not read installs (`gem install rails`): named NOT CHECKED (round 10, W14). */
  foreign?: string[];
  /**
   * Words the briefing withheld from the task before reading it (a credential shape, a package the
   * task's own command takes from a private registry, git or a path, an over-long word), each as it
   * is shown (redacted) and why: never looked up, never sent (briefing-task-screen.ts).
   */
  withheld?: TaskWordWithheld[];
}

/** A word of the task the briefing did not look up: how it is shown, and why. */
export interface TaskWordWithheld {
  shown: string;
  reason: string;
}

/** The (package, version) pairs a task names, in the order named (uncapped: the briefing checks MAX_REQUESTED and names the rest NOT CHECKED). */
export function detectRequestedVersions(task: string, deps: readonly ResolvedDependency[]): RequestedVersion[] {
  return readTaskVersions(task, deps).requested;
}

/**
 * Every version-like token in the task is tied to the nearest word before it that can be a package,
 * over connector words ("to", "at", "version", "==", "->", "back", "the ... package"), or after it in
 * "version X of name". The last version tied to a package is its target ("from 1.0 to 1.2",
 * "4.18.1 -> 4.17.20"). Wording the parser was not written for used to drop the version and judge
 * latest instead ("add event-stream at version 3.3.6" came back safe_to_delegate; blind audit round
 * 3, B3); now a dotted version tied to nothing is reported as unread, which keeps the briefing from
 * safe_to_delegate.
 */
/** Tokens of a (normalized) task: arrows, and words that keep package and version punctuation (a joined constraint whole). */
const TOKEN = new RegExp("(?:->|=>|→)|[@A-Za-z0-9`'\"(^~<>=][\\w./@*=<>~^!`'\"+:" + SPEC_JOINERS + "-]*", "g");
/** Words that join two items of a list. */
const LIST_JOINERS = new Set(["and", "plus"]);
/** Words between a package and its version that are no package ("by one patch to 0.7.29"). */
const STOP_WORDS = new Set(["one", "two", "three", "a", "an", "minor", "major", "patch", "level", "levels", "step", "steps", "notch", "bit", "release", "releases", "line"]);
/** Words that only lead to a version: "debug to 4.4.2", "chalk at version 5.6.1". */
const VERSION_LEADS = new Set(["to", "at", "version", "v", "=", "==", "===", ":", "->", "=>", "→"]);
const POPULAR = new Set<string>([...POPULAR_NPM, ...POPULAR_PYPI.map(normalizePypiName)]);
/**
 * A name on the bundled popular lists (npm's or PyPI's): it is sent to a registry with a version written
 * right after it even in a task with no dependency word or verb ("chalk 5.6.1/debug 4.4.2", the September
 * 2025 hijacked releases, left both versions unread; pre-publish round 10, W3). The lists are offline, so
 * a name off them (an internal codename) is still never sent on a guess.
 */
const popularName = (lower: string) => POPULAR.has(lower) || POPULAR.has(normalizePypiName(lower));

export function readTaskVersions(task: string, deps: readonly ResolvedDependency[]): TaskVersions {
  // Credentials, URLs, over-long words and whatever the task takes from a private registry, an index,
  // git, a path or a URL are blanked before anything is read (briefing-task-screen.ts; audit 2026-11-25, E1/E2/F-M3).
  const screen = screenTask(task);
  const read = readVersionsOf(screen.text, deps);
  const all = readTaskItems(normalizeVersionSyntax(screen.text), deps);
  const items = all.packages;
  const notes: string[] = [];
  if (all.truncated) notes.push(`every package after the first ${MAX_READ_PACKAGES} the task names (not read: the task names more packages than a briefing reads)`);
  const withheld: TaskWordWithheld[] = [];
  const holdWord = (shown: string, reason: string) => {
    if (!withheld.some((w) => w.shown === shown && w.reason === reason)) withheld.push({ shown, reason });
  };
  const requested = read.requested.filter((r) => {
    const why = screenedOut(screen, r.name, [r.ecosystem, ...(r.alternatives ?? [])]);
    if (why && !screen.names.has(r.name.toLowerCase())) holdWord(r.name, why);
    return why === null;
  });
  for (const p of items) {
    const why = screenedOut(screen, p.name, [p.ecosystem, ...(p.alternatives ?? [])]);
    if (why && !screen.names.has(p.name.toLowerCase())) holdWord(p.name, why);
  }
  // A credential, URL or address is named (redacted) only where a reader would have taken a name from it:
  // a name the unscreened task gives that the screened one does not, inside that span.
  const conditional = screen.withheld.filter((w) => !w.always);
  let lostTo: typeof conditional = [];
  if (conditional.length > 0) {
    const plain = boundWords(task);
    const before = new Set([...readTaskItems(normalizeVersionSyntax(plain), deps).packages.map((p) => p.name.toLowerCase()), ...readVersionsOf(plain, deps).requested.map((r) => r.name.toLowerCase())]);
    const after = new Set([...items.map((p) => p.name.toLowerCase()), ...read.requested.map((r) => r.name.toLowerCase())]);
    const lost = [...before].filter((n) => !after.has(n) && n.length > 1);
    lostTo = conditional.filter((w) => {
      const span = task.slice(w.start, w.end).toLowerCase();
      return lost.some((n) => span.includes(n));
    });
  }
  for (const w of [...screen.withheld.filter((x) => x.always), ...lostTo].sort((a, b) => a.start - b.start)) holdWord(w.label, w.why);
  const foreign = [...new Set([...(read.foreign ?? []), ...notes])];
  return { requested, unread: read.unread, ...(foreign.length > 0 ? { foreign } : {}), ...(withheld.length > 0 ? { withheld } : {}) };
}

/** The versions a task names, read from text the screen has already blanked. */
function readVersionsOf(task: string, deps: readonly ResolvedDependency[]): TaskVersions {
  task = normalizeVersionSyntax(task);
  // The versions the clause reader bound to a name ("pull in node-ipc 10.1.1", "replace request with
  // axios 0.21.0", "add lodash 4.17.21 and crossenv 6.1.1"), and the versions of what a swap takes out.
  const { bound, ignored, fixed, foreign } = readTaskItems(task, deps);
  const tokens = [...task.matchAll(TOKEN)];
  const raw = tokens.map((t) => t[0]);
  const at0 = (i: number) => tokens[i].index ?? 0;
  const overlaps = (i: number, s: { start: number; end: number }) => at0(i) < s.end && s.start < at0(i) + raw[i].length;
  const words = raw.map((t) => cleanToken(t).toLowerCase());
  /** The text between token `k` and the next one. */
  const gapAfter = (k: number) => task.slice(at0(k) + raw[k].length, k + 1 < raw.length ? at0(k + 1) : task.length);
  const stated = statedEcosystem(words);
  const fallback = proseEcosystem(words, deps);
  // The ecosystem of a bare name nobody installs is only a guess when the task names none and the
  // project uses several: the other ones are tried if the guess has no such release (a mixed npm +
  // Python repository read "add event-stream version 3.3.6" as PyPI; blind audit replay 2026-11-14).
  const others = stated ? [] : projectEcosystems(deps).filter((e) => e !== fallback);
  const aboutDependencies = DEPENDENCY_TASK.test(task) || words.some((w) => DEPENDENCY_VERBS.has(w));
  // Only packaging words or a dependency-only verb make a bare number a release ("set the timeout to 30" is a setting).
  const aboutPackages = DEPENDENCY_TASK.test(task) || words.some((w) => PACKAGE_VERBS.has(w));
  const found = new Map<string, RequestedVersion & { order: number }>();
  const unread: string[] = [];
  let order = 0;
  const add = (
    who: { name: string; ecosystem: CheckEcosystem; guessed?: true; fixed?: true; alternatives?: CheckEcosystem[]; fallbackOnly?: true; preferOnTie?: CheckEcosystem } | null,
    version: string,
    guess = false,
    another = false,
  ): boolean => {
    if (!who || !version) return false;
    const to = taskVersionText(version, who.ecosystem);
    // A pairing the task leaves open ("a, b to x, y, z") keeps every candidate version of a package.
    const key = `${who.ecosystem}\0${who.name}${another ? `\0${to}` : ""}`;
    const copies = deps.filter((d) => d.ecosystem === who.ecosystem && d.name === who.name && d.version);
    const versions = [...new Set(copies.map((d) => d.version!))];
    // A comparator-inferred PyPI reading carries its own fallback, npm (pre-publish round 10, W16).
    const alternatives = who.fixed ? (who.alternatives ?? []) : guess && who.guessed && who.ecosystem === fallback ? others.filter((e) => asName(who.name, e) !== null) : [];
    // A later version for the same package is its target ("from 1.0 to 1.2", "1.0 -> 1.2").
    found.set(key, {
      name: who.name,
      ecosystem: who.ecosystem,
      to,
      ...(versions.length === 1 && versions[0] !== to ? { from: versions[0] } : {}),
      ...(alternatives.length > 0 ? { alternatives } : {}),
      ...(alternatives.length > 0 && who.fallbackOnly ? { fallbackOnly: true as const } : {}),
      ...(alternatives.length > 0 && who.preferOnTie ? { preferOnTie: who.preferOnTie } : {}),
      order: found.get(key)?.order ?? order++,
    });
    return true;
  };

  // "upgrade chalk, debug to 5.6.1 and 4.4.2": a list of names, then "to", then a list of versions
  // (r8: neither version was read). The same number of each pairs them in order; any other count
  // leaves the pairing open, so every pairing is checked and the worst stands.
  const paired = new Set<number>();
  /** A list joiner between token `k` and the one after it: a comma, or the next token is "and" / "&". */
  const joinedAfter = (k: number) => /[,&+]/.test(gapAfter(k));
  for (let i = 1; i + 1 < raw.length; i++) {
    if (words[i] !== "to" && words[i] !== "at") continue;
    // The versions after the connector.
    const versions: number[] = [];
    let v = i + 1;
    while (v < raw.length && VERSIONISH.test(cleanToken(raw[v])) && !ignored.some((s) => overlaps(v, s))) {
      versions.push(v);
      if (joinedAfter(v)) v += 1;
      else if (v + 2 < raw.length && LIST_JOINERS.has(words[v + 1])) v += 2;
      else break;
    }
    if (versions.length === 0 || !versions.every((x) => DOTTED.test(cleanToken(raw[x])))) continue;
    // The names before it, back to a verb.
    const names: Array<{ name: string; ecosystem: CheckEcosystem; guessed?: true }> = [];
    let k = i - 1;
    while (k >= 0) {
      const w = words[k];
      if (TIE_BOUNDARIES.has(w) || RUNTIMES.has(w) || SETTING_NOUNS.has(w) || ENGLISH_TASK_WORDS.has(w)) break;
      // Explicit: the list shape says these are packages ("debug" is a common word, not here).
      const who = nameFor(raw[k], deps, fallback, true, stated);
      if (!who) break;
      names.unshift(who);
      if (k > 0 && LIST_JOINERS.has(words[k - 1])) k -= 2;
      else if (k > 0 && joinedAfter(k - 1)) k -= 1;
      else break;
    }
    // One version is the nearest name's alone ("add nanoid and ua-parser-js at 0.7.29" is ua-parser-js's).
    if (versions.length < 2 || names.length === 0 || (!aboutDependencies && names.some((n) => n.guessed))) continue;
    const text = versions.map((x) => cleanToken(raw[x]));
    const pairs: Array<[number, number]> =
      text.length === names.length ? names.map((_n, a) => [a, a]) : names.flatMap((_n, a) => text.map((_t, b) => [a, b] as [number, number]));
    const open = text.length !== names.length;
    for (const [a, b] of pairs) add(names[a], text[b], true, open);
    for (const x of versions) paired.add(x);
  }

  /**
   * The name in token `i` when a manager command or a PEP 440 specifier fixed its ecosystem: only that
   * ecosystem's installed copy, never the project's guess (round 10, W14: `poetry add pyyaml@5.3` was
   * judged as npm's pyyaml in an npm project).
   */
  const fixedName = (i: number, name: string) => {
    const span = fixed.find((s) => overlaps(i, s));
    const eco = span?.ecosystem;
    if (!eco) return undefined;
    const who = nameFor(name, deps.filter((d) => d.ecosystem === eco), eco, true, eco);
    if (!who) return null;
    // A comparator-inferred PyPI reading is also judged on npm (W16); an explicit manager command is not.
    const npmName = span.alternatives?.includes("npm") ? asName(name, "npm") : null;
    return {
      ...who,
      fixed: true as const,
      ...(npmName === who.name ? { alternatives: span.alternatives, ...(span.fallbackOnly ? { fallbackOnly: true as const } : { preferOnTie: "npm" as const }) } : {}),
    };
  };
  for (let i = 0; i < raw.length; i++) {
    if (paired.has(i)) continue;
    const token = cleanToken(raw[i]);
    if (ignored.some((s) => overlaps(i, s))) continue;
    // A manager whose registry is not read (`gem install rails -v 5.0.0`): its packages are named NOT CHECKED.
    if (foreign.some((s) => overlaps(i, s))) continue;
    const pair = bound.find((b) => overlaps(i, b));
    if (pair) {
      // Bound by the clause reader: this version is that name's, whatever stands nearer to it.
      const own = fixedName(i, pair.name);
      if (!add(own !== undefined ? own : nameFor(pair.name, deps, fallback, true, stated), pair.version, true)) unread.push(pair.version);
      continue;
    }
    // name@version (npm, `cargo add`, Go module@v1.2.3); a scoped npm name keeps its leading @.
    const at = token.indexOf("@", 1);
    if (at > 0) {
      const name = token.slice(0, at);
      const after = token.slice(at + 1);
      // A TOML manifest entry (`smallvec = { version = "..." }`) is the clause reader's crates.io or PyPI
      // package, never npm's (pre-publish round 10, W3: one package listed as avoid and as unknown).
      const tomlEntry = isTomlEntry(task, at0(i) + raw[i].indexOf(token));
      const eco: CheckEcosystem = GO_HOST_PATH.test(name) ? "Go" : tomlEntry ? tomlEcosystem(stated, deps) : stated === "crates.io" ? "crates.io" : "npm";
      const own = fixedName(i, name);
      if (VERSIONISH.test(after) || after.toLowerCase() === "latest") {
        if (!add(own !== undefined ? own : nameFor(name, deps, eco, true, tomlEntry ? eco : stated), after.toLowerCase() === "latest" ? "latest" : after) && DOTTED.test(after)) unread.push(specText(token));
        continue;
      }
      // Whatever else follows `name@` (a dist-tag, a branch, a tarball, a version in a form not read
      // here) is a version this briefing could not judge: unread, never dropped (`lodash@"4.17.20"`
      // came back safe_to_delegate; round 5 audits). An email address is not a package.
      if (after && !EMAIL_DOMAIN.test(after) && (aboutDependencies || eco === "Go" || /^[\d^~<>=v"'`]/i.test(after)) && asName(name, eco) !== null) unread.push(specText(token));
      continue;
    }
    // name==1.2.3, name~=3.1, name>=2,<3 (PyPI): the whole specifier is one constraint.
    const spec = PYPI_SPEC.exec(token);
    if (spec) {
      const own = fixedName(i, spec[1]);
      if (!add(own !== undefined ? own : nameFor(spec[1], deps, "PyPI", true, stated), spec[2])) unread.push(specText(token));
      continue;
    }
    if (!VERSIONISH.test(token)) continue;
    // A version: the package before it in the same item, over connector words, other versions and
    // words that are no package ("bump ua-parser-js by one patch to 0.7.29"); never past another verb,
    // a list word or a comma (r8: "patch" was judged as the package).
    let tied = false;
    for (let k = i - 1, steps = 0; k >= 0 && steps < 6; k--, steps++) {
      const w = words[k];
      if (/[,;]/.test(gapAfter(k))) break;
      if (CONNECTORS.has(w) || VERSIONISH.test(cleanToken(raw[k]))) continue;
      // "lodash in package.json to 4.17.20": the file the version goes in, and its preposition, are skipped.
      if (isManifestFile(raw[k])) continue;
      if (FILE_PREPOSITIONS.has(w) && k + 1 < i && isManifestFile(raw[k + 1])) continue;
      if (RUNTIMES.has(w)) {
        tied = true; // "node 20", "python 3.12": a runtime, not a package to judge
        break;
      }
      if (TIE_BOUNDARIES.has(w)) break;
      // "upgrade the @acme scope to 2.0": the word after a bare scope names the group, not a package
      // (it was read as a package called `scope`; blind audit round 4). The version is unread.
      if (GROUP_NOUNS.has(w) && k > 0 && BARE_SCOPE.test(cleanToken(raw[k - 1]))) break;
      // A name nobody installs is read from prose only in a task about dependencies, or when it is
      // quoted: "apply the 2.4.1 hotfix" is not a package called `apply`, and an internal codename in
      // a task is never sent to a registry on a guess. The version is then unread instead.
      const quotedName = /^[`'"]/.test(raw[k]);
      // A name right before a dotted version is written as one ("debug 4.4.2"), common word or not.
      const adjacent = k === i - 1 && DOTTED.test(token);
      // A popular name before a dotted version, over words that only lead to it ("debug to 4.4.2"), is
      // one too: "bump chalk to 5.6.1 / debug to 4.4.2" passed over `debug` (a common word) and tied 4.4.2
      // to chalk (pre-publish round 10, W3).
      const popularLead = DOTTED.test(token) && popularName(w) && words.slice(k + 1, i).every((x) => VERSION_LEADS.has(x));
      const who = nameFor(raw[k], deps, fallback, quotedName || adjacent || popularLead, stated);
      if (who?.guessed && !quotedName && SETTING_NOUNS.has(w)) {
        tied = true; // "timeout to 30", "port 8080": a setting, not a package to judge
        break;
      }
      // A word that is no package, or English prose ("one", "patch", "release"): passed over.
      if (!who || (who.guessed && !quotedName && (ENGLISH_TASK_WORDS.has(w) || STOP_WORDS.has(w)))) continue;
      const bareNumberOk = !who.guessed || quotedName || !BARE_NUMBER.test(token) || aboutPackages;
      tied = (!who.guessed || aboutDependencies || quotedName || popularLead || (adjacent && popularName(w))) && bareNumberOk && add(who, token, true);
      break;
    }
    // "version 1.2.3 of name"
    if (!tied && aboutDependencies && words[i - 1] === "version" && words[i + 1] === "of" && raw[i + 2]) tied = add(nameFor(raw[i + 2], deps, fallback, false, stated), token, true);
    if (!tied && DOTTED.test(token)) unread.push(specText(token));
  }
  const requested = [...found.values()].sort((a, b) => a.order - b.order).map(({ order: _order, ...r }) => r);
  const notRead = foreign.filter((f) => f.name).map((f) => `${f.name} (${f.registry}: not read by this server)`);
  return { requested, unread: [...new Set(unread)], ...(notRead.length > 0 ? { foreign: [...new Set(notRead)] } : {}) };
}

/**
 * dependency_check's verdict for each named version, within the briefing's budget. Offline or past
 * the budget a version is `unknown`: never read as safe.
 */
export async function checkRequestedVersions(liveIntel: NameCheckLive | null, requested: RequestedVersion[], now?: Date): Promise<RequestedVersionFinding[]> {
  if (requested.length === 0) return [];
  const unknown = ({ alternatives: _a, fallbackOnly: _f, preferOnTie: _p, ...r }: RequestedVersion, why: string): RequestedVersionFinding => ({
    ...r,
    verdict: "unknown",
    resolved: null,
    reason: `${r.name} ${r.to} could not be checked (${why}). Call dependency_check on it before writing it.`,
    malicious: false,
  });
  if (!liveIntel || !liveIntel.isEnabled()) return requested.map((r) => unknown(r, "live lookups are disabled"));
  if (!liveIntel.getReleaseSources || !liveIntel.getFixPathSources || !liveIntel.queryAdvisories) {
    return requested.map((r) => unknown(r, "the registry lookups are not available in this session"));
  }
  const deadline = Date.now() + CHECK_BUDGET_MS;
  /** One dependency_check run within what is left of the budget; null past it. */
  const run = async (list: RequestedVersion[]) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        executeDependencyCheck(
          null,
          // In the form dependency_check reads for that ecosystem (briefing-names.ts checkableSpec; round 10, W3).
          { items: list.map((r) => ({ ecosystem: r.ecosystem, package: r.name, to: checkableSpec(r.ecosystem, r.to) ?? r.to, ...(r.from ? { from: r.from } : {}) })) },
          liveIntel as LiveIntelligence,
          now ? { now } : {},
        ),
        new Promise<null>((resolve) => {
          timer = setTimeout(() => resolve(null), Math.max(0, deadline - Date.now()));
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
  type Answer = NonNullable<Awaited<ReturnType<typeof run>>>;
  const finding = (r: RequestedVersion, item: Answer["results"][number] | undefined): RequestedVersionFinding => {
    const { alternatives: _alternatives, fallbackOnly: _fallbackOnly, preferOnTie: _preferOnTie, ...own } = r;
    if (!item) return unknown(own, "no answer");
    const advisories = item.signals.find((s) => s.id === "advisories")?.value as { malicious_package?: unknown; critical_affecting_to?: string[] } | null | undefined;
    const rc = item.range_check;
    const out: RequestedVersionFinding = {
      ...own,
      verdict: item.verdict,
      resolved: item.to,
      reason: item.reason,
      ...(rc ? { safe: { smallest: rc.smallest_safe_upgrade ?? rc.smallest_safe_in_range, newest: rc.newest_safe_in_range } } : {}),
      malicious: Boolean(advisories?.malicious_package),
      ...(advisories?.critical_affecting_to?.length ? { critical: advisories.critical_affecting_to } : {}),
    };
    if (nameOnlyReview(item.verdict, item.signals)) nameOnly.add(out);
    else if (item.verdict !== "unknown" && nameClean(item.signals)) real.add(out);
    return out;
  };
  /** A namesake's near-miss review, and an answer about a release the ecosystem has and a name it knows (W16). */
  const nameOnly = new WeakSet<RequestedVersionFinding>();
  const real = new WeakSet<RequestedVersionFinding>();
  // No release matching the version (or no such name) is not an answer for it: "No published,
  // non-withdrawn release of rsa matches 4.7" on npm outranked PyPI's proceed (pre-publish round 10, W16).
  const unpublished = (item: Answer["results"][number] | undefined) => Boolean(item && item.verdict === "unknown" && NO_SUCH_RELEASE.test(item.reason));
  // dependency_check refuses a whole call over one constraint it cannot read: that one is unknown, said,
  // and the rest are still checked; an ecosystem tried on a guess that cannot read it is not tried
  // (pre-publish round 10, W3).
  const plan = requested.map((r): RequestedVersion | null => {
    const ecosystems = [r.ecosystem, ...(r.alternatives ?? [])].filter((e) => checkableSpec(e, r.to) !== null);
    if (ecosystems.length === 0) return null;
    const [ecosystem, ...alternatives] = ecosystems;
    return { ...r, ecosystem, alternatives: alternatives.length > 0 ? alternatives : undefined };
  });
  const asked = plan.filter((r): r is RequestedVersion => r !== null);
  try {
    const answer = asked.length > 0 ? await run(asked) : { results: [] as Answer["results"] };
    if (!answer) return requested.map((r) => unknown(r, "the lookups did not finish in time"));
    /** dependency_check's answer for requested[i], when it was asked. */
    const results = plan.map((r) => (r ? answer.results[asked.indexOf(r)] : undefined));
    const out = requested.map((r, i) => (plan[i] ? finding(plan[i]!, results[i]) : unknown(r, `dependency_check reads no ${r.ecosystem} version or constraint in "${r.to}"`)));
    // A guessed ecosystem: the project's other ecosystems too, in one more run, and the worst answer of
    // those that publish the release stands. Only the first ecosystem that had it used to be kept, so
    // npm's flask "proceed" could stand beside PyPI's "avoid" for one name (pre-publish round 10, W14).
    const retries = plan.flatMap((r, i) => (r ? (r.alternatives ?? []).map((ecosystem) => ({ i, r: { ...r, ecosystem, alternatives: undefined } })) : []));
    if (retries.length > 0) {
      const again = await run(retries.map((x) => x.r)).catch(() => null);
      if (again) {
        for (const i of new Set(retries.map((x) => x.i))) {
          const own = unpublished(results[i]) ? [] : [out[i]];
          // A fallback counts only when the task's own ecosystem has no such name or release (W16).
          const more = plan[i]?.fallbackOnly && own.length > 0 ? [] : retries.flatMap((x, k) => (x.i === i && again.results[k] && !unpublished(again.results[k]) ? [finding(x.r, again.results[k])] : []));
          let answers = [...own, ...more];
          // A namesake's near-miss review never outranks a real answer; malware and avoid still win (W16).
          if (answers.some((a) => real.has(a))) answers = answers.filter((a) => !nameOnly.has(a));
          // On a tie the project's own ecosystem is reported, not the comparator's guess (final check).
          const prefer = plan[i]?.preferOnTie;
          if (answers.length > 0) out[i] = answers.reduce((a, b) => (worse(b) > worse(a) || (worse(b) === worse(a) && prefer !== undefined && b.ecosystem === prefer) ? b : a));
        }
      }
    }
    return out;
  } catch (error) {
    // dependency_check refuses a malformed item (a version it cannot read): unknown, said.
    return requested.map((r) => unknown(r, `the check failed: ${String(error instanceof Error ? error.message : error).slice(0, 120)}`));
  }
}

/** How bad a named version's answer is: a malicious release, a critical advisory, then the verdict. */
function worse(f: RequestedVersionFinding): number {
  if (f.malicious) return 7;
  if (f.verdict === "avoid" && (f.critical?.length ?? 0) > 0) return 6;
  return { avoid: 5, review: 4, unknown: 3, wait: 2, proceed: 1 }[f.verdict];
}

/** How a finding reads in the delegation reason. */
export function sayRequested(r: RequestedVersionFinding): string {
  const safe = r.safe && (r.safe.smallest || r.safe.newest) ? `; safe: ${[r.safe.smallest, r.safe.newest].filter(Boolean).join(" to ")}` : "";
  return `${r.name} ${r.to} is ${r.verdict} by dependency_check${safe}`;
}
