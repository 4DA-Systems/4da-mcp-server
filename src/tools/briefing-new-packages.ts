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
 * - the same verb and a bare name only when the name is in code quotes ("add `expres`"), or the
 *   task speaks of packaging somewhere ("add expres to package.json") and the name is on the
 *   popular list or a near-miss of it. "Install" always names a package. A bare everyday word
 *   after "add" ("add routes to the app") is not read as a package: `routes` is one letter from
 *   `router`, and a briefing that cried typo-squat at it would be wrong far more often than right.
 *   dependency_check still judges the name when the agent asks before writing it.
 * A name the project already depends on is the task-scope module's, not this one's.
 */

import type { LiveIntelligence } from "../live/index.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import type { CheckEcosystem } from "../live/release-metadata.js";
import type { ResolvedDependency } from "../live/types.js";
import { isNpmPackageName } from "../untrusted-text.js";
import { COMMON_WORDS } from "./briefing-task-scope.js";
import { executeDependencyCheck } from "./dependency-check.js";
import { nearMissOf } from "./dependency-check-nearmiss.js";

export interface NewPackage {
  name: string;
  ecosystem: CheckEcosystem;
}

/** What the name check found for one package a task adds. */
export interface NewPackageFinding extends NewPackage {
  /** dependency_check's verdict for the package at `latest`; `unknown` when it could not be checked. */
  verdict: "proceed" | "wait" | "review" | "avoid" | "unknown";
  /** The release `latest` resolved to, when one did. */
  latest: string | null;
  /** dependency_check's reason, in this server's words. */
  reason: string;
  /** The name itself is malware (npm took it down, or a malicious-package record covers it). */
  malicious: boolean;
  /** The popular package the name is a near-miss of, when it is one. */
  did_you_mean: string | null;
  /** What the name check itself said, apart from the release's own signals: avoid, review, or null. */
  name_finding: "avoid" | "review" | null;
}

const POPULAR = new Set(POPULAR_NPM);
const MAX_NEW_PACKAGES = 3;
/** How long a briefing waits for the name checks. Past it they are unchecked, never clean. */
const NAME_CHECK_BUDGET_MS = 10_000;

const ADD_VERBS = new Set(["add", "adding", "adds", "use", "using", "adopt", "adopting", "introduce", "introducing", "import", "importing", "require", "requiring", "try", "trying"]);
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
/** A manifest or a packaging word anywhere in the task: it is about dependencies. */
const PACKAGING = /\b(?:package\.json|cargo\.toml|requirements(?:-[\w-]+)?\.txt|pyproject\.toml|go\.mod|dependenc(?:y|ies)|devdependenc(?:y|ies)|packages?|librar(?:y|ies)|crates?|npm|pnpm|yarn|pip|pypi)\b/i;
const VERSION_ONLY = /^v?\d+(?:\.(?:\d+|x|\*))*(?:[-+][\w.]+)?$/i;

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
      return /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:\/[\w.~-]+)+$/i.test(name) ? name : null;
  }
}

/** The ecosystem prose names ("the crate", "from PyPI"), else the project's most common, else npm. */
export function proseEcosystem(words: string[], deps: readonly ResolvedDependency[]): CheckEcosystem {
  const has = (...w: string[]) => w.some((x) => words.includes(x));
  if (has("crate", "crates", "cargo", "crates.io", "rust")) return "crates.io";
  if (has("pip", "pip3", "pypi", "python", "poetry", "uv", "requirements.txt", "pyproject.toml")) return "PyPI";
  if (has("npm", "pnpm", "yarn", "bun", "node", "nodejs", "package.json")) return "npm";
  const counts = new Map<CheckEcosystem, number>();
  for (const d of deps) {
    if (d.ecosystem === "npm" || d.ecosystem === "crates.io" || d.ecosystem === "PyPI" || d.ecosystem === "Go") counts.set(d.ecosystem, (counts.get(d.ecosystem) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "npm";
}

/**
 * The packages a task is about to add that the project does not already have (see the module
 * comment for what counts as naming one). At most three, in the order named.
 */
export function detectNewPackages(task: string, deps: readonly ResolvedDependency[]): NewPackage[] {
  const quoted = new Set((task.match(/`([^`\s]+)`/g) ?? []).map((q) => q.slice(1, -1).toLowerCase()));
  // Word-ish tokens that keep package punctuation; a leading "-" marks a command flag.
  const raw = task.match(/(?:--?[A-Za-z][\w-]*)|[@A-Za-z0-9][\w./@*=<>~^!-]*/g) ?? [];
  const words = raw.map((t) => t.replace(/[.,;:)]+$/, "").toLowerCase());
  const fallback = proseEcosystem(words, deps);
  const packaging = PACKAGING.test(task);
  const have = new Set(deps.map((d) => `${d.ecosystem}\0${d.name.toLowerCase()}`));
  const found: NewPackage[] = [];
  const add = (name: string | null, ecosystem: CheckEcosystem) => {
    if (!name || have.has(`${ecosystem}\0${name.toLowerCase()}`)) return false;
    if (!found.some((f) => f.ecosystem === ecosystem && f.name === name)) found.push({ name, ecosystem });
    return true;
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
        add(name, manager.ecosystem);
      }
      i = j - 1;
      continue;
    }
    const installing = INSTALL_VERBS.has(word);
    if (!installing && !ADD_VERBS.has(word)) continue;
    // The verb, then only articles and package words, then the name.
    let k = i + 1;
    let saidPackage = false;
    while (k < words.length && (FILLERS.has(words[k]) || PACKAGE_WORDS.has(words[k]))) {
      if (PACKAGE_WORDS.has(words[k])) saidPackage = true;
      k++;
    }
    for (; k < words.length; k++) {
      const name = asName(raw[k], fallback);
      if (!name) break;
      const after = words[k + 1];
      const isQuoted = quoted.has(words[k]) || quoted.has(name.toLowerCase());
      const known = packaging && fallback === "npm" && !COMMON_WORDS.has(name) && (POPULAR.has(name) || nearMissOf(name) !== null);
      if (!(saidPackage || PACKAGE_WORDS.has(after) || installing || isQuoted || known)) break;
      add(name, fallback);
      // "lodahs and expres", "lodahs, expres": the next name continues the list.
      if (after === "and" || after === "&" || after === "plus") k++;
      else if (PACKAGE_WORDS.has(after)) break;
    }
  }
  return found.slice(0, MAX_NEW_PACKAGES);
}

export type NameCheckLive = Pick<LiveIntelligence, "isEnabled"> & Partial<Pick<LiveIntelligence, "getReleaseSources" | "getFixPathSources" | "queryAdvisories">>;

function unchecked(pkg: NewPackage, why: string): NewPackageFinding {
  return {
    ...pkg,
    verdict: "unknown",
    latest: null,
    reason: `${pkg.name} could not be checked (${why}). Call dependency_check on it before adding it.`,
    malicious: false,
    did_you_mean: pkg.ecosystem === "npm" ? (nearMissOf(pkg.name)?.of ?? null) : null,
    name_finding: null,
  };
}

/**
 * dependency_check's answer for each package at `latest`, within the briefing's budget. Offline,
 * without the live layer, or past the budget, a package is `unknown`: never read as safe.
 */
export async function checkNewPackages(liveIntel: NameCheckLive | null, packages: NewPackage[], now?: Date): Promise<NewPackageFinding[]> {
  if (packages.length === 0) return [];
  if (!liveIntel || !liveIntel.isEnabled()) return packages.map((p) => unchecked(p, "live lookups are disabled"));
  if (!liveIntel.getReleaseSources || !liveIntel.getFixPathSources || !liveIntel.queryAdvisories) {
    return packages.map((p) => unchecked(p, "the registry lookups are not available in this session"));
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const answer = await Promise.race([
      executeDependencyCheck(null, { items: packages.map((p) => ({ ecosystem: p.ecosystem, package: p.name, to: "latest" })) }, liveIntel as LiveIntelligence, now ? { now } : {}),
      new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), NAME_CHECK_BUDGET_MS);
      }),
    ]);
    if (!answer) return packages.map((p) => unchecked(p, "the lookups did not finish in time"));
    return packages.map((p, i) => {
      const r = answer.results[i];
      if (!r) return unchecked(p, "no answer");
      const advisories = r.signals.find((s) => s.id === "advisories")?.value as { malicious_package?: { did_you_mean?: string | null } } | null | undefined;
      const nameCheck = r.signals.find((s) => s.id === "name_check");
      const nearMiss = (nameCheck?.value as { near_miss_of?: string } | undefined)?.near_miss_of;
      return {
        ...p,
        verdict: r.verdict,
        latest: r.to !== "latest" ? r.to : null,
        reason: r.reason,
        malicious: Boolean(advisories?.malicious_package),
        did_you_mean: advisories?.malicious_package?.did_you_mean ?? nearMiss ?? (p.ecosystem === "npm" ? (nearMissOf(p.name)?.of ?? null) : null),
        name_finding: nameCheck?.effect === "avoid" || nameCheck?.effect === "review" ? nameCheck.effect : null,
      };
    });
  } catch (error) {
    return packages.map((p) => unchecked(p, `the check failed: ${String(error instanceof Error ? error.message : error).slice(0, 120)}`));
  } finally {
    if (timer) clearTimeout(timer);
  }
}
