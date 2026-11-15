// SPDX-License-Identifier: Apache-2.0
/**
 * Every independently-locked project under a root, for standalone scanning.
 *
 * A repository root is often not where its lockfiles live: 4DA keeps
 * `src-tauri/Cargo.lock`, `relay/Cargo.lock`, `site/pnpm-lock.yaml` beside a
 * root `pnpm-lock.yaml`. Standalone mode used to read the root directory only,
 * so `npx @4da/mcp-server` started at the repo root never scanned the Rust
 * code at all (measured 2026-10-02: 0 of src-tauri's 791 crates). The desktop
 * app does not have this problem — it records each dependency's own manifest
 * directory — so this is the standalone counterpart of that inventory.
 *
 * A directory joins when it holds a lockfile (or go.mod / a requirements
 * file, which carry exact versions themselves). Workspace members that share
 * their root's lockfile are covered by the root.
 *
 * WHAT IS NOT READ IS ALWAYS SAID (2026-11-11). A lockfile is what is
 * installed, whatever .gitignore says about committing it, so the rule is
 * "label, never suppress":
 * - a lockfile that .gitignore lists, in an ordinary directory, is scanned
 *   (a project whose .gitignore named `package-lock.json` read "5
 *   dependencies, 0 vulnerable" while backend/package-lock.json held 750
 *   packages and 171 advisories);
 * - a dot-directory is an ordinary directory (`.github/actions/x`,
 *   `.design-system`): scanned, unless it is one of the kinds below;
 * - a directory .gitignore excludes is not scanned (it is as often a scratch
 *   clone or a sibling tool as the project's own code, and its advisories
 *   would be reported as the project's), but every lockfile in it is listed
 *   by path (`discovery.skipped`, reason `gitignored_directory`);
 * - directories of installed code, build output, caches, version-control
 *   data and tool state (SKIP_DIRS) are never entered: what they hold is a
 *   copy of something else. Those of them whose name is also an ordinary
 *   folder name (`build`, `dist`, `vendor`...) get one look, and a lockfile
 *   sitting directly in one is listed (reason `output_directory`);
 * - test-fixture directories are counted, not scanned (FIXTURE_DIRS);
 * - a manifest with no lockfile beside it, and which no lockfile above
 *   holds as a workspace member, is listed (`unlockedManifests`): its
 *   dependencies were resolved nowhere.
 * A scan never reads as clean while a lockfile it found was not read.
 *
 * Bounded (MAX_DEPTH levels below the root, MAX_PROJECTS projects), and the
 * bound is never silent. langchain keeps 108 lockfiles up to three levels
 * down; the old bounds (depth 2, 64 projects) read 64 and dropped 44 with no
 * trace in any answer (2026-10-10). Past a bound the walk keeps going without
 * scanning, up to MAX_WALK_DIRS directories, so `discovery` can name every
 * lockfile that was left out and say why.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { IgnoreRules } from "./gitignore.js";
import { readTextFile } from "./live/text-file.js";
import { parsePyprojectDependencies, tomlTable } from "./project-manifests.js";
import { scanCurrentProject, type ProjectScanResult } from "./project-scanner.js";
import { startWalkBudget, walkBudgetNote } from "./walk-budget.js";

const LOCK_MARKERS = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  // Bun's binary lockfile cannot be read, but a directory that holds one is a project, and the answer says so.
  "bun.lockb",
  "Cargo.lock",
  "poetry.lock",
  "uv.lock",
  "pdm.lock",
  "Pipfile.lock",
  "go.mod",
  "Gemfile.lock",
  "composer.lock",
];

/** The ecosystem (as the project scanner names it) a lockfile pins. */
const LOCK_ECOSYSTEM: Record<string, string> = {
  "package-lock.json": "npm",
  "npm-shrinkwrap.json": "npm",
  "pnpm-lock.yaml": "npm",
  "yarn.lock": "npm",
  "bun.lock": "npm",
  "bun.lockb": "npm",
  "Cargo.lock": "rust",
  "poetry.lock": "python",
  "uv.lock": "python",
  "pdm.lock": "python",
  "Pipfile.lock": "python",
  "go.mod": "go",
  "Gemfile.lock": "ruby",
  "composer.lock": "php",
};

/**
 * Directories never entered. Each holds a copy of something that is not this
 * project's own dependency set: installed code, build output, caches,
 * version-control data, or the state of an editor or agent (extensions, and
 * worktree copies of whole repositories: 4DA's `.claude/worktrees` held 55).
 */
const SKIP_DIRS = new Set([
  // installed code
  "node_modules", "bower_components", "jspm_packages", "site-packages", "vendor", "Pods",
  ".venv", "venv", ".tox", ".nox", ".eggs", "__pycache__", ".bundle",
  // build output
  "target", "dist", "build", "out", "coverage", ".next", ".nuxt", ".output", ".svelte-kit", ".turbo",
  ".parcel-cache", ".angular", ".vercel", ".netlify", ".serverless", ".docusaurus", ".expo", ".dart_tool", ".gradle", ".nx",
  // version control and caches
  ".git", ".hg", ".svn", ".cache", ".pnpm-store", ".yarn", ".npm", ".pnpm", ".bun", ".cargo", ".rustup",
  ".mypy_cache", ".pytest_cache", ".ruff_cache", ".terraform",
  // editor and agent state
  ".claude", ".codex", ".cursor", ".worktrees", ".vscode", ".vscode-test", ".vscode-server", ".idea", ".vs",
]);

/**
 * SKIP_DIRS names that are also ordinary folder names: microsoft/vscode keeps
 * `build/package-lock.json`, a real project. They are still not entered, but a
 * lockfile sitting directly in one is listed, not passed over.
 */
const AMBIGUOUS_OUTPUT_DIRS = new Set(["build", "dist", "out", "vendor", "coverage", "target", "venv"]);

/**
 * Directories whose lockfiles are test data, not the project's dependencies:
 * a scan of D:\4DA\src-tauri read the 4DA conformance corpus
 * (tests/conformance/cases, 10,000+ vendored packages) as the app's own
 * (audit A3, 2026-10-12). Left out by default, counted and named in the
 * answer (`not_scanned`), and scanned on request (include_test_fixtures).
 */
const FIXTURE_DIRS = new Set([
  "fixtures", "__fixtures__", "testdata", "test-data", "test-fixtures", "__tests__", "tests", "test", "conformance",
]);

/** Above this a setup.py or setup.cfg is not read to see whether it declares dependencies. */
const MAX_SETUP_BYTES = 256 * 1024;

/** Whether a setup.py or setup.cfg declares runtime dependencies of its own (`install_requires`). */
function declaresInstallRequires(file: string): boolean {
  try {
    const stat = fs.statSync(file);
    return stat.isFile() && stat.size <= MAX_SETUP_BYTES && /\binstall_requires\b/.test(readTextFile(file));
  } catch {
    return false;
  }
}

/**
 * Manifests and lockfiles this server does not read, by file name: those of
 * ecosystems it has no reader for, and files of ecosystems it does read in a
 * form it does not (conda's environment.yml, setup.py's install_requires, a
 * PEP 751 pylock.toml). Reported as `not_covered` so an empty or clean answer
 * is never read as "no dependencies" (audit A2: a Maven or .NET project was
 * told "No manifest files found... run from your project root"; audit
 * 2026-11-11: environment.yml and setup.py beside a lockfile went unmentioned).
 * `dir` lets setup.py / setup.cfg be opened: one that declares nothing is not listed.
 */
export function unsupportedEcosystem(name: string, names: string[], dir?: string): string | null {
  if (name === "pom.xml") return "Maven";
  if (/^build\.gradle(\.kts)?$/.test(name) || name === "gradle.lockfile") return "Maven (Gradle)";
  if (/\.(cs|fs|vb)proj$/i.test(name) || name === "packages.lock.json" || name === "packages.config" || name === "Directory.Packages.props") return "NuGet";
  if (name === "pubspec.lock") return "Pub";
  if (name === "mix.lock") return "Hex";
  if (name === "Package.resolved") return "SwiftPM";
  if (name === "Podfile.lock") return "CocoaPods";
  if (name === "conan.lock") return "ConanCenter";
  if (name === "renv.lock") return "CRAN";
  if (name === "Gemfile" && !names.includes("Gemfile.lock")) return "RubyGems (Gemfile with no Gemfile.lock)";
  if (name === "composer.json" && !names.includes("composer.lock")) return "Packagist (composer.json with no composer.lock)";
  if (/^environment\.ya?ml$/i.test(name)) return "Conda (environment.yml is not read)";
  if (/^pylock(\.[^.]+)?\.toml$/.test(name)) return "PyPI (pylock.toml, PEP 751, is not read)";
  if (name === "Pipfile" && !names.includes("Pipfile.lock")) return "PyPI (Pipfile with no Pipfile.lock)";
  if ((name === "setup.py" || name === "setup.cfg") && dir && declaresInstallRequires(path.join(dir, name))) {
    return `PyPI (${name}: install_requires is not read)`;
  }
  return null;
}

/** Entries listed in `notCovered`; the count covers the rest. */
const MAX_LISTED_NOT_COVERED = 25;

/**
 * Measured on langchain (108 lockfiles, up to 3 levels down; 2026-10-10):
 * the walk plus every project scan takes about 2 s. Depth 4 covers it with a
 * level to spare; 256 projects is 2.4x its count.
 */
export const MAX_DEPTH = 4;
export const MAX_PROJECTS = 256;
/** Directories visited in total, scanned or not: the hard cap on the walk itself. */
const MAX_WALK_DIRS = 20_000;
/**
 * Directories visited inside gitignored directories, a budget of its own: a
 * large ignored tree (a data folder, a scratch clone) must not use up the
 * walk of the project itself.
 */
const MAX_IGNORED_WALK_DIRS = 5_000;
/** Lockfile paths listed in `discovery.skipped`; the count covers the rest. */
const MAX_LISTED_SKIPS = 50;
/**
 * Registry configuration files whose directory is recorded (`discovery.registryConfigDirs`). A Pipfile
 * too: one with a private `[[source]]` and no lockfile is no resolution group, and its packages are
 * private wherever they are named (R8, B4).
 */
const REGISTRY_CONFIG_FILES = new Set([".npmrc", ".yarnrc.yml", "bunfig.toml", "Pipfile"]);
/** At most this many such directories are read for private scopes. */
const MAX_REGISTRY_CONFIG_DIRS = 500;
/** Manifests listed in `discovery.unlockedManifests`; the count covers the rest. */
const MAX_LISTED_UNLOCKED = 25;

export interface ProjectTreeEntry {
  dir: string;
  scan: ProjectScanResult;
}

/**
 * Why a lockfile the walk found was not scanned: past a bound, inside a
 * directory .gitignore excludes, or directly inside a build-output directory.
 */
export type SkipReason = "depth" | "project_limit" | "gitignored_directory" | "output_directory";

/** What the walk left out, so an answer can say it is partial. */
export interface TreeDiscovery {
  /** Projects scanned (the root included). */
  projects: number;
  maxDepth: number;
  maxProjects: number;
  /** Lockfiles found but not scanned, relative to the root (the first MAX_LISTED_SKIPS). */
  skipped: Array<{ path: string; reason: SkipReason }>;
  /** Every lockfile found but not scanned (`skipped` may list fewer). */
  skippedCount: number;
  /** True when the walk itself stopped at MAX_WALK_DIRS: lockfiles beyond it were not even counted. */
  walkTruncated: boolean;
  /** Set when the walk stopped on its time budget rather than at MAX_WALK_DIRS (walk-budget.ts). */
  walkStopped?: "time_budget";
  /** True when the search inside gitignored directories stopped at MAX_IGNORED_WALK_DIRS. */
  ignoredWalkTruncated?: boolean;
  /** Manifests and lockfiles of ecosystems this server does not read (the first MAX_LISTED_NOT_COVERED), relative to the root. */
  notCovered?: Array<{ path: string; ecosystem: string }>;
  /** Every such file found (`notCovered` may list fewer). */
  notCoveredCount?: number;
  /** Lockfiles under test-fixture directories, left out unless include_test_fixtures was set. */
  fixtures?: { count: number; dirs: string[] };
  /**
   * Manifests that declare dependencies, in a directory with no lockfile,
   * which no lockfile above holds as a workspace member (the first
   * MAX_LISTED_UNLOCKED), relative to the root. Nothing resolved them, so
   * nothing of theirs was checked.
   */
  unlockedManifests?: Array<{ path: string; ecosystem: string; dependencies: number }>;
  /** Every such manifest found (`unlockedManifests` may list fewer). */
  unlockedManifestsCount?: number;
  /** Lockfiles that were scanned although .gitignore lists them, relative to the root. */
  gitignoredScanned?: string[];
  /**
   * Directories below the root holding a package-registry configuration (`.npmrc`, `.yarnrc.yml`,
   * `bunfig.toml`), absolute. A member's private scope is private for the whole project, lockfile
   * or not (live/private-packages.ts; blind audit round 4).
   */
  registryConfigDirs?: string[];
}

/** Python requirement files: requirements.txt, requirements-dev.txt, dev_requirements.txt, _test_minimum_requirements.txt. */
export function isRequirementsFileName(name: string): boolean {
  return /requirements[\w.-]*\.txt$/i.test(name);
}

/** The lockfiles (and exact-pin files) that make a directory a project, by name. */
export function lockfilesIn(dir: string, listing?: string[]): string[] {
  let names: string[];
  try {
    names = listing ?? fs.readdirSync(dir);
  } catch {
    return [];
  }
  const found = names.filter((n) => LOCK_MARKERS.includes(n) || isRequirementsFileName(n));
  // pip-compile-multi and similar keep the pins in a requirements/ folder (superset: requirements/base.txt).
  if (names.includes("requirements")) {
    try {
      for (const n of fs.readdirSync(path.join(dir, "requirements"))) if (/\.txt$/i.test(n)) found.push(`requirements/${n}`);
    } catch {
      // a file named "requirements"
    }
  }
  return found;
}

/** The ecosystem a lockfile name (as lockfilesIn returns it) pins, or null. */
function lockEcosystem(name: string): string | null {
  return LOCK_ECOSYSTEM[name] ?? (isRequirementsFileName(name) || name.startsWith("requirements/") ? "python" : null);
}

/** Workspace patterns read per directory; a manifest with more is not a real one. */
const MAX_WORKSPACE_PATTERNS = 200;

/** `*` and `?` within one path segment, without a regex (a pattern from a cloned repository must not be able to stall the walk). */
function segmentMatches(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (p < pattern.length && (pattern[p] === "?" || pattern[p] === text[t])) {
      p++;
      t++;
    } else if (p < pattern.length && pattern[p] === "*") {
      star = p++;
      mark = t;
    } else if (star >= 0) {
      p = star + 1;
      t = ++mark;
    } else return false;
  }
  while (p < pattern.length && pattern[p] === "*") p++;
  return p === pattern.length;
}

/** A workspace glob (`packages/*`, `apps/**`, `tools/cli`) against a `/`-separated relative path: `**` spans directories. */
export function workspaceGlobMatches(pattern: string, relPath: string): boolean {
  const want = pattern.replace(/^\.\//, "").replace(/\/+$/, "").split("/").filter(Boolean);
  const have = relPath.split("/").filter(Boolean);
  // reachable[j]: the pattern so far can end at have[0..j).
  let reachable = new Array<boolean>(have.length + 1).fill(false);
  reachable[0] = true;
  for (const segment of want) {
    const next = new Array<boolean>(have.length + 1).fill(false);
    if (segment === "**") {
      let seen = false;
      for (let j = 0; j <= have.length; j++) {
        seen ||= reachable[j];
        next[j] = seen;
      }
    } else {
      for (let j = 0; j < have.length; j++) if (reachable[j] && segmentMatches(segment, have[j])) next[j + 1] = true;
    }
    reachable = next;
  }
  return reachable[have.length];
}

/**
 * What the lockfiles of one directory cover below it. A manifest in a
 * subdirectory is pinned by a lockfile above only when it is one of that
 * lockfile's workspace members; any other manifest there was resolved by
 * nothing. kairos-mvp keeps a root package-lock.json (5 packages) and a
 * frontend/package.json with 22 dependencies and no lockfile: the root's
 * lockfile says nothing about them (2026-11-11).
 *
 * Read lazily, once: most directories with a lockfile have no manifest-only
 * directory below them.
 */
class LockCover {
  private js: { include: string[]; exclude: string[]; locked: Set<string> } | null = null;
  private cargo: Set<string> | null = null;
  private python: Set<string> | null = null;

  constructor(
    private readonly dir: string,
    /** Relative to the walk's root ("" for the root itself). */
    readonly rel: string,
    private readonly locks: string[],
  ) {}

  private has(ecosystem: string): boolean {
    return this.locks.some((name) => lockEcosystem(name) === ecosystem);
  }

  private read(name: string): string {
    try {
      return readTextFile(path.join(this.dir, name));
    } catch {
      return "";
    }
  }

  /** npm, pnpm, Yarn and Bun: the member directory matches a `workspaces` (package.json) or `packages` (pnpm-workspace.yaml) pattern. */
  coversPackageJson(memberRel: string): boolean {
    if (!this.has("npm")) return false;
    if (!this.js) {
      const patterns: string[] = [];
      try {
        const workspaces = (JSON.parse(this.read("package.json") || "{}") as { workspaces?: unknown }).workspaces;
        const list = Array.isArray(workspaces) ? workspaces : Array.isArray((workspaces as { packages?: unknown } | undefined)?.packages) ? (workspaces as { packages: unknown[] }).packages : [];
        for (const p of list) if (typeof p === "string") patterns.push(p);
      } catch {
        // no readable package.json: no workspaces declared there
      }
      let inPackages = false;
      for (const line of this.read("pnpm-workspace.yaml").split(/\r?\n/)) {
        if (/^\S/.test(line)) inPackages = /^packages:\s*$/.test(line);
        else if (inPackages) {
          const item = /^\s*-\s*(?:'([^']*)'|"([^"]*)"|(\S.*?))\s*$/.exec(line);
          const value = item ? (item[1] ?? item[2] ?? item[3]) : null;
          if (value) patterns.push(value);
        }
      }
      const kept = patterns.slice(0, MAX_WORKSPACE_PATTERNS).map((p) => p.trim()).filter((p) => p.length > 0 && p.length <= 512);
      this.js = { include: kept.filter((p) => !p.startsWith("!")), exclude: kept.filter((p) => p.startsWith("!")).map((p) => p.slice(1)), locked: this.lockedDirectories() };
    }
    const { include, exclude, locked } = this.js;
    if (locked.has(memberRel)) return true;
    return include.some((p) => workspaceGlobMatches(p, memberRel)) && !exclude.some((p) => workspaceGlobMatches(p, memberRel));
  }

  /**
   * The directories the lockfile itself names as its own: package-lock.json
   * keys every workspace and `file:` link target by its path (`packages/a`,
   * `lib`), pnpm-lock.yaml lists them under `importers:`. Their dependencies
   * are resolved in that lockfile whatever the workspace patterns say.
   */
  private lockedDirectories(): Set<string> {
    const dirs = new Set<string>();
    for (const name of ["package-lock.json", "npm-shrinkwrap.json"]) {
      if (!this.locks.includes(name)) continue;
      try {
        const packages = (JSON.parse(this.read(name) || "{}") as { packages?: Record<string, unknown> }).packages ?? {};
        for (const key of Object.keys(packages)) if (key && !key.includes("node_modules")) dirs.add(key.replace(/\/+$/, ""));
      } catch {
        // unreadable: resolveNpm reports it
      }
    }
    if (this.locks.includes("pnpm-lock.yaml")) {
      let inImporters = false;
      for (const line of this.read("pnpm-lock.yaml").split(/\r?\n/)) {
        if (/^\S/.test(line)) inImporters = /^importers:\s*$/.test(line);
        else if (inImporters) {
          const key = /^ {2}(?:'([^']+)'|"([^"]+)"|([^\s:'"][^:]*)):\s*$/.exec(line);
          const dir = key ? (key[1] ?? key[2] ?? key[3]) : null;
          if (dir && dir !== ".") dirs.add(dir.replace(/^\.\//, "").replace(/\/+$/, ""));
        }
      }
    }
    return dirs;
  }

  /** Cargo: the lockfile holds the crate as a local package (a workspace member or path dependency has no `source`). */
  coversCrate(name: string): boolean {
    if (!this.has("rust")) return false;
    if (!this.cargo) {
      this.cargo = new Set();
      for (const block of this.read("Cargo.lock").split(/^\[\[package\]\]\s*$/m).slice(1)) {
        const body = block.split(/^\[/m)[0];
        const crate = /^name\s*=\s*"([^"]*)"/m.exec(body)?.[1];
        if (crate && !/^source\s*=/m.test(body)) this.cargo.add(crate);
      }
    }
    return this.cargo.has(name);
  }

  /** Python: one of the directory's lockfiles holds the project by name (a uv or Poetry workspace member, a path dependency). */
  coversPythonProject(name: string): boolean {
    if (!this.has("python")) return false;
    if (!this.python) {
      this.python = new Set();
      for (const lock of ["uv.lock", "poetry.lock", "pdm.lock"]) {
        if (!this.locks.includes(lock)) continue;
        for (const block of this.read(lock).split(/^\[\[package\]\]\s*$/m).slice(1)) {
          const project = /^name\s*=\s*"([^"]*)"/m.exec(block.split(/^\[/m)[0])?.[1];
          if (project) this.python.add(project.trim().toLowerCase().replace(/[-_.]+/g, "-"));
        }
      }
    }
    return this.python.has(name.trim().toLowerCase().replace(/[-_.]+/g, "-"));
  }
}

/** The path of `rel` below `base` (both relative to the walk's root). */
function below(base: string, rel: string): string {
  return base ? rel.slice(base.length + 1) : rel;
}

/**
 * The manifests in a directory with no lockfile of its own that declare
 * dependencies no lockfile above pins: the file, the ecosystem and how many
 * dependencies it declares. A manifest that declares nothing (a package.json
 * that only sets `"type": "module"`) and a workspace member of a lockfile
 * above (`covers`) are not listed.
 */
function unlockedManifestsIn(dir: string, rel: string, names: string[], covers: LockCover[]): Array<{ name: string; ecosystem: string; dependencies: number }> {
  const out: Array<{ name: string; ecosystem: string; dependencies: number }> = [];
  const read = (name: string) => {
    try {
      return readTextFile(path.join(dir, name));
    } catch {
      return null;
    }
  };
  if (names.includes("package.json")) {
    try {
      const pkg = JSON.parse(read("package.json") ?? "{}") as Record<string, unknown>;
      const count = ["dependencies", "devDependencies", "optionalDependencies"].reduce(
        (n, field) => n + (pkg[field] && typeof pkg[field] === "object" ? Object.keys(pkg[field] as object).length : 0),
        0,
      );
      if (count > 0 && !covers.some((c) => c.coversPackageJson(below(c.rel, rel)))) out.push({ name: "package.json", ecosystem: "npm", dependencies: count });
    } catch {
      // not JSON: nothing can be said about it
    }
  }
  if (names.includes("Cargo.toml")) {
    const content = read("Cargo.toml") ?? "";
    let table = "";
    let count = 0;
    let crate: string | null = null;
    for (const line of content.split(/\r?\n/)) {
      const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
      if (header) table = header[1].trim();
      else if (/(?:^|\.)(?:dev-|build-)?dependencies$/.test(table) && /^\s*[A-Za-z_][\w-]*\s*[=.]/.test(line)) count++;
      else if (table === "package") crate ??= /^\s*name\s*=\s*"([^"]*)"/.exec(line)?.[1] ?? null;
    }
    if (count > 0 && !(crate && covers.some((c) => c.coversCrate(crate as string)))) out.push({ name: "Cargo.toml", ecosystem: "crates.io", dependencies: count });
  }
  if (names.includes("pyproject.toml")) {
    try {
      const content = read("pyproject.toml") ?? "";
      const declared = parsePyprojectDependencies(content);
      const count = declared.deps.length + declared.devDeps.length;
      const project = /^name\s*=\s*["']([^"']+)["']/m.exec(tomlTable(content, "project") ?? tomlTable(content, "tool.poetry") ?? "")?.[1] ?? null;
      if (count > 0 && !(project && covers.some((c) => c.coversPythonProject(project)))) out.push({ name: "pyproject.toml", ecosystem: "PyPI", dependencies: count });
    } catch {
      // unreadable: nothing can be said about it
    }
  }
  return out;
}

/**
 * The root (always) and every locked project below it, each with its own
 * scan, plus everything the walk found and did not scan (see the header:
 * label, never suppress).
 */
export function scanProjectTree(
  root: string,
  limits: { maxDepth: number; maxProjects: number } = { maxDepth: MAX_DEPTH, maxProjects: MAX_PROJECTS },
  options: { includeFixtures?: boolean } = {},
): { entries: ProjectTreeEntry[]; discovery: TreeDiscovery } {
  const entries: ProjectTreeEntry[] = [{ dir: root, scan: scanCurrentProject(root) }];
  const ignore = new IgnoreRules(root);
  const budget = startWalkBudget(ignore);
  const skipped: TreeDiscovery["skipped"] = [];
  let skippedCount = 0;
  let visited = 0;
  let walkTruncated = false;
  let ignoredVisited = 0;
  let ignoredWalkTruncated = false;
  const notCovered: Array<{ path: string; ecosystem: string }> = [];
  let notCoveredCount = 0;
  const fixtures = { count: 0, dirs: [] as string[] };
  const unlocked: NonNullable<TreeDiscovery["unlockedManifests"]> = [];
  let unlockedCount = 0;
  const gitignoredScanned: string[] = [];
  const registryConfigDirs: string[] = [];
  const noteRegistryConfig = (dir: string, names: string[]) => {
    if (registryConfigDirs.length < MAX_REGISTRY_CONFIG_DIRS && names.some((n) => REGISTRY_CONFIG_FILES.has(n))) registryConfigDirs.push(dir);
  };
  const noteSkipped = (lockPath: string, reason: SkipReason) => {
    skippedCount++;
    if (skipped.length < MAX_LISTED_SKIPS) skipped.push({ path: lockPath, reason });
  };
  // Listed whether or not .gitignore names the file: a manifest nobody commits still declares what gets installed.
  const noteUnsupported = (dir: string, rel: string, names: string[]) => {
    for (const name of names) {
      const ecosystem = unsupportedEcosystem(name, names, dir);
      if (!ecosystem) continue;
      notCoveredCount++;
      if (notCovered.length < MAX_LISTED_NOT_COVERED) notCovered.push({ path: rel ? `${rel}/${name}` : name, ecosystem });
    }
  };
  // One directory listing per directory: it decides both whether the
  // directory is a project and which children to descend into.
  const listing = (dir: string): fs.Dirent[] | null => {
    try {
      return fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return null;
    }
  };
  // Test-fixture lockfiles: counted, never scanned (unless asked for).
  const countFixtures = (dir: string, children: fs.Dirent[]) => {
    for (const child of children) {
      if (!child.isDirectory() || SKIP_DIRS.has(child.name)) continue;
      if (++visited > MAX_WALK_DIRS || budget.spent()) {
        walkTruncated = true;
        return;
      }
      const sub = path.join(dir, child.name);
      const grandchildren = listing(sub);
      if (!grandchildren) continue;
      fixtures.count += lockfilesIn(sub, grandchildren.map((g) => g.name)).length;
      countFixtures(sub, grandchildren);
      if (walkTruncated) return;
    }
  };
  // A directory .gitignore excludes: not scanned, but every lockfile in it is named.
  const listIgnored = (dir: string, rel: string) => {
    if (budget.spent()) {
      walkTruncated = true;
      return;
    }
    if (++ignoredVisited > MAX_IGNORED_WALK_DIRS) {
      ignoredWalkTruncated = true;
      return;
    }
    const children = listing(dir);
    if (!children) return;
    for (const name of lockfilesIn(dir, children.map((c) => c.name))) noteSkipped(`${rel}/${name}`, "gitignored_directory");
    noteRegistryConfig(dir, children.map((c) => c.name));
    for (const child of children) {
      if (!child.isDirectory() || SKIP_DIRS.has(child.name)) continue;
      listIgnored(path.join(dir, child.name), `${rel}/${child.name}`);
      if (ignoredWalkTruncated || walkTruncated) return;
    }
  };
  // A build-output name that may be an ordinary folder: one look, no descent.
  const peekOutputDir = (dir: string, rel: string) => {
    const children = listing(dir);
    if (!children) return;
    for (const name of lockfilesIn(dir, children.filter((c) => c.isFile()).map((c) => c.name))) noteSkipped(`${rel}/${name}`, "output_directory");
  };
  // The lockfiles above a directory: a manifest below is covered only by one it is a workspace member of (LockCover).
  const walk = (dir: string, rel: string, depth: number, children: fs.Dirent[], covers: LockCover[]) => {
    for (const child of children) {
      if (!child.isDirectory()) continue;
      const childRel = rel ? `${rel}/${child.name}` : child.name;
      const sub = path.join(dir, child.name);
      if (SKIP_DIRS.has(child.name)) {
        if (AMBIGUOUS_OUTPUT_DIRS.has(child.name)) peekOutputDir(sub, childRel);
        continue;
      }
      if (++visited > MAX_WALK_DIRS || budget.spent()) {
        walkTruncated = true;
        return;
      }
      if (ignore.ignores(childRel, true)) {
        listIgnored(sub, childRel);
        continue;
      }
      const grandchildren = listing(sub);
      if (!grandchildren) continue;
      if (!options.includeFixtures && FIXTURE_DIRS.has(child.name.toLowerCase())) {
        const before = fixtures.count;
        fixtures.count += lockfilesIn(sub, grandchildren.map((g) => g.name)).length;
        countFixtures(sub, grandchildren);
        if (fixtures.count > before && fixtures.dirs.length < 10) fixtures.dirs.push(childRel);
        if (walkTruncated) return;
        continue;
      }
      // A .gitignore is only read where one exists.
      if (grandchildren.some((g) => g.name === ".gitignore")) ignore.load(childRel);
      const names = grandchildren.map((g) => g.name);
      noteUnsupported(sub, childRel, names);
      noteRegistryConfig(sub, names);
      // Every lockfile, .gitignore-listed or not: it is what is installed.
      const locks = lockfilesIn(sub, names);
      const here = locks.length > 0 ? [...covers, new LockCover(sub, childRel, locks)] : covers;
      if (locks.length > 0) {
        const reason = depth > limits.maxDepth ? "depth" : entries.length >= limits.maxProjects ? "project_limit" : null;
        if (reason === null) {
          entries.push({ dir: sub, scan: scanCurrentProject(sub) });
          for (const name of locks) if (ignore.ignores(`${childRel}/${name}`, false)) gitignoredScanned.push(`${childRel}/${name}`);
        } else {
          for (const name of locks) noteSkipped(`${childRel}/${name}`, reason);
        }
      } else {
        // No lockfile here: a manifest is covered only when a lockfile above holds it as a workspace member.
        for (const manifest of unlockedManifestsIn(sub, childRel, names, here)) {
          unlockedCount++;
          if (unlocked.length < MAX_LISTED_UNLOCKED) unlocked.push({ path: `${childRel}/${manifest.name}`, ecosystem: manifest.ecosystem, dependencies: manifest.dependencies });
        }
      }
      walk(sub, childRel, depth + 1, grandchildren, here);
      if (walkTruncated) return;
    }
  };
  const rootListing = listing(root) ?? [];
  const rootNames = rootListing.filter((d) => d.isFile()).map((d) => d.name);
  noteUnsupported(root, "", rootNames);
  const rootLocks = lockfilesIn(root, rootListing.map((d) => d.name));
  for (const name of rootLocks) if (ignore.ignores(name, false)) gitignoredScanned.push(name);
  walk(root, "", 1, rootListing, rootLocks.length > 0 ? [new LockCover(root, "", rootLocks)] : []);
  return {
    entries,
    discovery: {
      projects: entries.length,
      maxDepth: limits.maxDepth,
      maxProjects: limits.maxProjects,
      skipped,
      skippedCount,
      walkTruncated,
      ...(budget.stopped ? { walkStopped: "time_budget" as const } : {}),
      ...(ignoredWalkTruncated ? { ignoredWalkTruncated } : {}),
      ...(notCoveredCount > 0 ? { notCovered, notCoveredCount } : {}),
      ...(fixtures.count > 0 ? { fixtures } : {}),
      ...(unlockedCount > 0 ? { unlockedManifests: unlocked, unlockedManifestsCount: unlockedCount } : {}),
      ...(gitignoredScanned.length > 0 ? { gitignoredScanned } : {}),
      ...(registryConfigDirs.length > 0 ? { registryConfigDirs } : {}),
    },
  };
}

const walkedDiscovery = new Map<string, TreeDiscovery>();

/**
 * The walk's report for `root`, taken once per process. For answers that
 * had no walk recorded and must not claim "nothing here" unchecked (H3):
 * vulnerability_scan's "nothing found" message and dependency_health's
 * nothing-checked answer. Re-walking on every call cost a full tree walk per
 * call (review of H3, 2026-10-18).
 */
export function discoveryFor(root: string): TreeDiscovery {
  const key = path.resolve(root).toLowerCase();
  let found = walkedDiscovery.get(key);
  if (!found) {
    found = scanProjectTree(root).discovery;
    walkedDiscovery.set(key, found);
  }
  return found;
}

/** A lockfile problem as the notes read it (lockfile-types.ts LockfileProblem). */
export type LockfileProblemLike = { file: string; error: string; skipped?: number; partial?: true; conflict?: true; refused?: true };

/**
 * The kinds, kept apart: a file that could not be read (UNREADABLE), one read
 * but not all of it (PARTIAL: entries skipped, `skipped`, audit L5; or
 * truncated or damaged, `partial`), a requirements include refused because it
 * points outside the project (`refused`, B-11), and a second lockfile that
 * disagrees with the one that was read (`conflict`).
 */
export function splitLockfileProblems<P extends LockfileProblemLike>(problems: P[]): { unreadable: P[]; partial: P[]; refused: P[]; conflicts: P[] } {
  const isPartial = (p: P) => Boolean(p.skipped) || p.partial === true;
  return {
    unreadable: problems.filter((p) => !isPartial(p) && !p.refused && !p.conflict),
    partial: problems.filter((p) => isPartial(p) && !p.refused && !p.conflict),
    refused: problems.filter((p) => p.refused === true),
    conflicts: problems.filter((p) => p.conflict === true),
  };
}

/**
 * One wording for every tool (vulnerability_scan, dependency_health,
 * upgrade_planner). `show` renders a path (the scan shows it relative).
 */
export function lockfileProblemNotes(problems: LockfileProblemLike[], show: (file: string) => string = (f) => f): string[] {
  const listed = (ps: LockfileProblemLike[]) => `${ps.slice(0, 3).map((p) => `${show(p.file)} (${p.error})`).join("; ")}${ps.length > 3 ? "; ..." : ""}`;
  const { unreadable, partial, refused, conflicts } = splitLockfileProblems(problems);
  const notes: string[] = [];
  if (unreadable.length > 0) {
    notes.push(
      `UNREADABLE: ${unreadable.length} lockfile${unreadable.length === 1 ? "" : "s"} could not be read, so ${unreadable.length === 1 ? "its" : "their"} dependencies were not checked: ${listed(unreadable)}.`,
    );
  }
  const skippedEntries = partial.filter((p) => !p.partial);
  const damaged = partial.filter((p) => p.partial);
  if (skippedEntries.length > 0) {
    notes.push(`PARTIAL: ${skippedEntries.length} lockfile${skippedEntries.length === 1 ? " was" : "s were"} read with entries skipped: ${listed(skippedEntries)}.`);
  }
  if (damaged.length > 0) {
    notes.push(`PARTIAL: ${damaged.length} lockfile${damaged.length === 1 ? " was" : "s were"} NOT read to the end: ${listed(damaged)}.`);
  }
  if (refused.length > 0) {
    notes.push(`REFUSED: ${refused.length} requirements include${refused.length === 1 ? " was" : "s were"} not read: ${listed(refused)}.`);
  }
  if (conflicts.length > 0) {
    notes.push(
      `CONFLICT: ${conflicts.length} lockfile${conflicts.length === 1 ? "" : "s"} beside the one that was read ${conflicts.length === 1 ? "was" : "were"} not used: ${listed(conflicts)}.`,
    );
  }
  return notes;
}

/** Kept for its importers (upgrade_planner): lockfileProblemNotes. */
export function unreadableNotes(problems: LockfileProblemLike[]): string[] {
  return lockfileProblemNotes(problems);
}

/** What a scan left out on purpose or cannot read: ecosystems it does not cover, and test fixtures. */
export function exclusionNotes(discovery: TreeDiscovery | null): string[] {
  const notes: string[] = [];
  const unsupported = discovery?.notCoveredCount ?? 0;
  if (unsupported > 0) {
    const ecosystems = [...new Set((discovery?.notCovered ?? []).map((n) => n.ecosystem.split(" ")[0]))].join(", ");
    const listed = (discovery?.notCovered ?? []).slice(0, 3).map((n) => n.path).join(", ");
    notes.push(
      `NOT COVERED: ${unsupported} manifest/lockfile${unsupported === 1 ? "" : "s"} of ecosystems or formats this server does not read (${ecosystems}): ${listed}${unsupported > 3 ? ", ..." : ""}. Their dependencies were not checked at all; see not_covered.`,
    );
  }
  const fixtures = discovery?.fixtures;
  if (fixtures && fixtures.count > 0) {
    notes.push(
      `Not scanned: ${fixtures.count} test-fixture lockfile${fixtures.count === 1 ? "" : "s"} under ${fixtures.dirs.slice(0, 3).join(", ")}${fixtures.dirs.length > 3 ? ", ..." : ""} (pass include_test_fixtures: true to scan them).`,
    );
  }
  return notes;
}

/** Why lockfiles were found and not scanned, in the order the reasons are worded. */
const SKIP_WORDING: Array<[SkipReason, (d: TreeDiscovery) => string]> = [
  ["depth", (d) => `deeper than ${d.maxDepth} levels`],
  ["project_limit", (d) => `past the ${d.maxProjects}-project limit`],
  ["gitignored_directory", () => "in a directory .gitignore excludes"],
  ["output_directory", () => "directly inside a build-output directory"],
];

/** One sentence for an answer, or null when nothing was left out. */
export function discoveryNote(discovery: TreeDiscovery | null): string | null {
  if (!discovery) return null;
  const unlocked = discovery.unlockedManifestsCount ?? 0;
  if (discovery.skippedCount === 0 && !discovery.walkTruncated && !discovery.ignoredWalkTruncated && unlocked === 0) return null;
  const parts: string[] = [];
  if (discovery.skippedCount > 0) {
    const why = SKIP_WORDING.filter(([reason]) => discovery.skipped.some((s) => s.reason === reason))
      .map(([, words]) => words(discovery))
      .join(" or ");
    const listed = discovery.skipped.slice(0, 5).map((s) => s.path).join(", ");
    parts.push(
      `${discovery.skippedCount} lockfile${discovery.skippedCount === 1 ? " was" : "s were"} found but NOT scanned (${why}): ${listed}${discovery.skippedCount > 5 ? ", ..." : ""}; pass project_path to scan one of them`,
    );
  }
  if (unlocked > 0) {
    const listed = (discovery.unlockedManifests ?? []).slice(0, 5).map((m) => m.path).join(", ");
    parts.push(
      `${unlocked} manifest${unlocked === 1 ? " has" : "s have"} no lockfile beside ${unlocked === 1 ? "it" : "them"} and ${unlocked === 1 ? "is" : "are"} no workspace member of one above (${listed}${unlocked > 5 ? ", ..." : ""}), so the dependencies ${unlocked === 1 ? "it declares" : "they declare"} were not resolved and NOT checked; generate a lockfile there`,
    );
  }
  if (discovery.walkTruncated) parts.push(discovery.walkStopped ? walkBudgetNote() : `the directory walk stopped after ${MAX_WALK_DIRS} directories, so lockfiles beyond that were not counted`);
  if (discovery.ignoredWalkTruncated) {
    parts.push(`the search of gitignored directories stopped after ${MAX_IGNORED_WALK_DIRS} directories, so lockfiles deeper in them were not counted`);
  }
  return `Partial scan: ${parts.join("; ")}.`;
}

/** Lockfiles that make an ecosystem scannable in a directory even when no direct dependency was parsed. */
const LOCKS_BY_LANGUAGE: Record<string, string[]> = {
  // bun.lockb cannot be read, but its group is what reports that it is there and unread.
  npm: ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"],
  rust: ["Cargo.lock"],
  python: ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"],
  go: ["go.mod"],
  ruby: ["Gemfile.lock"],
  php: ["composer.lock"],
};

/**
 * Resolution groups for the live layer: one per (project directory, ecosystem).
 * A lockfile whose manifest declared nothing the scanner could read still gets
 * a group, so its installed packages are scanned (as transitives) rather than
 * silently dropped.
 */
export function treeResolutionGroups(entries: ProjectTreeEntry[]): Array<{
  dir: string;
  language: string;
  deps: string[];
  devDeps: string[];
  targets: Record<string, string>;
}> {
  return entries.flatMap(({ dir, scan }) => {
    const byLanguage = { ...scan.depsByEcosystem };
    const present = lockfilesIn(dir);
    const pins = present.some((n) => isRequirementsFileName(n) || n.startsWith("requirements/"));
    for (const [language, locks] of Object.entries(LOCKS_BY_LANGUAGE)) {
      const pinned = language === "python" && pins;
      if (!byLanguage[language] && (pinned || locks.some((lock) => present.includes(lock)))) {
        byLanguage[language] = { deps: [], devDeps: [] };
      }
    }
    return Object.entries(byLanguage).map(([language, { deps, devDeps }]) => ({
      dir,
      language,
      deps,
      devDeps,
      targets: scan.depTargets,
    }));
  });
}
