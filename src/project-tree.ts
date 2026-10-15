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
 * their root's lockfile are covered by the root. Directories that hold
 * installed code, build output, test fixtures or tool worktrees are skipped.
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
import { scanCurrentProject, type ProjectScanResult } from "./project-scanner.js";

const LOCK_MARKERS = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "Cargo.lock",
  "poetry.lock",
  "uv.lock",
  "pdm.lock",
  "Pipfile.lock",
  "go.mod",
  "Gemfile.lock",
  "composer.lock",
];

const SKIP_DIRS = new Set([
  "node_modules", "target", ".git", "dist", "build", "out", "vendor", ".venv", "venv",
  "__pycache__", ".next", ".nuxt", "coverage", ".claude", ".codex", ".cursor",
  ".turbo", ".cache", ".pnpm-store",
]);

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

/**
 * Manifests and lockfiles of ecosystems this server does not read, by file
 * name: reported as `not_covered` so an empty or clean answer is never read
 * as "no dependencies" (audit A2: a Maven or .NET project was told "No
 * manifest files found... run from your project root").
 */
export function unsupportedEcosystem(name: string, names: string[]): string | null {
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
/** Lockfile paths listed in `discovery.skipped`; the count covers the rest. */
const MAX_LISTED_SKIPS = 50;

export interface ProjectTreeEntry {
  dir: string;
  scan: ProjectScanResult;
}

/** What the walk left out, so an answer can say it is partial. */
export interface TreeDiscovery {
  /** Projects scanned (the root included). */
  projects: number;
  maxDepth: number;
  maxProjects: number;
  /** Lockfiles found but not scanned, relative to the root (the first MAX_LISTED_SKIPS). */
  skipped: Array<{ path: string; reason: "depth" | "project_limit" }>;
  /** Every lockfile found but not scanned (`skipped` may list fewer). */
  skippedCount: number;
  /** True when the walk itself stopped at MAX_WALK_DIRS: lockfiles beyond it were not even counted. */
  walkTruncated: boolean;
  /** Manifests and lockfiles of ecosystems this server does not read (the first MAX_LISTED_NOT_COVERED), relative to the root. */
  notCovered?: Array<{ path: string; ecosystem: string }>;
  /** Every such file found (`notCovered` may list fewer). */
  notCoveredCount?: number;
  /** Lockfiles under test-fixture directories, left out unless include_test_fixtures was set. */
  fixtures?: { count: number; dirs: string[] };
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

/**
 * The root (always) and every locked project below it, each with its own
 * scan, plus what the bounds left out. Directories and lockfiles the
 * repository's .gitignore excludes are not part of the project and are
 * skipped (gitignore.ts); they are not reported as left out either.
 */
export function scanProjectTree(
  root: string,
  limits: { maxDepth: number; maxProjects: number } = { maxDepth: MAX_DEPTH, maxProjects: MAX_PROJECTS },
  options: { includeFixtures?: boolean } = {},
): { entries: ProjectTreeEntry[]; discovery: TreeDiscovery } {
  const entries: ProjectTreeEntry[] = [{ dir: root, scan: scanCurrentProject(root) }];
  const ignore = new IgnoreRules(root);
  const skipped: TreeDiscovery["skipped"] = [];
  let skippedCount = 0;
  let visited = 0;
  let walkTruncated = false;
  const notCovered: Array<{ path: string; ecosystem: string }> = [];
  let notCoveredCount = 0;
  const fixtures = { count: 0, dirs: [] as string[] };
  const noteUnsupported = (rel: string, names: string[]) => {
    for (const name of names) {
      const ecosystem = unsupportedEcosystem(name, names);
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
      if (!child.isDirectory() || SKIP_DIRS.has(child.name) || child.name.startsWith(".")) continue;
      if (++visited > MAX_WALK_DIRS) {
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
  const walk = (dir: string, rel: string, depth: number, children: fs.Dirent[]) => {
    for (const child of children) {
      if (!child.isDirectory() || SKIP_DIRS.has(child.name) || child.name.startsWith(".")) continue;
      if (++visited > MAX_WALK_DIRS) {
        walkTruncated = true;
        return;
      }
      const childRel = rel ? `${rel}/${child.name}` : child.name;
      if (ignore.ignores(childRel, true)) continue;
      const sub = path.join(dir, child.name);
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
      noteUnsupported(childRel, names.filter((n) => !ignore.ignores(`${childRel}/${n}`, false)));
      const locks = lockfilesIn(sub, names).filter((name) => !ignore.ignores(`${childRel}/${name}`, false));
      if (locks.length > 0) {
        const reason = depth > limits.maxDepth ? "depth" : entries.length >= limits.maxProjects ? "project_limit" : null;
        if (reason === null) {
          entries.push({ dir: sub, scan: scanCurrentProject(sub) });
        } else {
          skippedCount += locks.length;
          for (const name of locks) if (skipped.length < MAX_LISTED_SKIPS) skipped.push({ path: `${childRel}/${name}`, reason });
        }
      }
      walk(sub, childRel, depth + 1, grandchildren);
      if (walkTruncated) return;
    }
  };
  const rootListing = listing(root) ?? [];
  noteUnsupported("", rootListing.filter((d) => d.isFile()).map((d) => d.name));
  walk(root, "", 1, rootListing);
  return {
    entries,
    discovery: {
      projects: entries.length,
      maxDepth: limits.maxDepth,
      maxProjects: limits.maxProjects,
      skipped,
      skippedCount,
      walkTruncated,
      ...(notCoveredCount > 0 ? { notCovered, notCoveredCount } : {}),
      ...(fixtures.count > 0 ? { fixtures } : {}),
    },
  };
}

/** One note for lockfiles present but unreadable (conflict markers, invalid JSON), or none. */
export function unreadableNotes(problems: Array<{ file: string; error: string }>): string[] {
  if (problems.length === 0) return [];
  return [
    `UNREADABLE: ${problems.length} lockfile${problems.length === 1 ? "" : "s"} could not be read and ${problems.length === 1 ? "its" : "their"} dependencies were not checked: ${problems
      .slice(0, 3)
      .map((p) => `${p.file} (${p.error})`)
      .join("; ")}${problems.length > 3 ? "; ..." : ""}.`,
  ];
}

/** What a scan left out on purpose or cannot read: ecosystems it does not cover, and test fixtures. */
export function exclusionNotes(discovery: TreeDiscovery | null): string[] {
  const notes: string[] = [];
  const unsupported = discovery?.notCoveredCount ?? 0;
  if (unsupported > 0) {
    const ecosystems = [...new Set((discovery?.notCovered ?? []).map((n) => n.ecosystem.split(" ")[0]))].join(", ");
    const listed = (discovery?.notCovered ?? []).slice(0, 3).map((n) => n.path).join(", ");
    notes.push(
      `NOT COVERED: ${unsupported} manifest/lockfile${unsupported === 1 ? "" : "s"} of ecosystems this server does not read (${ecosystems}): ${listed}${unsupported > 3 ? ", ..." : ""}. Their dependencies were not checked at all; see not_covered.`,
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

/** One sentence for an answer, or null when nothing was left out. */
export function discoveryNote(discovery: TreeDiscovery | null): string | null {
  if (!discovery || (discovery.skippedCount === 0 && !discovery.walkTruncated)) return null;
  const parts: string[] = [];
  if (discovery.skippedCount > 0) {
    const depth = discovery.skipped.some((s) => s.reason === "depth");
    const limit = discovery.skipped.some((s) => s.reason === "project_limit");
    const why = [
      depth ? `deeper than ${discovery.maxDepth} levels` : null,
      limit ? `past the ${discovery.maxProjects}-project limit` : null,
    ].filter(Boolean).join(" or ");
    const listed = discovery.skipped.slice(0, 5).map((s) => s.path).join(", ");
    parts.push(
      `${discovery.skippedCount} lockfile${discovery.skippedCount === 1 ? " was" : "s were"} found but NOT scanned (${why}): ${listed}${discovery.skippedCount > 5 ? ", ..." : ""}; pass project_path to scan one of them`,
    );
  }
  if (discovery.walkTruncated) parts.push(`the directory walk stopped after ${MAX_WALK_DIRS} directories, so lockfiles beyond that were not counted`);
  return `Partial scan: ${parts.join("; ")}.`;
}

/** Lockfiles that make an ecosystem scannable in a directory even when no direct dependency was parsed. */
const LOCKS_BY_LANGUAGE: Record<string, string[]> = {
  npm: ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"],
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
