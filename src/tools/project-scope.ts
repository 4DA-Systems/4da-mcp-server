// SPDX-License-Identifier: Apache-2.0
/**
 * Which project a planning or briefing answer is about.
 *
 * Measured 2026-10-07: upgrade_planner called from D:\4DA returned the 4DA
 * app's cross-project plan, and its top steps were for navcal, verax and
 * 4da-ledger. upgrade_planner and what_should_i_know now take `project_path`:
 * omitted, it is the project the server was started for (FOURDA_PROJECT_DIR,
 * else the working directory) when that directory is a project; `"*"` asks
 * for every project.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { FourDADatabase } from "../db.js";
import { getServerCacheDb } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";

/** Files that make a directory a project (manifests and lockfiles of the supported ecosystems). */
const PROJECT_MARKERS = [
  "package.json",
  "Cargo.toml",
  "pyproject.toml",
  "setup.py",
  "requirements.txt",
  "Pipfile",
  "go.mod",
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
  "bun.lock",
  "Cargo.lock",
  "poetry.lock",
  "uv.lock",
];

export const ALL_PROJECTS = "*";

/** The project the server was started for: FOURDA_PROJECT_DIR (an unsubstituted "${...}" template is ignored), else cwd. */
export function serverProjectDir(): string {
  const dir = process.env.FOURDA_PROJECT_DIR?.trim();
  if (dir && !dir.includes("${")) return dir;
  return process.cwd();
}

/** True when `dir` holds a manifest or lockfile of a supported ecosystem. */
export function isProjectDir(dir: string): boolean {
  return PROJECT_MARKERS.some((m) => {
    try {
      return fs.statSync(path.join(dir, m)).isFile();
    } catch {
      return false;
    }
  });
}

/** Lowercased, forward slashes, no trailing slash: the form the app's plan stores project paths in. */
export function normalizeProjectPath(p: string): string {
  return path.resolve(p).replace(/\\/g, "/").toLowerCase().replace(/\/+$/, "");
}

/** True when `candidate` is `root` or inside it. */
export function isWithin(candidate: string, root: string): boolean {
  const c = normalizeProjectPath(candidate);
  const r = normalizeProjectPath(root);
  return c === r || c.startsWith(`${r}/`);
}

export type ProjectScope =
  | { kind: "project"; path: string; source: "argument" | "server_project" }
  | { kind: "all"; reason: string }
  | { kind: "error"; error: string };

/**
 * The scope for one call. An explicit path must be a directory on this
 * machine; `"*"` is every project; omitted, the server's project when it is
 * one, otherwise every project (a server started in a home directory has no
 * project to narrow to).
 */
export function resolveProjectScope(projectPath: string | undefined): ProjectScope {
  const given = projectPath?.trim();
  if (given === ALL_PROJECTS) return { kind: "all", reason: 'project_path "*" asks for every project' };
  if (given) {
    const abs = path.resolve(given);
    let isDir = false;
    try {
      isDir = fs.statSync(abs).isDirectory();
    } catch {
      isDir = false;
    }
    if (!isDir) {
      return {
        kind: "error",
        error: `project_path "${given}" is not a directory on this machine. Pass the absolute path of a project root, "*" for every project, or omit it for ${serverProjectDir()}.`,
      };
    }
    return { kind: "project", path: abs, source: "argument" };
  }
  const own = serverProjectDir();
  if (isProjectDir(own)) return { kind: "project", path: path.resolve(own), source: "server_project" };
  return { kind: "all", reason: `the server's directory ${own} is not a project (no manifest or lockfile)` };
}

/**
 * The live layer for `scope`: the server's own when it already covers that
 * root, otherwise a fresh one resolved from the project tree at that path (as
 * vulnerability_scan does for its `project_path`).
 */
export function liveIntelFor<T extends Pick<LiveIntelligence, "getProjectRoot">>(
  liveIntel: T | null,
  db: FourDADatabase | null,
  scope: ProjectScope,
): T | LiveIntelligence | null {
  if (scope.kind !== "project" || !liveIntel) return liveIntel;
  const root = liveIntel.getProjectRoot();
  if (root && normalizeProjectPath(root) === normalizeProjectPath(scope.path)) return liveIntel;
  // A scope the server did not start for: resolve that tree. The connection
  // is only used for its cache (LiveCache never writes to the app's database).
  let raw;
  try {
    raw = db?.getRawDb();
  } catch {
    raw = undefined;
  }
  const scoped = new LiveIntelligence(raw ?? getServerCacheDb());
  const { entries, discovery } = scanProjectTree(scope.path);
  scoped.initFromProjectTree(scope.path, treeResolutionGroups(entries), discovery);
  return scoped;
}
