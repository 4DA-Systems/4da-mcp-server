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

/**
 * True when the 4DA app tracks a project at or below `root`: its
 * `project_dependencies` table has a row there. A desktop-mode server started
 * in a directory the app never indexed must read that project from disk. The
 * app's tables say nothing about it, and its plan's "0 steps" for it is not an
 * answer (audit 6.2.5 D-1: NodeGoat, 83 vulnerable packages, got 0 steps).
 */
export function appTracksProject(db: FourDADatabase, root: string): boolean {
  if (db.isStandalone) return false;
  try {
    const rows = db
      .getRawDb()
      .prepare("SELECT DISTINCT project_path FROM project_dependencies")
      .all() as Array<{ project_path: string | null }>;
    return rows.some((r) => !!r.project_path && isWithin(r.project_path, root));
  } catch {
    return false;
  }
}

/** POSIX directories that are the system's own, by exact path (a project may well live below /opt, /var or /usr/local/src). */
const POSIX_SYSTEM_DIRS = [
  "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/share", "/usr/include", "/usr/local",
  "/bin", "/sbin", "/lib", "/lib64", "/etc", "/var", "/opt", "/home", "/mnt", "/media",
  "/Users", "/Library", "/Applications", "/Volumes", "/private", "/private/var", "/private/etc", "/cores",
];
/** POSIX trees no project lives in: the directory and everything below it. */
const POSIX_SYSTEM_TREES = ["/proc", "/sys", "/dev", "/boot", "/run", "/System"];

/**
 * Why `dir` is not scanned, when it is an operating-system directory or a filesystem root; null
 * for anything else. The sentence starts with the quoted path, so a caller can put "project_path"
 * or nothing before it.
 *
 * `project_path` was unconfined, and a server is started wherever its host happens to be
 * (`C:\Windows\System32` for many Windows hosts, `/` for a macOS app). A scan of System32 read
 * the clones that had landed there and sent 2,122 package pairs to OSV.dev and the registries
 * (audit 2026-11-11, M15). Refused: a drive or filesystem root; Windows' own directory and
 * everything below it; the roots of Program Files, ProgramData and Users; on POSIX the system's
 * own directories by exact path and the kernel/system trees whole.
 */
export function systemDirectoryProblem(dir: string, options: { platform?: NodeJS.Platform; env?: NodeJS.ProcessEnv } = {}): string | null {
  // Judged in every spelling that names the same directory: the check was lexical, and
  // `\\127.0.0.1\C$\Windows\System32` (2,119 dependencies scanned), `\\?\C:\Windows`,
  // `\\localhost\C$\Windows` and `C:\PROGRA~1` all passed it (blind audit round 3, should-fix 3).
  const platform = options.platform ?? process.platform;
  if (platform === "win32" && /^[\\/]{2}\.[\\/]/.test(dir)) {
    return `"${dir}" is a Windows device path, not a project, so it is not scanned. Pass project_path with the absolute path of your project's root (or set FOURDA_PROJECT_DIR for the server).`;
  }
  for (const form of sameDirectoryForms(dir, platform, options.platform === undefined)) {
    const why = lexicalSystemDirectoryProblem(form, options);
    if (why) return form === dir ? why : why.replace(`"${form}"`, `"${dir}" (${form})`);
  }
  return null;
}

/**
 * The spellings of one directory: as given; on Windows without a `\\?\` prefix, and an
 * administrative share (`\\host\C$\x`) as the drive path it shares; and, on the live filesystem,
 * its real path (8.3 short names expanded, links followed).
 */
function sameDirectoryForms(dir: string, platform: NodeJS.Platform, live: boolean): string[] {
  const forms = new Set<string>();
  const add = (d: string | null | undefined) => {
    if (!d) return;
    forms.add(d);
    if (platform !== "win32") return;
    const unprefixed = d.replace(/^[\\/]{2}\?[\\/]UNC[\\/]/i, "\\\\").replace(/^[\\/]{2}\?[\\/]/, "");
    forms.add(unprefixed);
    const share = /^[\\/]{2}[^\\/]+[\\/]([a-z])\$(?:[\\/](.*))?$/i.exec(unprefixed);
    if (share) forms.add(`${share[1].toUpperCase()}:\\${(share[2] ?? "").replace(/\//g, "\\")}`);
  };
  add(dir);
  if (live) {
    for (const d of [...forms]) {
      try {
        add(fs.realpathSync.native(d));
      } catch {
        // Not there, or not readable: the spellings above still stand.
      }
    }
  }
  return [...forms];
}

function lexicalSystemDirectoryProblem(dir: string, options: { platform?: NodeJS.Platform; env?: NodeJS.ProcessEnv } = {}): string | null {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const p = platform === "win32" ? path.win32 : path.posix;
  if (!p.isAbsolute(dir)) return null;
  const caseless = platform === "win32" || platform === "darwin";
  const norm = (x: string) => {
    const clean = p.normalize(x).replace(/[\\/]+$/, "");
    return caseless ? clean.toLowerCase() : clean;
  };
  const at = norm(dir);
  const within = (root: string) => at === norm(root) || at.startsWith(`${norm(root)}${p.sep}`);
  let what: string | null = null;
  if (at === norm(p.parse(p.normalize(dir)).root)) what = platform === "win32" ? "a drive root" : "the filesystem root";
  else if (platform === "win32") {
    const drive = env.SystemDrive || "C:";
    const windows = env.SystemRoot || env.windir || `${drive}\\Windows`;
    const exact = [env.ProgramFiles || `${drive}\\Program Files`, env["ProgramFiles(x86)"] || `${drive}\\Program Files (x86)`, env.ProgramData || `${drive}\\ProgramData`, `${drive}\\Users`];
    if (within(windows)) what = at === norm(windows) ? "the Windows directory" : `an operating-system directory (inside ${windows})`;
    else if (exact.some((d) => at === norm(d))) what = "an operating-system directory";
  } else if (POSIX_SYSTEM_TREES.some(within)) what = `an operating-system directory (inside ${POSIX_SYSTEM_TREES.find(within)})`;
  else if (POSIX_SYSTEM_DIRS.some((d) => at === norm(d))) what = "an operating-system directory";
  // WSL mounts each Windows drive at /mnt/<letter>.
  else if (/^\/mnt\/[a-z]$/.test(at)) what = "a drive root";
  if (!what) return null;
  return `"${dir}" is ${what}, not a project, so it is not scanned: a scan there would read every lockfile below it and send each package name and version to OSV.dev and the registries. Pass project_path with the absolute path of your project's root (or set FOURDA_PROJECT_DIR for the server).`;
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
    const refused = systemDirectoryProblem(abs);
    if (refused) return { kind: "error", error: `project_path ${refused}` };
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
