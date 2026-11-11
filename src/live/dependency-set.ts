// SPDX-License-Identifier: Apache-2.0
/**
 * Set operations over resolved dependencies, shared by the live layer.
 * (Moved out of live/index.ts; behaviour unchanged except for the install
 * fields, which did not exist before.)
 */

import type { ResolvedDependency, VulnerabilityScanResult } from "./types.js";

/**
 * Deepest common ancestor of a set of directories (segment-wise, both slash
 * styles). Null for an empty set; a single dir is its own root.
 */
export function commonPathRoot(dirs: string[]): string | null {
  if (dirs.length === 0) return null;
  const split = (p: string) => p.replace(/\\/g, "/").replace(/\/+$/, "").split("/");
  let common = split(dirs[0]);
  for (const dir of dirs.slice(1)) {
    const parts = split(dir);
    let i = 0;
    while (i < common.length && i < parts.length && common[i].toLowerCase() === parts[i].toLowerCase()) i++;
    common = common.slice(0, i);
    if (common.length === 0) break;
  }
  return common.length > 0 ? common.join("/") : null;
}

/**
 * One entry per (ecosystem, name, version), with platform activity kept PER LOCKFILE.
 *
 * Whether a crate is built on this host is a fact about one lockfile's resolution, not about a
 * name and a version. The merge ORs it across directories (a crate reachable via any active path
 * is active: nothing a host may build is hidden), and it used to keep nothing else, so the entry
 * could not say WHICH lockfile builds it. One lockfile that cannot be platform-resolved (a stale
 * example lockfile: `cargo tree --locked` fails, so every crate there stays active) then switched
 * the host-platform filter off for every crate it shares with the project's real lockfile, and the
 * finding read as the project's (audit 2026-11-11).
 *
 * `sourceDirs` is still every directory that locks the copy (the inventory the conformance corpus
 * scores per directory). `platformInactiveDirs` now names the ones among them that lock it WITHOUT
 * building it here, so every answer can say where the copy counts and where it does not, and a fix
 * is aimed at the directories that build it.
 */
export function dedupeDependencies(deps: ResolvedDependency[]): ResolvedDependency[] {
  const unique = new Map<string, ResolvedDependency>();
  const add = (list: string[], dirs: readonly string[] | undefined) => {
    for (const dir of dirs ?? []) if (!list.includes(dir)) list.push(dir);
  };
  for (const dep of deps) {
    const key = `${dep.ecosystem}\0${dep.name}\0${dep.version ?? ""}`;
    const existing = unique.get(key);
    if (existing) {
      existing.isDirect ||= dep.isDirect;
      existing.devScopeKnown &&= dep.devScopeKnown;
      existing.isDev = existing.devScopeKnown && existing.isDev && dep.isDev;
      // A crate reachable via ANY active path is active, and its target label
      // is then the active copy's: rsa 0.9.10, built for relay and not for
      // src-tauri on Windows, read "not built for x86_64-pc-windows-msvc"
      // beside platform_active: true (2026-10-02 agent eval).
      if (dep.platformActive && !existing.platformActive) existing.target = dep.target;
      else if (existing.platformActive === dep.platformActive) existing.target = existing.target ?? dep.target;
      // The side that does not build it, when the two disagree: the directories seen so far, or this one's.
      if (existing.platformActive !== dep.platformActive) {
        add((existing.platformInactiveDirs ??= []), existing.platformActive ? dep.sourceDirs : existing.sourceDirs);
      }
      if (dep.platformInactiveDirs) add((existing.platformInactiveDirs ??= []), dep.platformInactiveDirs);
      existing.platformActive ||= dep.platformActive;
      // Union the provenance rather than discarding it — the same version can
      // legitimately be pinned by several workspaces, and the reader needs all
      // of them to know where to apply the fix.
      add(existing.sourceDirs, dep.sourceDirs);
      mergeInstallContext(existing, dep);
    } else {
      unique.set(key, { ...dep, sourceDirs: [...(dep.sourceDirs ?? [])], ...(dep.platformInactiveDirs ? { platformInactiveDirs: [...dep.platformInactiveDirs] } : {}) });
    }
  }
  return [...unique.values()];
}

/**
 * A drift entry exists only because node_modules holds a version the lockfile
 * does not pin. When a lockfile really does pin that same version somewhere,
 * the merged entry is a lockfile instance, not drift, and must not read as
 * "only in node_modules". Two drift entries keep the first one's context.
 * A drifted install reading wins over a matching one, so a merge never hides
 * a disagreement.
 */
function mergeInstallContext(existing: ResolvedDependency, dep: ResolvedDependency): void {
  if (existing.installDriftOf !== undefined && dep.installDriftOf === undefined) {
    existing.installDriftOf = undefined;
    existing.installFix = undefined;
  }
  if (dep.installedVersion === undefined) return;
  const drifted = (d: ResolvedDependency) =>
    d.installedVersion !== undefined && d.installedVersion !== null && d.installedVersion !== d.version;
  if (existing.installedVersion === undefined || (drifted(dep) && !drifted(existing))) {
    existing.installedVersion = dep.installedVersion;
  }
}

/**
 * A scan with no findings. `unchecked` dependencies (offline: none of them
 * could be asked) are counted in `totalScanned` and reported as unchecked,
 * never as clean.
 */
export function emptyVulnResult(
  projectPath: string,
  offline: boolean,
  unchecked: { count: number; reason: string } | null = null,
): VulnerabilityScanResult {
  return {
    scannedAt: new Date().toISOString(),
    projectPath,
    ecosystemsScanned: [],
    totalScanned: unchecked?.count ?? 0,
    totalVulnerable: 0,
    platformInactiveVulnerable: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    vulnerabilities: [],
    cleanCount: 0,
    scanDurationMs: 0,
    cached: false,
    offline,
    unchecked: unchecked?.count ?? 0,
    uncheckedReason: unchecked?.reason ?? null,
    staleAnswers: 0,
  };
}
