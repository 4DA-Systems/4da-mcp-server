// SPDX-License-Identifier: Apache-2.0
/**
 * Transitive dev/runtime scope from the desktop app's dependency inventory.
 *
 * A lockfile read tells the MCP server whether a package is direct. For a
 * transitive it cannot tell dev from runtime, so under the shared severity
 * rule a transitive gets the clamp but never the dev discount. In
 * full-database mode the app's `dependency_instances` table records every
 * installed instance with `is_dev` and `scope`; this module reads it.
 *
 * Only a real determination counts: `is_dev = 1`, or a `scope` of runtime,
 * dev or build. The app's current writers stamp every row `is_dev = 0,
 * scope = 'unknown'` as a placeholder. Reading that as "known runtime" would
 * claim a certainty the app itself does not have. The grade would not change
 * (unknown and runtime both get no discount), but `dev_scope_known` would lie.
 *
 * A row saying dev is never used: it would lower a grade on the app's word
 * alone, and the app's inventory can be older than the lockfile on disk
 * (audit 2026-11-25, G-2). See applyInstanceDevScope.
 */

import type { SqliteDatabase } from "../sqlite-driver.js";
import type { ResolvedDependency } from "./types.js";

interface InstanceScope {
  known: boolean;
  isDev: boolean;
}

type ScopeIndex = Map<string, InstanceScope>;

const DETERMINED_SCOPES = new Set(["runtime", "dev", "build"]);

/**
 * A project path in the app's storage form: forward slashes, lowercased on
 * Windows only. Must match `project_inclusion::canonical_storage_path` in the
 * app, or the lookup misses every row.
 */
export function canonicalStoragePath(p: string): string {
  const forward = p.replace(/\\/g, "/").replace(/\/+$/, "");
  return process.platform === "win32" ? forward.toLowerCase() : forward;
}

function instanceKey(ecosystem: string, name: string, version: string): string {
  const normalized = ecosystem === "PyPI" ? name.toLowerCase() : name;
  return `${normalized}\0${version}`;
}

function hasInstancesTable(db: SqliteDatabase): boolean {
  try {
    return (
      db
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'dependency_instances'")
        .get() !== undefined
    );
  } catch {
    return false;
  }
}

/** Every instance row for one (project, ecosystem), keyed by name + version. Null when unreadable. */
function loadScopeIndex(db: SqliteDatabase, dir: string, ecosystem: string): ScopeIndex | null {
  const project = canonicalStoragePath(dir);
  type Row = { package_name: string; version: string; is_dev: number; scope?: string | null };
  let rows: Row[];
  try {
    rows = db
      .prepare(
        "SELECT package_name, version, is_dev, scope FROM dependency_instances WHERE project_path = ? AND ecosystem = ?",
      )
      .all(project, ecosystem) as Row[];
  } catch {
    try {
      // A table without the `scope` column: only `is_dev = 1` can count.
      rows = db
        .prepare(
          "SELECT package_name, version, is_dev FROM dependency_instances WHERE project_path = ? AND ecosystem = ?",
        )
        .all(project, ecosystem) as Row[];
    } catch {
      return null;
    }
  }
  const index: ScopeIndex = new Map();
  for (const row of rows) {
    const scope = (row.scope ?? "").toLowerCase();
    const isDev = row.is_dev === 1 || scope === "dev";
    index.set(instanceKey(ecosystem, row.package_name, row.version), {
      known: row.is_dev === 1 || DETERMINED_SCOPES.has(scope),
      isDev,
    });
  }
  return index;
}

/**
 * Mark transitive dependencies whose scope the lockfile on disk does not say
 * (devScopeKnown false) as known RUNTIME when the app determined runtime for
 * them in every workspace that pins them. The app's data never lowers a grade
 * (audit 2026-11-25, G-2): a row saying dev, however recent, changes nothing,
 * and a scope the server's own lockfile reading already knows (npm's `dev`
 * flag) is never overridden. The app's inventory can be older than the
 * lockfile (it is rewritten only when the app rescans), and a stale dev row
 * lowered severities and dropped vulnerable packages from the health count
 * (6 -> 3). Direct dependencies are untouched: their manifest already says.
 * Returns new objects; never throws; a database without the table changes
 * nothing.
 */
export function applyInstanceDevScope(
  db: SqliteDatabase | null,
  deps: ResolvedDependency[],
): ResolvedDependency[] {
  if (!db || !hasInstancesTable(db)) return deps;
  const indexes = new Map<string, ScopeIndex | null>();
  const indexFor = (dir: string, ecosystem: string) => {
    const key = `${canonicalStoragePath(dir)}\0${ecosystem}`;
    if (!indexes.has(key)) indexes.set(key, loadScopeIndex(db, dir, ecosystem));
    return indexes.get(key) ?? null;
  };

  return deps.map((dep) => {
    if (dep.isDirect || dep.devScopeKnown || !dep.version || dep.sourceDirs.length === 0) return dep;
    for (const dir of dep.sourceDirs) {
      const row = indexFor(dir, dep.ecosystem)?.get(instanceKey(dep.ecosystem, dep.name, dep.version));
      // Only a determined runtime row counts; a dev row would lower the grade on the app's word alone.
      if (!row || !row.known || row.isDev) return dep;
    }
    return { ...dep, devScopeKnown: true, isDev: false };
  });
}
