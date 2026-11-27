// SPDX-License-Identifier: Apache-2.0
/**
 * NOTES: how it reads; not part of the contract (what-should-i-know.ts THE CONTRACT).
 *
 * Advisory-database rows in the 4DA feed about a package a task touches.
 *
 * Only the feed's advisory sources count (`cve`, `osv`). A row is about a package only when the
 * app's copy of the advisory (`osv_advisories`, by the row's advisory id or an alias of it) or the
 * row itself (the app's OSV feed writes "<name> (<ecosystem>)") names that package in that
 * ecosystem, by its exact name. A word in the text is not a package: the node-forge and fast-jwt
 * advisories ("RSA signature forgery") were listed under the Rust crate `rsa`, and OpenAI company
 * news became "Critical: Security issue affects openai" (2026-10-01). Rows the relevance judge
 * rejected (`feed_relevant = 0`) are left out. These rows are NOT matched to installed versions;
 * the briefing says so, and with a ready scan keeps them only for packages the scan confirms
 * vulnerable.
 */

import type { FourDADatabase } from "../db.js";
import { isMaintenanceNotice } from "../live/maintenance.js";
import { normalizeStoredPriority } from "./signal-classifier.js";
import type { TaskPackage } from "./briefing-task-scope.js";

export interface StoredAdvisory {
  package: string;
  ecosystem: string;
  title: string;
  url: string | null;
  priority: string;
  /** The row reads as a maintenance notice ("X is unmaintained"), not a vulnerability. */
  maintenance: boolean;
}

const ADVISORY_SOURCES = ["cve", "osv"];

/** A package an advisory row is about. */
interface Subject {
  name: string;
  ecosystem: string;
}

/** The same package name, as the ecosystem compares names (crates: `-` and `_` alike; PyPI: PEP 503). */
function sameName(a: string, b: string, ecosystem: string): boolean {
  const norm = (s: string) => {
    const lower = s.trim().toLowerCase();
    if (ecosystem === "crates.io") return lower.replace(/_/g, "-");
    if (ecosystem === "PyPI") return lower.replace(/[-_.]+/g, "-");
    return lower;
  };
  return norm(a) === norm(b);
}

/** The packages the row states it is about: "<name> (<ecosystem>)" first, or on an "Affected:" line. */
function statedSubjects(content: string | null): Subject[] {
  const text = content ?? "";
  const out: Subject[] = [];
  const first = /^(\S+) \(([^)\n]+)\)\s*\n/.exec(text);
  if (first) out.push({ name: first[1], ecosystem: first[2] });
  for (const m of text.matchAll(/^Affected: (\S+) \(([^)\n]+)\)[ \t\r]*$/gm)) out.push({ name: m[1], ecosystem: m[2] });
  return out;
}

export function storedAdvisoriesFor(db: FourDADatabase, packages: TaskPackage[], limit = 5): StoredAdvisory[] {
  if (packages.length === 0) return [];
  const raw = db.getRawDb();
  const hasFeedRelevant = db.hasColumn("source_items", "feed_relevant");
  // The app's copy of OSV.dev: which package, in which ecosystem, an advisory id (or alias) is about.
  const mirror = (() => {
    if (!db.hasColumn("osv_advisories", "advisory_id") || !db.hasColumn("osv_advisories", "package_name") || !db.hasColumn("osv_advisories", "ecosystem")) return null;
    const aliases = db.hasColumn("osv_advisories", "aliases");
    try {
      const stmt = raw.prepare(`SELECT package_name AS name, ecosystem FROM osv_advisories WHERE upper(advisory_id) = ?${aliases ? " OR upper(aliases) LIKE ? ESCAPE '\\'" : ""}`);
      return (id: string): Subject[] => {
        const key = id.trim().toUpperCase();
        if (!key) return [];
        return (aliases ? stmt.all(key, `%"${key.replace(/[\\%_]/g, "\\$&")}"%`) : stmt.all(key)) as Subject[];
      };
    } catch {
      return null;
    }
  })();
  const out: StoredAdvisory[] = [];
  for (const pkg of packages) {
    const name = pkg.name.toLowerCase();
    let rows: Array<{ title: string; url: string | null; signal_priority: string | null; source_id: string | null; content: string | null }>;
    try {
      rows = raw
        .prepare(
          `SELECT title, url, signal_priority, source_id, content FROM source_items
           WHERE source_type IN (${ADVISORY_SOURCES.map(() => "?").join(", ")})
             AND created_at > datetime('now', '-90 days')
             AND (LOWER(title) LIKE ? OR LOWER(content) LIKE ?)
             ${hasFeedRelevant ? "AND (feed_relevant IS NULL OR feed_relevant = 1)" : ""}${db.enabledSourceClause("source_type")}
           ORDER BY created_at DESC LIMIT 50`,
        )
        .all(...ADVISORY_SOURCES, `%${name}%`, `%${name}%`) as typeof rows;
    } catch {
      continue;
    }
    for (const row of rows) {
      // What the app's copy of the advisory says first; the row's own statement when it has none.
      const known = mirror?.(row.source_id ?? "") ?? [];
      const subjects = known.length > 0 ? known : statedSubjects(row.content);
      if (!subjects.some((s) => s.ecosystem.toLowerCase() === pkg.ecosystem.toLowerCase() && sameName(s.name, pkg.name, pkg.ecosystem))) continue;
      out.push({
        package: pkg.name,
        ecosystem: pkg.ecosystem,
        title: row.title,
        url: row.url,
        priority: row.signal_priority ? normalizeStoredPriority(row.signal_priority) : "medium",
        maintenance: isMaintenanceNotice({ summary: row.title }),
      });
      if (out.length >= limit) return out;
    }
  }
  return out;
}
