// SPDX-License-Identifier: Apache-2.0
/**
 * Which of this project's dependencies a task touches, and what is known
 * about each — the core of the what_should_i_know briefing.
 *
 * Measured 2026-10-01: asked about "bump fastembed 5 -> 7", the briefing
 * returned eleven advisories and none about fastembed. It never asked which
 * packages the task names; it merged feed items by recency and keyword class,
 * so a 7-day-old `fastembed v7.1.0` release row was outside its 72-hour window
 * while an arXiv dataset paper and three OpenAI-company headlines were in.
 * This module starts from the task instead: the dependencies it names (exact
 * package names from the resolved dependency set), then facts about exactly
 * those packages.
 */

import type { FourDADatabase } from "../db.js";
import type { ResolvedDependency, VulnerabilityEntry } from "../live/types.js";
import { isActionableVulnerability } from "../live/maintenance.js";
import { presentedSeverity } from "../live/severity-scope.js";
import { compareVersions } from "../live/version-compare.js";

/** A dependency the task names, with every installed copy. */
export interface TaskPackage {
  name: string;
  ecosystem: string;
  installed: string[];
  direct: boolean;
  dev: boolean;
  /** Versions the task text names after the package ("5.x to 7.x" -> from 5.x, to 7.x). */
  requested_from: string | null;
  requested_to: string | null;
  /** Set when the package was found through a family the task names ("all tauri plugins" -> "tauri"). */
  family?: string;
}

/**
 * Package names that are also everyday words. One of these counts as named
 * only with a qualifier beside it — "the next crate", "`next`", "upgrade
 * next to 15" — so "the next step" does not drag the `next` package in.
 */
export const COMMON_WORDS = new Set([
  "next", "open", "debug", "ms", "ai", "test", "core", "util", "utils", "path", "fs", "os", "url", "http",
  "log", "time", "rand", "bytes", "once", "glob", "which", "yes", "color", "colors", "async", "events",
  "image", "regex", "net", "io", "fetch", "form", "data", "config", "cache", "queue", "stream",
  "buffer", "assert", "base", "env", "error", "errors", "string", "table", "tree",
  "safe", "lock", "slash", "sort", "type", "types", "web",
]);

const QUALIFIERS = /^(?:crate|crates|package|packages|pkg|dependency|dependencies|dep|deps|library|lib|module|version|upgrade|upgrading|bump|bumping|update|updating|migrate|migrating|install|v?\d[\w.*-]*)$/i;

const VERSION_TOKEN = /^v?\d+(?:\.(?:\d+|x|\*))*(?:\.\d+)?(?:-[\w.]+)?$/i;

/** Lowercased word-ish tokens, keeping package punctuation (@scope/name, a-b_c.d). */
function tokenize(text: string): string[] {
  return (text.match(/[@A-Za-z0-9][\w./@*-]*/g) ?? []).map((t) => t.replace(/[.,;:)]+$/, "").toLowerCase());
}

/** Spellings a token may name a dependency by. */
function nameKeys(dep: ResolvedDependency): string[] {
  const name = dep.name.toLowerCase();
  const keys = new Set([name]);
  if (dep.ecosystem === "crates.io") {
    keys.add(name.replace(/-/g, "_"));
    keys.add(name.replace(/_/g, "-"));
  }
  if (dep.ecosystem === "PyPI") keys.add(name.replace(/[-_.]+/g, "-"));
  if (dep.ecosystem === "Go") {
    const last = name.split("/").pop() ?? name;
    if (last.length >= 3 && !/^v\d+$/.test(last)) keys.add(last);
  }
  return [...keys];
}

/**
 * The dependencies a task (and its file list) names. Exact names only; a
 * common-word name needs a qualifier within two tokens or code quoting.
 * Direct dependencies first; at most `limit` packages.
 */
export function detectTaskPackages(
  task: string,
  files: string[],
  deps: ResolvedDependency[],
  limit = 5,
): TaskPackage[] {
  const quoted = new Set((task.match(/`([^`]+)`/g) ?? []).map((q) => q.slice(1, -1).toLowerCase()));
  const tokens = tokenize(`${task} ${files.join(" ")}`);
  const byKey = new Map<string, ResolvedDependency[]>();
  for (const dep of deps) {
    if (!dep.name) continue;
    for (const key of nameKeys(dep)) byKey.set(key, [...(byKey.get(key) ?? []), dep]);
  }

  const found = new Map<string, { deps: ResolvedDependency[]; at: number }>();
  tokens.forEach((token, i) => {
    const matches = byKey.get(token);
    if (!matches) return;
    if (COMMON_WORDS.has(token) && !quoted.has(token)) {
      const window = [...tokens.slice(Math.max(0, i - 2), i), ...tokens.slice(i + 1, i + 3)];
      if (!window.some((w) => QUALIFIERS.test(w))) return;
    }
    const key = `${matches[0].ecosystem}\0${matches[0].name}`;
    if (!found.has(key)) found.set(key, { deps: matches, at: i });
  });

  const packages = [...found.values()].map(({ deps: copies, at }) => {
    const versions = tokens.slice(at + 1, at + 8).filter((t) => VERSION_TOKEN.test(t));
    const first = copies[0];
    return {
      name: first.name,
      ecosystem: first.ecosystem,
      installed: [...new Set(copies.map((d) => d.version).filter((v): v is string => Boolean(v)))],
      direct: copies.some((d) => d.isDirect),
      dev: copies.every((d) => d.isDev),
      requested_from: versions.length >= 2 ? versions[0] : null,
      requested_to: versions.length >= 1 ? versions[versions.length - 1] : null,
    };
  });
  packages.sort((a, b) => Number(b.direct) - Number(a.direct));
  return packages.slice(0, limit);
}

/** Words after a name that make it a family: "tauri plugins", "@tauri-apps packages". */
const FAMILY_NOUNS = /^(?:plugins?|packages?|crates?|family|families|ecosystem|deps|dependencies|libraries|libs|modules|siblings)$/i;

/**
 * The package families a task names, as base names: "all tauri plugins",
 * "tauri and its plugins", "@tauri-apps packages", "tauri-plugin-*",
 * "@tauri-apps/*". A name alone ("bump tauri") is not a family.
 */
export function detectFamilyBases(task: string, files: string[] = []): string[] {
  const tokens = tokenize(`${task} ${files.join(" ")}`);
  const bases = new Set<string>();
  let lastName: string | null = null;
  tokens.forEach((token, i) => {
    // Globs: "tauri-plugin-*" -> tauri, "@tauri-apps/*" -> @tauri-apps.
    const glob = /^(@?[a-z0-9][\w.-]*?)(?:-plugin)?(?:[-_/]\*)$/.exec(token);
    if (glob) {
      bases.add(glob[1]);
      return;
    }
    const next = tokens[i + 1];
    if (next && FAMILY_NOUNS.test(next) && /^@?[a-z][\w.@/-]*$/.test(token) && !FAMILY_NOUNS.test(token)) {
      if (!/^(?:all|every|its|their|the|other|any|some|these|those|related|official|first-party|in|of|for|with|from|our|my|your|and|or|to|dev|npm|cargo|pip|go|rust|js|node|python|workspace|root|outdated|vulnerable|new|old|unused|direct|transitive)$/.test(token)) {
        bases.add(token);
      } else if (token === "its" || token === "their") {
        // "tauri and its plugins": the name the possessive refers to.
        if (lastName) bases.add(lastName);
      }
    }
    if (/^@?[a-z][\w.@/-]*$/.test(token) && !FAMILY_NOUNS.test(token) && !/^(?:and|or|its|their|all|every|to|the|bump|upgrade|update)$/.test(token)) {
      lastName = token;
    }
  });
  return [...bases];
}

/** True when `name` belongs to the family of `base`: base-*, base_*, @base/*, @base-apps/*. */
export function inFamily(name: string, base: string): boolean {
  const n = name.toLowerCase();
  const b = base.toLowerCase();
  if (n === b) return false;
  if (b.startsWith("@")) return n.startsWith(`${b}/`);
  return (
    n.startsWith(`${b}-`) ||
    n.startsWith(`${b}_`) ||
    n.startsWith(`@${b}/`) ||
    n.startsWith(`@${b}-`) // @tauri-apps/api, @tauri-apps/plugin-shell
  );
}

/**
 * The direct dependencies in the families the task names, other than the
 * packages it names exactly. Only packages this project actually declares:
 * a family is expanded against the lockfiles, never guessed. Measured
 * 2026-10-07: "bump tauri and all tauri plugins" matched only `tauri`.
 */
export function detectFamilyPackages(
  task: string,
  files: string[],
  deps: ResolvedDependency[],
  exact: TaskPackage[],
  limit = 25,
): TaskPackage[] {
  const bases = detectFamilyBases(task, files);
  if (bases.length === 0) return [];
  const taken = new Set(exact.map((p) => `${p.ecosystem}\0${p.name}`));
  const groups = new Map<string, { base: string; copies: ResolvedDependency[] }>();
  for (const dep of deps) {
    if (!dep.name || !dep.isDirect) continue;
    const key = `${dep.ecosystem}\0${dep.name}`;
    if (taken.has(key)) continue;
    const base = bases.find((b) => inFamily(dep.name, b));
    if (!base) continue;
    const group = groups.get(key) ?? { base, copies: [] };
    group.copies.push(dep);
    groups.set(key, group);
  }
  const out = [...groups.values()].map(({ base, copies }) => ({
    name: copies[0].name,
    ecosystem: copies[0].ecosystem,
    installed: [...new Set(copies.map((d) => d.version).filter((v): v is string => Boolean(v)))],
    direct: true,
    dev: copies.every((d) => d.isDev),
    requested_from: null,
    requested_to: null,
    family: base,
  }));
  out.sort((a, b) => a.ecosystem.localeCompare(b.ecosystem) || a.name.localeCompare(b.name));
  return out.slice(0, limit);
}

/** True when the task asks for the newest release ("to latest", "newest major"). */
export function wantsLatest(task: string): boolean {
  return /\b(?:latest|newest|most recent)\b/i.test(task);
}

/** The caret line a version sits on: "2" for 2.12.1, "0.13" for 0.13.5. */
export function caretLine(version: string | null): string | null {
  const m = version ? /^v?(\d+)\.(\d+)/.exec(version) : null;
  if (!m) return null;
  return m[1] === "0" ? `0.${m[2]}` : m[1];
}

/** Actionable advisories on the installed copies of one package, highest presented severity first. */
export function advisoriesFor(pkg: TaskPackage, vulns: VulnerabilityEntry[]) {
  const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
  return vulns
    .filter((v) => v.package === pkg.name && v.ecosystem === pkg.ecosystem && isActionableVulnerability(v))
    .map((v) => ({
      id: v.vulnId,
      installed: v.currentVersion,
      severity: presentedSeverity(v),
      fixed_version: v.fixedVersion,
      summary: v.summary.length > 160 ? `${v.summary.slice(0, 157)}...` : v.summary,
    }))
    .sort((a, b) => rank[b.severity] - rank[a.severity]);
}

const RELEASE_SOURCES: Record<string, { source: string; prefix: string }> = {
  "crates.io": { source: "crates_io", prefix: "crates.io: " },
  npm: { source: "npm_registry", prefix: "npm: " },
};

/**
 * Registry release rows the desktop app's feed holds for one package, newer
 * than the installed version. Matched on the registry's own title format
 * (`crates.io: fastembed v7.1.0`), never on a free-text mention. Empty in
 * standalone mode (no feed) or for ecosystems the feed does not watch.
 */
export function releasesFor(db: FourDADatabase, pkg: TaskPackage): Array<{ version: string; seen: string; url: string | null }> {
  const spec = RELEASE_SOURCES[pkg.ecosystem];
  if (!spec) return [];
  let rows: Array<{ title: string; url: string | null; created_at: string }>;
  try {
    rows = db
      .getRawDb()
      .prepare(
        `SELECT title, url, created_at FROM source_items
         WHERE source_type = ? AND title LIKE ? ORDER BY created_at DESC LIMIT 50`,
      )
      .all(spec.source, `${spec.prefix}${pkg.name} v%`) as typeof rows;
  } catch {
    return [];
  }
  const newest = pkg.installed.reduce<string | null>(
    (max, v) => (max === null || compareVersions(v, max, pkg.ecosystem) > 0 ? v : max),
    null,
  );
  const seen = new Set<string>();
  const out: Array<{ version: string; seen: string; url: string | null }> = [];
  for (const row of rows) {
    const version = row.title.slice(`${spec.prefix}${pkg.name} v`.length).trim();
    if (!version || seen.has(version) || (row.title !== `${spec.prefix}${pkg.name} v${version}`)) continue;
    if (newest && compareVersions(version, newest, pkg.ecosystem) <= 0) continue;
    seen.add(version);
    out.push({ version, seen: row.created_at, url: row.url });
  }
  return out.sort((a, b) => compareVersions(b.version, a.version, pkg.ecosystem)).slice(0, 5);
}

/**
 * Feed items about the task's packages that the app's relevance judge
 * accepted (latest `llm_judgments` verdict >= 0.5) and that the feed kept
 * (`feed_relevant` = 1). Exact package-name match on a word boundary in the
 * title. Third-party text: reported as data. Empty without the desktop feed.
 */
export function judgedReadingFor(db: FourDADatabase, packages: TaskPackage[], limit = 5) {
  if (packages.length === 0) return [];
  const raw = db.getRawDb();
  let rows: Array<{ id: number; title: string; url: string | null; source_type: string; verdict: number; created_at: string }>;
  try {
    rows = raw
      .prepare(
        `WITH latest AS (
           SELECT source_item_id, relevance_score,
                  ROW_NUMBER() OVER (PARTITION BY source_item_id ORDER BY id DESC) AS rn
           FROM llm_judgments)
         SELECT s.id, s.title, s.url, s.source_type, l.relevance_score AS verdict, s.created_at
         FROM source_items s JOIN latest l ON l.source_item_id = s.id AND l.rn = 1
         WHERE s.feed_relevant = 1 AND l.relevance_score >= 0.5
           AND s.created_at > datetime('now', '-30 days')
         ORDER BY l.relevance_score DESC, s.created_at DESC LIMIT 2000`,
      )
      .all() as typeof rows;
  } catch {
    return [];
  }
  const patterns = packages.map((p) => ({
    name: p.name,
    re: new RegExp(`(^|[^\\w@/-])${p.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w-])`, "i"),
  }));
  const out: Array<{ id: number; title: string; url: string | null; source: string; judge_relevance: number; package: string }> = [];
  for (const row of rows) {
    const hit = patterns.find((p) => p.re.test(row.title));
    if (!hit) continue;
    out.push({ id: row.id, title: row.title, url: row.url, source: row.source_type, judge_relevance: Math.round(row.verdict * 100) / 100, package: hit.name });
    if (out.length >= limit) break;
  }
  return out;
}
