// SPDX-License-Identifier: Apache-2.0
/**
 * NOTES: how it reads; not part of the contract (what-should-i-know.ts THE CONTRACT).
 *
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
import { isActionableVulnerability, isMaintenanceNotice } from "../live/maintenance.js";
import { presentedSeverity } from "../live/severity-scope.js";
import { collapseAliases } from "./vulnerability-scan-format.js";
import { compareVersions } from "../live/version-compare.js";
import { quoteThirdParty } from "../untrusted-text.js";

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

/**
 * For each token of tokenize(text): whether a clause ends after it (a comma, semicolon or full
 * stop follows it). A version is read only from its package's own clause.
 */
function clauseBreaks(text: string): boolean[] {
  const found = [...text.matchAll(/[@A-Za-z0-9][\w./@*-]*/g)];
  return found.map((m, i) => {
    const end = (m.index ?? 0) + m[0].length;
    const gap = text.slice(end, i + 1 < found.length ? (found[i + 1].index ?? end) : text.length);
    return /[.,;:]$/.test(m[0]) || /[,;]|\.(?:\s|$)/.test(gap);
  });
}

/** Words that start another clause or action: the versions after one belong to it, not to the package before. */
const CLAUSE_WORDS = /^(?:and|then|also|plus|but|while|after|before|or|&|add|adding|install|installing|upgrade|upgrading|bump|bumping|update|updating|remove|removing|uninstall|drop|pin|pinning|downgrade|downgrading|replace|replacing|migrate|migrating|swap|set|use|require)$/;

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
    // One package per ecosystem and name: jsonwebtoken on crates.io and jsonwebtoken on npm are two
    // packages, each with its own copies (one row of both read `installed: ["11.1.0", "9.0.3"]`).
    for (const dep of matches) {
      const key = `${dep.ecosystem}\0${dep.name}`;
      const entry = found.get(key);
      if (!entry) found.set(key, { deps: [dep], at: i });
      else if (entry.at === i) entry.deps.push(dep);
    }
  });

  // The versions after a name, up to the end of its clause: another verb, a joiner ("and", "then"),
  // another dependency's name or punctuation ends it. "upgrade minimist to 1.2.8 and install react
  // 18.3.1" gave minimist from 1.2.8 to 18.3.1.
  const breaks = clauseBreaks(`${task} ${files.join(" ")}`);
  const clauseVersions = (at: number): string[] => {
    const out: string[] = [];
    if (breaks[at]) return out;
    for (let j = at + 1; j < Math.min(tokens.length, at + 8); j++) {
      const t = tokens[j];
      if (CLAUSE_WORDS.test(t) || byKey.has(t)) break;
      if (VERSION_TOKEN.test(t)) out.push(t);
      if (breaks[j]) break;
    }
    return out;
  };
  const packages = [...found.values()].map(({ deps: copies, at }) => {
    const versions = clauseVersions(at);
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

/** A package's name as a sentence says it: with its ecosystem when another ecosystem's package in `all` has the same name. */
export function packageLabel(pkg: { name: string; ecosystem: string }, all: ReadonlyArray<{ name: string; ecosystem: string }>): string {
  const twin = all.some((p) => p.ecosystem !== pkg.ecosystem && p.name.toLowerCase() === pkg.name.toLowerCase());
  return twin ? `${pkg.name} (${pkg.ecosystem})` : pkg.name;
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
  // One row per advisory, as vulnerability_scan counts them: the aliases of one advisory (GHSA,
  // PYSEC, CVE records) were each a row, so django read 96 confirmed vulnerabilities where the scan,
  // health and planner said 51 (audit 6.2.5 D-7).
  return collapseAliases(vulns.filter((v) => v.package === pkg.name && v.ecosystem === pkg.ecosystem && isActionableVulnerability(v)))
    .map((v) => ({
      id: v.vulnId,
      installed: v.currentVersion,
      severity: presentedSeverity(v),
      fixed_version: v.fixedVersion,
      // OSV.dev's text: one line, capped.
      summary: quoteThirdParty(v.summary, 160),
    }))
    .sort((a, b) => rank[b.severity] - rank[a.severity]);
}

/**
 * The maintenance notices ("X is unmaintained") on the installed copies of one package that this
 * host builds: listed apart from its vulnerabilities, as the scan lists them, never as an
 * advisory with no fix.
 */
export function maintenanceNoticesFor(pkg: TaskPackage, vulns: VulnerabilityEntry[]): Array<{ id: string; installed: string; summary: string }> {
  return collapseAliases(vulns.filter((v) => v.package === pkg.name && v.ecosystem === pkg.ecosystem && v.platformActive !== false && isMaintenanceNotice(v))).map((v) => ({
    id: v.vulnId,
    installed: v.currentVersion,
    summary: quoteThirdParty(v.summary, 160),
  }));
}

const RELEASE_SOURCES: Record<string, { source: string; prefix: string }> = {
  "crates.io": { source: "crates_io", prefix: "crates.io: " },
  npm: { source: "npm_registry", prefix: "npm: " },
};

/**
 * Registry release rows the desktop app's feed holds for one package, newer
 * than the installed version. Matched on the registry's own title format
 * (`crates.io: fastembed v7.1.0`), never on a free-text mention. Null when the
 * feed holds no release of this package at all (standalone mode, an ecosystem
 * the feed does not watch, a package it does not follow): that is no answer,
 * and [] would read as "nothing newer". [] only when it follows the package and
 * recorded nothing above the installed version.
 */
export function releasesFor(db: FourDADatabase, pkg: TaskPackage): Array<{ version: string; seen: string; url: string | null }> | null {
  const spec = RELEASE_SOURCES[pkg.ecosystem];
  if (!spec) return null;
  let rows: Array<{ title: string; url: string | null; created_at: string }>;
  try {
    rows = db
      .getRawDb()
      .prepare(
        `SELECT title, url, created_at FROM source_items
         WHERE source_type = ? AND title LIKE ?${db.enabledSourceClause("source_type")} ORDER BY created_at DESC LIMIT 50`,
      )
      .all(spec.source, `${spec.prefix}${pkg.name} v%`) as typeof rows;
  } catch {
    return null;
  }
  const newest = pkg.installed.reduce<string | null>(
    (max, v) => (max === null || compareVersions(v, max, pkg.ecosystem) > 0 ? v : max),
    null,
  );
  const seen = new Set<string>();
  const out: Array<{ version: string; seen: string; url: string | null }> = [];
  let follows = false;
  for (const row of rows) {
    const version = row.title.slice(`${spec.prefix}${pkg.name} v`.length).trim();
    if (!version || seen.has(version) || (row.title !== `${spec.prefix}${pkg.name} v${version}`)) continue;
    follows = true;
    if (newest && compareVersions(version, newest, pkg.ecosystem) <= 0) continue;
    seen.add(version);
    out.push({ version, seen: row.created_at, url: row.url });
  }
  if (!follows) return null;
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
           AND s.created_at > datetime('now', '-30 days')${db.enabledSourceClause("s.source_type")}
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
