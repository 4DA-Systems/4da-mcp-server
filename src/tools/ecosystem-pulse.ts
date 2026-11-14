// SPDX-License-Identifier: Apache-2.0
/**
 * ecosystem_pulse tool
 *
 * Surfaces live ecosystem news relevant to the user's tech stack.
 * Data is already fetched on server startup from Hacker News via Algolia API.
 * This tool makes it queryable.
 */

import * as fs from "node:fs";
import type { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { scanCurrentProject } from "../project-scanner.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { COMMON_WORDS } from "./briefing-task-scope.js";
import { isWithin, normalizeProjectPath, systemDirectoryProblem } from "./project-scope.js";

export interface EcosystemPulseParams {
  min_points?: number;
  limit?: number;
}

interface EcosystemPulseResult {
  headlines: Array<{
    title: string;
    url: string | null;
    points: number;
    comments: number;
    published: string;
    relevance_score: number;
    relevance_reason: string;
    hn_discussion: string;
  }>;
  total: number;
  source: string;
  note: string;
}

export const ecosystemPulseTool = {
  name: "ecosystem_pulse",
  description:
    "Live ecosystem news relevant to your tech stack. Surfaces trending Hacker News discussions filtered by your detected technologies. Updated on server startup.",
  inputSchema: {
    type: "object" as const,
    properties: {
      min_points: {
        type: "number",
        description: "Minimum HN points to include. Default: 0",
      },
      limit: {
        type: "number",
        description: "Maximum headlines to return. Default: 15",
      },
    },
  },
};

/** Languages: matching a headline on one is matching the whole language's news. */
const LANGUAGES = new Set(["rust", "javascript", "typescript", "python", "go", "golang", "java", "kotlin", "ruby", "php", "c", "c++", "c#", "swift", "dart", "npm"]);
const MAX_TERMS = 8;

/**
 * The terms HN headlines are searched and matched on: the frameworks the
 * project uses and its most-used direct dependencies — names specific enough
 * that a headline naming one is about something this project runs. Language
 * names are the fallback only: matched on "rust", the pulse was "What Zig felt
 * like, coming from Rust" and an Emacs fork (live 2026-10-01). Package names
 * that are everyday words are left out (they match unrelated titles).
 * Works on both the desktop DB and the standalone minimal schema.
 *
 * Only the CURRENT project's (`live.getProjectRoot()`): the database is shared by every project a
 * server was started in (and the desktop app indexes every project it sees), and a server started
 * in a public project searched Hacker News for `acme-ledger`, another project's private package,
 * and for that project's public stack too (blind audit round 4). A term is also never sent when the
 * current rules call it private in any ecosystem, or when another project the database knows
 * installs it from a private source. No project known: no terms.
 */
export function deriveTechStackForHeadlines(db: FourDADatabase, live: PulseScope | null = null): string[] {
  const root = live?.getProjectRoot?.() ?? null;
  if (!root) return [];
  const terms: string[] = [];
  const add = (term: string | null | undefined) => {
    const t = (term ?? "").toLowerCase().trim();
    if (t.length >= 3 && !LANGUAGES.has(t) && !COMMON_WORDS.has(t) && !terms.includes(t) && !t.includes("/")) terms.push(t);
  };
  const rawDb = db.getRawDb();
  const rows = dependencyRows(db);
  const here = rows.filter((r) => !!r.project_path && isWithin(r.project_path, root));
  // Ranked by how many projects use a name (a count, nothing else of theirs), then by name.
  const users = new Map<string, Set<string>>();
  for (const r of rows) {
    const key = (r.package_name ?? "").toLowerCase();
    const set = users.get(key) ?? new Set<string>();
    set.add(r.project_path ?? "");
    users.set(key, set);
  }
  const fromDb = here.filter((r) => r.is_direct === undefined || r.is_direct === null || Number(r.is_direct) === 1).map((r) => r.package_name);
  // A project the database does not track (desktop mode reading it from disk): the live layer's own direct dependencies.
  const fromLive = here.length === 0 ? (live?.getResolvedDeps?.() ?? []).filter((d) => d.isDirect).map((d) => d.name) : [];
  const ownNames = [...new Set([...fromDb, ...fromLive].map((n) => (n ?? "").toLowerCase()))].sort(
    (a, b) => (users.get(b)?.size ?? 0) - (users.get(a)?.size ?? 0) || a.localeCompare(b),
  );
  // Frameworks: the ones this project's own manifests name, ranked by the database's confidence.
  const scan = safeScan(root);
  const ownFrameworks = new Set((scan?.frameworks ?? []).map((f) => f.toLowerCase()));
  const ownNameSet = new Set(ownNames);
  try {
    for (const row of rawDb
      .prepare("SELECT name FROM detected_tech WHERE category IN ('framework', 'library') ORDER BY confidence DESC LIMIT 50")
      .all() as Array<{ name: string }>) {
      const name = (row.name ?? "").toLowerCase();
      if (ownFrameworks.has(name) || ownNameSet.has(name)) add(name);
    }
  } catch {
    // detected_tech may not exist on exotic DBs.
  }
  for (const f of ownFrameworks) add(f);
  for (const name of ownNames) add(name);
  // Then the project's languages, as language-level news (labelled so by the
  // fetcher): HN titles rarely name a library in a two-week window, and an
  // asked-for ecosystem pulse should still say what moved in the language.
  const languages: string[] = [];
  for (const term of [...here.map((r) => r.language ?? ""), ...(scan?.languages ?? [])].map((l) => l.toLowerCase())) {
    if (term && PULSE_LANGUAGES.has(term) && !languages.includes(term)) languages.push(term);
  }
  const elsewhere = new PrivateElsewhere(rows, root);
  const specific: string[] = [];
  for (const t of terms) {
    if (specific.length >= MAX_TERMS - 2) break;
    if (!privateNow(live, t) && !elsewhere.reason(t)) specific.push(t);
  }
  return [...specific, ...languages.slice(0, MAX_TERMS - specific.length)];
}

/** What the pulse needs from the live layer: the project it is for, and its private-name rules. */
export type PulseScope = Partial<Pick<LiveIntelligence, "getProjectRoot" | "getResolvedDeps" | "privateReason">>;

type DependencyRow = { package_name: string; project_path: string | null; language: string | null; is_direct?: number | null };

/** Every stored dependency row (any project), or none when the table is missing. */
function dependencyRows(db: FourDADatabase): DependencyRow[] {
  try {
    const direct = db.hasColumn?.("project_dependencies", "is_direct") ? ", is_direct" : "";
    return db.getRawDb().prepare(`SELECT package_name, project_path, language${direct} FROM project_dependencies`).all() as DependencyRow[];
  } catch {
    return [];
  }
}

/** The project scan of `root` (its own manifests), or null when it cannot be read. */
function safeScan(root: string): ReturnType<typeof scanCurrentProject> | null {
  try {
    return scanCurrentProject(root);
  } catch {
    return null;
  }
}

const RULE_ECOSYSTEMS = ["npm", "crates.io", "PyPI", "Go", "RubyGems", "Packagist"];

/** Whether the current project's rules call `term` private, in any ecosystem and any spelling. */
function privateNow(live: PulseScope | null, term: string): boolean {
  const reason = live?.privateReason?.bind(live);
  return reason ? RULE_ECOSYSTEMS.some((eco) => Boolean(reason(eco, term))) : false;
}

/** How many other projects' directories one pulse reads for their private names. */
const MAX_OTHER_PROJECTS = 20;

/**
 * Whether another project the database knows installs a name from a private source. The database
 * stores names, not where they came from, so that project's own files say: its lockfiles' sources
 * and its private-registry rules, read locally (nothing is sent), and only for the projects that
 * store a name this pulse would send.
 */
class PrivateElsewhere {
  private readonly layers = new Map<string, LiveIntelligence | null>();

  constructor(
    private readonly rows: DependencyRow[],
    private readonly root: string,
  ) {}

  reason(term: string): string | null {
    const dirs = new Set<string>();
    for (const r of this.rows) {
      if (r.project_path && (r.package_name ?? "").toLowerCase() === term && !isWithin(r.project_path, this.root)) dirs.add(r.project_path);
    }
    for (const dir of dirs) {
      const live = this.layerFor(dir);
      const why = live ? RULE_ECOSYSTEMS.map((eco) => live.privateReason(eco, term)).find(Boolean) : null;
      if (why) return why;
    }
    return null;
  }

  private layerFor(dir: string): LiveIntelligence | null {
    const key = normalizeProjectPath(dir);
    if (this.layers.has(key)) return this.layers.get(key) ?? null;
    let live: LiveIntelligence | null = null;
    if (this.layers.size < MAX_OTHER_PROJECTS && fs.existsSync(dir) && !systemDirectoryProblem(dir)) {
      try {
        live = new LiveIntelligence(null);
        const { entries, discovery } = scanProjectTree(dir);
        live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
      } catch {
        live = null;
      } finally {
        // Read for its rules only, never a source the request guard consults for other requests.
        live?.dispose();
      }
    }
    this.layers.set(key, live);
    return live;
  }
}

/**
 * Languages with distinctive enough names to search HN for: not
 * "javascript"/"typescript" (they flood), not "go" (an everyday word in titles).
 */
const PULSE_LANGUAGES = new Set(["rust", "python", "zig", "kotlin", "swift", "ruby", "elixir"]);

export async function executeEcosystemPulse(
  db: FourDADatabase,
  params: EcosystemPulseParams,
  liveIntel: LiveIntelligence | null,
): Promise<EcosystemPulseResult> {
  if (!liveIntel) {
    return {
      headlines: [],
      total: 0,
      source: "hacker_news",
      note: "Live intelligence not available. Set FOURDA_OFFLINE=false and restart.",
    };
  }

  // Fetched when asked for, never at startup: the search terms are names from
  // the user's projects, and HN should see them only when the user asks for
  // the pulse. The cache serves warm repeat calls.
  let headlines = liveIntel.getHeadlines();
  let noStack = false;
  if (headlines.length === 0 && liveIntel.isEnabled()) {
    const techStack = deriveTechStackForHeadlines(db, liveIntel);
    if (techStack.length > 0) {
      headlines = await liveIntel.fetchHeadlines(techStack);
    } else {
      noStack = true;
    }
  }
  const minPoints = params.min_points ?? 0;
  const limit = params.limit ?? 15;

  const filtered = headlines
    .filter((h) => h.points >= minPoints)
    .slice(0, limit)
    .map((h) => ({
      title: h.title,
      url: h.url,
      points: h.points,
      comments: h.comments,
      published: h.published,
      relevance_score: h.relevanceScore,
      relevance_reason: h.relevanceReason,
      hn_discussion: `https://news.ycombinator.com/item?id=${h.id}`,
    }));

  return {
    headlines: filtered,
    total: filtered.length,
    source: "hacker_news",
    // Nothing to search for is not "no relevant headlines": nothing was searched (blind audit round 4).
    note: filtered.length === 0 && liveIntel.getHeadlineError?.()
      ? `NOT CHECKED: ${liveIntel.getHeadlineError?.()}, so no headlines were read. This says nothing about your stack: call again later.`
      : filtered.length === 0 && noStack
      ? `NOT CHECKED: no stack was detected for ${liveIntel.getProjectRoot?.() ?? "this project"} (no dependency or framework this server can search for, or every one is private), so Hacker News was not searched. This says nothing about news for your stack.`
      : filtered.length === 0
      ? "No relevant headlines found for your tech stack. Headlines are filtered by detected technologies."
      : `${filtered.length} headline${filtered.length !== 1 ? "s" : ""} relevant to your tech stack.`,
  };
}
