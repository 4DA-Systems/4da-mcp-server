// SPDX-License-Identifier: Apache-2.0
/**
 * get_actionable_signals tool
 *
 * Classifies source items into actionable signal types (security alerts,
 * breaking changes, tool discoveries, etc.) with priority levels.
 * Cross-references against the user's ACE-detected tech stack.
 */

import type { FourDADatabase } from "../db.js";
import type { LiveIntelligence } from "../live/index.js";
import type { VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { isMaintenanceNotice } from "../live/maintenance.js";
import { LOOKUPS_DISABLED, vulnerabilityCoverage } from "../live/scan-coverage.js";
import { presentedSeverity, scopeAdjustmentReason } from "../live/severity-scope.js";
import { getLiveIntelligence } from "../live-singleton.js";
import { scanUnfinishedText, withinCallBudget } from "../call-budget.js";
import { adviceFor, FEED_MAINTENANCE_ACTION, maintenanceAction, scanAdvice } from "./scan-advice.js";
import { normalizeStoredPriority, type SignalPriority, type SignalType } from "./signal-classifier.js";
import type { ScanStatus } from "./what-should-i-know.js";
import { hoursText, type FeedWindow } from "./get-relevant-content.js";
import { HEADLINE_MAX, quoteThirdParty } from "../untrusted-text.js";

// The priority vocabulary lives in signal-classifier.ts; re-exported for existing importers.
export { normalizeStoredPriority, type SignalPriority, type SignalType } from "./signal-classifier.js";

/** Feed sources whose rows are structured facts (an advisory record, a registry release), not prose. */
const STRUCTURED_SOURCES = new Set(["cve", "osv", "crates_io", "npm_registry", "pypi", "go_modules", "github"]);
const ADVISORY_SOURCES = new Set(["cve", "osv"]);

interface ClassifiedSignal {
  id: number;
  title: string;
  url: string | null;
  source_type: string;
  relevance_score: number;
  signal_type: SignalType;
  signal_priority: SignalPriority;
  action: string;
  triggers: string[];
  confidence: number;
  discovered_ago: string;
}

// ============================================================================
// Tool Definition
// ============================================================================

export const getActionableSignalsTool = {
  name: "get_actionable_signals",
  description: `Get actionable signals classified from recent content.

Categorizes items into signal types: security_alert, breaking_change,
tool_discovery, tech_trend, learning, competitive_intel.
Each signal has a priority level (critical/high/medium/low) based on
signal type, relevance score, and tech stack match.

This project's own vulnerabilities come from its vulnerability scan, which
the call starts and waits for when none has run in this session; \`scan\`
says whether it completed, and when it did not, \`note\` starts NOT CHECKED
(an empty list is then not a clean result).

since_hours, when you pass it, is never widened: \`note\` says when nothing in
the feed matched in that window. The default 48 hours is widened to 168 and
then 720 when empty, and \`window\` ({ requested_hours, used_hours, widened })
and \`note\` say so. Live findings are not windowed.

Use this to get prioritized, actionable intelligence from 4DA's feed.`,
  inputSchema: {
    type: "object" as const,
    properties: {
      priority_filter: {
        type: "string",
        description: 'Filter by priority level: "critical", "high", "medium", "low". Leave empty for all.',
        enum: ["critical", "high", "medium", "low"],
      },
      signal_type: {
        type: "string",
        description: 'Filter by signal type. Leave empty for all.',
        enum: [
          "security_alert", "breaking_change", "tool_discovery",
          "tech_trend", "learning", "competitive_intel",
        ],
      },
      limit: {
        type: "number",
        description: "Maximum number of signals to return. Default: 20",
        default: 20,
      },
      since_hours: {
        type: "number",
        description: "Only include items from the last N hours. Default: 48, max: 720 (30 days)",
        default: 48,
      },
    },
  },
};

export interface GetActionableSignalsParams {
  priority_filter?: SignalPriority;
  signal_type?: SignalType;
  limit?: number;
  since_hours?: number;
}

/**
 * The slice of the live layer this tool reads; a stub suffices in tests. Without
 * `ensureVulnerabilities` the stored scan is read as it is.
 */
export type SignalsLiveIntel = Pick<LiveIntelligence, "getVulnerabilities"> &
  Partial<Pick<LiveIntelligence, "ensureVulnerabilities" | "isEnabled" | "getProjectRoot" | "getAuditDeps">>;

/** What backed the live findings: the scan this answer read, and whether it is a complete one. */
export interface SignalsScan {
  status: ScanStatus;
  scanned_at: string | null;
}

/** Widest window a caller may ask for: 30 days. */
const MAX_SINCE_HOURS = 720;
/** The window when the caller passes none; it is widened when it holds nothing, and the answer says so. */
const DEFAULT_SINCE_HOURS = 48;
/** Windows past this reach rows the current scoring pipeline may not have re-scored. */
const DEEP_WINDOW_HOURS = 168;
/** How long a call waits for the project's scan when none has run yet (bounded by the call's budget). */
const SCAN_WAIT_MS = 60_000;
/** Kept back from the call's budget for what follows the scan. */
const SCAN_RESERVE_MS = 8_000;

/**
 * The project's vulnerability scan, started and awaited when none has run in this session: the
 * feed rows alone are not this project's findings. `note` is set, starting NOT CHECKED, whenever
 * the scan is missing or incomplete, so an empty list never reads as a clean project.
 */
async function projectScan(liveIntel: SignalsLiveIntel | null): Promise<{ scan: VulnerabilityScanResult | null; block: SignalsScan; note: string | null }> {
  if (!liveIntel) {
    return {
      scan: null,
      block: { status: "disabled", scanned_at: null },
      note: "NOT CHECKED: no live vulnerability layer is running (FOURDA_OFFLINE, or it was not initialised), so this project's dependencies were not scanned; the absence of live findings here is not a clean result.",
    };
  }
  const enabled = liveIntel.isEnabled?.() ?? true;
  const waitMs = withinCallBudget(SCAN_WAIT_MS, SCAN_RESERVE_MS);
  let scan: VulnerabilityScanResult | null = null;
  if (enabled && liveIntel.ensureVulnerabilities) {
    try {
      scan = await liveIntel.ensureVulnerabilities(liveIntel.getProjectRoot?.() ?? process.cwd(), waitMs, { includeDev: true });
    } catch {
      scan = null;
    }
  }
  // A scan that could not complete is still read for what it found; the note says what it is not.
  scan = scan ?? liveIntel.getVulnerabilities();
  const ready = scan !== null && scan.totalScanned > 0 && !scan.offline && !(scan.staleAnswers ?? 0);
  const block: SignalsScan = { status: !enabled ? "disabled" : ready ? "ready" : "unavailable", scanned_at: scan?.scannedAt ?? null };
  const gap = vulnerabilityCoverage(scan, {
    enabled,
    expectedTotal: liveIntel.getAuditDeps?.().length ?? 0,
    notLoaded: `${scanUnfinishedText(waitMs)}, or OSV.dev was unreachable`,
  });
  if (gap) return { scan, block, note: gap.note };
  if (!enabled) return { scan, block, note: `NOT CHECKED: ${LOOKUPS_DISABLED}, so this project's dependencies were not scanned; the absence of live findings here is not a clean result.` };
  if (scan && scan.totalScanned === 0) {
    return { scan, block, note: "NOT CHECKED: no dependency version was read for this project (no lockfile the server reads), so nothing was scanned; the absence of live findings here is not a clean result. vulnerability_scan says what was found." };
  }
  return { scan, block, note: null };
}

// ============================================================================
// Alias clustering for live vulnerabilities
// ============================================================================

/** One signal's worth of live findings: the entry to report and every id it is known by. */
export interface VulnerabilityCluster {
  representative: VulnerabilityEntry;
  ids: string[];
}

/**
 * Group scan entries that are the same vulnerability under different ids.
 *
 * OSV returns a GHSA record and a RUSTSEC (or CVE) record for one bug, each
 * naming the other in `aliases`; injected one-per-record they read as two
 * problems and doubled the advisory count in every briefing. Union-find over
 * `[vulnId, ...aliases]` connects the records transitively (A knows B, B knows
 * C), scoped to the affected (ecosystem, package, version) so one advisory
 * against two packages — or two pinned versions of one package — stays two
 * things to fix. The representative is the GHSA record when the cluster has
 * one (the richest and most stable id), else the first seen; `ids` lists
 * every identifier in first-seen order.
 */
export function clusterVulnerabilities(vulns: VulnerabilityEntry[]): VulnerabilityCluster[] {
  const parent = new Map<string, string>();
  const find = (key: string): string => {
    let root = key;
    while (parent.get(root) !== root) root = parent.get(root)!;
    // Path compression keeps repeated lookups flat.
    let cursor = key;
    while (parent.get(cursor) !== root) {
      const next = parent.get(cursor)!;
      parent.set(cursor, root);
      cursor = next;
    }
    return root;
  };
  const union = (a: string, b: string): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };
  const scopeOf = (v: VulnerabilityEntry) => `${v.ecosystem}\0${v.package}\0${v.currentVersion}`;
  const idsOf = (v: VulnerabilityEntry) => [v.vulnId, ...v.aliases].filter(Boolean);

  for (const v of vulns) {
    const scope = scopeOf(v);
    const keys = idsOf(v).map((id) => `${scope}\0${id}`);
    for (const key of keys) if (!parent.has(key)) parent.set(key, key);
    for (let i = 1; i < keys.length; i++) union(keys[0], keys[i]);
  }

  const groups = new Map<string, VulnerabilityEntry[]>();
  for (const v of vulns) {
    const root = find(`${scopeOf(v)}\0${v.vulnId}`);
    const members = groups.get(root);
    if (members) members.push(v);
    else groups.set(root, [v]);
  }

  return [...groups.values()].map((members) => {
    const representative = members.find((m) => m.vulnId.startsWith("GHSA-")) ?? members[0];
    const ids = [...new Set(members.flatMap(idsOf))];
    return { representative, ids };
  });
}

/** Latest relevance-judge verdict per item (`llm_judgments`), when the desktop app has judged it. */
function judgeVerdicts(db: FourDADatabase, ids: number[]): Map<number, number> {
  const out = new Map<number, number>();
  if (ids.length === 0) return out;
  try {
    const raw = db.getRawDb();
    for (let i = 0; i < ids.length; i += 500) {
      const chunk = ids.slice(i, i + 500);
      const rows = raw
        .prepare(
          `SELECT source_item_id AS id, relevance_score AS v FROM llm_judgments
           WHERE id IN (SELECT MAX(id) FROM llm_judgments WHERE source_item_id IN (${chunk.map(() => "?").join(",")}) GROUP BY source_item_id)`,
        )
        .all(...chunk) as Array<{ id: number; v: number }>;
      for (const row of rows) out.set(row.id, row.v);
    }
  } catch {
    // No llm_judgments table (standalone or an older app): no verdicts.
  }
  return out;
}

/** The advisory ids a feed row of an advisory source stands for: its source id, and the `[ID]` its title starts with. */
function feedAdvisoryIds(item: { source_id?: string | null; title: string }): string[] {
  const ids = [item.source_id ?? "", /^\[([^\]\s]+)\]/.exec(item.title)?.[1] ?? ""].map((id) => id.trim().toUpperCase()).filter(Boolean);
  return [...new Set(ids)];
}

const GRADES: Record<string, SignalPriority> = { critical: "critical", high: "high", moderate: "medium", medium: "medium", low: "low" };

/**
 * The advisory's own grade in the app's copy of OSV.dev (`osv_advisories.severity_label`), the
 * highest over its records, or null when that copy has none: then the row keeps its stored grade.
 */
function ownGrade(db: FourDADatabase, ids: string[]): SignalPriority | null {
  if (ids.length === 0 || !db.hasColumn("osv_advisories", "severity_label") || !db.hasColumn("osv_advisories", "advisory_id")) return null;
  const aliases = db.hasColumn("osv_advisories", "aliases");
  const live = db.hasColumn("osv_advisories", "withdrawn_at") ? " AND withdrawn_at IS NULL" : "";
  const rank: Record<SignalPriority, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  let best: SignalPriority | null = null;
  try {
    const stmt = db
      .getRawDb()
      .prepare(`SELECT severity_label AS label FROM osv_advisories WHERE (upper(advisory_id) = ?${aliases ? " OR upper(aliases) LIKE ? ESCAPE '\\'" : ""})${live}`);
    for (const id of ids) {
      const rows = (aliases ? stmt.all(id, `%"${id.replace(/[\\%_]/g, "\\$&")}"%`) : stmt.all(id)) as Array<{ label: string | null }>;
      for (const row of rows) {
        const grade = GRADES[(row.label ?? "").toLowerCase()];
        if (grade && (best === null || rank[grade] > rank[best])) best = grade;
      }
    }
  } catch {
    return null;
  }
  return best;
}

/** What an agent can do with an advisory-source row the project's scan did not report. */
function advisoryRowAction(scanReady: boolean): string {
  return scanReady
    ? "Advisory record not matched to any installed version this project's vulnerability scan read: it may concern another project the 4DA app tracks (vulnerability_scan with that project's project_path checks it)."
    : "Advisory record, NOT CHECKED against this project's installed versions (its vulnerability scan did not complete; see note): run vulnerability_scan.";
}

/** What an agent can do with a signal of this type and source. */
function actionFor(type: SignalType, source: string): string {
  if (source === "crates_io" || source === "npm_registry" || source === "pypi" || source === "go_modules") {
    return "New release of a dependency: call upgrade_impact for what changed before bumping.";
  }
  if (type === "security_alert") return "Security news (not an advisory against your versions): read for context.";
  if (type === "breaking_change") return "Possible breaking change: check whether it touches a dependency you use.";
  return "Read for context.";
}

// ============================================================================
// Execution
// ============================================================================

export async function executeGetActionableSignals(
  db: FourDADatabase,
  params: GetActionableSignalsParams,
  liveIntel: SignalsLiveIntel | null = getLiveIntelligence(),
): Promise<{ signals: ClassifiedSignal[]; total: number; summary: Record<string, number>; scan: SignalsScan; window?: FeedWindow; note?: string }> {
  const limit = Math.max(1, Math.min(100, params.limit ?? 20));
  // A window the caller passes is never widened; the default one is, and the answer says so.
  const asked = typeof params.since_hours === "number" && Number.isFinite(params.since_hours);
  const requestedHours = asked ? params.since_hours! : DEFAULT_SINCE_HOURS;
  const sinceHours = Math.max(1, Math.min(MAX_SINCE_HOURS, requestedHours));

  // Get items from DB (low min score to get more items). A signal_type filter
  // is pushed into the read as well: the general read is capped at the top
  // 200 ranked items across EVERY type, and on a real corpus that cap starved
  // a type-specific pass — live 2026-09-07, the two in-window stored security
  // alerts ranked 299th and 582nd, so a security-only read returned nothing.
  // Stored matches are fetched by type and merged ahead of the general read,
  // which still carries the unstamped rows for keyword classification.
  const fetchItems = (minScore: number, hours: number, requireCurrentVersion: boolean) => {
    const general = db.getRelevantContent(minScore, undefined, 200, hours, requireCurrentVersion);
    if (!params.signal_type) return general;
    const stored = db.getRelevantContent(minScore, undefined, 200, hours, requireCurrentVersion, params.signal_type);
    const seen = new Set(stored.map((item) => item.id));
    return [...stored, ...general.filter((item) => !seen.has(item.id))];
  };

  // The default window only: progressively wider when it holds nothing. A window wider than
  // seven days reaches the stale-epoch tail, so it carries the same current-pipeline-version
  // guard as the deep fallback below.
  let items = fetchItems(0.1, sinceHours, sinceHours > DEEP_WINDOW_HOURS);
  let usedHours = sinceHours;
  let anyScore = false;
  if (!asked && items.length === 0 && sinceHours < DEEP_WINDOW_HOURS) {
    items = fetchItems(0.1, DEEP_WINDOW_HOURS, false); // Try 7 days
    usedHours = DEEP_WINDOW_HOURS;
  }
  if (!asked && items.length === 0) {
    // Deep 30-day/any-score fallback reaches the stale-epoch tail after a
    // pipeline-version bump. This path trusts stored signal_type/signal_priority
    // verbatim (confidence 0.90 below), so it MUST only see current-version
    // rows — stale persisted signals are claims the live brain no longer makes.
    items = fetchItems(0.0, MAX_SINCE_HOURS, true);
    usedHours = MAX_SINCE_HOURS;
    anyScore = true;
  }

  const signals: ClassifiedSignal[] = [];
  const verdicts = judgeVerdicts(db, items.map((item) => item.id));
  // The project's scan first: a feed row about an advisory it found is that finding, reported once
  // below at the scan's grade with the scan's instruction.
  const { scan: vulnResult, block: scanBlock, note: scanNote } = await projectScan(liveIntel);
  const clusters = vulnResult ? clusterVulnerabilities(vulnResult.vulnerabilities) : [];
  const foundIds = new Set(clusters.flatMap((c) => c.ids.map((id) => id.toUpperCase())));

  for (const item of items) {
    // Only the pipeline's own classifications, and only when they can be
    // stood behind: a prose item (news, social, papers) appears when the
    // relevance judge accepted it (latest verdict >= 0.5); a structured row
    // (advisory record, registry release) may appear unjudged. Measured
    // 2026-10-01: of 154 items stamped security_alert in 14 days the judge
    // accepted 10, rejected 62 and never saw 82; 3 came from an advisory source.
    if (!item.signal_type || !item.signal_priority) continue;
    const verdict = verdicts.get(item.id);
    const structured = STRUCTURED_SOURCES.has(item.source_type);
    if (verdict !== undefined ? verdict < 0.5 : !structured) continue;

    const storedType = item.signal_type as SignalType;
    const advisoryRow = ADVISORY_SOURCES.has(item.source_type);
    const advisoryIds = advisoryRow ? feedAdvisoryIds(item) : [];
    if (advisoryIds.some((id) => foundIds.has(id))) continue;
    // An advisory record is graded by the advisory's own grade where the app's copy of it knows
    // one, not by the feed's stamp (RUSTSEC-2026-0461, CVSS 7.5, was stamped critical).
    let priority = (advisoryRow ? ownGrade(db, advisoryIds) : null) ?? normalizeStoredPriority(item.signal_priority);
    // A headline about security is not an advisory against your versions:
    // never above medium unless it comes from an advisory database.
    if (storedType === "security_alert" && !advisoryRow && (priority === "critical" || priority === "high")) {
      priority = "medium";
    }
    // An advisory record that reads as a maintenance notice is one: low, as the scan's own are.
    const notice = advisoryRow && isMaintenanceNotice({ summary: item.title });
    if (notice) priority = "low";

    // Apply filters
    if (params.priority_filter && priority !== params.priority_filter) continue;
    if (params.signal_type && storedType !== params.signal_type) continue;

    signals.push({
      id: item.id,
      title: quoteThirdParty(item.title, HEADLINE_MAX),
      url: item.url,
      source_type: item.source_type,
      relevance_score: item.relevance_score,
      signal_type: storedType,
      signal_priority: priority,
      action: notice
        ? `${FEED_MAINTENANCE_ACTION} ${scanBlock.status === "ready" ? "This project's vulnerability scan matched it to no installed version." : "NOT CHECKED against this project's installed versions (its vulnerability scan did not complete)."}`
        : advisoryRow
          ? advisoryRowAction(scanBlock.status === "ready")
          : actionFor(storedType, item.source_type),
      triggers: [],
      // The judge's verdict when there is one; a structured row carries none.
      confidence: verdict ?? (structured ? 0.5 : 0),
      discovered_ago: item.discovered_ago,
    });
  }

  // Inject live vulnerability data as security_alert signals — one per
  // vulnerability (alias clusters), not one per OSV record.
  if (vulnResult && vulnResult.vulnerabilities.length > 0) {
    if (!params.signal_type || params.signal_type === "security_alert") {
      // Each finding's instruction is the scan's for that package version (scan-advice.ts).
      const advice = await scanAdvice(liveIntel, vulnResult);
      for (const { representative: vuln, ids } of clusters) {
        // The grade every surface shares (AD-046; twin of the app's
        // `osv::identity::scope_adjusted_urgency`), not the raw advisory tier:
        // a transitive of unknown scope read "CRITICAL: Sandbox Breakout" here
        // while the app graded it High (sandbox@3.1.2, 2026-09-10).
        const presented = presentedSeverity(vuln);
        // Low stays low (a "LOW: ..." finding was listed at medium); an
        // advisory with no severity at all is medium, not hidden.
        let priority: SignalPriority =
          presented === "critical" ? "critical" :
          presented === "high" ? "high" :
          presented === "low" ? "low" : "medium";
        let relevance = presented === "critical" ? 1.0 : presented === "high" ? 0.9 : presented === "low" ? 0.5 : 0.7;
        // An installed copy the lockfile does not pin is fixed by a reinstall, not an upgrade: the
        // lockfile is already where it should be. Every other copy: the scan's verdict for it.
        let action = adviceFor(advice, vuln);
        const adjusted = scopeAdjustmentReason(vuln);
        if (adjusted) {
          action += ` (the advisory rates it ${vuln.severity}; graded ${presented} as a ${adjusted})`;
        }
        let label = presented.toUpperCase();

        // "X is unmaintained" is information to plan around, not a fix to
        // apply today; an advisory against a crate this host never builds is
        // not this host's exposure. Both stay visible at LOW so they cannot
        // outrank, or be mistaken for, a live CVE — and the briefing's
        // delegation verdict does not read them at all.
        const maintenance = isMaintenanceNotice(vuln);
        if (maintenance) {
          priority = "low";
          relevance = 0.3;
          action = maintenanceAction(vuln.package, vuln.currentVersion);
          label = "MAINTENANCE";
        }
        if (vuln.platformActive === false) {
          priority = "low";
          relevance = 0.3;
          // The scan gives no step for a copy this host never builds: none is needed here, and the
          // checked fix for a build that compiles it is on the scan's platform_inactive_vulnerabilities row.
          action = maintenance
            ? `Not built on this host — ${action}`
            : `Not built on this host${vuln.target ? ` (only for ${vuln.target})` : ""}: nothing to fix for this host. For a build that compiles it, vulnerability_scan's platform_inactive_vulnerabilities row gives the checked fix.`;
          // The title must agree with the priority: "MEDIUM: ... (glib@0.18.5)" at
          // priority low read as a medium issue on a Windows host that never builds glib.
          if (!maintenance) label = `NOT BUILT HERE (${presented})`;
        }

        if (params.priority_filter && priority !== params.priority_filter) continue;

        signals.push({
          id: -1,
          // OSV.dev's summary is third-party text: one line, capped, never raw in the title.
          title: `${label}: ${quoteThirdParty(vuln.summary, HEADLINE_MAX)} (${vuln.package}@${vuln.currentVersion})`,
          url: vuln.references[0] || null,
          source_type: "osv_live",
          relevance_score: relevance,
          signal_type: "security_alert",
          signal_priority: priority,
          action,
          triggers: ids,
          confidence: 1.0,
          discovered_ago: vuln.published ? `published ${vuln.published}` : "recently",
        });
      }
    }
  }

  // Sort by priority (critical first), then by relevance score
  const priorityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  signals.sort((a, b) => {
    const pd = (priorityOrder[b.signal_priority] || 0) - (priorityOrder[a.signal_priority] || 0);
    if (pd !== 0) return pd;
    return b.relevance_score - a.relevance_score;
  });

  // Summary counts by type
  const summary: Record<string, number> = {};
  for (const s of signals) {
    summary[s.signal_type] = (summary[s.signal_type] || 0) + 1;
  }

  // The scan's state first: a missing or partial scan is said before anything else.
  const window: FeedWindow = { requested_hours: requestedHours, used_hours: usedHours, widened: usedHours > sinceHours };
  const windowNote = feedWindowNote(window, sinceHours, signals.filter((s) => s.source_type !== "osv_live").length, anyScore, asked);
  const notes = [
    scanNote,
    windowNote,
    !asked && signals.length === 0 && items.length === 0 ? "No source items in the database. Run the 4DA desktop app to fetch content, or use vulnerability_scan to check dependencies directly." : null,
  ].filter((n): n is string => n !== null);
  return {
    signals: signals.slice(0, limit),
    total: signals.length,
    summary,
    scan: scanBlock,
    ...(windowNote ? { window } : {}),
    ...(notes.length > 0 ? { note: notes.join(" ") } : {}),
  };
}

/** What the answer says about the feed's window, or null when the window asked for answered. */
function feedWindowNote(window: FeedWindow, sinceHours: number, feedSignals: number, anyScore: boolean, asked: boolean): string | null {
  const parts: string[] = [];
  if (window.requested_hours > sinceHours) parts.push(`since_hours is at most ${MAX_SINCE_HOURS}, so the 4DA feed's last ${hoursText(sinceHours)} were read`);
  if (window.widened) {
    parts.push(
      `The 4DA feed had nothing in the last ${hoursText(sinceHours)}, so the default window was widened to the last ${hoursText(window.used_hours)}${anyScore ? " at any relevance score" : ""}${feedSignals === 0 ? ", and nothing matched there either" : ": each feed signal's discovered_ago says how old it is"}`,
    );
  } else if (asked && feedSignals === 0) {
    parts.push(`Nothing in the 4DA feed matched in the last ${hoursText(sinceHours)}; the window was not widened (omit since_hours to let it widen, or pass a larger one)`);
  }
  return parts.length > 0 ? `${parts.join(". ")}. This project's live findings are not windowed.` : null;
}
