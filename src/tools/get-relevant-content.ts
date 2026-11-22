// SPDX-License-Identifier: Apache-2.0
/**
 * get_relevant_content tool
 *
 * Get filtered relevant content from 4DA's personalized feed.
 */

import type { FourDADatabase } from "../db.js";
import type { GetRelevantContentParams, RelevantItem } from "../types.js";
import { HEADLINE_MAX, quoteThirdParty } from "../untrusted-text.js";

/**
 * Tool definition for MCP registration
 */
export const getRelevantContentTool = {
  name: "get_relevant_content",
  description: `Get filtered relevant content from 4DA's personalized feed.

Returns content items that match the user's explicit interests, tech stack, and ACE-detected context.
Items are scored based on:
- Explicit interests declared by the user
- Tech stack and domains
- ACE-detected context (recent files, projects, git activity)

since_hours, when you pass it (at most 168), is never widened: an empty answer's \`summary\` says
nothing matched in that window. The default 24 hours is widened to 168 and then 720 when empty, and
the answer's \`window\` ({ requested_hours, used_hours, widened }) and \`summary\` say so.

Each item includes necessity fields (necessity_score, necessity_reason, necessity_category, necessity_urgency) indicating how critical the item is — e.g., security vulnerabilities affecting your deps, breaking changes in your stack, or deprecation notices. These are populated from the full PASIFA analysis pipeline when available.

Use this to find content relevant to the user's current context.`,
  inputSchema: {
    type: "object" as const,
    properties: {
      min_score: {
        type: "number",
        description: "Minimum relevance score (0.0-1.0). Default: 0.35",
        default: 0.35,
      },
      source_type: {
        type: "string",
        description: "Only items from this source. Leave empty for all sources.",
        // Every source the app fetches; the enum used to list three of them.
        enum: [
          "hackernews", "reddit", "lobsters", "devto", "arxiv", "huggingface", "papers_with_code",
          "github", "crates_io", "npm_registry", "pypi", "go_modules", "cve", "osv", "stackoverflow",
          "rss", "youtube", "mastodon", "lemmy", "bluesky", "twitter", "producthunt",
        ],
      },
      limit: {
        type: "number",
        description: "Maximum number of items to return. Default: 20, max: 100",
        default: 20,
      },
      since_hours: {
        type: "number",
        description: "Only include items discovered in the last N hours. Default: 24",
        default: 24,
      },
    },
  },
};

type ContentItem = RelevantItem & { judge_relevance: number | null };

/** The time window an answer covers: the one asked for (or the default), and the one read. */
export interface FeedWindow {
  requested_hours: number;
  used_hours: number;
  widened: boolean;
}

/** An answer that needs a word about its window: what was read, said in `summary`, beside the items. */
export interface WindowedContent {
  window: FeedWindow;
  summary: string;
  item_count: number;
  items: ContentItem[];
}

const DEFAULT_SINCE_HOURS = 24;
/** The widest window a caller may ask for: one week. */
const MAX_SINCE_HOURS = 168;

/** "1 hour", "168 hours". */
export function hoursText(hours: number): string {
  return `${hours} hour${hours === 1 ? "" : "s"}`;
}

/**
 * get_relevant_content's answer: the items alone when the window asked for (or the default)
 * answered; otherwise `window` and a `summary` saying what was read, beside them. A window the
 * caller passes is never widened; the default one is, said in `window`.
 */
export function getRelevantContentAnswer(db: FourDADatabase, params: GetRelevantContentParams): ContentItem[] | WindowedContent {
  const { items, window, summary } = readRelevantContent(db, params);
  return summary ? { window, summary, item_count: items.length, items } : items;
}

/** The items get_relevant_content answers with (the answer adds the window's note: getRelevantContentAnswer). */
export function executeGetRelevantContent(db: FourDADatabase, params: GetRelevantContentParams): ContentItem[] {
  return readRelevantContent(db, params).items;
}

/** The items for `params`, the window they were read from, and what to say about it (null: nothing). */
function readRelevantContent(
  db: FourDADatabase,
  params: GetRelevantContentParams
): { items: ContentItem[]; window: FeedWindow; summary: string | null } {
  const minScore = Math.max(0, Math.min(1, params.min_score ?? 0.35));
  const limit = Math.max(1, Math.min(100, params.limit ?? 20));
  const asked = typeof params.since_hours === "number" && Number.isFinite(params.since_hours);
  const requestedHours = asked ? params.since_hours! : DEFAULT_SINCE_HOURS;
  const sinceHours = Math.max(1, Math.min(MAX_SINCE_HOURS, requestedHours));

  let items = db.getRelevantContent(minScore, params.source_type, limit, sinceHours);
  let usedHours = sinceHours;
  let anyScore = false;
  if (!asked) {
    // The default window only: expand progressively when it holds nothing.
    if (items.length === 0 && sinceHours < MAX_SINCE_HOURS) {
      items = db.getRelevantContent(minScore, params.source_type, limit, MAX_SINCE_HOURS);
      usedHours = MAX_SINCE_HOURS;
    }
    if (items.length === 0) {
      // Deep 30-day fallback at zero floor reaches the stale-epoch tail after a
      // pipeline-version bump — require current-version scores so we never rank
      // numbers the live scoring brain doesn't stand behind.
      items = db.getRelevantContent(0.0, params.source_type, limit, 720, true);
      usedHours = 720;
      anyScore = true;
    }
  }
  // Items the relevance judge rejected are not "relevant content", whatever
  // their score: measured 2026-10-01, 151 of 950 feed-relevant items carried
  // a latest judge verdict below 0.5. Unjudged items stay (scored, not yet
  // judged) and carry `judge_relevance: null`.
  const verdicts = latestJudgeVerdicts(db, items.map((item) => item.id));
  const out = items
    .filter((item) => (verdicts.get(item.id) ?? 1) >= 0.5)
    // A headline is third-party text: one line, no `|`, capped (untrusted-text.ts).
    .map((item) => ({ ...item, title: quoteThirdParty(item.title, HEADLINE_MAX), judge_relevance: verdicts.get(item.id) ?? null }));

  const window: FeedWindow = { requested_hours: requestedHours, used_hours: usedHours, widened: usedHours > sinceHours };
  return { items: out, window, summary: windowSummary(window, sinceHours, out.length, anyScore) };
}

/** What an answer says about its window, or null when the window asked for answered. */
function windowSummary(window: FeedWindow, sinceHours: number, count: number, anyScore: boolean): string | null {
  const parts: string[] = [];
  if (window.requested_hours > sinceHours) parts.push(`since_hours is at most ${MAX_SINCE_HOURS} here, so the last ${hoursText(sinceHours)} were read`);
  if (window.widened) {
    parts.push(
      `Nothing matched in the last ${hoursText(sinceHours)}, so the default window was widened to the last ${hoursText(window.used_hours)}${anyScore ? " at any relevance score" : ""}${count === 0 ? ", and nothing matched there either" : ": each item's discovered_ago says how old it is"}`,
    );
  } else if (count === 0) {
    parts.push(`Nothing matched in the last ${hoursText(sinceHours)}; the window was not widened (omit since_hours to let it widen, or pass a larger one)`);
  }
  return parts.length > 0 ? `${parts.join(". ")}.` : null;
}

/** Latest relevance-judge verdict per item, when the desktop app has judged it. */
function latestJudgeVerdicts(db: FourDADatabase, ids: number[]): Map<number, number> {
  const out = new Map<number, number>();
  if (ids.length === 0) return out;
  try {
    const rows = db
      .getRawDb()
      .prepare(
        `SELECT source_item_id AS id, relevance_score AS v FROM llm_judgments
         WHERE id IN (SELECT MAX(id) FROM llm_judgments WHERE source_item_id IN (${ids.map(() => "?").join(",")}) GROUP BY source_item_id)`,
      )
      .all(...ids) as Array<{ id: number; v: number }>;
    for (const row of rows) out.set(row.id, Math.round(row.v * 100) / 100);
  } catch {
    // No llm_judgments table: nothing judged.
  }
  return out;
}
