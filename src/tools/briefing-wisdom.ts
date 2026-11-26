// SPDX-License-Identifier: Apache-2.0
/**
 * Wisdom retrieval for the what_should_i_know briefing.
 *
 * Ranks the developer's recorded decisions and agent memories against the
 * task — lexically by default, blended with embedding similarity when a
 * provider is configured. Split out of what-should-i-know.ts, which is the
 * briefing's assembly and delegation logic.
 */

import type { FourDADatabase } from "../db.js";
import { rankRowsByRecall, type RankedRecall, type RecallField } from "./recall.js";

export interface WisdomEntry {
  type: string;
  subject: string;
  detail: string;
}

export type WisdomRecallMode = "hybrid" | "ranked_lexical";

interface WisdomDecisionRow {
  id: number;
  subject: string;
  decision: string;
  rationale: string | null;
  alternatives_rejected: string;
  context_tags: string;
  updated_at: string;
}

interface WisdomMemoryRow {
  id: number;
  memory_type: string;
  subject: string;
  content: string;
  context_tags: string;
  created_at: string;
}

/** Weighted fields for ranking decisions (mirrors the decision tools' weights). */
const WISDOM_DECISION_FIELDS: RecallField<WisdomDecisionRow>[] = [
  { name: "alternatives", weight: 5, value: (row) => row.alternatives_rejected },
  { name: "subject", weight: 4, value: (row) => row.subject },
  { name: "tags", weight: 3, value: (row) => row.context_tags },
  { name: "decision", weight: 2, value: (row) => row.decision },
  { name: "rationale", weight: 1, value: (row) => row.rationale },
];

/** Weighted fields for ranking memories. */
const WISDOM_MEMORY_FIELDS: RecallField<WisdomMemoryRow>[] = [
  { name: "subject", weight: 4, value: (row) => row.subject },
  { name: "tags", weight: 3, value: (row) => row.context_tags },
  { name: "content", weight: 2, value: (row) => row.content },
  { name: "type", weight: 1, value: (row) => row.memory_type },
];

const WISDOM_LIMIT = 6;

function loadWisdomDecisions(rawDb: ReturnType<FourDADatabase["getRawDb"]>): WisdomDecisionRow[] {
  try {
    return rawDb
      .prepare(
        `SELECT id, subject, decision, rationale, alternatives_rejected, context_tags, updated_at
         FROM developer_decisions
         WHERE status = 'active'
         ORDER BY updated_at DESC
         LIMIT 300`,
      )
      .all() as WisdomDecisionRow[];
  } catch {
    return []; // Older DBs may not have decision memory yet.
  }
}

function loadWisdomMemories(rawDb: ReturnType<FourDADatabase["getRawDb"]>): WisdomMemoryRow[] {
  try {
    return rawDb
      .prepare(
        `SELECT id, memory_type, subject, content, context_tags, created_at
         FROM agent_memory
         WHERE (expires_at IS NULL OR expires_at > datetime('now'))
         ORDER BY created_at DESC
         LIMIT 300`,
      )
      .all() as WisdomMemoryRow[];
  } catch {
    return []; // Older DBs may not have agent memory yet.
  }
}

/** Map a ranked decision/memory row to the public WisdomEntry shape. */
function toWisdomEntry(item: {
  type: "decision" | "memory";
  row: WisdomDecisionRow | WisdomMemoryRow;
}): WisdomEntry {
  if (item.type === "decision") {
    const row = item.row as WisdomDecisionRow;
    return {
      type: "decision",
      subject: row.subject,
      detail: row.rationale ? `${row.decision} Rationale: ${row.rationale}` : row.decision,
    };
  }
  const row = item.row as WisdomMemoryRow;
  return {
    type: `memory:${row.memory_type}`,
    subject: row.subject,
    detail: row.content,
  };
}

/**
 * Lexical wisdom retrieval (the default, provider-free path): rank decisions and
 * memories independently, merge by score, take the top entries.
 */
export function getRelevantWisdom(db: FourDADatabase, task: string, files: string[]): WisdomEntry[] {
  const rawDb = db.getRawDb();
  const query = [task, ...files].join(" ");

  const entries: Array<RankedRecall<WisdomDecisionRow | WisdomMemoryRow> & {
    type: "decision" | "memory";
  }> = [
    ...rankRowsByRecall(loadWisdomDecisions(rawDb), query, WISDOM_DECISION_FIELDS, WISDOM_LIMIT).map(
      (item) => ({ ...item, type: "decision" as const }),
    ),
    ...rankRowsByRecall(loadWisdomMemories(rawDb), query, WISDOM_MEMORY_FIELDS, WISDOM_LIMIT).map(
      (item) => ({ ...item, type: "memory" as const }),
    ),
  ];

  return entries
    .sort((a, b) => b.score - a.score)
    .slice(0, WISDOM_LIMIT)
    .map(toWisdomEntry);
}

