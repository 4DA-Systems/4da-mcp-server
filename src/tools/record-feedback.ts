// SPDX-License-Identifier: Apache-2.0
/**
 * record_feedback tool
 *
 * Record explicit user interaction history for an item.
 */

import type { FourDADatabase } from "../db.js";
import type { RecordFeedbackParams, FeedbackResult, FeedbackAction } from "../types.js";

/**
 * Tool definition for MCP registration
 */
export const recordFeedbackTool = {
  name: "record_feedback",
  description: `Record explicit user interaction history for a content item.

Feedback actions:
- "click": User clicked/opened the item
- "save": User saved/bookmarked the item, or said it is relevant (also records a relevance label)
- "dismiss": User dismissed the item
- "mark_irrelevant": User said the item is not relevant (also records a relevance label)

Only "save" and "mark_irrelevant" are relevance labels. Use them only when the user actually says whether the item matters to them. This does not train content preferences. Recorded in the 4DA desktop app's own interactions/feedback tables.`,
  inputSchema: {
    type: "object" as const,
    properties: {
      item_id: {
        type: "number",
        description: "The database ID of the item",
      },
      source_type: {
        type: "string",
        description: "Optional. The item's source type (e.g. \"hackernews\", \"crates_io\", \"lobsters\"); if given it must match the item.",
      },
      action: {
        type: "string",
        description: 'The feedback action: "click", "save", "dismiss", or "mark_irrelevant"',
        enum: ["click", "save", "dismiss", "mark_irrelevant"],
      },
    },
    required: ["item_id", "action"],
  },
};

const validActions: FeedbackAction[] = ["click", "save", "dismiss", "mark_irrelevant"];

/** A failed record carries `error` too, which makes the call an error (`isError: true`, tool-dispatch.ts). */
type FeedbackAnswer = FeedbackResult & { error?: string };

/** Nothing was recorded: say so as an error, and for a lock (the app writing), that a retry will do. */
function failed(result: FeedbackResult): FeedbackAnswer {
  const locked = /database is locked|SQLITE_BUSY/i.test(result.message);
  const error = locked ? `${result.message}. The 4DA app is writing to its database; retry in a few seconds.` : result.message;
  return { ...result, error };
}

/**
 * Execute the record_feedback tool
 */
export function executeRecordFeedback(
  db: FourDADatabase,
  params: RecordFeedbackParams
): FeedbackAnswer {
  if (!params.item_id || !params.action) {
    return failed({
      success: false,
      message: "item_id and action are required",
    });
  }

  if (!validActions.includes(params.action)) {
    return failed({
      success: false,
      message: `Invalid action: ${params.action}. Valid actions: ${validActions.join(", ")}`,
    });
  }

  const result = db.recordFeedback(params.item_id, params.source_type, params.action);
  return result.success ? result : failed(result);
}
