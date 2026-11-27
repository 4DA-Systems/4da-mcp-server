// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14, X1: the one screen on what the server returns. Every tool result and every error text of a tools/call
 * (validation errors, unknown tools, thrown errors, all tools) passes through screenToolResult before it leaves:
 * each substring of a credential shape this server knows (CREDENTIAL_SHAPES, the task screen's own token shapes,
 * matched anywhere, no word or length limit) is rendered by shape, its first four characters and its length.
 *
 * The one exemption is the `task` field of a what_should_i_know answer: the reading copy of the caller's own task
 * (markup dropped, line continuations joined, blanks collapsed), which the caller gave.
 *
 * Cost: one pass of one regex per string; each alternative's open quantifier is capped at 1,024 characters, so a
 * position is tried in bounded time and a string is scanned in time linear in its length.
 */
import { CREDENTIAL_SHAPES } from "./tools/briefing-task-screen.js";

const SHAPED = new RegExp(CREDENTIAL_SHAPES.source.replace(/^\\b/, "").replace(/\{(\d+),\}/g, "{$1,1024}"), "g");

/** A credential as an answer may show it: its first four characters and its length. */
export const byShape = (value: string) => `${value.slice(0, 4)}... (${value.length} characters)`;

/** Whether a text holds a substring of a CREDENTIAL_SHAPES shape (round 14b: the argument stage uses this). */
export function hasCredentialShape(text: string): boolean {
  SHAPED.lastIndex = 0;
  const found = SHAPED.test(text);
  SHAPED.lastIndex = 0;
  return found;
}

/** The same as screenText: each credential-shaped substring replaced by its shape (for arguments stored or sent). */
export const maskCredentialShapes = (text: string) => screenText(text);

/** A text with every substring of a CREDENTIAL_SHAPES shape rendered by shape. */
export function screenText(text: string): string {
  SHAPED.lastIndex = 0;
  return SHAPED.test(text) ? text.replace(SHAPED, byShape) : text;
}

/** Every string of a value, keys included, screened; `exempt` names a top-level key left as it is. */
export function screenValue(value: unknown, exempt?: string, depth = 0): unknown {
  if (typeof value === "string") return screenText(value);
  if (depth > 64 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => screenValue(v, undefined, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) out[screenText(k)] = depth === 0 && k === exempt ? v : screenValue(v, undefined, depth + 1);
  return out;
}

type ToolResultLike = { content?: Array<{ type?: string; text?: string } & Record<string, unknown>>; structuredContent?: Record<string, unknown> } & Record<string, unknown>;

/** A tools/call result as it leaves the server: its text parts and its structured form screened. */
export function screenToolResult<T>(tool: string, result: T): T {
  const exempt = tool === "what_should_i_know" ? "task" : undefined;
  const r = result as ToolResultLike;
  if (!r || typeof r !== "object") return result;
  const content = Array.isArray(r.content)
    ? r.content.map((part) => {
        if (typeof part?.text !== "string") return part;
        try {
          return { ...part, text: JSON.stringify(screenValue(JSON.parse(part.text), exempt)) };
        } catch {
          return { ...part, text: screenText(part.text) };
        }
      })
    : r.content;
  const structuredContent = r.structuredContent ? (screenValue(r.structuredContent, exempt) as Record<string, unknown>) : undefined;
  return { ...r, ...(content ? { content } : {}), ...(structuredContent ? { structuredContent } : {}) } as T;
}
