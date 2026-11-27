// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14, X1 / round 15, A2: the one screen on what the server returns. Every JSON-RPC response the server writes
 * (results and errors of every method: tools, resources, prompts, completion, logging) passes screenJsonRpc at the
 * transport's send (index.ts for stdio, http-transport.ts for HTTP): each substring of a credential shape this server
 * knows (CREDENTIAL_SHAPES, the task screen's own token shapes) is rendered by shape, its first four characters and
 * its length. A token is consumed whole: the shape's own character class to its end, with no length cap.
 *
 * The one exemption is the `task` field of a what_should_i_know answer: the reading copy of the caller's own task.
 *
 * Cost: linear in the text. The alternatives with one open run (`ghp_` and a class to its end) are matched by one
 * regex whose failed starts fail within the shape's minimum; the two-segment shapes (a JWT, `SG.`) are matched by a
 * scan that knows, for each position, where its run of `[\w-]` ends (one backward pass), so no start rescans a run.
 */
import { CREDENTIAL_SHAPES } from "./tools/briefing-task-screen.js";

/** CREDENTIAL_SHAPES' alternatives, split at the top level. */
function alternatives(src: string): string[] {
  const body = src.replace(/^\\b\(\?:/, "").replace(/\)$/, "");
  const out: string[] = [];
  let depth = 0;
  let cls = false;
  let start = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (cls) {
      if (c === "]") cls = false;
      continue;
    }
    if (c === "[") cls = true;
    else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === "|" && depth === 0) {
      out.push(body.slice(start, i));
      start = i + 1;
    }
  }
  out.push(body.slice(start));
  return out;
}
const ALTS = alternatives(CREDENTIAL_SHAPES.source);
/** Two-segment shapes: a literal head, `[\w-]{a,}`, a dot, `[\w-]{b,}` (a JWT may have a third segment). */
const TWO_SEGMENT = /^((?:\\.|[A-Za-z])+)\[\\w-\]\{(\d+),\}\\\.\[\\w-\]\{(\d+),\}(\(\?:\\\.\[\\w-\]\*\)\?)?$/;
const SEGMENTED = ALTS.map((a) => TWO_SEGMENT.exec(a)).filter((m): m is RegExpExecArray => m !== null).map((m) => ({ head: m[1].replace(/\\(.)/g, "$1"), a: Number(m[2]), b: Number(m[3]), third: Boolean(m[4]) }));
const SINGLE = new RegExp(ALTS.filter((a) => !TWO_SEGMENT.test(a)).join("|"), "g");
const WORDISH = /[\w-]/;

/** The [start, end) spans of CREDENTIAL_SHAPES matches in a text, whole tokens, in linear time. */
function spans(text: string): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  SINGLE.lastIndex = 0;
  for (let m = SINGLE.exec(text); m; m = SINGLE.exec(text)) {
    if (m[0].length === 0) {
      SINGLE.lastIndex++;
      continue;
    }
    out.push([m.index, m.index + m[0].length]);
  }
  if (SEGMENTED.length > 0) {
    // runEnd[i]: the end of the run of [\w-] that starts at or covers i.
    let runEnd: Int32Array | null = null;
    for (const s of SEGMENTED) {
      let at = text.indexOf(s.head);
      while (at >= 0) {
        if (!runEnd) {
          runEnd = new Int32Array(text.length + 1);
          runEnd[text.length] = text.length;
          for (let i = text.length - 1; i >= 0; i--) runEnd[i] = WORDISH.test(text[i]) ? runEnd[i + 1] : i;
        }
        const segStart = at + s.head.length;
        const e1: number = runEnd[segStart] ?? segStart;
        let next = at + 1;
        if (e1 - segStart >= s.a && text[e1] === ".") {
          const e2: number = runEnd[e1 + 1] ?? e1 + 1;
          if (e2 - (e1 + 1) >= s.b) {
            let end = e2;
            if (s.third && text[e2] === ".") end = runEnd[e2 + 1] ?? e2 + 1;
            out.push([at, end]);
            next = end;
          } else next = Math.max(next, e1);
        } else next = Math.max(next, e1);
        at = text.indexOf(s.head, next);
      }
    }
  }
  return out;
}

/** A credential as an answer may show it: its first four characters and its length. */
export const byShape = (value: string) => `${value.slice(0, 4)}... (${value.length} characters)`;

/** A text with every CREDENTIAL_SHAPES token rendered by shape (overlapping matches: the earliest, longest wins). */
export function screenText(text: string): string {
  const found = spans(text).sort((x, y) => x[0] - y[0] || y[1] - x[1]);
  if (found.length === 0) return text;
  let out = "";
  let last = 0;
  for (const [s, e] of found) {
    if (s < last) continue;
    out += text.slice(last, s) + byShape(text.slice(s, e));
    last = e;
  }
  return out + text.slice(last);
}

/** Whether a text holds a CREDENTIAL_SHAPES token (round 14b: the argument stage uses this). */
export function hasCredentialShape(text: string): boolean {
  return spans(text).length > 0;
}

/** The same as screenText: each credential-shaped substring replaced by its shape (for arguments stored or sent). */
export const maskCredentialShapes = (text: string) => screenText(text);

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

/** A what_should_i_know answer, by its shape: the one result whose `task` is exempt. */
const isBriefing = (o: unknown): boolean => !!o && typeof o === "object" && "task" in (o as object) && "delegation_assessment" in (o as object);

/** One JSON-RPC message (or batch) as the server writes it: every method's result and error screened. */
export function screenJsonRpc(message: unknown): unknown {
  if (Array.isArray(message)) return message.map(screenJsonRpc);
  if (!message || typeof message !== "object") return screenValue(message);
  const m = message as Record<string, unknown>;
  const result = m.result as ToolResultLike | undefined;
  if (result && typeof result === "object" && (isBriefing(result.structuredContent) || (Array.isArray(result.content) && result.content.some((p) => typeof p?.text === "string" && /"delegation_assessment"/.test(p.text))))) {
    return { ...(screenValue({ ...m, result: undefined }) as Record<string, unknown>), result: screenToolResult("what_should_i_know", result) };
  }
  return screenValue(m);
}

/** Wire text as a transport writes it (JSON lines, or an event stream's `data:` lines), screened line by line. */
export function screenWireText(text: string): string {
  return text
    .split("\n")
    .map((line) => {
      const data = line.startsWith("data: ") ? "data: " : "";
      const body = line.slice(data.length);
      if (!/^\s*[[{]/.test(body)) return screenText(line);
      try {
        return data + JSON.stringify(screenJsonRpc(JSON.parse(body)));
      } catch {
        return screenText(line);
      }
    })
    .join("\n");
}
