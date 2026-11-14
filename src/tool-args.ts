// SPDX-License-Identifier: Apache-2.0
/**
 * Tool-argument validation against each tool's published inputSchema, and the
 * text hygiene applied to every tool result.
 *
 * Validation: a call with a wrong type, an out-of-enum value or an unknown
 * parameter name used to reach the executor anyway. Measured 2026-10-02:
 * `project_path: 42` surfaced as a raw Node TypeError, an invalid
 * `severity_filter` was silently ignored, and a misspelled parameter vanished.
 * The spec (2025-11-25, SEP-1303) asks for input errors as tool execution
 * errors the model can read and correct; the message names the fix.
 *
 * Hygiene: results carry third-party text — advisory summaries, changelog
 * entries, headlines, package deprecation messages. Characters that render as
 * nothing (zero-width, bidi controls, variation selectors, the soft hyphen,
 * Unicode tag characters) and control characters (C0 and C1) are the raw
 * material of hidden prompt-injection payloads and have no legitimate use in
 * this data, so they are removed from every string.
 */

interface PropertySchema {
  type?: string;
  enum?: readonly unknown[];
  items?: { type?: string };
  minimum?: number;
  maximum?: number;
}

interface InputSchema {
  properties?: Record<string, unknown>;
  required?: readonly string[];
}

function typeOf(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function matchesType(value: unknown, type: string | undefined): boolean {
  if (!type) return true;
  if (type === "integer") return typeof value === "number" && Number.isInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  return typeOf(value) === type;
}

/**
 * Length limits for string arguments, by parameter name.
 *
 * A version or constraint is a few dozen characters and a package name at most a few hundred
 * (npm allows 214). Nothing bounded them: a `to` of 8 KB (">=" and 4,000 one-digit tokens) was
 * parsed once per published release and held the event loop for 7 s, so a concurrent `tools/list`
 * waited with it, and 40 KB never answered (audit 2026-11-11, M15). The parser is linear now
 * (live/range-satisfies.ts); the limit keeps every later step bounded as well, and the error says
 * what was too long instead of echoing kilobytes back.
 */
export const MAX_VERSION_ARG_LENGTH = 256;
export const MAX_NAME_ARG_LENGTH = 512;
const MAX_PATH_ARG_LENGTH = 4_096;
/** Free text (a task, a decision, a memory entry). */
const MAX_TEXT_ARG_LENGTH = 200_000;

const STRING_LIMITS: Record<string, number> = {
  to: MAX_VERSION_ARG_LENGTH,
  from: MAX_VERSION_ARG_LENGTH,
  to_version: MAX_VERSION_ARG_LENGTH,
  from_version: MAX_VERSION_ARG_LENGTH,
  package: MAX_NAME_ARG_LENGTH,
  project_path: MAX_PATH_ARG_LENGTH,
};

/** The message for a string argument over its limit, or null. `where` names it ("dependency_check: items[0].to"). */
export function lengthProblem(where: string, name: string, value: string): string | null {
  const max = (Object.hasOwn(STRING_LIMITS, name) ? STRING_LIMITS[name] : undefined) ?? MAX_TEXT_ARG_LENGTH;
  if (value.length <= max) return null;
  return `${where} is ${value.length.toLocaleString("en-US")} characters long; the limit is ${max.toLocaleString("en-US")}. It starts ${JSON.stringify(value.slice(0, 40))}.`;
}

/**
 * An actionable message for the first problem with `args`, or null when they are valid.
 *
 * Own properties only, on both sides: `properties[name]` found Object.prototype's members, so
 * `constructor`, `__proto__` and `toString` passed as known parameters and the length check
 * answered "the limit is function toString() { [native code] }" (pre-publish round 7).
 */
export function validateToolArgs(toolName: string, schema: InputSchema, args: Record<string, unknown>): string | null {
  const properties = (schema.properties ?? {}) as Record<string, PropertySchema>;
  const known = Object.keys(properties);
  const own = (name: string): unknown => (Object.hasOwn(args, name) ? args[name] : undefined);

  for (const name of schema.required ?? []) {
    if (own(name) === undefined || own(name) === null || own(name) === "") {
      return `${toolName}: missing required parameter "${name}". Required: ${(schema.required ?? []).join(", ")}.`;
    }
  }

  for (const [name, value] of Object.entries(args)) {
    const prop = Object.hasOwn(properties, name) ? properties[name] : undefined;
    if (!prop || typeof prop !== "object") {
      return `${toolName}: unknown parameter "${name}". Valid parameters: ${known.join(", ") || "(none)"}.`;
    }
    if (value === undefined || value === null) continue;
    if (!matchesType(value, prop.type)) {
      return `${toolName}: "${name}" must be ${prop.type === "array" ? "an array" : `a ${prop.type}`}, got ${typeOf(value)} ${JSON.stringify(value)}.`;
    }
    if (typeof value === "string") {
      const long = lengthProblem(`${toolName}: "${name}"`, name, value);
      if (long) return long;
    }
    if (prop.enum && !prop.enum.includes(value)) {
      return `${toolName}: "${name}" must be one of ${prop.enum.map((e) => JSON.stringify(e)).join(", ")}; got ${JSON.stringify(value)}.`;
    }
    if (typeof value === "number") {
      if (prop.minimum !== undefined && value < prop.minimum) return `${toolName}: "${name}" must be >= ${prop.minimum}; got ${value}.`;
      if (prop.maximum !== undefined && value > prop.maximum) return `${toolName}: "${name}" must be <= ${prop.maximum}; got ${value}.`;
    }
    if (Array.isArray(value) && prop.items?.type) {
      const bad = value.findIndex((item) => !matchesType(item, prop.items?.type));
      if (bad >= 0) {
        return `${toolName}: every "${name}" entry must be a ${prop.items.type}; entry ${bad} is ${typeOf(value[bad])}.`;
      }
    }
  }
  return null;
}

// Characters that render as nothing, or that reorder or restyle what is shown, written as escapes so
// the source shows what it matches (the earlier literal characters were invisible in an editor):
// - C0 controls except tab / newline / carriage return, DEL, and the C1 controls (U+0080..U+009F);
// - the soft hyphen (U+00AD), the Arabic letter mark (U+061C), the Mongolian vowel separator (U+180E);
// - zero-width spaces and joiners and the left-to-right / right-to-left marks (U+200B..U+200F);
// - bidi embeddings, overrides and isolates (U+202A..U+202E, U+2066..U+2069), the word joiner,
//   invisible operators and deprecated format characters (U+2060..U+206F);
// - variation selectors (U+FE00..U+FE0F, U+E0100..U+E01EF), which change a glyph and can carry
//   hidden bits; the BOM (U+FEFF); Unicode tag characters (U+E0000..U+E007F).
const INVISIBLE =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F\uFEFF\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

// The line and paragraph separators (U+2028, U+2029) break a line where no "\n" shows: a space.
const LINE_SEPARATORS = /[\u2028-\u2029]/g;

/** Remove invisible and control characters from one string. */
export function cleanText(text: string): string {
  return text.replace(LINE_SEPARATORS, " ").replace(INVISIBLE, "");
}

/** Deep copy of a JSON-like value with every string cleaned. */
export function cleanStrings<T>(value: T): T {
  if (typeof value === "string") return cleanText(value) as T;
  if (Array.isArray(value)) return value.map((v) => cleanStrings(v)) as T;
  if (value && typeof value === "object" && (value as object).constructor === Object) {
    const out: Record<string, unknown> = {};
    // defineProperty: an own "__proto__" key (JSON.parse makes one) stays a key, never the prototype.
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      Object.defineProperty(out, k, { value: cleanStrings(v), enumerable: true, writable: true, configurable: true });
    }
    return out as T;
  }
  return value;
}
