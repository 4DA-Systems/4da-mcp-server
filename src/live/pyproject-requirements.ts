// SPDX-License-Identifier: Apache-2.0
/**
 * The PEP 508 requirement strings a pyproject.toml declares, as written: `[project]
 * dependencies`, `[project.optional-dependencies]` and `[dependency-groups]` (PEP 735).
 *
 * project-manifests.ts reads the NAMES these tables declare; this reads the whole strings, so
 * the Python reader can tell an exact pin (`requests==2.19.1`) from a range and check a
 * lockfile against what the manifest asks for. Text in, strings out: no file is read here and
 * nothing is imported, so both readers can use it.
 *
 * Not a TOML parser. It reads what the three tables need: table headers at the start of a
 * line, `key = [` arrays that may span lines, basic and literal strings, comments. An inline
 * table inside an array (`{include-group = "test"}`) is not a requirement and is skipped. One
 * pass over the text per table, no pattern that can backtrack on a long line.
 */

export interface PyprojectRequirement {
  /** The requirement as written: `requests[socks]==2.19.1 ; python_version >= "3.8"`. */
  text: string;
  section: "dependencies" | "optional-dependencies" | "dependency-groups";
  /** The extra or group the requirement is listed under; null for `[project] dependencies`. */
  group: string | null;
}

/** A string longer than this is no requirement (the requirements reader's line cap). */
const MAX_REQUIREMENT_STRING = 4096;

/** A table or array-of-tables header on a line of its own. */
const HEADER = /^[ \t]*\[\[?([^[\]\r\n]+)\]\]?[ \t]*(?:#[^\r\n]*)?\r?$/gm;
/** `key = [` at the start of a line: the opening of an array value. */
const ARRAY_KEY = /^[ \t]*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([A-Za-z0-9_.-]+))[ \t]*=[ \t]*\[/gm;

/** The text of every table named `name` (a table may be written once; an array-of-tables is not one of these). */
function tableBodies(content: string, name: string): string[] {
  const headers = [...content.matchAll(HEADER)];
  const bodies: string[] = [];
  for (const [i, header] of headers.entries()) {
    if (header[0].trimStart().startsWith("[[") || header[1].trim() !== name) continue;
    const from = (header.index ?? 0) + header[0].length;
    bodies.push(content.slice(from, i + 1 < headers.length ? headers[i + 1].index : content.length));
  }
  return bodies;
}

/**
 * The strings directly inside the array that opens just before `from`, and where the array ends.
 * Strings nested in an inline table or an inner array are someone else's values. Stops at the
 * array's closing bracket, or at the end of the text when the array is never closed.
 */
function arrayStrings(text: string, from: number): { strings: string[]; end: number } {
  const strings: string[] = [];
  let depth = 1;
  let braces = 0;
  let i = from;
  for (; i < text.length && depth > 0; i++) {
    const ch = text[i];
    if (ch === "#") {
      const newline = text.indexOf("\n", i);
      if (newline < 0) return { strings, end: text.length };
      i = newline;
    } else if (ch === '"' || ch === "'") {
      let value = "";
      let from = i + 1;
      let j = from;
      // A requirement is one line: a quote still open at the line's end closes there.
      while (j < text.length && text[j] !== ch && text[j] !== "\n") {
        if (ch === '"' && text[j] === "\\" && j + 1 < text.length) {
          // A basic string's escape: the character after the backslash stands for itself.
          value += text.slice(from, j);
          from = j + 1;
          j++;
        }
        j++;
      }
      // Longer than any requirement is not one, and is not kept.
      if (depth === 1 && braces === 0 && j - i <= MAX_REQUIREMENT_STRING) strings.push(value + text.slice(from, j));
      i = j;
    } else if (ch === "[") depth++;
    else if (ch === "]") depth--;
    else if (ch === "{") braces++;
    else if (ch === "}") braces = Math.max(0, braces - 1);
  }
  return { strings, end: i };
}

export function pyprojectRequirements(content: string): PyprojectRequirement[] {
  const out: PyprojectRequirement[] = [];
  const collect = (table: string, section: PyprojectRequirement["section"], only: string | null) => {
    for (const body of tableBodies(content, table)) {
      // The search for the next key resumes where the last array ended, so every character is
      // read once however many arrays the table opens and never closes.
      const nextKey = new RegExp(ARRAY_KEY.source, ARRAY_KEY.flags);
      for (let key = nextKey.exec(body); key !== null; key = nextKey.exec(body)) {
        const name = key[1] ?? key[2] ?? key[3];
        const { strings, end } = arrayStrings(body, key.index + key[0].length);
        nextKey.lastIndex = Math.max(end, nextKey.lastIndex);
        if (only !== null && name !== only) continue;
        for (const text of strings) {
          if (text.trim() !== "") out.push({ text: text.trim(), section, group: only === null ? name : null });
        }
      }
    }
  };
  collect("project", "dependencies", "dependencies");
  collect("project.optional-dependencies", "optional-dependencies", null);
  collect("dependency-groups", "dependency-groups", null);
  return out;
}
