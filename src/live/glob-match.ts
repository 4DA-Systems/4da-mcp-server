// SPDX-License-Identifier: Apache-2.0
/**
 * Wildcard matching for patterns that come from files a repository controls
 * (Cargo `members` and `exclude`, workspace member globs).
 *
 * No regular expression is built from the pattern. A pattern of many `*`
 * turned into `.*.*.*...` backtracks exponentially against a name that does
 * not match, and one such line in a manifest stalled the whole server. The
 * walk below keeps a single saved `*` position, so it costs at most
 * pattern x text steps whatever the pattern holds.
 */

/** `*` matches any run of characters (none included), `?` exactly one; every other character is literal. */
export function wildcardMatch(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (p < pattern.length && pattern[p] === "*") {
      // A run of `*` is one `*`.
      while (p + 1 < pattern.length && pattern[p + 1] === "*") p++;
      star = p++;
      mark = t;
    } else if (p < pattern.length && (pattern[p] === "?" || pattern[p] === text[t])) {
      p++;
      t++;
    } else if (star !== -1) {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === "*") p++;
  return p === pattern.length;
}

/** True when the pattern holds a wildcard this matcher reads. */
export function hasWildcard(pattern: string): boolean {
  return pattern.includes("*") || pattern.includes("?");
}
