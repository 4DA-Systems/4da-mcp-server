// SPDX-License-Identifier: Apache-2.0
/** Samples of CREDENTIAL_SHAPES, generated from the constant: one per top-level alternative (rounds 14, 14b). */
import { CREDENTIAL_SHAPES } from "../../tools/briefing-task-screen.js";

/** One sample string for a regex alternative: literal characters kept, a class's first character, quantifiers' minimum. */
export function sample(src: string): string {
  let out = "";
  let i = 0;
  const atom = (): string => {
    const c = src[i];
    if (c === "\\") {
      const n = src[i + 1];
      i += 2;
      return n === "w" ? "a" : n === "d" ? "7" : n === "b" ? "" : n;
    }
    if (c === "[") {
      let j = i + 1;
      let first = "";
      if (src[j] === "^") throw new Error("negated class");
      while (src[j] !== "]") {
        if (!first) first = src[j] === "\\" ? (src[j + 1] === "w" ? "a" : src[j + 1]) : src[j];
        j += src[j] === "\\" ? 2 : 1;
      }
      i = j + 1;
      return first;
    }
    if (c === "(") {
      let depth = 0;
      let j = i;
      for (; j < src.length; j++) {
        if (src[j] === "\\") {
          j++;
          continue;
        }
        if (src[j] === "(") depth++;
        else if (src[j] === ")" && --depth === 0) break;
      }
      const inner = src.slice(i + (src.startsWith("(?:", i) ? 3 : 1), j);
      i = j + 1;
      return sample(topAlternatives(inner)[0]);
    }
    i++;
    return c;
  };
  while (i < src.length) {
    const a = atom();
    const q = /^(\{(\d+)(?:,\d*)?\}|[*+?])/.exec(src.slice(i));
    if (q) {
      i += q[0].length;
      const n = q[2] !== undefined ? Number(q[2]) : q[0] === "+" ? 1 : 0;
      out += a.repeat(Math.max(n, q[0] === "?" || q[0] === "*" ? 0 : n));
    } else out += a;
  }
  return out;
}
export function topAlternatives(src: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cls = false;
  let start = 0;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
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
      out.push(src.slice(start, i));
      start = i + 1;
    }
  }
  out.push(src.slice(start));
  return out;
}
/** One sample per alternative of CREDENTIAL_SHAPES, each lengthened so it is a realistic token. */
export const SHAPES: string[] = (() => {
  const body = CREDENTIAL_SHAPES.source.replace(/^\\b\(\?:/, "").replace(/\)$/, "");
  return topAlternatives(body).map((alt) => {
    let s = sample(alt);
    if (!/[.]/.test(s) || !s.startsWith("eyJ")) s = `${s}Q9wE7rT5yU3iO1pA`;
    return s;
  });
})();

