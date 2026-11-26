// SPDX-License-Identifier: Apache-2.0
/**
 * Round 12, R2(b): a multiline regex of the briefing's readers never lets `\s` run across lines where a line-local
 * class is meant. Under the `m` flag `^\s*` and `\s*$` (or `+`) are tried at every line start and run over every blank
 * line after it: 199,990 newlines cost 8 s each (tenth check, e10b). This scans the reader sources for regex literals
 * and `new RegExp(..., "...m...")` and fails on such a pattern or a quantified group that starts with `\s*`.
 */
import { readdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";

const TOOLS = path.join(__dirname, "..", "tools");
const FILES = readdirSync(TOOLS).filter((f) => /^(?:briefing-.*|what-should-i-know|dependency-check-screen)\.ts$/.test(f));
const LITERAL = /\/((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n[])+)\/([dgimsuvy]*)/g;
const CONSTRUCTED = /new RegExp\(\s*(`(?:\\.|[^`\\])*`|"(?:\\.|[^"\\])*")\s*,\s*["'`]([dgimsuvy]*)["'`]/g;
const BAD = [/\^\\s[*+]/, /\\s[*+]\$/, /\(\?:\\s\*[^)]*\)[*+]/, /\(\\s\*[^)]*\)[*+]/];

export function offenders(source: string): string[] {
  const out: string[] = [];
  for (const m of source.matchAll(LITERAL)) if (m[2].includes("m") && BAD.some((b) => b.test(m[1]))) out.push(`/${m[1]}/${m[2]}`);
  for (const m of source.matchAll(CONSTRUCTED)) {
    const body = m[1].slice(1, -1).replace(/\\\\/g, "\\");
    if (m[2].includes("m") && BAD.some((b) => b.test(body))) out.push(`new RegExp(${m[1].slice(0, 80)}, "${m[2]}")`);
  }
  return out;
}

describe("multiline regexes of the readers stay line-local", () => {
  it("the scanner itself finds the two patterns of the tenth check", () => {
    expect(offenders("const a = /^\\s*(?:```|~~~)/m.test(x);")).toHaveLength(1);
    expect(offenders("x.split(/^\\s*(?:```|~~~)[^\\n]*$/m)")).toHaveLength(1);
    expect(offenders("const ok = /^[ \\t]*(?:```|~~~)/m;")).toEqual([]);
  });
  it.each(FILES)("%s holds none", (file) => {
    expect(offenders(readFileSync(path.join(TOOLS, file), "utf8"))).toEqual([]);
  });
});
