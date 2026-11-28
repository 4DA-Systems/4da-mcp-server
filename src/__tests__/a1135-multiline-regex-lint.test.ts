// SPDX-License-Identifier: Apache-2.0
/**
 * Round 12, R2(b) and round 13, U4(b): the regexes of the briefing's readers and the parsers they call never let
 * whitespace runs be matched more than one way.
 * - Under the `m` flag, `^\s*` and `\s*$` (or `+`) are tried at every line start and run over every blank line after
 *   it: 199,990 newlines cost 8 s each (tenth check, e10b).
 * - In any regex, two quantified whitespace classes adjacent, or separated only by optional atoms (`\s*(?:x)?\s*`),
 *   split one run of blanks every possible way: three of them cost 50 s on 6,000 blanks (eleventh check, e11).
 * This scans the sources for regex literals and `new RegExp(...)` strings and fails on either pattern.
 */
import { readdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";

const SRC = path.join(__dirname, "..");
const FILES = [
  ...readdirSync(path.join(SRC, "tools"))
    .filter((f) => /^(?:briefing-.*|what-should-i-know|dependency-check-screen)\.ts$/.test(f))
    .map((f) => path.join("tools", f)),
  ...["lockfile-parsers-pygo.ts", "lockfile-parsers-rbphp.ts", "private-configs.ts", "pygo-parents.ts", "pypi-releases.ts", "pep508-marker.ts"].map((f) => path.join("live", f)),
];
const LITERAL = /\/((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n[])+)\/([dgimsuvy]*)/g;
const CONSTRUCTED = /new RegExp\(\s*(`(?:\\.|[^`\\])*`|"(?:\\.|[^"\\])*")\s*(?:,\s*["'`]([dgimsuvy]*)["'`])?/g;
const MULTILINE_BAD = [/\^\\s[*+]/, /\\s[*+]\$/, /\(\?:\\s\*[^)]*\)[*+]/, /\(\\s\*[^)]*\)[*+]/];
const WS = String.raw`(?:\\s|\[ ?\\t\]|\[\\t ?\]| )[*+]`;
const OPT = String.raw`(?:\((?:\?:)?(?:[^()]|\([^()]*\))*\)[?*]|\[(?:\\.|[^\]\\])*\][?*]|\\.[?*]|[^\\()[\]|][?*])`;
const ADJACENT = new RegExp(`${WS}${OPT}*${WS}`);

export function offenders(source: string): string[] {
  const out: string[] = [];
  const check = (body: string, flags: string, shown: string) => {
    if ((flags.includes("m") && MULTILINE_BAD.some((b) => b.test(body))) || ADJACENT.test(body)) out.push(shown);
  };
  for (const m of source.matchAll(LITERAL)) check(m[1], m[2], `/${m[1].slice(0, 120)}/${m[2]}`);
  for (const m of source.matchAll(CONSTRUCTED)) check(m[1].slice(1, -1).replace(/\\\\/g, "\\"), m[2] ?? "", `new RegExp(${m[1].slice(0, 80)})`);
  return out;
}

describe("the readers' regexes match a run of whitespace one way only", () => {
  it("the scanner finds the patterns of the tenth and eleventh checks", () => {
    expect(offenders("const a = /^\\s*(?:```|~~~)/m.test(x);")).toHaveLength(1);
    expect(offenders("x.split(/^\\s*(?:```|~~~)[^\\n]*$/m)")).toHaveLength(1);
    expect(offenders("const u = /^(x)\\s*(?:\\[[^\\]]*\\])?\\s*@\\s*\\S+$/;")).toHaveLength(1);
    expect(offenders("const p = new RegExp(`^(x)\\\\s*(?:\\\\[y\\\\])?\\\\s*(z)`);")).toHaveLength(1);
    expect(offenders("const ok = /^[ \\t]*(?:```|~~~)/m;")).toEqual([]);
    expect(offenders("const ok2 = /^(x)(?:\\s*\\[[^\\]]*\\])?\\s*(.*)$/;")).toEqual([]);
    expect(offenders("const ok3 = /\\s*,\\s*/;")).toEqual([]);
  });
  it.each(FILES)("%s holds none", (file) => {
    expect(offenders(readFileSync(path.join(SRC, file), "utf8"))).toEqual([]);
  });
});
