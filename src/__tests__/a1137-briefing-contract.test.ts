// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14, X5: THE CONTRACT of what_should_i_know is one block at the top of what-should-i-know.ts. This checks the
 * block: at most 30 sentences; each numbered sentence ends with the tests that pin it, and each named test file
 * exists; a sentence with a universal word (every, always, only, never, exactly, nothing) names a generated or
 * property test; each constant it names in backticks exists as an export of the source.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";

const SRC = path.join(__dirname, "..");
const file = readFileSync(path.join(SRC, "tools", "what-should-i-know.ts"), "utf8");
const start = file.indexOf(" * THE CONTRACT (round 14).");
const end = file.indexOf(" * END OF THE CONTRACT.");
const block = file.slice(start, end);
const sentences = [...block.matchAll(/^ \* (\d+)\. (.+)$/gm)].map((m) => ({ n: Number(m[1]), text: m[2] }));
const TESTS = readdirSync(__dirname).filter((f) => f.endsWith(".test.ts"));
const allSource = (dir: string): string[] =>
  readdirSync(dir).flatMap((f) => {
    const p = path.join(dir, f);
    return statSync(p).isDirectory() ? allSource(p) : p.endsWith(".ts") ? [readFileSync(p, "utf8")] : [];
  });
const SOURCE = allSource(SRC).join("\n");
const BANNED = /\b(?:every|always|only|never|exactly|nothing)\b/i;

describe("THE CONTRACT of what_should_i_know", () => {
  it("is one block, found, of at most 30 sentences, numbered in order", () => {
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    expect(sentences.length).toBeGreaterThan(0);
    expect(sentences.map((s) => s.n)).toEqual(sentences.map((_, i) => i + 1));
    const count = sentences.reduce((n, s) => n + 1 + (s.text.replace(/\[tests:[^\]]*\]$/, "").match(/\. (?=[A-Z`])/g) ?? []).length, 0);
    expect(count).toBeLessThanOrEqual(30);
  });
  it.each(sentences.map((s) => [s.n, s.text] as const))("sentence %i names its tests, and they exist", (_n, text) => {
    const refs = /\[tests: ([^\]]+)\]$/.exec(text);
    expect(refs, text).not.toBeNull();
    for (const ref of refs![1].split(/,\s*/)) {
      const name = ref.replace(/\s*\((?:generated|property)\)$/, "").trim();
      expect(TESTS.some((f) => f.startsWith(name)), `${name} (in: ${text.slice(0, 60)})`).toBe(true);
    }
  });
  it.each(sentences.map((s) => [s.n, s.text] as const))("sentence %i: a universal word is backed by a generated or property test", (_n, text) => {
    const claim = text.replace(/\[tests:[^\]]*\]$/, "");
    if (BANNED.test(claim)) expect(text, text.slice(0, 80)).toMatch(/\((?:generated|property)\)/);
  });
  it.each(sentences.flatMap((s) => [...s.text.matchAll(/`([A-Za-z_][\w]*)`/g)].map((m) => [m[1], s.n] as const)).filter(([name]) => /^[A-Z][A-Z0-9_]+$/.test(name) || /^[a-z]+[A-Z]\w*$/.test(name)))("the constant %s (sentence %i) exists in the source", (name) => {
    expect(new RegExp(`export (?:const|function|async function|class|type|interface) ${name}\\b`).test(SOURCE), name).toBe(true);
  });
});
