// SPDX-License-Identifier: Apache-2.0
/**
 * A changelog is its publisher's text. Reading one is bounded in time and in what comes back:
 * - the parse runs under a time allowance, and a cut-off parse says so (a 2 MB file of lines
 *   built to be slow held the event loop for 24 to 33 seconds, past the 20 s call budget);
 * - the default (concise) answer has an entry cap (19,110 entries and 3 MB came back);
 * - patterns that were quadratic on one line are no longer run on a long line.
 */

import { describe, expect, it } from "vitest";

import { parseChangelog, parseChangelogWithin, PARSE_BUDGET_MS, CHANGELOG_PARSER_VERSION } from "../live/changelog.js";
import { classificationText, classifyEntry } from "../live/changelog-classify.js";
import { shapeChangelog } from "../tools/upgrade-impact-report.js";
import { createUpgradeNet, getChangelog, type RegistryIndex } from "../live/upgrade-sources.js";
import { gzipSync } from "node:zlib";
import type { FetchFn } from "../live/package-archive.js";

const doc = (sections: number, bullets: number) =>
  Array.from({ length: sections }, (_, s) => `## ${sections - s}.0.0\n\n${Array.from({ length: bullets }, (_, b) => `- Change ${s}-${b}`).join("\n")}\n`).join("\n");

describe("the parse runs under a time allowance", () => {
  it("a changelog read to its end is complete, and parseChangelog is the same parse", () => {
    const text = doc(5, 3);
    const parsed = parseChangelogWithin(text);
    expect(parsed.complete).toBe(true);
    expect(parsed.sections.map((s) => s.version)).toEqual(["5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.0"]);
    expect(parseChangelog(text)).toEqual(parsed.sections);
    expect(PARSE_BUDGET_MS).toBeGreaterThan(0);
  });

  it("when the allowance runs out, the sections read whole are returned and the cut one is not", () => {
    const text = doc(40, 30);
    const whole = parseChangelog(text);
    // A clock that passes the allowance on its third reading: the cut-off falls mid-document.
    let reads = 0;
    const clock = () => (++reads >= 3 ? 10_000 : 0);
    const cut = parseChangelogWithin(text, 100, clock);
    expect(cut.complete).toBe(false);
    expect(cut.sections.length).toBeGreaterThan(0);
    expect(cut.sections.length).toBeLessThan(whole.length);
    // Every section returned is exactly as the full parse reads it: none is cut mid-list.
    expect(cut.sections).toEqual(whole.slice(0, cut.sections.length));
  });

  it("an allowance that is already spent stops at the first check, still on whole sections", () => {
    const text = doc(40, 30);
    const whole = parseChangelog(text);
    const cut = parseChangelogWithin(text, 0, (() => { let t = 0; return () => t++; })());
    expect(cut.complete).toBe(false);
    expect(cut.sections.length).toBeLessThan(5);
    expect(cut.sections).toEqual(whole.slice(0, cut.sections.length));
  });

  it("a short changelog is read whole even with no allowance left (the clock is read between blocks of lines)", () => {
    const cut = parseChangelogWithin(doc(2, 3), 0, (() => { let t = 0; return () => t++; })());
    expect(cut.complete).toBe(true);
    expect(cut.sections).toHaveLength(2);
  });

  it("the cache key changed with the parser", () => {
    expect(CHANGELOG_PARSER_VERSION).toBeGreaterThanOrEqual(5);
  });
});

describe("upgrade_impact says when a changelog was not read to its end", () => {
  // One tar entry `package/CHANGELOG.md`.
  function tgz(body: string): Buffer {
    const data = Buffer.from(body, "utf8");
    const h = Buffer.alloc(512);
    h.write("package/CHANGELOG.md", 0, "utf8");
    h.write("0000644\0", 100, "ascii");
    h.write("0000000\0", 108, "ascii");
    h.write("0000000\0", 116, "ascii");
    h.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124, "ascii");
    h.write("00000000000\0", 136, "ascii");
    h.write("0", 156, "ascii");
    h.write("ustar\0", 257, "ascii");
    h.write("00", 263, "ascii");
    h.fill(0x20, 148, 156);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
    const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
    data.copy(padded);
    return gzipSync(Buffer.concat([h, padded, Buffer.alloc(1024)]));
  }

  it("a complete read carries no note and is cached for the usual week", async () => {
    const sets: Array<{ key: string; ttl: number }> = [];
    const cache = { get: () => null, set: (key: string, _d: unknown, _s: string, ttl: number) => void sets.push({ key, ttl }) };
    const fetchFn: FetchFn = async () => new Response(new Uint8Array(tgz(doc(3, 2))), { status: 200 });
    const index: RegistryIndex = { name: "zqpkg", ecosystem: "npm", versions: [], repository: null };
    const result = await getChangelog(createUpgradeNet(cache, fetchFn), index, { version: "3.0.0", published: null, tarball: "https://registry.npmjs.org/zqpkg/-/zqpkg-3.0.0.tgz" });
    expect(result.found).toBe(true);
    expect(result.incomplete).toBeUndefined();
    expect(sets).toHaveLength(1);
    expect(sets[0].ttl).toBe(7 * 86_400);
    expect(sets[0].key).toContain(`:p${CHANGELOG_PARSER_VERSION}:`);
  });
});

describe("the concise answer has an entry cap", () => {
  it("a changelog whose every line reads as breaking comes back capped, with the count intact", () => {
    const sections = parseChangelog(`## 2.0.0\n\n${Array.from({ length: 5000 }, (_, i) => `- BREAKING: removed \`thing${i}()\``).join("\n")}\n`);
    expect(sections[0].entries).toHaveLength(5000);
    const shaped = shapeChangelog(sections, [], "concise");
    const shown = shaped.sections.reduce((n, s) => n + s.entries.length, 0);
    expect(shown).toBe(150);
    expect(shaped.breaking).toBe(5000);
    expect(shaped.truncated).toBe("concise output is capped at 150 entries; 4850 later entries were left out (counts still include them; ask for a narrower version range to read them)");
  });

  it("an ordinary changelog is not truncated", () => {
    const shaped = shapeChangelog(parseChangelog(doc(4, 5)), [], "concise");
    expect(shaped.truncated).toBeUndefined();
    expect(shaped.sections.reduce((n, s) => n + s.entries.length, 0)).toBe(20);
  });

  it("the detailed cap is unchanged", () => {
    const sections = parseChangelog(`## 2.0.0\n\n${Array.from({ length: 600 }, (_, i) => `- BREAKING: removed \`thing${i}()\``).join("\n")}\n`);
    const shaped = shapeChangelog(sections, [], "detailed");
    expect(shaped.sections.reduce((n, s) => n + s.entries.length, 0)).toBe(400);
    expect(shaped.truncated).toMatch(/^detailed output is capped at 400 entries; 200 later entries were left out/);
  });
});

describe("line patterns stay bounded", () => {
  it("link targets are dropped as before", () => {
    expect(classificationText("Drop support for Go 1.21 ([docs](https://go.dev/doc/go1.21)) and [x](y)")).toBe("Drop support for Go 1.21 ([docs]) and [x]");
    expect(classificationText("no links here")).toBe("no links here");
    expect(classificationText("an open ](target with no close")).toBe("an open ](target with no close");
    expect(classificationText("a](b)c](d")).toBe("a]c](d");
  });

  it("a long line of unclosed link openers, colons or brackets parses to a result", () => {
    const lines = [`- **${"](".repeat(2000)}:`, `- remove ${":".repeat(4000)}: x`, `- ${"[".repeat(4000)}`, `- remove \`${"a".repeat(4000)}`];
    const text = `## 1.0.0\n\n${lines.join("\n")}\n`;
    const parsed = parseChangelogWithin(text);
    expect(parsed.complete).toBe(true);
    expect(parsed.sections[0].entries.length).toBeGreaterThan(0);
    for (const e of parsed.sections[0].entries) expect(e.text.length).toBeLessThanOrEqual(400);
  });

  it("classification still reads headings and markers", () => {
    expect(classifyEntry("Removed `foo()`", "removal")).toBe("breaking");
    expect(classifyEntry("BREAKING: the default changed", null)).toBe("breaking");
    expect(classifyEntry("Fix a typo", "fixes")).toBe("change");
  });
});
