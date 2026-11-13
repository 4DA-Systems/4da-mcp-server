// SPDX-License-Identifier: Apache-2.0
/**
 * Every `_meta.privacy` statement says what the README says (pre-publish audit 2026-11-13, S5:
 * vulnerability_scan still said "...sent (private names included)" after private names stopped
 * being sent).
 */
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const sources: Array<{ file: string; text: string }> = [];
(function walk(dir: string) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    if (fs.statSync(p).isDirectory()) {
      if (name !== "__tests__") walk(p);
    } else if (p.endsWith(".ts")) sources.push({ file: path.relative(src, p).replaceAll("\\", "/"), text: fs.readFileSync(p, "utf8") });
  }
})(src);

const STRING = /"((?:[^"\\]|\\.)*)"/g;

/** The text behind every `privacy:` property: string literals, or the constants it names. */
function privacyTexts(): Array<{ file: string; text: string }> {
  const found: Array<{ file: string; text: string }> = [];
  for (const { file, text } of sources) {
    for (const m of text.matchAll(/\bprivacy:\s*([^\n]+)/g)) {
      const expr = m[1];
      if (/_meta\.privacy/.test(expr)) continue; // passed through from another answer
      for (const lit of expr.matchAll(STRING)) found.push({ file, text: lit[1] });
      for (const id of expr.match(/\b[A-Z][A-Z0-9_]+\b/g) ?? []) {
        const def = new RegExp(`const ${id}\\s*=\\s*([\\s\\S]*?);\\n`).exec(text);
        if (def) found.push({ file, text: [...def[1].matchAll(STRING)].map((l) => l[1]).join("") });
      }
    }
  }
  return found;
}

describe("privacy statements", () => {
  it("each _meta.privacy says a private package's name is never sent, as the README does", () => {
    const readme = fs.readFileSync(path.join(src, "..", "README.md"), "utf8");
    expect(readme).toContain("Private packages are never sent.");
    const texts = privacyTexts();
    expect([...new Set(texts.map((t) => t.file))].sort(), JSON.stringify(texts)).toEqual(
      expect.arrayContaining(["tools/dependency-check.ts", "tools/upgrade-impact.ts", "tools/vulnerability-scan-format.ts"]),
    );
    for (const { file, text } of texts) {
      expect(text, file).not.toMatch(/private[^.;]*included|included[^.;]*private/i);
      expect(text, `${file}: ${text}`).toMatch(/private package('s)? name[^.;]*(never sent|sent nowhere)/i);
    }
  });

  it("no shipped text says private names are sent", () => {
    const offenders = sources.filter(({ text }) => /\(private names included\)|private ones in your lockfiles included|\(private too\)/i.test(text)).map((s) => s.file);
    expect(offenders).toEqual([]);
  });
});
