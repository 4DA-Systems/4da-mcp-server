// SPDX-License-Identifier: Apache-2.0
/**
 * B-10 (audit 2026-10-12): polynomial regexes on attacker-controlled text.
 * A package's CHANGELOG (upgrade_impact) and a cloned repo's yarn.lock (read
 * at startup) are third-party input, and every parse runs synchronously on
 * the event loop. Measured on 6.2.4: an ATX heading with 1,000+ interior
 * spaces took over 20 s; a 64 KB yarn.lock line about 5 s per regex. Each
 * input below must parse in well under a second, and ordinary input must
 * parse exactly as before.
 */
import { describe, expect, it } from "vitest";
import { parseChangelog } from "../live/changelog.js";
import { readYarnLock } from "../live/js-lockfile-readers.js";
import { yarnParents } from "../live/lockfile-parents.js";
import { versionFromTag } from "../live/github-releases.js";

function timed(fn: () => void): number {
  const t = performance.now();
  fn();
  return performance.now() - t;
}

const BUDGET_MS = 250;

describe("ReDoS: pathological input stays linear", () => {
  it("an ATX heading with thousands of interior spaces", () => {
    const text = `## 1.0.0\n\n# a${" ".repeat(20_000)}\u0000x\n- fixed a bug\n`;
    expect(timed(() => parseChangelog(text))).toBeLessThan(BUDGET_MS);
  });

  it("a 64 KB yarn.lock version line and dependency line", () => {
    const longVersion = `"a@^1.0.0":\n  version "1.0.0${" ".repeat(64_000)}\\"x"\n`;
    const depLine = `"b@^1.0.0":\n  version "1.0.0"\n  dependencies:\n    a: b${" ".repeat(64_000)}"x\n`;
    const blank = `"c@^1.0.0":\n${" \n".repeat(32_000)}x\n`;
    for (const content of [longVersion, depLine, blank]) {
      expect(timed(() => readYarnLock(content, new Map()))).toBeLessThan(BUDGET_MS);
      expect(timed(() => yarnParents(content, "a", "1.0.0"))).toBeLessThan(BUDGET_MS);
    }
  });

  it("a long release tag", () => {
    expect(timed(() => versionFromTag("1.1".repeat(20_000) + "!", "pkg", null))).toBeLessThan(BUDGET_MS);
  });
});

describe("ReDoS fixes keep ordinary parses", () => {
  it("ATX headings: closing hashes and trailing spaces are stripped, a `C#` keeps its meaning as before", () => {
    const sections = parseChangelog("## [2.0.0] - 2024-01-02 ##  \n### Breaking ###\n- removed foo\n## 1.0.0\n- init\n");
    expect(sections.map((s) => s.version)).toEqual(["2.0.0", "1.0.0"]);
    expect(sections[0].entries[0].text).toContain("removed foo");
  });

  it("yarn v1 and berry blocks still read versions and dependency edges", () => {
    const v1 = `a@^1.0.0:\n  version "1.2.3"\n  dependencies:\n    b "^2.0.0"\n\nb@^2.0.0:\n  version "2.1.0"\n`;
    const versions = new Map<string, string>();
    readYarnLock(v1, versions);
    expect(versions.get("a")).toBe("1.2.3");
    expect(versions.get("b")).toBe("2.1.0");
    expect(yarnParents(v1, "b", "2.1.0").map((p) => p.parent)).toEqual(["a"]);

    const berry = `"a@npm:^1.0.0":\n  version: 1.2.3\n  dependencies:\n    "@s/b": "npm:^2.0.0"\n\n"@s/b@npm:^2.0.0":\n  version: 2.1.0\n`;
    const bv = new Map<string, string>();
    readYarnLock(berry, bv);
    expect(bv.get("a")).toBe("1.2.3");
    expect(bv.get("@s/b")).toBe("2.1.0");
    expect(yarnParents(berry, "@s/b", "2.1.0").map((p) => p.parent)).toEqual(["a"]);
  });

  it("tags still parse", () => {
    expect(versionFromTag("v1.2.3", "pkg", null)).toBe("1.2.3");
    expect(versionFromTag("pkg@1.2.3", "pkg", null)).toBe("1.2.3");
  });
});
