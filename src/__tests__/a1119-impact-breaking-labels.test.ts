// SPDX-License-Identifier: Apache-2.0
/**
 * Breaking-change labels on three real changelogs an end-to-end audit read against upstream:
 * - gin files its breaking changes under "### BREAK CHANGES"; the `RemoteIP()` signature change
 *   there was labelled a plain change;
 * - PyYAML's CHANGES titles a release as `6.0 (2021-10-13)` with no underline; nothing after 5.2
 *   was read, so "always require `Loader` arg to `yaml.load()`" was absent for a project that
 *   calls `yaml.load(x)`;
 * - Jinja's release notes say a release "should not result in breaking changes", and that
 *   sentence was flagged breaking.
 * Excerpts are quoted from the projects' own changelogs (gin v1.9.1 CHANGELOG.md, PyYAML 6.0.3
 * CHANGES, Jinja 3.1.6 GitHub release notes).
 */

import { describe, expect, it } from "vitest";

import { parseChangelog } from "../live/changelog.js";
import { classifyHeading, classifyText } from "../live/changelog-classify.js";

const GIN = `# Gin ChangeLog

## Gin v1.9.0

### BREAK CHANGES

* Stop useless panicking in context and render [#2150](https://github.com/gin-gonic/gin/pull/2150)

### BUG FIXES

* fix(router): tree bug where loop index is not decremented. [#3460](https://github.com/gin-gonic/gin/pull/3460)

## Gin v1.8.0

### BREAK CHANGES

* TrustedProxies: Add default IPv6 support and refactor [#2967](https://github.com/gin-gonic/gin/pull/2967). Please replace \`RemoteIP() (net.IP, bool)\` with \`RemoteIP() net.IP\`
* gin.Context with fallback value from gin.Context.Request.Context() [#2751](https://github.com/gin-gonic/gin/pull/2751)

### BUG FIXES

* Fixed SetOutput() panics on go 1.17 [#2861](https://github.com/gin-gonic/gin/pull/2861)
`;

const PYYAML = `
For a complete changelog, see:

* https://github.com/yaml/pyyaml/commits/

6.0.1 (2023-07-18)

* https://github.com/yaml/pyyaml/pull/702 -- pin Cython build dep to < 3.0

6.0 (2021-10-13)

* https://github.com/yaml/pyyaml/pull/550 -- drop Python 2.7
* https://github.com/yaml/pyyaml/pull/553 -- Fix spelling of “hexadecimal”
* https://github.com/yaml/pyyaml/pull/561 -- always require \`Loader\` arg to \`yaml.load()\`

5.4.1 (2021-01-20)

* https://github.com/yaml/pyyaml/pull/480 -- Fix stub compat with older pyyaml versions that may unwittingly load it

5.2 (2019-12-02)
------------------

* Repair incompatibilities introduced with 5.1.
`;

describe("gin: entries under BREAK CHANGES are breaking", () => {
  it("the heading is a breaking heading", () => {
    expect(classifyHeading("BREAK CHANGES")).toBe("breaking");
    expect(classifyHeading("Break change")).toBe("breaking");
    expect(classifyHeading("BUG FIXES")).toBe("fixes");
    // Not every heading with "break" in it: "Line breaks" is about something else.
    expect(classifyHeading("Line breaks")).toBeNull();
  });

  it("all three entries are labelled, and the fixes beside them are not", () => {
    const sections = parseChangelog(GIN);
    expect(sections.map((s) => s.version)).toEqual(["1.9.0", "1.8.0"]);
    const kinds = (v: string) => sections.find((s) => s.version === v)!.entries.map((e) => `${e.kind}:${e.text.slice(0, 24)}`);
    expect(kinds("1.9.0")).toEqual(["breaking:Stop useless panicking i", "change:fix(router): tree bug wh"]);
    expect(kinds("1.8.0")).toEqual(["breaking:TrustedProxies: Add defa", "breaking:gin.Context with fallbac", "change:Fixed SetOutput() panics"]);
  });
});

describe("PyYAML: a release titled by a version and a date in parentheses", () => {
  it("every release in the file is read, old and new title styles alike", () => {
    const sections = parseChangelog(PYYAML);
    expect(sections.map((s) => [s.version, s.date])).toEqual([
      ["6.0.1", "2023-07-18"],
      ["6.0", "2021-10-13"],
      ["5.4.1", "2021-01-20"],
      ["5.2", "2019-12-02"],
    ]);
  });

  it("6.0's mandatory argument and dropped interpreter are breaking; the spelling fix is not", () => {
    const six = parseChangelog(PYYAML).find((s) => s.version === "6.0")!;
    expect(six.entries.map((e) => e.kind)).toEqual(["breaking", "change", "breaking"]);
    expect(six.entries[2].text).toContain("always require `Loader` arg to `yaml.load()`");
  });

  it("a version and date inside a paragraph, or without the blank line before, is not a title", () => {
    const text = "## 2.0.0\n\n- Reverts the behaviour of\n1.9.0 (2020-01-01)\n- and another change\n";
    expect(parseChangelog(text).map((s) => s.version)).toEqual(["2.0.0"]);
    expect(parseChangelog("## 2.0.0\n\n- See 1.9.0 (2020-01-01) for the earlier fix\n").map((s) => s.version)).toEqual(["2.0.0"]);
    expect(parseChangelog("## 2.0.0\n\n- x\n\n1.9.0 (the old line)\n\n- y\n").map((s) => s.version)).toEqual(["2.0.0"]);
  });
});

describe("a denial a few words before the words is a denial", () => {
  it("Jinja 3.1.6's release sentence is not a breaking change", () => {
    const sentence = "This is the Jinja 3.1.6 security release, which fixes security issues but does not otherwise change behavior and should not result in breaking changes compared to the latest feature release.";
    expect(classifyText(sentence)).not.toBe("breaking");
  });

  it("other denials, and what is still breaking", () => {
    for (const t of ["This release contains no breaking changes.", "Upgrade without any breaking change.", "There shouldn't be any breaking changes here.", "It is not a breaking change."]) {
      expect(classifyText(t), t).not.toBe("breaking");
    }
    for (const t of ["This is a breaking change: the default is now strict.", "Not a fix but a breaking change to the API.", "Breaking change in the config loader.", "No new features. This is a breaking change for plugin authors."]) {
      expect(classifyText(t), t).toBe("breaking");
    }
  });
});
