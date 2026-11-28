// SPDX-License-Identifier: Apache-2.0
/**
 * Bun catalogs in the root package.json (`workspaces.catalog`, `workspaces.catalogs.<name>`, and
 * the top-level `catalog` / `catalogs.<name>` Bun also reads) set the versions every `catalog:`
 * dependency installs, and the server reads them; the hook never did, so a version with an `avoid`
 * on record went through (audit 2026-11-25, D-M2).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial, timedWithin } from "./helpers/a1125-hook-run.js";

const AVOID = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "advisories: GHSA-35jh-r3h4-6jhm (high)" };
const json = (doc: unknown) => JSON.stringify(doc, null, 2) + "\n";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const SHAPES: Array<[string, (v: string) => unknown]> = [
  ["workspaces.catalog", (v) => ({ name: "r", private: true, workspaces: { packages: ["packages/*"], catalog: { lodash: v } } })],
  ["workspaces.catalogs.<name>", (v) => ({ name: "r", private: true, workspaces: { packages: ["packages/*"], catalogs: { legacy: { lodash: v } } } })],
  ["top-level catalog", (v) => ({ name: "r", private: true, workspaces: ["packages/*"], catalog: { lodash: v } })],
  ["top-level catalogs.<name>", (v) => ({ name: "r", private: true, workspaces: ["packages/*"], catalogs: { legacy: { lodash: v } } })],
];

describe("each place Bun reads a catalog from", () => {
  it.each(SHAPES)("%s: an avoided version is held, by Write and by Edit", (_label, make) => {
    s.ledger([AVOID]);
    expect(s.write(s.file("a/package.json", "{}\n"), json(make("4.17.20"))).decision).toBe("deny");
    const file = s.file("b/package.json", json(make("^4.17.21")));
    const run = s.edit(file, '"^4.17.21"', '"4.17.20"');
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain('"lodash" "4.17.20" (npm): dependency_check answered avoid');
  });

  it.each(SHAPES)("%s: the denial's own call releases it", (_label, make) => {
    const file = s.file("package.json", json(make("^4.17.21")));
    const first = s.edit(file, '"^4.17.21"', '"4.17.21"');
    expect(first.items).toEqual([{ ecosystem: "npm", package: "lodash", to: "4.17.21" }]);
    answerDenial(s, first);
    expect(s.edit(file, '"^4.17.21"', '"4.17.21"').decision).toBe("allow");
  });

  it.each(SHAPES)("%s: re-saved unchanged, or edited elsewhere, is not held", (_label, make) => {
    s.ledger([AVOID]);
    const text = json(make("4.17.20"));
    const file = s.file("package.json", text);
    expect(s.write(file, text).decision).toBe("allow");
    expect(s.edit(file, '"private": true', '"private": false').decision).toBe("allow");
  });

  it("an alias in a catalog is the package it names", () => {
    s.ledger([AVOID]);
    const run = s.write(s.file("package.json", "{}\n"), json({ name: "r", workspaces: { packages: [], catalog: { utils: "npm:lodash@4.17.20" } } }));
    expect(run.decision).toBe("deny");
    expect(run.text).toContain("answered avoid");
  });

  it("a top-level catalog in a package.json that is no workspace root (no `workspaces` field) is another tool's field: not held", () => {
    s.ledger([AVOID]);
    const file = s.file("package.json", "{}\n");
    expect(s.write(file, json({ name: "shop", catalog: { title: "2 items", lodash: "4.17.20" } })).decision).toBe("allow");
    expect(s.write(file, json({ name: "shop", catalogs: { winter: { coats: "3.0.0" } } })).decision).toBe("allow");
    // With a workspaces field it is Bun's.
    expect(s.write(file, json({ name: "shop", workspaces: ["p/*"], catalog: { lodash: "4.17.20" } })).decision).toBe("deny");
  });

  it("a catalog: dependency itself names no version, and a workspaces array is not a catalog", () => {
    s.ledger([AVOID]);
    const file = s.file("package.json", json({ name: "r", workspaces: { packages: ["p/*"], catalog: { lodash: "4.17.20" } } }));
    expect(s.edit(file, '"name": "r"', '"name": "r",\n  "dependencies": { "lodash": "catalog:" }').decision).toBe("allow");
    expect(s.write(s.file("b/package.json", "{}\n"), json({ name: "r", workspaces: ["4.17.20"] })).decision).toBe("allow");
  });
});

describe("line endings, a byte order mark and size", () => {
  it("CRLF and a BOM: held with an avoid; re-saved not held", () => {
    s.ledger([AVOID]);
    for (const [rel, text] of [
      ["a/package.json", json(SHAPES[0][1]("4.17.20")).replace(/\n/g, "\r\n")],
      ["b/package.json", "\uFEFF" + json(SHAPES[2][1]("4.17.20"))],
    ] as const) {
      expect(s.write(s.file(rel, "{}\n"), text).decision, rel).toBe("deny");
      const file = s.file(`same-${rel}`, text);
      expect(s.write(file, text).decision, rel).toBe("allow");
      expect(s.edit(file, '"private": true', '"private": false').decision, rel).toBe("allow");
    }
  });

  it("1,000 entries and 7 MB: held when a catalog version changes, not held when re-saved, inside the CPU bound", () => {
    s.ledger([AVOID]);
    const catalog = Object.fromEntries([...Array.from({ length: 1000 }, (_, i) => [`package-number-${i}`, `1.0.${i}`]), ["lodash", "^4.17.21"]]);
    for (const [pad, limit] of [
      [0, 500],
      [7 * 1024 * 1024, 1000],
    ] as const) {
      const before = json({ name: "r", description: "x".repeat(pad), workspaces: { packages: ["packages/*"], catalog } });
      const file = s.file(`p${pad}/package.json`, before);
      const write = (content: string) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: file, content } });
      const held = timedWithin(s.home, write(before.replace('"^4.17.21"', '"4.17.20"')), limit);
      expect(held.decision, held.text).toBe("deny");
      expect(held.text).toContain("answered avoid");
      expect(timedWithin(s.home, write(before), limit).decision).toBe("allow");
    }
  });
});
