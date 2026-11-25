// SPDX-License-Identifier: Apache-2.0
/**
 * Poetry dependencies written as an inline table (`[tool.poetry]` with `dependencies = { requests =
 * "2.19.0" }`, and the same under `[tool.poetry.group.dev]`) were not read, so a version with an
 * `avoid` on record went through (audit 2026-11-25, D minors; a 6.5.2 Known limit). The hook now
 * follows an inline table's keys onto the key path until it reaches a Poetry dependency, as Poetry
 * reads them.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial, timedWithin } from "./helpers/a1125-hook-run.js";

const HEAD = '[tool.poetry]\nname = "a"\nversion = "0.1.0"\n';
const AVOID = { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "PYSEC-2018-28" };

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

/** Each spelling with `V` where the version goes. */
const SHAPES: Array<[string, string]> = [
  ["dependencies = { ... } under [tool.poetry]", `${HEAD}dependencies = { python = "^3.10", requests = "V" }\n`],
  ["an inline table value", `${HEAD}dependencies = { requests = { version = "V", extras = ["socks"] } }\n`],
  ["a dotted key inside the inline table", `${HEAD}dependencies = { requests.version = "V" }\n`],
  ["dev-dependencies = { ... }", `${HEAD}dev-dependencies = { requests = "V" }\n`],
  ["dependencies = { ... } under [tool.poetry.group.dev]", `${HEAD}\n[tool.poetry.group.dev]\ndependencies = { requests = "V" }\n`],
  ["group = { dev = { dependencies = { ... } } }", `${HEAD}group = { dev = { dependencies = { requests = "V" } } }\n`],
  ["poetry = { dependencies = { ... } } under [tool]", `[tool]\npoetry = { name = "a", dependencies = { requests = "V" } }\n`],
  ["a list of constraints inside the inline table", `${HEAD}dependencies = { requests = [{ version = "V", python = "<3.12" }, { version = "2.31.0", python = ">=3.12" }] }\n`],
  ["a byte order mark", `\uFEFF${HEAD}dependencies = { requests = "V" }\n`],
];
const at = (text: string, v: string) => text.replace("V", v);

describe("each inline spelling is held with an avoid on record", () => {
  it.each(SHAPES)("%s: Write, an Edit of the version, CRLF", (_label, shape) => {
    s.ledger([AVOID]);
    const written = s.write(s.file("a/pyproject.toml", HEAD), at(shape, "2.19.0"));
    expect(written.decision, written.text).toBe("deny");
    expect(written.text).toContain('"requests" "2.19.0" (PyPI): dependency_check answered avoid');
    const file = s.file("b/pyproject.toml", at(shape, "2.19.1"));
    expect(s.edit(file, '"2.19.1"', '"2.19.0"').text).toContain("answered avoid");
    expect(s.write(s.file("c/pyproject.toml", HEAD), at(shape, "2.19.0").replace(/\n/g, "\r\n")).decision).toBe("deny");
  });
});

describe("the denial's own call releases it", () => {
  it.each(SHAPES)("%s", (_label, shape) => {
    const file = s.file("pyproject.toml", HEAD);
    const first = s.write(file, at(shape, "2.19.1"));
    // The list-of-constraints form names its second release (2.31.0) too.
    expect(first.items?.[0]).toEqual({ ecosystem: "PyPI", package: "requests", to: "2.19.1" });
    answerDenial(s, first);
    expect(s.write(file, at(shape, "2.19.1")).decision).toBe("allow");
  });
});

describe("what changes no version is not held, with the avoid on record", () => {
  it.each(SHAPES)("%s: re-saved, CRLF re-saved, an edit elsewhere", (_label, shape) => {
    s.ledger([AVOID]);
    const text = at(shape, "2.19.0");
    const file = s.file("pyproject.toml", text);
    expect(s.write(file, text).decision).toBe("allow");
    expect(s.write(file, text.replace(/\n/g, "\r\n")).decision).toBe("allow");
    expect(s.edit(file, 'name = "a"', 'name = "b"').decision).toBe("allow");
  });

  it("moving a dependency between the inline and the table spelling changes no version", () => {
    s.ledger([AVOID]);
    const file = s.file("pyproject.toml", `${HEAD}dependencies = { requests = "2.19.0" }\n`);
    expect(s.write(file, `${HEAD}\n[tool.poetry.dependencies]\nrequests = "2.19.0"\n`).decision).toBe("allow");
  });
});

describe("what Poetry takes from elsewhere stays unread", () => {
  it.each([
    ["a path source", `${HEAD}dependencies = { requests = { path = "../requests", version = "2.19.0" } }\n`],
    ["a git source", `${HEAD}dependencies = { requests = { git = "https://example.com/r.git", version = "2.19.0" } }\n`],
    ["another index", `${HEAD}dependencies = { requests = { version = "2.19.0", source = "internal" } }\n`],
    ["an inline table that holds no dependency", `${HEAD}urls = { changelog = "https://example.com/2.19.0" }\n`],
  ])("%s", (_label, text) => {
    s.ledger([AVOID]);
    expect(s.write(s.file("pyproject.toml", HEAD), text).decision).toBe("allow");
  });

  it("[project] as a root inline table stays a documented limit (a652)", () => {
    s.ledger([AVOID]);
    expect(s.write(s.file("pyproject.toml", ""), 'project = { name = "a", version = "1", dependencies = ["requests==2.19.0"] }\n').decision).toBe("allow");
  });
});

describe("size", () => {
  it("1,000 inline entries and a 7 MB file, inside the CPU bound", () => {
    s.ledger([AVOID]);
    for (const [pad, limit] of [
      [0, 500],
      [7 * 1024 * 1024, 1000],
    ] as const) {
      const entries = Array.from({ length: 1000 }, (_, i) => `package-number-${i} = "1.0.${i}"`).join(", ");
      const before = `# ${"x".repeat(pad)}\n${HEAD}dependencies = { ${entries}, requests = "2.19.1" }\n`;
      const file = s.file(`p${pad}/pyproject.toml`, before);
      const write = (content: string) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: file, content } });
      const held = timedWithin(s.home, write(before.replace('requests = "2.19.1"', 'requests = "2.19.0"')), limit);
      expect(held.decision).toBe("deny");
      expect(held.text).toContain("answered avoid");
      expect(timedWithin(s.home, write(before), limit).decision).toBe("allow");
    }
  });
});
