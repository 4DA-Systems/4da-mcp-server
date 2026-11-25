// SPDX-License-Identifier: Apache-2.0
/**
 * Cargo.toml spellings cargo reads as dependencies (`cargo metadata` shows each one) that the guard
 * hook did not, so a version with an `avoid` on record went through (audit 2026-11-25, D minors;
 * listed under Known limits in 6.5.2): a root dotted key (`dependencies.time = "0.3.17"`), a root
 * inline table (`dependencies = { time = "0.3.17" }`), the same under `[target.'cfg(windows)']`
 * or `[workspace]`, and the old table names `[dev_dependencies]` / `[build_dependencies]`. Also a
 * byte order mark before the first table, which cargo reads and which hid that table.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial, timedWithin } from "./helpers/a1125-hook-run.js";

const P = '[package]\nname = "x"\nversion = "0.1.0"\nedition = "2021"\n';
const AVOID = { ecosystem: "crates.io", package: "smallvec", version: "1.6.0", verdict: "avoid", reason: "RUSTSEC-2021-0003" };

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

/** Each spelling with `V` where the version goes. */
const SHAPES: Array<[string, string]> = [
  ["a root dotted key", `dependencies.smallvec = "V"\n${P}`],
  ["a root dotted key with a field", `dependencies.smallvec.version = "V"\n${P}`],
  ["a root inline table", `dependencies = { smallvec = "V" }\n${P}`],
  ["a root inline table with a table value", `dependencies = { smallvec = { version = "V", features = ["write"] } }\n${P}`],
  ["a root inline table with a dotted key", `dependencies = { smallvec.version = "V" }\n${P}`],
  ["a dotted key under [target.'cfg(windows)']", `${P}\n[target.'cfg(windows)']\ndependencies.smallvec = "V"\n`],
  ["an inline table under [target.'cfg(windows)']", `${P}\n[target.'cfg(windows)']\ndependencies = { smallvec = "V" }\n`],
  ["a root dotted key through target", `target.'cfg(windows)'.dependencies.smallvec = "V"\n${P}`],
  ["[target] with an inline cfg table", `${P}\n[target]\n'cfg(windows)' = { dependencies = { smallvec = "V" } }\n`],
  ["[dev_dependencies]", `${P}\n[dev_dependencies]\nsmallvec = "V"\n`],
  ["[build_dependencies]", `${P}\n[build_dependencies]\nsmallvec = "V"\n`],
  ["[dev_dependencies.smallvec]", `${P}\n[dev_dependencies.smallvec]\nversion = "V"\n`],
  ["[target.'cfg(unix)'.build_dependencies]", `${P}\n[target.'cfg(unix)'.build_dependencies]\nsmallvec = "V"\n`],
  ["a root dotted workspace dependency", `workspace.dependencies.smallvec = "V"\n${P}`],
  ["an inline table under [workspace]", `[workspace]\ndependencies = { smallvec = "V" }\n${P}`],
  ["a root dotted dev-dependencies key", `dev-dependencies.smallvec = "V"\n${P}`],
  ["a byte order mark before the first table", `\uFEFF[dependencies]\nsmallvec = "V"\n${P}`],
];
const at = (text: string, v: string) => text.replace("V", v);

describe("each spelling cargo reads is held with an avoid on record", () => {
  it.each(SHAPES)("%s: Write", (_label, shape) => {
    s.ledger([AVOID]);
    const run = s.write(s.file("Cargo.toml", P), at(shape, "1.6.0"));
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain('"smallvec" "1.6.0" (crates.io): dependency_check answered avoid');
  });

  it.each(SHAPES)("%s: an Edit of the version", (_label, shape) => {
    s.ledger([AVOID]);
    const file = s.file("Cargo.toml", at(shape, "1.6.1"));
    const run = s.edit(file, '"1.6.1"', '"1.6.0"');
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain("answered avoid");
  });

  it.each(SHAPES)("%s: CRLF", (_label, shape) => {
    s.ledger([AVOID]);
    expect(s.write(s.file("Cargo.toml", P), at(shape, "1.6.0").replace(/\n/g, "\r\n")).decision).toBe("deny");
  });
});

describe("the denial's own call releases it", () => {
  it.each(SHAPES)("%s", (_label, shape) => {
    const file = s.file("Cargo.toml", P);
    const first = s.write(file, at(shape, "1.6.1"));
    expect(first.items).toEqual([{ ecosystem: "crates.io", package: "smallvec", to: "1.6.1" }]);
    answerDenial(s, first);
    expect(s.write(file, at(shape, "1.6.1")).decision).toBe("allow");
  });
});

describe("what changes no version is not held, with the avoid on record", () => {
  it.each(SHAPES)("%s: re-saved, CRLF re-saved, an edit elsewhere", (_label, shape) => {
    s.ledger([AVOID]);
    const text = at(shape, "1.6.0");
    const file = s.file("Cargo.toml", text);
    expect(s.write(file, text).decision).toBe("allow");
    expect(s.write(file, text.replace(/\n/g, "\r\n")).decision).toBe("allow");
    expect(s.edit(file, 'name = "x"', 'name = "y"').decision).toBe("allow");
  });

  it("moving a dependency between the dotted, inline and table spellings changes no version", () => {
    s.ledger([AVOID]);
    const file = s.file("Cargo.toml", `dependencies.smallvec = "1.6.0"\n${P}`);
    expect(s.write(file, `dependencies = { smallvec = "1.6.0" }\n${P}`).decision).toBe("allow");
    expect(s.write(file, `${P}\n[dependencies]\nsmallvec = "1.6.0"\n`).decision).toBe("allow");
  });
});

describe("what cargo does not read as a crates.io dependency stays unread", () => {
  it.each([
    ["a path dependency in a root inline table", `dependencies = { smallvec = { path = "../sv", version = "1.6.0" } }\n${P}`],
    ["a git dependency as a root dotted key", `dependencies.smallvec = { git = "https://example.com/sv", version = "1.6.0" }\n${P}`],
    ["a dotted key under [package.metadata]", `${P}\n[package.metadata.x]\ndependencies.smallvec = "1.6.0"\n`],
    ["[package] fields", P.replace('"0.1.0"', '"1.6.0"')],
    ["a workspace reference", `${P}\n[dependencies]\nsmallvec = { workspace = true }\n`],
  ])("%s", (_label, text) => {
    s.ledger([AVOID]);
    expect(s.write(s.file("Cargo.toml", P), text).decision).toBe("allow");
  });
});

describe("size", () => {
  it("1,000 root inline entries and a 7 MB file, inside the CPU bound", () => {
    s.ledger([AVOID]);
    for (const [count, pad, limit] of [
      [1000, 0, 500],
      [1000, 7 * 1024 * 1024, 1000],
    ] as const) {
      const entries = Array.from({ length: count }, (_, i) => `crate-number-${i} = "1.0.${i}"`).join(", ");
      const before = `# ${"x".repeat(pad)}\ndependencies = { ${entries}, smallvec = "1.6.1" }\n${P}`;
      const file = s.file(`c${pad}/Cargo.toml`, before);
      const write = (content: string) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: file, content } });
      const held = timedWithin(s.home, write(before.replace('smallvec = "1.6.1"', 'smallvec = "1.6.0"')), limit);
      expect(held.decision).toBe("deny");
      expect(held.text).toContain("answered avoid");
      expect(timedWithin(s.home, write(before), limit).decision).toBe("allow");
    }
  });
});
