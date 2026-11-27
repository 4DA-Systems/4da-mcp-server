// SPDX-License-Identifier: Apache-2.0
/**
 * Round 7 of the a1125 hook lane, from the fifth independent check:
 * - G2: time. The Cargo dotted-key walk copied the path once per part (99,000 parts: 24-27 s), and
 *   the ledger guard's glob pattern backtracked (`ls *************z; npm i x@1`: 20 s). Each loop
 *   added in rounds 5 and 6 is now linear and ticks the read budget; a read past the budget is held.
 * - G3a: inside a Cargo dependency table every key is a dependency, `version` and `name` included.
 * - G3b: a new or changed Cargo.toml / pyproject.toml line with a backslash in a double-quoted string
 *   or key is held as not read (TOML escapes are not decoded); an unchanged one never is.
 * - G3c: PEP 621, PEP 735 and uv requirement arrays written as inline tables are read.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { timedWithin } from "./helpers/a1125-hook-run.js";

const PKG = '[package]\nname = "probe"\nversion = "0.1.0"\nedition = "2021"\n';
const AVC = { ecosystem: "crates.io", package: "smallvec", version: "1.6.0", verdict: "avoid", reason: "RUSTSEC-2021-0003" };
const AVP = { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "CVE-2018-18074" };
const AVN = { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "GHSA-35jh-r3h4-6jhm" };
const NOT_READ = "could not be read";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([AVC, AVP, AVN]);
});
afterEach(() => s.dispose());

const write = (file: string, content: string) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: s.file(file, ""), content } });
// Round 17 (L1 c): the commands run in the sandbox project; without a cwd they ran in this repository, a pnpm workspace.
const bash = (command: string, tool = "Bash") => ({ hook_event_name: "PreToolUse", tool_name: tool, cwd: s.project, tool_input: { command } });
const dotted = (n: number) => Array.from({ length: n }, () => "a").join(".");

describe("G2: the inputs that ran past Claude Code's 10 s, and 200,000-character variants of each new shape, inside the CPU bound", () => {
  it.each([
    ["a root dotted key of 99,000 parts beside an avoided dependency", () => write("Cargo.toml", `${dotted(99_000)} = 1\n${PKG}\n[dependencies]\nsmallvec = "1.6.0"\n`), "answered avoid"],
    ["a 40,000-part header with 8,000 keys", () => write("Cargo.toml", `${PKG}\n[dependencies]\nsmallvec = "1.6.0"\n\n[${dotted(40_000)}]\n${Array.from({ length: 8_000 }, (_, i) => `x${i} = 1`).join("\n")}\n`), "answered avoid"],
    ["a 40,000-part dependency header with 8,000 keys", () => write("Cargo.toml", `${PKG}\n[${dotted(40_000)}.dependencies]\n${Array.from({ length: 8_000 }, (_, i) => `c${i} = "1"`).join("\n")}\nsmallvec = "1.6.0"\n`), "answered avoid"],
    ["root dotted dependencies, 200,000 characters", () => write("Cargo.toml", `${Array.from({ length: 9_000 }, (_, i) => `dependencies.crate-${i} = "1.0.${i}"`).join("\n")}\ndependencies.smallvec = "1.6.0"\n${PKG}`), "answered avoid"],
    ["a root inline dependency table, 200,000 characters", () => write("Cargo.toml", `dependencies = { ${Array.from({ length: 11_000 }, (_, i) => `c${i} = "1.0.${i}"`).join(", ")}, smallvec = "1.6.0" }\n${PKG}`), "answered avoid"],
    ["a Poetry inline table, 200,000 characters", () => write("pyproject.toml", `[tool.poetry]\ndependencies = { ${Array.from({ length: 11_000 }, (_, i) => `p${i} = "1.0.${i}"`).join(", ")}, requests = "2.19.0" }\n`), "answered avoid"],
    ["a PEP 621 inline table, 200,000 characters", () => write("pyproject.toml", `project = { name = "a", dependencies = [${Array.from({ length: 9_000 }, (_, i) => `"p${i}==1.0.${i}"`).join(", ")}, "requests==2.19.0"] }\n`), "answered avoid"],
    ["escaped strings, 200,000 characters", () => write("pyproject.toml", `[tool.ruff]\nexclude = [${Array.from({ length: 12_000 }, (_, i) => `"a\\\\${i}"`).join(", ")}]\n`), NOT_READ],
    ["a glob of 28 stars before an install", () => bash(`ls ${"*".repeat(28)}z; npm i lodash@4.17.20`), "answered avoid"],
    ["?* thirty times before an install", () => bash(`ls ${"?*".repeat(15)}z; npm i lodash@4.17.20`), "answered avoid"],
    ["a 60 KB PowerShell line of commas before an install", () => bash(`${"echo a,b;".repeat(6_000)}npm i lodash@4.17.20`, "PowerShell"), "answered avoid"],
    ["60 KB naming the ledger", () => bash(`${"echo check-ledger;".repeat(3_500)}`), "names the 4da check ledger"],
    ["60 KB of names alone", () => bash(`npm i ${Array.from({ length: 6_000 }, (_, i) => `p${i}`).join(" ")}`), '"to":"latest"'],
  ])("%s", (_label, payload, says) => {
    const run = timedWithin(s.home, payload(), 1000);
    expect(run.decision, run.text).toBe("deny");
    expect(run.text).toContain(says);
  });
});

describe("G3a: inside a Cargo dependency table every key is a dependency", () => {
  it.each([
    ["version = { version, package }", `${PKG}\n[dependencies]\nversion = { version = "1.6.0", package = "smallvec" }\n`],
    ["name = { version, package }", `${PKG}\n[dependencies]\nname = { version = "1.6.0", package = "smallvec" }\n`],
    ["edition, dotted", `${PKG}\n[dependencies]\nedition.version = "1.6.0"\nedition.package = "smallvec"\n`],
    ["rust-version, inline", `dependencies = { rust-version = { version = "1.6.0", package = "smallvec" } }\n${PKG}`],
    ["python, under a target", `${PKG}\n[target.'cfg(unix)'.dependencies]\npython = { version = "1.6.0", package = "smallvec" }\n`],
    ["resolver, dev", `${PKG}\n[dev-dependencies]\nresolver = { version = "1.6.0", package = "smallvec" }\n`],
  ])("%s: held with the avoid", (_label, text) => {
    expect(s.write(s.file("Cargo.toml", PKG), text).text).toContain('"smallvec" "1.6.0" (crates.io): dependency_check answered avoid');
  });

  it("[package] fields stay unread", () => {
    expect(s.write(s.file("Cargo.toml", ""), PKG.replace('"0.1.0"', '"1.6.0"')).decision).toBe("allow");
  });
});

describe("G3b: a changed line with a TOML escape is held as not read, with a remedy that releases it", () => {
  it.each([
    ["an escaped name", "Cargo.toml", `${PKG}\n[dependencies]\n"smallve\\u0063" = "1.6.0"\n`, `${PKG}\n[dependencies]\nsmallvec = "1.6.0"\n`],
    ["an escaped table name", "Cargo.toml", `${PKG}\n["dependencie\\u0073"]\nsmallvec = "1.6.0"\n`, `${PKG}\n[dependencies]\nsmallvec = "1.6.0"\n`],
    ["an escaped package =", "Cargo.toml", `${PKG}\n[dependencies]\nsv = { version = "1.6.0", package = "smallve\\u0063" }\n`, `${PKG}\n[dependencies]\nsv = { version = "1.6.0", package = "smallvec" }\n`],
    ["an escaped version", "Cargo.toml", `${PKG}\n[dependencies]\nsmallvec = "1.6.\\u0030"\n`, `${PKG}\n[dependencies]\nsmallvec = "1.6.0"\n`],
    ["a line-ending backslash in a multi-line string", "Cargo.toml", `${PKG}\n[dependencies]\nsmallvec = """1.6.\\\n  0"""\n`, `${PKG}\n[dependencies]\nsmallvec = "1.6.0"\n`],
    ["a Poetry escaped name", "pyproject.toml", `[tool.poetry.dependencies]\n"re\\u0071uests" = "2.19.0"\n`, `[tool.poetry.dependencies]\nrequests = "2.19.0"\n`],
    ["a PEP 621 escaped requirement", "pyproject.toml", `[project]\ndependencies = ["requests==2.19.\\u0030"]\n`, `[project]\ndependencies = ["requests==2.19.0"]\n`],
  ])("%s", (_label, file, escaped, plain) => {
    const path = s.file(file, "");
    const held = s.write(path, escaped);
    expect(held.decision).toBe("deny");
    expect(held.text).toContain(NOT_READ);
    expect(held.text).toContain("without escapes");
    // The remedy literally: the same without escapes is read, and judged by its versions.
    expect(s.write(path, plain).text).toContain("answered avoid");
  });

  it("an unchanged escaped line, a literal string and a comment are never held", () => {
    const text = `${PKG}description = "a \\"quoted\\" probe"\n\n[dependencies]\nserde = "1.0.100"\n`;
    const file = s.file("Cargo.toml", text);
    expect(s.write(file, text).decision).toBe("allow");
    expect(s.edit(file, 'name = "probe"', 'name = "probe2"').decision).toBe("allow");
    expect(s.edit(file, 'serde = "1.0.100"', "serde = \"1.0.100\"\n# a \\comment\nregex = '1.10.0'").text).not.toContain(NOT_READ);
    const py = `[tool.ruff]\nexclude = ["a\\\\b"]\n`;
    const pf = s.file("pyproject.toml", py);
    expect(s.edit(pf, "[tool.ruff]", "[tool.ruff]\nline-length = 100").decision).toBe("allow");
    expect(s.edit(pf, '"a\\\\b"', "'a\\b'").decision).toBe("allow");
  });

  it("CRLF and a BOM", () => {
    const file = s.file("Cargo.toml", "");
    expect(s.write(file, `\uFEFF${PKG}\r\n[dependencies]\r\n"smallve\\u0063" = "1.6.0"\r\n`).text).toContain(NOT_READ);
  });
});

describe("G3c: PEP 621, PEP 735 and uv inline tables are read", () => {
  it.each([
    ["project as a root inline table", `project = { name = "probe", version = "0.1.0", dependencies = ["requests==2.19.0"] }\n`],
    ["[project] optional-dependencies inline", `[project]\nname = "probe"\noptional-dependencies = { dev = ["requests==2.19.0"] }\n`],
    ["root dependency-groups inline", `dependency-groups = { dev = ["requests==2.19.0"] }\n[project]\nname = "probe"\n`],
    ["[tool] uv inline", `[project]\nname = "probe"\n\n[tool]\nuv = { dev-dependencies = ["requests==2.19.0"] }\n`],
    ["root tool inline", `tool = { uv = { constraint-dependencies = ["requests==2.19.0"] } }\n`],
  ])("%s: held with the avoid; re-saved not held", (_label, text) => {
    expect(s.write(s.file("a/pyproject.toml", ""), text).text).toContain("answered avoid");
    const file = s.file("b/pyproject.toml", text);
    expect(s.write(file, text).decision).toBe("allow");
  });
});
