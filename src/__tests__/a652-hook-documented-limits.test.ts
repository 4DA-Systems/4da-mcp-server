// SPDX-License-Identifier: Apache-2.0
/**
 * The guard hook's limits that the 6.6.0 changelog's 6.5.2 draft listed under "Known limits", held as they are now (most are read or held since; the rows say which).
 *
 * An independent check of the 6.5.1 hook (2026-11-25) found six spellings that go ahead unread
 * while the plain spelling beside each is held. They are documented, not fixed: a fix for one of
 * them (a ninth version clause held as not read, pull request 114) was withdrawn after its own
 * check found it held edits that remove such a line, held names a private rule covers, and went
 * silent in advise mode. Each row here pins a sentence of the changelog, with the control that
 * shows the hook does read the plain form. A row that starts failing means the hook changed: fix
 * the changelog sentence with it.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import "./helpers/a1125-poetry-on-path.js";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";

let dir: string;
let home: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "a652-limits-"));
  home = join(dir, "home");
  mkdirSync(home);
  writeFileSync(join(home, LEDGER_FILE), "");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

type Decision = "allow" | "not read" | "no verdict";
function decide(input: Record<string, unknown>): { decision: Decision; text: string } {
  const out = respond({ hook_event_name: "PreToolUse", cwd: dir, ...input }, { FOURDA_MCP_HOME: home }, Date.now());
  if (out === "") return { decision: "allow", text: "" };
  const text = (JSON.parse(out) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason;
  return { decision: text.includes("could not be read") ? "not read" : "no verdict", text };
}
const bash = (command: string) => decide({ tool_name: "Bash", tool_input: { command } });
function write(file: string, content: string) {
  const path = join(dir, file);
  writeFileSync(path, "");
  return decide({ tool_name: "Write", tool_input: { file_path: path, content } });
}
/** A `proceed` for one PyPI release, a minute old. */
function proceed(pkg: string, version: string): void {
  writeFileSync(join(home, LEDGER_FILE), JSON.stringify({ sv: "6.6.0", t: new Date(Date.now() - 60_000).toISOString(), ecosystem: "PyPI", package: pkg, version, verdict: "proceed", reason: "ok" }) + "\n");
}

const LONG = "1." + "0".repeat(80); // a version over 80 characters
const NINE = ">=1,>=1,>=1,>=1,>=1,>=1,>=1,>=1,<2";
const EXTRAS = Array.from({ length: 30 }, (_, i) => `extra${i}`).join(","); // 229 characters
const pyproject = (dependencies: string) => `[project]\nname = "a"\nversion = "1"\ndependencies = ${dependencies}\n`;

// Round 8 (R8-1): no longer a limit: the detector reads the raw text, so a wrapped install with a part past a bound is held too.
describe("a part past a bound holds a command wherever the detector sees the install", () => {
  it("the plain command is held as not read", () => {
    expect(bash(`pip install 'requests==${LONG}'`).decision).toBe("not read");
  });

  const WRAPPED: [string, (install: string) => string][] = [
    ["inside a quoted argument", (i) => `bash -c "${i}"`],
    ["after a prefix option that takes an argument", (i) => `sudo -u root ${i}`],
    ["after if", (i) => `if ${i}; then :; fi`],
    ["after a leading redirection", (i) => `2>/dev/null ${i}`],
  ];
  it.each(WRAPPED)("%s: the unreadable install is held as not read, the readable one for its verdict", (_label, wrap) => {
    expect(bash(wrap(`pip install 'requests==${LONG}'`)).decision).toBe("not read");
    expect(bash(wrap("pip install 'requests==2.31.0'")).decision).toBe("no verdict");
  });
});

// Round 8: no longer a limit: pip joins a line ending in a backslash with the next, and so does the hook.
describe("a requirement continued with a backslash is read whole", () => {
  it("the second line's exclusion is seen", () => {
    proceed("requests", "2.31.0");
    expect(write("requirements.txt", "requests<=2.31.0,!=2.31.0\n").decision).toBe("no verdict");
    expect(write("requirements.txt", "requests<=2.31.0,\\\n!=2.31.0\n").decision).toBe("no verdict");
  });

  it("a pin whose continuation lines hold only --hash options is read whole", () => {
    const r = write("requirements.txt", `requests==2.31.0 \\\n    --hash=sha256:${"a".repeat(64)} \\\n    --hash=sha256:${"b".repeat(64)}\n`);
    expect(r.decision).toBe("no verdict");
    expect(r.text).toContain('"requests" "==2.31.0" (PyPI)');
  });
});

describe("a pip requirement with more than eight version clauses", () => {
  // Round 8 (R8-2): a command whose operand is not read is held as not read; the array is still a limit.
  // Round 24 (Y1 b, default deny): the pyproject array is no longer a limit.
  it("is held as not read in a command and in a pyproject array", () => {
    expect(bash(`pip install 'requests${NINE}'`).decision).toBe("not read");
    expect(bash(`uv add 'requests${NINE}'`).decision).toBe("not read");
    expect(bash(`poetry add 'requests${NINE}'`).decision).toBe("not read");
    expect(write("pyproject.toml", pyproject(`["requests${NINE}"]`)).decision).toBe("not read");
  });

  it("is judged on its first eight clauses in a requirements file", () => {
    const r = write("requirements.txt", `requests${NINE}\n`);
    expect(r.decision).toBe("no verdict");
    expect(r.text).toContain('">=1,>=1,>=1,>=1,>=1,>=1,>=1,>=1"');
    expect(r.text).not.toContain("<2");
  });
});

describe("extras over 200 characters", () => {
  it("the requirement is held as not read in a command (round 8) and in a file (round 24, Y1 b)", () => {
    expect(bash("pip install 'requests[socks]==2.31.0'").decision).toBe("no verdict");
    expect(bash(`pip install 'requests[${EXTRAS}]==2.31.0'`).decision).toBe("not read");
    expect(write("requirements.txt", `requests[${EXTRAS}]==2.31.0\n`).decision).toBe("not read");
  });
});

describe("two TOML spellings of a pyproject requirement (no longer limits since round 7 of the a1125 hook lane)", () => {
  it("a line-ending backslash in a multi-line basic string is held as not read; project as a root inline table is read", () => {
    expect(write("pyproject.toml", pyproject(`["requests==2.31.0"]`)).decision).toBe("no verdict");
    expect(write("pyproject.toml", pyproject(`["""requests==\\\n    2.31.0"""]`)).decision).toBe("not read");
    expect(write("pyproject.toml", `project = { name = "a", version = "1", dependencies = ["requests==2.31.0"] }\n`).decision).toBe("no verdict");
  });
});

describe("a Poetry constraint with clauses separated by a blank", () => {
  it("is held as not read (round 8); with a comma it is read", () => {
    expect(bash(`poetry add "requests@>=2.0,!=2.31.0"`).decision).toBe("no verdict");
    expect(bash(`poetry add "requests@>=2.0 !=2.31.0"`).decision).toBe("not read");
  });
});
