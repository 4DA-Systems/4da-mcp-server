// SPDX-License-Identifier: Apache-2.0
/**
 * A pip requirement with more than eight version clauses is HELD as not read (6.5.2).
 *
 * The specifier reader takes at most eight clauses. Up to 6.5.1 a ninth was dropped: a requirements
 * line was judged on its first eight clauses, and a command or pyproject entry with nine was read as
 * naming no version at all, so it went ahead. A ninth clause can exclude or cap the release the
 * first eight admit (`x>=1,...,<2`), so what the hook judged was not what pip would install. Now a
 * ninth clause holds the manifest write or the install command as "could not be read", naming the
 * part, like every other bound (a651-hook-bounds-held). Eight clauses are still read whole.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";

let dir: string;
let home: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "a652-nine-clauses-"));
  home = join(dir, "home");
  mkdirSync(home);
  writeFileSync(join(home, LEDGER_FILE), "");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function decide(input: Record<string, unknown>): { decision: "allow" | "deny"; text: string } {
  const out = respond({ hook_event_name: "PreToolUse", cwd: dir, ...input }, { FOURDA_MCP_HOME: home }, Date.now());
  return out === "" ? { decision: "allow", text: "" } : { decision: "deny", text: (JSON.parse(out) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason };
}
const bash = (command: string) => decide({ tool_name: "Bash", tool_input: { command } });
function write(file: string, content: string) {
  const path = join(dir, file);
  writeFileSync(path, "");
  return decide({ tool_name: "Write", tool_input: { file_path: path, content } });
}

const EIGHT = ">=1,>=1,>=1,>=1,>=1,>=1,>=1,<2";
const NINE = ">=1,>=1,>=1,>=1,>=1,>=1,>=1,>=1,<2";
const WHY = /a requirement with more than eight version clauses/;

describe("nine clauses: held as not read", () => {
  it.each([
    [`pip install 'requests${NINE}'`],
    [`pip install 'requests[socks]${NINE}'`],
    [`pip install 'requests (${NINE})'`],
    [`pip install 'requests${NINE} ; python_version >= "3"'`],
    [`python -m pip install 'requests${NINE}'`],
    [`uv add 'requests${NINE}'`],
    [`poetry add 'requests${NINE}'`],
    [`poetry add 'requests@${NINE}'`],
    [`pip install 'requests${NINE.replaceAll(",", " , ")}'`],
  ])("%s", (command) => {
    const r = bash(command);
    expect(r.decision).toBe("deny");
    expect(r.text).toMatch(/could not be read/);
    expect(r.text).toMatch(WHY);
  });

  it("a requirements file line", () => {
    for (const line of [`requests${NINE}`, `requests ${NINE}  # pinned by hand`, `requests[socks] (${NINE})`]) {
      const r = write("requirements.txt", `flask==3.0.0\n${line}\n`);
      expect(r.decision).toBe("deny");
      expect(r.text).toMatch(/could not be read/);
      expect(r.text).toMatch(WHY);
    }
  });

  it("a pyproject dependency string", () => {
    const r = write("pyproject.toml", `[project]\nname = "app"\nversion = "1.0.0"\ndependencies = ["requests${NINE}"]\n`);
    expect(r.decision).toBe("deny");
    expect(r.text).toMatch(/could not be read/);
    expect(r.text).toMatch(WHY);
  });
});

describe("eight clauses are still read whole", () => {
  it("a command is held as unchecked, naming all eight", () => {
    const r = bash(`pip install 'requests${EIGHT}'`);
    expect(r.decision).toBe("deny");
    expect(r.text).not.toMatch(/could not be read/);
    expect(r.text).toContain(EIGHT);
  });

  it("a requirements line and a pyproject string name all eight", () => {
    const req = write("requirements.txt", `requests${EIGHT}\n`);
    expect(req.text).not.toMatch(/could not be read/);
    expect(req.text).toContain(EIGHT);
    const py = write("pyproject.toml", `[project]\nname = "app"\nversion = "1.0.0"\ndependencies = ["requests${EIGHT}"]\n`);
    expect(py.text).not.toMatch(/could not be read/);
    expect(py.text).toContain(EIGHT);
  });
});

describe("what is not a ninth clause, and what is not an install", () => {
  it("a trailing comma, a comment and an option line hold nothing", () => {
    expect(write("requirements.txt", `# requests${NINE}\n--hash=sha256:${"a".repeat(64)}\n`).decision).toBe("allow");
    const r = write("requirements.txt", `requests${EIGHT},\n`);
    expect(r.text).not.toMatch(WHY);
  });

  it("a command that installs nothing goes ahead whatever it quotes", () => {
    expect(bash(`echo 'requests${NINE}'`).decision).toBe("allow");
    expect(bash(`git commit -m 'pin requests${NINE}'`).decision).toBe("allow");
  });
});
