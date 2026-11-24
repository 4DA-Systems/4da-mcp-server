// SPDX-License-Identifier: Apache-2.0
/**
 * Too big or too deep means HELD, decided before the work (round 3 of the hook review, item 3).
 *
 * Round 2 bounded each token and skipped one past its bound, so the call went ahead unread: a pin
 * followed by a 4,000-character comment, 51 `--hash` options on one line (pip-compile writes them),
 * a 455-character PEP 508 marker, a go.mod require or a pnpm catalog line with a long comment, a
 * version longer than 80 characters (equal to 2.0.0 by PEP 440, or with build metadata), a command
 * over 64 KB, TOML nested past what the reader's recursion survives. 6.5.0 and 0d30b40 held them.
 * Now comments and markers are dropped by plain searches first and real long lines are read; what
 * is still past a bound holds a manifest write or a package-manager command as "could not be read",
 * saying which part. A call that is neither goes ahead, whatever its size.
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
  dir = mkdtempSync(join(tmpdir(), "a651-bounds-held-"));
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

const zeros = (n: number) => "2.0.0" + ".0".repeat(n);
const marker = ' ; python_version >= "3"' + ' and python_version >= "3"'.repeat(16);

describe("held: each case round 2 let through (the checker's a5-bounds)", () => {
  it.each([
    [`pip install requests==${zeros(38)}`, /a version over 80 characters/],
    [`pip install requests===${zeros(38)}`, /a version over 80 characters/],
    [`pip install 'requests==${"0".repeat(80)}2.0.0'`, /a version over 80 characters/],
    [`poetry add 'requests==${zeros(38)}'`, /a version over 80 characters/],
    [`cargo add serde@${"1.0.100+" + "a".repeat(80)}`, /a version over 80 characters/],
    [`npm i lodash@4.17.20+${"a".repeat(80)}`, /a version over 80 characters/],
    [`npm i lodash@4.17.20 # ${"x".repeat(70 * 1024)}`, /a command over 64 KB/],
  ])("%s", (command, why) => {
    const r = bash(command.length > 200 ? command : command);
    expect(r.decision).toBe("deny");
    expect(r.text).toMatch(/could not be read/);
    expect(r.text).toMatch(why);
  });

  it("a long marker is read (not refused) and the pin is held as unchecked", () => {
    const r = bash(`pip install 'requests==2.0.0${marker}'`);
    expect(r.text).toContain('"requests" "==2.0.0" (PyPI)');
    expect(bash(`uv add 'requests==2.0.0${marker}'`).text).toContain('"requests" "==2.0.0" (PyPI)');
  });

  it("manifests: a long comment is dropped and the pin read; long hashes are read", () => {
    expect(write("requirements.txt", `flask==3.0.0\nrequests==2.0.0  # ${"x".repeat(4000)}\n`).text).toContain('"requests" "==2.0.0" (PyPI)');
    const hashes = Array.from({ length: 51 }, (_, i) => ` --hash=sha256:${String(i).padStart(64, "a")}`).join("");
    expect(write("requirements.txt", `requests==2.0.0${hashes}\n`).text).toContain('"requests" "==2.0.0" (PyPI)');
    expect(write("go.mod", `module example.com/app\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.8.0 // ${"x".repeat(5000)}\n`).text).toContain('"github.com/pkg/errors" "v0.8.0" (Go)');
    expect(write("pnpm-workspace.yaml", `catalog:\n  react: 18.0.0 # ${"x".repeat(5000)}\n`).text).toContain('"react" "18.0.0" (npm)');
    expect(write("pyproject.toml", `[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["requests==2.0.0${marker.replace(/"/g, "'")}"]\n`).text).toContain('"requests" "==2.0.0" (PyPI)');
  });

  it("manifests: a version past the bound, a line past the bound and TOML nested too deeply are held as not read", () => {
    expect(write("requirements.txt", `requests==${zeros(38)}\n`).text).toMatch(/could not be read \(a version over 80 characters\)/);
    expect(write("requirements.txt", `requests==2.0.0 ${"x".repeat(70_000)}\n`).text).toMatch(/could not be read \(a requirements line over 65536 characters\)/);
    expect(write("Cargo.toml", `[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0.0"\n\n[package.metadata]\nx = ${"[".repeat(8000)}${"]".repeat(8000)}\n`).text).toMatch(/could not be read \(a TOML value nested more than 100 levels deep\)/);
  });

  it("a MultiEdit whose work is past the bound is held before any edit is applied", () => {
    const big = Array.from({ length: 200_000 }, (_, i) => `pkg${i}==1.0.${i}`).join("\n") + "\n";
    const path = join(dir, "requirements.txt");
    writeFileSync(path, big);
    const edits = Array.from({ length: 8000 }, (_, i) => ({ old_string: `pkg${i}==1.0.${i}\n`, new_string: `pkg${i}==1.0.${i}\n` }));
    const t0 = performance.now();
    const r = decide({ tool_name: "MultiEdit", tool_input: { file_path: path, edits } });
    expect(performance.now() - t0).toBeLessThan(1000);
    expect(r.text).toMatch(/could not be read \(8000 edits to a file of \d+ KB, more work than the hook takes on\)/);
  });
});

describe("harmless calls go ahead whatever their size", () => {
  it.each([`git commit -m "${"x".repeat(70 * 1024)}"`, `echo ${"y".repeat(70 * 1024)}`, `npm run build -- ${"z".repeat(70 * 1024)}`])("%#", (command) => {
    expect(bash(command).decision).toBe("allow");
  });

  it("a non-manifest file of any size", () => {
    expect(write("README.md", "x".repeat(2_000_000)).decision).toBe("allow");
  });
});
