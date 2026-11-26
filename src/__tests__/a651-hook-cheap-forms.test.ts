// SPDX-License-Identifier: Apache-2.0
/**
 * Smaller reading gaps of the 6.5.1 candidate guard (blind review 2026-11-24, item 7, and the third
 * review's H3, H5):
 * - a value-taking npm option before the subcommand (`npm --location project install x@1`) left
 *   the command unread;
 * - the public index named explicitly (`pip install -i https://pypi.org/simple`, `--index-url`,
 *   `cargo add --registry crates-io`) was read as a private one, and the command went ahead;
 * - a PEP 508 requirement with its specifier in parentheses (`"requests (==2.25.0)"`) was unread;
 * - an npm alias added to package.json (`"yargs-parser": "npm:minimist@1.2.6"`, or on the command
 *   line) and a `"latest"` tag went ahead, although the alias installs minimist 1.2.6;
 * and three false denials: a PowerShell block comment `<# npm i lodash@4.17.20 #>`, a PEP 503
 * spelling-only rename (`requests_toolbelt` -> `requests-toolbelt`), and an edit of a
 * `syntax_test_requirements.txt` (the server reads no such file).
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { installsIn, respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";

let dir: string;
let home: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "a651-hook-cheap-"));
  home = join(dir, "home");
  mkdirSync(home);
  writeFileSync(join(home, LEDGER_FILE), "");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const read = (command: string, dialect: "bash" | "powershell" = "bash") => installsIn(command, dialect).map((r) => `${r.ecosystem} ${r.name} ${r.spec}`);

function editDecision(file: string, before: string, oldString: string, newString: string): string | null {
  const path = join(dir, file);
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, before);
  const out = respond(
    { hook_event_name: "PreToolUse", tool_name: "Edit", cwd: dir, tool_input: { file_path: path, old_string: oldString, new_string: newString } },
    { FOURDA_MCP_HOME: home },
    Date.now(),
  );
  return out === "" ? null : (JSON.parse(out) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason;
}

describe("commands", () => {
  it("an npm option that takes a value, before the subcommand", () => {
    expect(read("npm --location project install lodash@4.17.20")).toEqual(["npm lodash 4.17.20"]);
    expect(read("npm --audit-level high install lodash@4.17.20")).toEqual(["npm lodash 4.17.20"]);
  });

  it("the public index or registry named explicitly is the public one", () => {
    expect(read("pip install -i https://pypi.org/simple requests==2.25.0")).toEqual(["PyPI requests ==2.25.0"]);
    expect(read("pip install --index-url https://pypi.org/simple/ requests==2.25.0")).toEqual(["PyPI requests ==2.25.0"]);
    expect(read("pip install --index-url=https://pypi.org/simple requests==2.25.0")).toEqual(["PyPI requests ==2.25.0"]);
    expect(read("uv lock --upgrade-package requests==2.25.0 --index-url https://pypi.org/simple")).toEqual(["PyPI requests ==2.25.0"]);
    expect(read("cargo add --registry crates-io serde@1.0.100")).toEqual(["crates.io serde 1.0.100"]);
    expect(read("cargo add --registry=crates-io serde@1.0.100")).toEqual(["crates.io serde 1.0.100"]);
  });

  it("another index or registry still leaves the command unread", () => {
    expect(read("pip install -i https://pypi.example.com/simple requests==2.25.0")).toEqual([]);
    expect(read("pip install --index-url https://pypi.org.evil.example/simple requests==2.25.0")).toEqual([]);
    expect(read("pip install --find-links https://pypi.org/simple requests==2.25.0")).toEqual([]);
    expect(read("cargo add --registry my-company serde@1.0.100")).toEqual([]);
  });

  it("a PEP 508 specifier in parentheses", () => {
    expect(read("pip install 'requests (==2.25.0)'")).toEqual(["PyPI requests ==2.25.0"]);
    expect(read('pip install "requests[socks] (>=2.25,<3)"')).toEqual(["PyPI requests >=2.25,<3"]);
  });

  it("an npm alias is read as the package it installs", () => {
    expect(read("npm i yargs-parser@npm:minimist@1.2.6")).toEqual(["npm minimist 1.2.6"]);
    expect(read("pnpm add my-lodash@npm:lodash@^4.17.0")).toEqual(["npm lodash ^4.17.0"]);
    expect(read("npm i x@npm:@scope/pkg@1.0.0")).toEqual(["npm @scope/pkg 1.0.0"]);
    // An alias with no version installs its target's newest release (wave 2: the request "latest").
    expect(read("npm i x@npm:lodash")).toEqual(["npm lodash latest"]);
  });

  it("a PowerShell block comment is not a command", () => {
    expect(read("<# npm i lodash@4.17.20 #> npm ci", "powershell")).toEqual([]);
    expect(read("<# a\nnpm i lodash@4.17.20\n#>\nnpm i left-pad@1.3.0", "powershell")).toEqual(["npm left-pad 1.3.0"]);
  });
});

describe("manifest edits", () => {
  it("an npm alias added to package.json is held as its target", () => {
    const reason = editDecision("package.json", '{\n  "dependencies": {\n    "a": "1.0.0"\n  }\n}\n', '"a": "1.0.0"', '"a": "1.0.0",\n    "yargs-parser": "npm:minimist@1.2.6"');
    expect(reason).toContain('"minimist" "1.2.6" (npm)');
  });

  it('Cargo `registry = "crates-io"` is the public registry: held; another registry goes ahead', () => {
    const before = '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\ntokio = "1.35.0"\n';
    expect(editDecision("Cargo.toml", before, 'tokio = "1.35.0"', 'tokio = { version = "1.18.0", registry = "crates-io" }')).toContain('"tokio" "1.18.0" (crates.io)');
    expect(editDecision("Cargo.toml", before, 'tokio = "1.35.0"', 'tokio = { version = "1.18.0", registry = "corp" }')).toBeNull();
  });

  it('"latest" is held with a call for latest', () => {
    const reason = editDecision("package.json", '{\n  "dependencies": {\n    "a": "1.0.0"\n  }\n}\n', '"a": "1.0.0"', '"a": "1.0.0",\n    "debug": "latest"');
    expect(reason).toContain('{"ecosystem":"npm","package":"debug","to":"latest"}');
  });

  it("a PEP 503 spelling-only rename in requirements.txt introduces nothing", () => {
    expect(editDecision("requirements.txt", "requests_toolbelt==1.0.0\n", "requests_toolbelt==1.0.0", "requests-toolbelt==1.0.0")).toBeNull();
    expect(editDecision("requirements.txt", "Requests.Toolbelt==1.0.0\n", "Requests.Toolbelt==1.0.0", "requests-toolbelt==1.0.0")).toBeNull();
  });

  it("the same in pyproject.toml", () => {
    const before = '[project]\nname = "app"\ndependencies = ["requests_toolbelt==1.0.0"]\n';
    expect(editDecision("pyproject.toml", before, '"requests_toolbelt==1.0.0"', '"requests-toolbelt==1.0.0"')).toBeNull();
  });

  it("a syntax_test_requirements.txt is not a manifest", () => {
    expect(editDecision("syntax_test_requirements.txt", "requests==2.31.0\n", "requests==2.31.0", "requests==2.25.0")).toBeNull();
    expect(editDecision("requirements/syntax_test_base.txt", "requests==2.31.0\n", "requests==2.31.0", "requests==2.25.0")).toBeNull();
  });
});
