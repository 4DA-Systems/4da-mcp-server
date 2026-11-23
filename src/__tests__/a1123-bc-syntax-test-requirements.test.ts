// SPDX-License-Identifier: Apache-2.0
/**
 * A Sublime Text syntax test is never a requirements file. That convention names every test file
 * `syntax_test_*`; its lines exercise a highlighter and pin nothing.
 *
 * bat (a Rust project) keeps `assets/syntaxes/02_Extra/syntax_test_requirements.txt`. It was read
 * as a pinned requirements file: a `gopher://` index line made a "private" PyPI package of the
 * word `name`, the whole scan of a Cargo project turned into "NOT CHECKED (private)" with null
 * totals, and gitpython and pygments appeared as rows of a Rust project's upgrade plan.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LiveIntelligence } from "../live/index.js";
import { requirementFiles } from "../live/lockfile-parsers-pygo.js";
import { isRequirementsFileName, lockfilesIn, scanProjectTree } from "../project-tree.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

/** The shape of bat's file: a syntax header, option lines, URL requirements, pins, assertion comments. */
const SYNTAX_TEST = [
  '# SYNTAX TEST "Packages/Requirements/requirements.sublime-syntax"',
  "--index-url gopher://example.invalid/simple",
  "# ^^^^^^^^^ variable.parameter",
  "name @ gopher://example.invalid/name-1.0.tar.gz",
  "gitpython==3.0.7",
  "# ^^^^^^ string.package_name",
  "pygments==2.7.4",
  "",
].join("\n");

let dir: string;
let asked: string[];
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-bc-syntaxtest-"));
  asked = [];
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version?: string }> };
      for (const q of queries) asked.push(`${q.package.ecosystem}:${q.package.name}@${q.version}`);
      return new Response(JSON.stringify({ results: queries.map(() => ({})) }), { status: 200 });
    }
    throw new TypeError(`fetch failed (${url})`);
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

const write = (rel: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), content);
};
const scan = async () => (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;

describe("which names are requirement files", () => {
  it.each(["requirements.txt", "requirements-dev.txt", "dev_requirements.txt", "test_requirements.txt", "_test_minimum_requirements.txt", "Requirements.TXT"])("%s is one", (name) => {
    expect(isRequirementsFileName(name)).toBe(true);
  });

  it.each(["syntax_test_requirements.txt", "SYNTAX_TEST_requirements.txt", "syntax_test_requirements-dev.txt", "requirements.md", "notes.txt"])("%s is not", (name) => {
    expect(isRequirementsFileName(name)).toBe(false);
  });
});

describe("a Sublime syntax test beside real files", () => {
  it("is not found as a pin file, in a directory or in a requirements/ folder", () => {
    write("requirements.txt", "requests==2.31.0\n");
    write("syntax_test_requirements.txt", SYNTAX_TEST);
    write("requirements/base.txt", "idna==3.4\n");
    write("requirements/syntax_test_requirements.txt", SYNTAX_TEST);
    expect(lockfilesIn(dir).sort()).toEqual(["requirements.txt", "requirements/base.txt"]);
    expect(requirementFiles(dir).map((f) => path.relative(dir, f).replace(/\\/g, "/")).sort()).toEqual(["requirements.txt", "requirements/base.txt"]);
  });

  it("is not sniffed as a file that includes requirements either", () => {
    write("requirements.txt", "requests==2.31.0\n");
    write("syntax_test_extra.txt", "-r requirements.txt\npytest==5.4.2\n");
    expect(requirementFiles(dir).map((f) => path.basename(f))).toEqual(["requirements.txt"]);
  });
});

describe("a Cargo project that keeps one among its assets", () => {
  it("is scanned as the Cargo project it is: no PyPI ecosystem, nothing private, a complete answer", async () => {
    write("Cargo.toml", '[package]\nname = "viewer"\nversion = "0.1.0"\n\n[dependencies]\nregex = "1"\n');
    write(
      "Cargo.lock",
      'version = 3\n\n[[package]]\nname = "regex"\nversion = "1.10.2"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "viewer"\nversion = "0.1.0"\ndependencies = [\n "regex",\n]\n',
    );
    write("assets/syntaxes/02_Extra/syntax_test_requirements.txt", SYNTAX_TEST);

    expect(scanProjectTree(dir).entries.map((e) => path.relative(dir, e.dir).replace(/\\/g, "/") || ".")).toEqual(["."]);
    const r = await scan();
    expect(r.ecosystems_scanned).toEqual(["crates.io"]);
    expect(asked).toEqual(["crates.io:regex@1.10.2"]);
    expect(String(r.summary ?? "")).not.toMatch(/NOT CHECKED/);
    expect(r.total_vulnerable_packages).toBe(0);
    expect(r.coverage).toMatchObject({ complete: true, lockfiles_read: 1 });
    expect(JSON.stringify(r)).not.toMatch(/gitpython|pygments|gopher/i);
  });
});
