// SPDX-License-Identifier: Apache-2.0
/**
 * A lockfile or manifest that holds git merge-conflict markers is not parsed at all: neither side
 * is known to be what is installed. It is listed under `coverage.not_scanned.lockfiles` with
 * reason `merge_conflict`, the answer is not complete, and the tools say NOT CHECKED for it.
 * A conflicted uv.lock used to be read as clean with one side taken, and a conflicted go.sum was
 * not named at all.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { hasMergeConflict } from "../live/text-file.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import type { OsvEcosystem } from "../live/types.js";

/** Packages the OSV stub reports one HIGH advisory for. */
const VULNERABLE = new Set(["jinja2", "lodash", "smallvec", "golang.org/x/net", "rack", "monolog/monolog", "django"]);

/** Both sides of a conflict, as git writes them into the file. */
const conflict = (ours: string, theirs: string) => `<<<<<<< HEAD\n${ours}\n=======\n${theirs}\n>>>>>>> feature\n`;

describe("a1123 discovery: merge-conflict markers", () => {
  let dir: string;
  let priorOffline: string | undefined;
  let asked: Array<{ name: string; version?: string; ecosystem: string }>;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-conflict-"));
    asked = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version?: string }> };
        for (const q of queries) asked.push({ name: q.package.name, version: q.version, ecosystem: q.package.ecosystem });
        return new Response(
          JSON.stringify({ results: queries.map((q) => (VULNERABLE.has(q.package.name.toLowerCase()) ? { vulns: [{ id: `GHSA-${q.package.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}` }] } : {})) }),
          { status: 200 },
        );
      }
      if (url.includes("/v1/vulns/")) {
        const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
        return new Response(JSON.stringify({ id, summary: id, database_specific: { severity: "HIGH" } }), { status: 200 });
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
  const scan = async (extra: Record<string, unknown> = {}) =>
    (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true, ...extra }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
  const npmLock = (deps: Record<string, string>) =>
    JSON.stringify({
      name: "x",
      lockfileVersion: 3,
      packages: {
        "": { name: "x", dependencies: deps },
        ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` }])),
      },
    });
  const expectListed = (result: Record<string, any>, file: string) => {
    expect(result.coverage).toMatchObject({ complete: false });
    expect(result.coverage.not_scanned?.lockfiles).toEqual(expect.arrayContaining([{ path: file, reason: "merge_conflict" }]));
    expect((result.coverage.unreadable_lockfiles ?? []).map((p: { path: string }) => p.path)).not.toContain(file);
    expect((result.coverage.partial_lockfiles ?? []).map((p: { path: string }) => p.path)).not.toContain(file);
    expect(result.coverage.note).toMatch(new RegExp(`NOT CHECKED \\(merge conflict\\): .*${file.replace(/[.]/g, "\\.")}`));
  };

  it("recognises git's markers only as a whole conflict: <<<<<<<, then =======, then >>>>>>>, at line start", () => {
    expect(hasMergeConflict(conflict("a", "b"))).toBe(true);
    expect(hasMergeConflict(conflict("a", "b").replace(/\n/g, "\r\n"))).toBe(true);
    // A reStructuredText underline or a stray marker is not a conflict.
    expect(hasMergeConflict('[project]\nname = "x"\ndescription = """\nTitle\n=======\n"""\n')).toBe(false);
    expect(hasMergeConflict("a\n>>>>>>> b\n=======\n<<<<<<< c\n")).toBe(false);
    expect(hasMergeConflict("  <<<<<<< HEAD\nx\n=======\ny\n>>>>>>> b\n")).toBe(false);
  });

  it("a conflicted uv.lock is not read: neither side reaches OSV, and pyproject.toml's pins are not taken in its place", async () => {
    write("pyproject.toml", '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["jinja2>=3", "markupsafe==2.1.5"]\n');
    write(
      "uv.lock",
      [
        "version = 1",
        'requires-python = ">=3.9"',
        "",
        "[[package]]",
        'name = "app"',
        'version = "0.1.0"',
        'source = { editable = "." }',
        "",
        "[[package]]",
        'name = "jinja2"',
        conflict('version = "3.1.6"', 'version = "3.1.4"').trimEnd(),
        'source = { registry = "https://pypi.org/simple" }',
        "",
        "[[package]]",
        'name = "markupsafe"',
        'version = "2.1.5"',
        'source = { registry = "https://pypi.org/simple" }',
        "",
      ].join("\n"),
    );
    const read = resolveVersionSource(dir, "PyPI");
    expect(read.instances).toEqual([]);
    expect(read.problems).toEqual([expect.objectContaining({ file: path.join(dir, "uv.lock"), mergeConflict: true })]);

    const result = await scan();
    expect(asked).toEqual([]);
    expect(result.total_vulnerable_packages).toBeNull();
    expectListed(result, "uv.lock");
    expect(JSON.stringify(result)).not.toMatch(/NO LOCKFILE/);
  });

  it("go.sum with markers beside a clean go.mod (go 1.21): go.mod is read, go.sum is named", async () => {
    write("go.mod", "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/net v0.17.0\n");
    write("go.sum", conflict("golang.org/x/net v0.17.0 h1:aaa=", "golang.org/x/net v0.23.0 h1:bbb="));
    const result = await scan();
    expect(asked.map((q) => `${q.name}@${q.version}`)).toEqual(["golang.org/x/net@v0.17.0"]);
    expect(result.total_vulnerable_packages).toBe(1);
    expectListed(result, "go.sum");
  });

  it("package.json with markers beside a clean package-lock.json: the lockfile is read, the manifest is named", async () => {
    write("package.json", `{\n${conflict('  "dependencies": { "lodash": "4.17.20" }', '  "dependencies": { "lodash": "4.17.21" }')}}\n`);
    write("package-lock.json", npmLock({ lodash: "4.17.20" }));
    const result = await scan();
    expect(asked.map((q) => `${q.name}@${q.version}`)).toEqual(["lodash@4.17.20"]);
    expectListed(result, "package.json");
  });

  it("a conflicted package-lock.json: package.json's pins are not taken in its place, and the totals are null", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
    write("package-lock.json", `{\n${conflict('  "lockfileVersion": 3,', '  "lockfileVersion": 2,')}}\n`);
    const result = await scan();
    expect(asked).toEqual([]);
    expect(result.total_vulnerable_packages).toBeNull();
    expectListed(result, "package-lock.json");
    expect(JSON.stringify(result)).not.toMatch(/NO LOCKFILE/);
  });

  // Every text format the server reads: the conflict is caught before any reader takes a side.
  const cases: Array<{ file: string; ecosystem: OsvEcosystem; body: string; beside?: Record<string, string> }> = [
    {
      file: "pnpm-lock.yaml",
      ecosystem: "npm",
      beside: { "package.json": JSON.stringify({ dependencies: { lodash: "^4.17.0" } }) },
      body: `lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.0\n${conflict("        version: 4.17.20", "        version: 4.17.21")}\npackages:\n\n  lodash@4.17.20:\n    resolution: {integrity: sha512-aaa}\n\nsnapshots:\n\n  lodash@4.17.20: {}\n`,
    },
    {
      file: "yarn.lock",
      ecosystem: "npm",
      beside: { "package.json": JSON.stringify({ dependencies: { lodash: "^4.17.0" } }) },
      body: `# yarn lockfile v1\n\nlodash@^4.17.0:\n${conflict('  version "4.17.20"', '  version "4.17.21"')}  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz#abc"\n`,
    },
    {
      file: "bun.lock",
      ecosystem: "npm",
      beside: { "package.json": JSON.stringify({ dependencies: { lodash: "^4.17.0" } }) },
      body: `{\n  "lockfileVersion": 1,\n  "workspaces": { "": { "dependencies": { "lodash": "^4.17.0" } } },\n  "packages": {\n${conflict('    "lodash": ["lodash@4.17.20", "", {}, "sha512-a"],', '    "lodash": ["lodash@4.17.21", "", {}, "sha512-b"],')}  }\n}\n`,
    },
    {
      file: "Cargo.lock",
      ecosystem: "crates.io",
      body: `version = 3\n\n[[package]]\nname = "smallvec"\n${conflict('version = "1.6.0"', 'version = "1.13.2"')}source = "registry+https://github.com/rust-lang/crates.io-index"\n`,
    },
    {
      file: "poetry.lock",
      ecosystem: "PyPI",
      body: `[[package]]\nname = "django"\n${conflict('version = "3.2.0"', 'version = "4.2.16"')}description = "x"\n\n[metadata]\nlock-version = "2.0"\n`,
    },
    {
      file: "pdm.lock",
      ecosystem: "PyPI",
      body: `[[package]]\nname = "django"\n${conflict('version = "3.2.0"', 'version = "4.2.16"')}summary = "x"\n`,
    },
    {
      file: "Pipfile.lock",
      ecosystem: "PyPI",
      body: `{\n  "default": {\n${conflict('    "django": { "version": "==3.2.0" }', '    "django": { "version": "==4.2.16" }')}  },\n  "develop": {}\n}\n`,
    },
    { file: "requirements.txt", ecosystem: "PyPI", body: conflict("django==3.2.0", "django==4.2.16") },
    {
      file: "Gemfile.lock",
      ecosystem: "RubyGems",
      body: `GEM\n  remote: https://rubygems.org/\n  specs:\n${conflict("    rack (2.0.1)", "    rack (3.1.8)")}\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n`,
    },
    {
      file: "composer.lock",
      ecosystem: "Packagist",
      body: `{\n  "packages": [\n${conflict('    { "name": "monolog/monolog", "version": "1.0.0" }', '    { "name": "monolog/monolog", "version": "3.7.0" }')}  ],\n  "packages-dev": []\n}\n`,
    },
    { file: "go.mod", ecosystem: "Go", body: `module example.com/app\n\ngo 1.21\n\n${conflict("require golang.org/x/net v0.17.0", "require golang.org/x/net v0.23.0")}` },
  ];

  it.each(cases)("$file with markers is not read and is reported as a merge conflict", ({ file, ecosystem, body, beside }) => {
    for (const [name, content] of Object.entries(beside ?? {})) write(name, content);
    write(file, body);
    const read = resolveVersionSource(dir, ecosystem);
    expect(read.instances).toEqual([]);
    expect(read.problems ?? []).toEqual(expect.arrayContaining([expect.objectContaining({ file: path.join(dir, file), mergeConflict: true })]));
    // One problem per file: never also "unreadable", "partial" or "could not be compared".
    expect((read.problems ?? []).filter((p) => p.file === path.join(dir, file))).toHaveLength(1);
  });

  it("dependency_health withholds the score and says NOT CHECKED for a conflicted lockfile", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
    write("package-lock.json", npmLock({ lodash: "4.17.20" }));
    write("Cargo.toml", '[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\nsmallvec = "1"\n');
    write("Cargo.lock", `version = 3\n\n[[package]]\nname = "smallvec"\n${conflict('version = "1.6.0"', 'version = "1.13.2"')}source = "registry+https://github.com/rust-lang/crates.io-index"\n`);
    const live = new LiveIntelligence(new Database(":memory:"));
    const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
    const { entries, discovery } = scanProjectTree(dir);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    live.fetchRegistryHealth = async () => [];
    const health = await executeDependencyHealth(null, {}, live);
    expect(health.healthScore).toBeNull();
    expect(health.summary).toMatch(/NOT CHECKED \(merge conflict\): .*Cargo\.lock/);
  });
});
