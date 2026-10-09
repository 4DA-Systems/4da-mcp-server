// SPDX-License-Identifier: Apache-2.0
/**
 * What the standalone scan reads, and saying so when it reads less
 * (fixture corpus vs osv-scanner and pip-audit, 2026-10-10):
 *
 * - langchain: 108 lockfiles up to 3 levels down; the walk (depth 2, 64
 *   projects) read 64 and dropped 44 without a word in any answer.
 * - Python: one source per directory. langchain's libs/community has a
 *   poetry.lock AND _test_minimum_requirements.txt (only the lock was read);
 *   superset keeps its runtime pins in requirements/base.txt (never read).
 * - No lockfile: package.json / Cargo.toml range floors were scanned as if
 *   installed (nushell samples/wasm: 2 false findings), and Cargo.toml's own
 *   [package] `version` / `edition` keys were read as crates.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { MAX_PROJECTS, discoveryNote, scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { resolvePython, readRequirementsFile } from "../live/lockfile-parsers-pygo.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { resolveGroup } from "../live/resolution.js";
import { formatScanResult } from "../tools/vulnerability-scan-format.js";
import { conciseScanResult } from "../tools/vulnerability-scan-concise.js";
import type { VulnerabilityScanResult } from "../live/types.js";

let dir: string;
const write = (rel: string, content: string) => {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
};
const rels = (entries: Array<{ dir: string }>) => entries.map((e) => path.relative(dir, e.dir).replace(/\\/g, "/") || ".").sort();
const POETRY = (name: string, version: string) => `[[package]]\nname = "${name}"\nversion = "${version}"\n`;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-discovery-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("project-tree bounds are wider and never silent", () => {
  it("reads lockfiles three levels down (langchain libs/partners/*/poetry.lock)", () => {
    write("libs/partners/openai/poetry.lock", POETRY("openai", "1.6.1"));
    write("libs/partners/openai/pyproject.toml", '[tool.poetry]\nname = "langchain-openai"\n');
    const { entries, discovery } = scanProjectTree(dir);
    expect(rels(entries)).toEqual([".", "libs/partners/openai"]);
    expect(discovery.skippedCount).toBe(0);
    expect(discoveryNote(discovery)).toBeNull();
  });

  it("past the project limit, every skipped lockfile is counted and named, and the note says so", () => {
    for (let i = 0; i < MAX_PROJECTS + 4; i++) write(`templates/t${String(i).padStart(3, "0")}/poetry.lock`, POETRY("x", "1.0.0"));
    const { entries, discovery } = scanProjectTree(dir);
    expect(entries.length).toBe(MAX_PROJECTS);
    expect(discovery.skippedCount).toBe(5);
    expect(discovery.skipped.every((s) => s.reason === "project_limit")).toBe(true);
    expect(discoveryNote(discovery)).toMatch(/^Partial scan: 5 lockfiles were found but NOT scanned \(past the 256-project limit\): templates\/t\d+\/poetry\.lock/);
  });

  it("a lockfile deeper than the depth bound is reported, not dropped silently", () => {
    write("a/b/c/d/e/package-lock.json", "{}");
    const { entries, discovery } = scanProjectTree(dir);
    expect(rels(entries)).toEqual(["."]);
    expect(discovery.skipped).toEqual([{ path: "a/b/c/d/e/package-lock.json", reason: "depth" }]);
    expect(discoveryNote(discovery)).toMatch(/deeper than 4 levels/);
  });

  it("a `dir/*/` gitignore rule ignores the subdirectories, not the files beside them (langchain docs/api_reference)", () => {
    write(".gitignore", "docs/api_reference/*/\n");
    write("docs/api_reference/requirements.txt", "sphinx==4.5.0\n");
    write("docs/api_reference/_build/requirements.txt", "sphinx==1.0.0\n");
    expect(rels(scanProjectTree(dir).entries)).toEqual([".", "docs/api_reference"]);
  });

  it("vulnerability_scan carries the gap in both formats", () => {
    write("a/b/c/d/e/package-lock.json", "{}");
    const { discovery } = scanProjectTree(dir);
    const scan: VulnerabilityScanResult = {
      scannedAt: "2026-10-10T00:00:00Z", projectPath: dir, ecosystemsScanned: ["npm"], totalScanned: 3, totalVulnerable: 0,
      platformInactiveVulnerable: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities: [],
      cleanCount: 3, scanDurationMs: 1, cached: false, offline: false,
    };
    const ctx = {
      resolution: null, reResolvedThisCall: false, drift: [], includeDev: false, discovery,
      unresolved: [{ dir: path.join(dir, "samples", "wasm"), manifest: path.join(dir, "samples", "wasm", "Cargo.toml"), ranges: 12 }],
    };
    const detailed = formatScanResult(scan, undefined, ctx);
    expect(detailed.coverage).toMatchObject({
      complete: false,
      lockfiles_not_scanned: 1,
      skipped_lockfiles: [{ path: "a/b/c/d/e/package-lock.json", reason: "depth" }],
      unresolved_manifests: [{ manifest: "samples/wasm/Cargo.toml", declared_ranges: 12, fix: "cargo generate-lockfile in samples/wasm" }],
    });
    expect(detailed.coverage!.note).toMatch(/12 dependencies in 1 manifest with no lockfile \(samples\/wasm\/Cargo\.toml\) are declared ranges, not installed versions, and were not checked/);
    const concise = conciseScanResult(detailed);
    expect(concise.coverage).toMatchObject({ complete: false, lockfiles_not_scanned: 1 });
    expect(concise.coverage!.note).toBe(detailed.coverage!.note);
    // A complete scan carries no coverage block at all.
    expect(formatScanResult(scan, undefined, { resolution: null, reResolvedThisCall: false, drift: [], includeDev: false }).coverage).toBeUndefined();
  });
});

describe("Python: every source in a directory, merged", () => {
  it("poetry.lock and _test_minimum_requirements.txt side by side are both read (langchain libs/community)", () => {
    write("poetry.lock", POETRY("aiohttp", "3.9.1"));
    write("_test_minimum_requirements.txt", "langchain-core==0.1.0\nSQLAlchemy==1.4.0\n");
    const read = resolvePython(dir);
    expect(read.kind).toBe("lockfile");
    expect(read.instances.map((i) => `${i.name}@${i.version}${i.dev ? " dev" : ""}`).sort()).toEqual([
      "aiohttp@3.9.1", "langchain-core@0.1.0 dev", "sqlalchemy@1.4.0 dev",
    ]);
    expect([read.source, ...(read.extraSources ?? [])].map((f) => path.basename(f!))).toEqual(["poetry.lock", "_test_minimum_requirements.txt"]);
  });

  it("requirements/ folder pins (superset requirements/base.txt) and -r includes are read; dev scope by name only", () => {
    write("requirements/base.txt", "-e file:.\nalembic==1.6.5\n    # via flask-migrate\ncelery==5.2.2\n");
    write("requirements/development.txt", "-r base.txt\npytest==7.1.2\n");
    write("requirements/base.in", "alembic\n");
    const read = resolvePython(dir);
    const by = Object.fromEntries(read.instances.map((i) => [i.name, i]));
    expect(Object.keys(by).sort()).toEqual(["alembic", "celery", "pytest"]);
    expect(by.pytest.dev).toBe(true);
    // In base.txt (scope unknown) and, through -r, development.txt: never claimed dev.
    expect(by.alembic.dev).toBeUndefined();
    // The group resolves python from these files.
    const { entries } = scanProjectTree(dir);
    expect(treeResolutionGroups(entries).map((g) => g.language)).toContain("python");
  });

  it("a .txt that includes requirements.txt and pins packages is a requirements file (CTFd development.txt)", () => {
    write("requirements.txt", "alembic==1.4.3\n");
    write("development.txt", "-r requirements.txt\npytest==5.4.2\nmoto==1.3.16\n");
    write("LICENSE.txt", "Apache License 2.0 -r not a pin\n");
    const read = resolvePython(dir);
    expect([read.source, ...(read.extraSources ?? [])].map((f) => path.basename(f!)).sort()).toEqual(["development.txt", "requirements.txt"]);
    const by = Object.fromEntries(read.instances.map((i) => [i.name, i.dev]));
    expect(by).toEqual({ alembic: undefined, pytest: true, moto: true });
  });

  it("a constraints file gives versions only to names the requirements list", () => {
    write("constraints.txt", "flask==2.0.1\nrequests==2.25.0\n");
    write("requirements.txt", "-c constraints.txt\nflask\n");
    expect(readRequirementsFile(path.join(dir, "requirements.txt"))).toEqual([{ name: "flask", version: "2.0.1" }]);
  });

  it("pdm.lock is read", () => {
    write("pdm.lock", POETRY("urllib3", "1.26.5"));
    expect(resolvePython(dir).instances).toEqual([{ name: "urllib3", version: "1.26.5" }]);
  });
});

describe("no lockfile: declared ranges are labelled, never scanned as installs", () => {
  it("Cargo.toml: ranges are not audited, [package] keys are not crates, exact pins are", () => {
    write(
      "Cargo.toml",
      '[package]\nname = "wasm"\nversion = "0.60.0"\nedition = "2018"\n\n[dependencies]\nwasm-bindgen = "0.2.63"\nfutures = {version = "0.3", features = ["compat"]}\nonce = "=1.2.3"\n',
    );
    const read = resolveVersionSource(dir, "crates.io");
    expect(read.kind).toBe("declared_ranges");
    expect([...read.versions.keys()].sort()).toEqual(["futures", "once", "wasm-bindgen"]);
    const group = resolveGroup({ dir, language: "rust", deps: ["wasm-bindgen", "futures", "once"], devDeps: [], targets: {} });
    expect(group.audit.map((d) => `${d.name}@${d.version}`)).toEqual(["once@1.2.3"]);
    expect(group.resolved.find((d) => d.name === "wasm-bindgen")).toMatchObject({ version: "0.2.63", declaredRange: "0.2.63" });
    expect(group.unresolved).toEqual({ manifest: path.join(dir, "Cargo.toml"), ranges: 2 });
    expect(group.source?.kind).toBe("declared_ranges");
  });

  it("package.json without a lockfile: only exact pins reach OSV", () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "^4.17.0", "left-pad": "1.3.0" }, devDependencies: { jest: "~29.0.0" } }));
    const group = resolveGroup({ dir, language: "javascript", deps: ["lodash", "left-pad"], devDeps: ["jest"], targets: {} });
    expect(group.audit.map((d) => d.name)).toEqual(["left-pad"]);
    expect(group.resolved.find((d) => d.name === "lodash")?.declaredRange).toBe("^4.17.0");
    expect(group.unresolved?.ranges).toBe(2);
  });
});
