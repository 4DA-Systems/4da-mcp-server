// SPDX-License-Identifier: Apache-2.0
/**
 * Statements that were still wrong, held to what the code does: which tools send an installed or a
 * fix version to a registry, who the breaking-change raters were, what leaves the machine (the
 * bundle's long description), the Ruby lockfiles read, what an unreadable manifest is called, and
 * the concise scan's measured size.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { lockfileProblemNotes } from "../project-tree.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const text = (file: string) => readFileSync(join(root, file), "utf8");
const readme = text("README.md");

describe("README: which versions reach a registry", () => {
  it("holds the installed-version claim to dependency_check and names upgrade_planner's real exceptions", () => {
    expect(readme).not.toContain("a1119: verify installed-version claim");
    const line = readme.split("\n").find((l) => l.includes("**npm full packument**"))!;
    expect(line).toMatch(/`dependency_check` requests per-release documents of the releases it is judging/);
    expect(line).toMatch(/The version you have installed \(`from`\) is named only to the Go proxy \(its `\.info`\) and, on PyPI, only when it is also `to`/);
    expect(line).not.toMatch(/the version you have installed is never sent to a registry/);
    expect(line).toMatch(/`upgrade_planner` names a version to a registry in two cases: on PyPI, a parent that uv\.lock or a compiled requirements file names without its requirement is asked for by its own release/);
    expect(line).toMatch(/on npm, PyPI and Go a fix version is asked for by name/);
  });

  it("states the concise scan's size as measured on the merged build", () => {
    expect(readme).not.toMatch(/10\.5k tokens/);
    expect(readme).toMatch(/about 10k tokens on a project with about 290 advisories/);
  });
});

describe("tool and listing text", () => {
  it("upgrade_impact says its blind raters were model instances", () => {
    const source = text("src/tools/upgrade-impact.ts");
    expect(source).toMatch(/three blind raters, each a model instance, 2026-10-11/);
    expect(source).not.toMatch(/three blind raters, 2026/);
  });

  it("the bundle's long description names Hacker News search beside OSV.dev and the registries", () => {
    const script = text("scripts/build-mcpb.mjs");
    const long = /long_description:\s*\n\s*"([^"]+)"/.exec(script)?.[1] ?? "";
    expect(long).toMatch(/ecosystem pulse sends your dependency names to Hacker News search \(hn\.algolia\.com\)/);
    expect(long).not.toMatch(/The only data that ever leaves your machine is public package names and versions sent to OSV\.dev and the packages' own registries/);
  });

  it("every static list that names Gemfile.lock names gems.locked too", () => {
    for (const file of ["src/tools/vulnerability-scan.ts", "src/tools/dependency-health.ts"]) {
      // Sentences and lists; the restore-command map has its own gems.locked entry.
      const source = text(file);
      const lines = source.split("\n").filter((l) => l.includes("Gemfile.lock") && !l.includes('"Gemfile.lock": '));
      if (source.includes('"Gemfile.lock": ')) expect(source, file).toContain('"gems.locked": ');
      expect(lines.length, file).toBeGreaterThan(0);
      for (const line of lines) expect(line, `${file}: ${line.trim()}`).toContain("gems.locked");
    }
  });
});

describe("an unreadable file is named for what it is", () => {
  it("a manifest is a file, not a lockfile", () => {
    const [note] = lockfileProblemNotes([{ file: "app/package.json", error: "invalid JSON" }]);
    expect(note).toMatch(/^UNREADABLE: 1 file could not be read, so its dependencies were not checked: app\/package\.json \(invalid JSON\)/);
  });

  it("lockfiles are still lockfiles, and a mix is files", () => {
    expect(lockfileProblemNotes([{ file: "a/package-lock.json", error: "x" }, { file: "b\\Gemfile.lock", error: "y" }])[0]).toMatch(/^UNREADABLE: 2 lockfiles could not be read/);
    expect(lockfileProblemNotes([{ file: "pyproject.toml", error: "x" }, { file: "uv.lock", error: "y" }])[0]).toMatch(/^UNREADABLE: 2 files could not be read/);
  });
});
