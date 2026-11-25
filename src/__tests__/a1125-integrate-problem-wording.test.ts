// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25: lockfileProblemNotes worded every lockfile not compared with its manifest
 * "against the package.json files" (a Gemfile, composer.json, Pipfile or pyproject.toml makes it
 * too), and a lockfile that is whole but older than its manifest "NOT read to the end". The second
 * now reads "older than its manifest: <manifest> declares <names>, but this lockfile has no entry
 * for them"; damage inside a file keeps its wording.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { resolveVersionSource } from "../live/lockfile-parsers.js";
import type { OsvEcosystem } from "../live/types.js";
import { lockfileProblemNotes } from "../project-tree.js";

let dir: string;
beforeEach(() => {
  dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1125-int-words-")));
});
afterEach(() => {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

const write = (files: Record<string, string>) => {
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
};
const notes = (ecosystem: OsvEcosystem) => lockfileProblemNotes(resolveVersionSource(dir, ecosystem).problems ?? [], (f) => path.basename(f)).join(" ");

const GEMFILE_LOCK_RAKE = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.2.1)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake (= 13.2.1)\n\nBUNDLED WITH\n   2.4.22\n";

describe("a lockfile older than its manifest", () => {
  it("Gemfile.lock (audit fixture C1): older than its manifest, not 'NOT read to the end'", () => {
    write({ Gemfile: "source 'https://rubygems.org'\n\ngem 'rake', '13.2.1'\ngem 'carrierwave', '1.3.1'\n", "Gemfile.lock": GEMFILE_LOCK_RAKE });
    const text = notes("RubyGems");
    expect(text).toMatch(/PARTIAL: 1 lockfile is older than its manifest: Gemfile\.lock \(Gemfile declares carrierwave, but this lockfile has no entry for it/);
    expect(text).not.toMatch(/NOT read to the end/);
  });

  it("Pipfile.lock (audit fixture C2): the same", () => {
    write({
      Pipfile: '[[source]]\nurl = "https://pypi.org/simple"\nverify_ssl = true\nname = "pypi"\n\n[packages]\nsix = "==1.16.0"\ndjango = "==2.2.0"\n',
      "Pipfile.lock": JSON.stringify({
        _meta: { hash: { sha256: "0".repeat(64) }, "pipfile-spec": 6, requires: {}, sources: [{ name: "pypi", url: "https://pypi.org/simple", verify_ssl: true }] },
        default: { six: { hashes: [], index: "pypi", version: "==1.16.0" } },
        develop: {},
      }),
    });
    const text = notes("PyPI");
    expect(text).toMatch(/PARTIAL: 1 lockfile is older than its manifest: Pipfile\.lock \(Pipfile declares django, but this lockfile has no entry for it/);
    expect(text).not.toMatch(/NOT read to the end/);
  });

  it("package-lock.json missing a declared dependency, nothing damaged: older than its manifest", () => {
    write({
      "package.json": JSON.stringify({ name: "x", version: "1.0.0", dependencies: { lodash: "4.17.21", qs: "6.5.2" } }),
      "package-lock.json": JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", version: "1.0.0", dependencies: { lodash: "4.17.21", qs: "6.5.2" } }, "node_modules/lodash": { version: "4.17.21" } } }),
    });
    expect(notes("npm")).toMatch(/PARTIAL: 1 lockfile is older than its manifest: package-lock\.json \(package\.json declares qs/);
  });

  it("a damaged file keeps 'NOT read to the end'", () => {
    const text = lockfileProblemNotes([{ file: "Cargo.lock", error: "it is truncated or damaged: x", partial: true }]).join(" ");
    expect(text).toMatch(/NOT read to the end/);
    expect(text).not.toMatch(/older than its manifest/);
  });

  it("two of each are counted apart", () => {
    const text = lockfileProblemNotes([
      { file: "a/Gemfile.lock", error: "e1", partial: true, behindManifest: true },
      { file: "b/Gemfile.lock", error: "e2", partial: true, behindManifest: true },
      { file: "c/Cargo.lock", error: "e3", partial: true },
    ]).join(" ");
    expect(text).toMatch(/PARTIAL: 2 lockfiles are older than their manifests: a\/Gemfile\.lock \(e1\); b\/Gemfile\.lock \(e2\)\./);
    expect(text).toMatch(/PARTIAL: 1 lockfile was NOT read to the end: c\/Cargo\.lock \(e3\)\./);
  });
});

describe("a lockfile not cross-checked", () => {
  it("names the manifests that declare its dependencies, not only package.json", () => {
    const text = lockfileProblemNotes([{ file: "Gemfile.lock", error: "Gemfile could not be read", notCrossChecked: true }]).join(" ");
    expect(text).toMatch(/NOT CROSS-CHECKED: 1 lockfile was not cross-checked against the manifests that declare its dependencies: Gemfile\.lock/);
    expect(text).not.toMatch(/package\.json files/);
  });
});
