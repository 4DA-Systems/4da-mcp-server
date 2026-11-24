// SPDX-License-Identifier: Apache-2.0
/**
 * A manifest that cannot be parsed is never a clean, complete answer, with or without a lockfile.
 *
 * Review of the 6.5.1 candidate (2026-11-24, p-agree.mjs / p-stale.mjs; claims review
 * projects/unread-manifest): package.json that is not valid JSON beside a readable package-lock.json
 * read as complete and healthy with "0 direct dependencies checked", and the lockfile/package.json
 * cross-check was silently skipped (readManifestDeclarations swallowed the error,
 * declaredWithoutEntry returned nothing, scanCurrentProject turned the failure into no
 * dependencies). The same for Cargo.toml beside Cargo.lock, a subdirectory package.json, a
 * subdirectory pyproject.toml, a Cargo.toml made invalid while the server runs, and an
 * unparseable pnpm-lock.yaml beside a package-lock.json. Now the file is named as unreadable,
 * coverage.complete is false and the plan says NOT CHECKED, as for an unreadable lockfile.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { tomlSyntaxProblem } from "../live/lockfile-parsers.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM = { ms: { latest: "2.1.3", versions: { "2.1.3": {} } } };
  h.CRATES = { serde: [{ vers: "1.0.200" }] };
});
afterEach(() => h.dispose());

const npmLock = JSON.stringify({ name: "x", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "x", dependencies: { ms: "2.1.3" } }, "node_modules/ms": { version: "2.1.3" } } });
const cargoToml = '[package]\nname = "x"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = "1.0.200"\n';
const cargoLock = 'version = 3\n\n[[package]]\nname = "x"\nversion = "0.1.0"\ndependencies = [\n "serde",\n]\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n';

/** The scan and the plan of the project, and what they name as not read. */
async function answers() {
  const scan = await h.scan();
  const { result: plan } = await h.plan();
  return { scan, plan, named: JSON.stringify(scan.coverage ?? {}) };
}

function expectIncomplete(a: Awaited<ReturnType<typeof answers>>, file: string) {
  expect(a.scan.coverage.complete).toBe(false);
  expect(a.named).toContain(file);
  expect(a.plan.vulnerabilityDataAvailable).toBe(false);
  expect(String(a.plan.summary)).toMatch(/^NOT CHECKED/);
}

describe("tomlSyntaxProblem", () => {
  it("finds an unclosed table header, an unclosed array, a line that is no key", () => {
    expect(tomlSyntaxProblem(cargoToml)).toBeNull();
    expect(tomlSyntaxProblem('[project]\nname = "x"\ndependencies = [\n  "a==1",\n  "b>=2",\n]\n[tool.x]\ny = { a = 1, b = "c" }\nz = """\nmulti\n"""\n')).toBeNull();
    expect(tomlSyntaxProblem('[package]\nname = "x"\n[dependencies\nserde = "1"\n')).not.toBeNull();
    expect(tomlSyntaxProblem('[project]\nname = "x"\ndependencies = ["requests==2.32.3", "idna==3.7"\n')).not.toBeNull();
    expect(tomlSyntaxProblem("[project\nname = 'x'\n")).not.toBeNull();
    expect(tomlSyntaxProblem('[package]\nthis is not toml\n')).not.toBeNull();
  });
});

describe("a manifest that cannot be parsed beside a lockfile that can", () => {
  it("package.json beside package-lock.json", async () => {
    h.write("package-lock.json", npmLock);
    h.write("package.json", '{"name":"x","dependencies":{"ms":"2.1.3",');
    expectIncomplete(await answers(), "package.json");
  });

  it("Cargo.toml beside Cargo.lock", async () => {
    h.write("Cargo.lock", cargoLock);
    h.write("Cargo.toml", '[package]\nname = "x"\n[dependencies\nserde = "1"\n');
    expectIncomplete(await answers(), "Cargo.toml");
  });

  it("an unparseable pnpm-lock.yaml beside a package-lock.json", async () => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    h.write("package-lock.json", npmLock);
    h.write("pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: [\n");
    expectIncomplete(await answers(), "pnpm-lock.yaml");
  });
});

describe("a subdirectory manifest that cannot be parsed, beside a clean root", () => {
  beforeEach(() => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
    h.write("package-lock.json", npmLock);
  });

  it("apps/b/package.json", async () => {
    h.write("apps/b/package.json", '{"name": "b", "dependencies": {');
    expectIncomplete(await answers(), "apps/b/package.json");
  });

  it("py/pyproject.toml", async () => {
    h.write("py/pyproject.toml", "[project\nname = 'x'\n");
    expectIncomplete(await answers(), "pyproject.toml");
  });
});

describe("a manifest made invalid while the server runs", () => {
  it("Cargo.toml with no Cargo.lock", async () => {
    h.write("Cargo.toml", cargoToml);
    const li = await h.live();
    const file = path.join(h.dir, "Cargo.toml");
    fs.writeFileSync(file, '[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies\nserde = "1.0.200"\n');
    const later = new Date(Date.now() + 5000);
    fs.utimesSync(file, later, later);
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expectIncomplete(await answers(), "Cargo.toml");
  });
});
