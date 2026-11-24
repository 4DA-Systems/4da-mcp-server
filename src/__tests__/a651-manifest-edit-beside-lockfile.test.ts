// SPDX-License-Identifier: Apache-2.0
/**
 * A manifest edited beside a lockfile that was read, and a manifest or requirements file created
 * while the server runs, are seen on the next call.
 *
 * Review of the 6.5.1 candidate (2026-11-24, p-stale.mjs): resolution.ts dropped the manifest's
 * signature whenever a lockfile was read, so with package-lock.json (or Cargo.lock, ...) adding a
 * dependency to package.json alone never made the group stale: no row, no "lockfile older than its
 * manifest" partial check, and `coverage.complete: true` until a restart. A requirements file
 * created mid-session was not watched either (lockfileCandidates lists only files present at
 * resolution). A script edited in package.json still re-resolves nothing (what the resolution read
 * is unchanged), and an unchanged project costs stat calls only.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import type { LiveIntelligence } from "../live/index.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM = { ms: { latest: "2.1.3", versions: { "2.1.3": {} } }, lodash: { latest: "4.18.1", versions: { "4.18.1": {} } } };
});
afterEach(() => h.dispose());

function rewrite(file: string, body: string): void {
  h.write(file, body);
  const later = new Date(Date.now() + 5_000);
  fs.utimesSync(path.join(h.dir, file), later, later);
}
const direct = (li: LiveIntelligence, ecosystem: string) =>
  li
    .getResolvedDeps()
    .filter((d) => d.ecosystem === ecosystem)
    .map((d) => d.name)
    .sort();

describe("a manifest edited beside a lockfile that was read", () => {
  it("package-lock.json: a dependency added to package.json alone is a row, and the lockfile is partial", async () => {
    h.npmProject({ ms: "2.1.3" }, {}, { ms: { version: "2.1.3" } });
    const li = await h.live();
    expect(direct(li, "npm")).toEqual(["ms"]);
    rewrite("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3", lodash: "4.18.1" }, devDependencies: {} }));
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    const scan = await h.scan();
    expect(scan.coverage.complete).toBe(false);
    expect(JSON.stringify(scan.coverage.partial_lockfiles ?? [])).toContain("lodash");
  });

  it("package-lock.json: a dependency removed from package.json alone is no longer a row", async () => {
    h.npmProject({ ms: "2.1.3", lodash: "4.18.1" }, {}, { ms: { version: "2.1.3" }, lodash: { version: "4.18.1" } });
    const li = await h.live();
    expect(direct(li, "npm")).toEqual(["lodash", "ms"]);
    rewrite("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { lodash: "4.18.1" }, devDependencies: {} }));
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expect(direct(li, "npm")).toEqual(["lodash"]);
  });

  it("Cargo.lock: a crate added to Cargo.toml alone is a row", async () => {
    h.write("Cargo.toml", '[package]\nname = "x"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = "1.0.200"\n');
    h.write("Cargo.lock", 'version = 3\n\n[[package]]\nname = "x"\nversion = "0.1.0"\ndependencies = [\n "serde",\n]\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n');
    const li = await h.live();
    expect(direct(li, "crates.io")).toEqual(["serde"]);
    rewrite("Cargo.toml", '[package]\nname = "x"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = "1.0.200"\nanyhow = "1.0.80"\n');
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expect(direct(li, "crates.io")).toContain("anyhow");
  });

  it("a script edited in package.json beside a read lockfile re-resolves nothing", async () => {
    h.npmProject({ ms: "2.1.3" }, {}, { ms: { version: "2.1.3" } });
    const li = await h.live();
    const at = li.getResolutionProvenance()?.resolvedAt;
    rewrite("package.json", JSON.stringify({ name: "x", version: "1.0.0", scripts: { test: "vitest" }, dependencies: { ms: "2.1.3" }, devDependencies: {} }));
    expect(li.refreshIfLockfilesChanged()).toBe(false);
    expect(li.refreshIfLockfilesChanged()).toBe(false);
    expect(li.getResolutionProvenance()?.resolvedAt).toBe(at);
  });
});

describe("a manifest or requirements file created while the server runs", () => {
  it("requirements-dev.txt created beside requirements.txt is read", async () => {
    h.write("requirements.txt", "requests==2.32.3\n");
    const li = await h.live();
    expect(direct(li, "PyPI")).toEqual(["requests"]);
    h.write("requirements-dev.txt", "idna==3.7\n");
    const later = new Date(Date.now() + 5_000);
    fs.utimesSync(h.dir, later, later);
    expect(li.refreshIfLockfilesChanged()).toBe(true);
    expect(li.getAuditDeps().map((d) => d.name)).toContain("idna");
  });

  it("an unrelated file created beside requirements.txt re-resolves nothing", async () => {
    h.write("requirements.txt", "requests==2.32.3\n");
    const li = await h.live();
    h.write("notes.md", "x\n");
    const later = new Date(Date.now() + 5_000);
    fs.utimesSync(h.dir, later, later);
    expect(li.refreshIfLockfilesChanged()).toBe(false);
  });

  it("package.json created beside a package-lock.json that was read alone", async () => {
    h.npmProject({ ms: "2.1.3" }, {}, { ms: { version: "2.1.3" } });
    fs.rmSync(path.join(h.dir, "package.json"));
    const li = await h.live();
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3", lodash: "4.18.1" } }));
    expect(li.refreshIfLockfilesChanged()).toBe(true);
  });
});
