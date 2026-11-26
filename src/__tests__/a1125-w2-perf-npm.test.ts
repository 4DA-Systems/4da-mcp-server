// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, Track F, M1: a tree of large package-lock.json files held the event loop for
 * tens of seconds (20 copies of a 62 MB lockfile: a ping waited 21.8 s, the first call took 77.7 s
 * against its 20 s budget). The private-source pass (npmLockPrivateSourcesSteps) read and parsed
 * every package-lock.json a second time and walked every entry with no pause point, and the npm
 * reader (readNpmLockFile / readPackageLock) walked every entry with none either.
 *
 * Now each package-lock.json is parsed once per resolution (the private-source pass takes the
 * locations the reader kept, per file state), and every loop over its entries has pause points.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { readPackageLockSteps, resolveVersionSource } from "../live/lockfile-parsers.js";
import { _resetNpmLockLocations, npmLockPrivateSources, npmLockPrivateSourcesSteps } from "../live/private-packages.js";
import type { Steps } from "../live/yield-point.js";

let dir: string;

/** A package-lock.json of `n` packages (made-up names; nothing here is sent anywhere). */
function lockOf(n: number, host = (i: number) => (i % 997 === 5 ? "https://npm.zq-internal.example" : "https://registry.npmjs.org")): string {
  const packages: Record<string, unknown> = { "": { name: "app", version: "1.0.0", dependencies: { "zqpkg-0": "^1.0.0" } } };
  for (let i = 0; i < n; i++) {
    const name = `zqpkg-${i}`;
    packages[`node_modules/${name}`] = { version: "1.0.0", resolved: `${host(i)}/${name}/-/${name}-1.0.0.tgz`, dependencies: i + 1 < n ? { [`zqpkg-${i + 1}`]: "^1.0.0" } : undefined };
  }
  return JSON.stringify({ name: "app", version: "1.0.0", lockfileVersion: 3, requires: true, packages });
}

function write(lock: string): void {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "zqpkg-0": "^1.0.0" } }));
  fs.writeFileSync(path.join(dir, "package-lock.json"), lock);
}

function countYields<T>(steps: Steps<T>): { yields: number; value: T } {
  let yields = 0;
  for (;;) {
    const r = steps.next();
    if (r.done) return { yields, value: r.value };
    yields++;
  }
}

beforeEach(() => {
  _resetNpmLockLocations();
  dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-npm-")));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("large package-lock.json files never hold the event loop (audit 2026-11-25, F-M1)", () => {
  it("the npm reader pauses inside its loops over entries", () => {
    const lock = JSON.parse(lockOf(20_000));
    const { yields, value } = countYields(readPackageLockSteps(lock));
    expect(value.instances.size).toBe(20_000);
    // At least one pause per 2,048 entries of each pass over them.
    expect(yields).toBeGreaterThanOrEqual(9);
  });

  it("the private-source pass pauses inside its loop over a package-lock.json it has to read itself", () => {
    write(lockOf(20_000));
    const { yields, value } = countYields(npmLockPrivateSourcesSteps(dir, new Set()));
    expect(yields).toBeGreaterThanOrEqual(9);
    expect(value.map((p) => p.name)).toContain("zqpkg-5");
  });

  it("parses each package-lock.json once per resolution", () => {
    const text = lockOf(5_000);
    write(text);
    const parse = vi.spyOn(JSON, "parse");
    const li = new LiveIntelligence(new Database(":memory:"));
    li.initFromProjectTree(dir, [{ dir, language: "javascript", deps: ["zqpkg-0"], devDeps: [], targets: {} }]);
    const bigParses = parse.mock.calls.filter(([s]) => typeof s === "string" && s.length >= text.length - 16).length;
    expect(bigParses).toBe(1);
    // And the private source it found is the one the lockfile names.
    expect(li.getAuditDeps().some((d) => d.name === "zqpkg-5")).toBe(false);
  });

  it("the private sources found from the reader's parse equal those found by reading the file again", () => {
    // Public registry, a private host, a public mirror passed in, a code host, a scoped name, a nested copy.
    const lock = {
      name: "app",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "app", version: "1.0.0" },
        "node_modules/pub": { version: "1.0.0", resolved: "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz" },
        "node_modules/@zq/priv": { version: "2.0.0", resolved: "https://npm.zq-internal.example/@zq/priv/-/priv-2.0.0.tgz" },
        "node_modules/mirrored": { version: "1.0.0", resolved: "https://mirror.zq.example/mirrored/-/mirrored-1.0.0.tgz" },
        "node_modules/gh": { version: "1.0.0", resolved: "https://codeload.github.com/zq/gh/tar.gz/abc" },
        "node_modules/a/node_modules/nested": { name: "nested-real", version: "3.0.0", resolved: "http://10.0.0.9/nested-real-3.0.0.tgz" },
        "node_modules/linked": { link: true, resolved: "packages/linked" },
      },
    };
    write(JSON.stringify(lock));
    const mirrors = new Set(["mirror.zq.example"]);
    const fresh = npmLockPrivateSources(dir, mirrors);
    _resetNpmLockLocations();
    resolveVersionSource(dir, "npm");
    const fromReader = npmLockPrivateSources(dir, mirrors);
    expect(fromReader).toEqual(fresh);
    expect(fresh.map((p) => `${p.name}@${p.version}`).sort()).toEqual(["@zq/priv@2.0.0", "nested-real@3.0.0"]);
  });

  it("a lockfile changed after the reader's parse is read again, never answered from the old parse", () => {
    write(lockOf(10, () => "https://registry.npmjs.org"));
    resolveVersionSource(dir, "npm");
    expect(npmLockPrivateSources(dir, new Set())).toEqual([]);
    // Same size, new content and mtime: a private host now.
    const changed = lockOf(10, () => "https://npm.zq-internal.example");
    fs.writeFileSync(path.join(dir, "package-lock.json"), changed);
    const later = new Date(Date.now() + 5_000);
    fs.utimesSync(path.join(dir, "package-lock.json"), later, later);
    expect(npmLockPrivateSources(dir, new Set()).length).toBe(10);
  });

  it("a lockfile with more private locations than are kept is read again, with the same answer", () => {
    write(lockOf(20_050, () => "https://npm.zq-internal.example"));
    const fresh = npmLockPrivateSources(dir, new Set());
    expect(fresh.length).toBe(20_050);
    _resetNpmLockLocations();
    resolveVersionSource(dir, "npm");
    expect(npmLockPrivateSources(dir, new Set())).toEqual(fresh);
  });

  it("the kept locations serve one pass: a second pass (a rule change) reads the file", () => {
    write(lockOf(50));
    resolveVersionSource(dir, "npm");
    const first = npmLockPrivateSources(dir, new Set());
    const parse = vi.spyOn(JSON, "parse");
    expect(npmLockPrivateSources(dir, new Set())).toEqual(first);
    expect(parse.mock.calls.some(([s]) => typeof s === "string" && s.includes("zqpkg-49"))).toBe(true);
  });

  it("a v1 lockfile's locations are kept as well", () => {
    const v1 = { name: "app", version: "1.0.0", lockfileVersion: 1, dependencies: { "@zq/old": { version: "1.0.0", resolved: "https://npm.zq-internal.example/@zq/old/-/old-1.0.0.tgz", dependencies: { inner: { version: "https://npm.zq-internal.example/inner-2.0.0.tgz" } } }, pub: { version: "1.0.0", resolved: "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz" } } };
    write(JSON.stringify(v1));
    const fresh = npmLockPrivateSources(dir, new Set());
    _resetNpmLockLocations();
    resolveVersionSource(dir, "npm");
    expect(npmLockPrivateSources(dir, new Set())).toEqual(fresh);
    expect(fresh.map((p) => p.name).sort()).toEqual(["@zq/old", "inner"]);
  });
});
