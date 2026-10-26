// SPDX-License-Identifier: Apache-2.0
/**
 * What a scan did not cover is said, never implied clean (audit A2, A3, B-9,
 * 2026-10-12):
 * - Ruby (Gemfile.lock) and PHP (composer.lock) are read now;
 * - Maven, Gradle, .NET and other unread ecosystems are listed as
 *   `not_covered`, and a project made only of them is told so instead of
 *   "No manifest files found... run from your project root";
 * - test-fixture lockfiles (tests/, fixtures/, conformance/ ...) are not
 *   scanned as the project's own, and are counted (`not_scanned`);
 * - a lockfile that cannot be read (conflict markers, invalid JSON) is named
 *   with the reason instead of falling through to "no lockfile".
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { readComposerLock, readGemfileLock } from "../live/lockfile-parsers-rbphp.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { LiveIntelligence } from "../live/index.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

const GEMFILE_LOCK = `GIT
  remote: https://github.com/rails/webpacker.git
  revision: abc
  specs:
    webpacker (5.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    actionpack (6.0.0)
      rack (~> 2.0)
    nokogiri (1.10.4-x86_64-linux)
      mini_portile2 (~> 2.4.0)
    rack (2.0.7)
    rails (6.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 6.0.0)
  webpacker!

BUNDLED WITH
   2.0.2
`;

describe("Gemfile.lock reader", () => {
  it("reads GEM specs, drops platform suffixes, skips git/path gems, and names the direct dependencies", () => {
    const read = readGemfileLock(GEMFILE_LOCK);
    expect(read.instances.toArray().map((i) => `${i.name}@${i.version}`).sort()).toEqual([
      "actionpack@6.0.0", "nokogiri@1.10.4", "rack@2.0.7", "rails@6.0.0",
    ]);
    expect(read.direct).toEqual(["rails", "webpacker"]);
  });
});

describe("composer.lock reader", () => {
  it("strips a leading v, keeps dev scope, skips branch checkouts", () => {
    const read = readComposerLock({
      packages: [{ name: "symfony/http-kernel", version: "v5.4.0" }, { name: "acme/fork", version: "dev-main" }],
      "packages-dev": [{ name: "phpunit/phpunit", version: "9.5.10" }, { name: "friendsofphp/php-cs-fixer", version: "3.0.x-dev" }],
    });
    expect(read.instances.toArray()).toEqual([
      { name: "symfony/http-kernel", version: "5.4.0", dev: false },
      { name: "phpunit/phpunit", version: "9.5.10", dev: true },
      { name: "friendsofphp/php-cs-fixer", version: "3.0.x-dev", dev: true },
    ]);
  });
});

describe("project scans say what they did not cover", () => {
  let dir: string;
  let priorOffline: string | undefined;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-coverage-"));
    // OSV answers: rails 6.0.0 and lodash 4.17.15 have one advisory each.
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string } }> };
        return new Response(JSON.stringify({
          results: queries.map((q) => (q.package.name === "rails" || q.package.name === "lodash" ? { vulns: [{ id: `GHSA-${q.package.name}` }] } : {})),
        }), { status: 200 });
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
  const npmLock = (deps: Record<string, string>) =>
    JSON.stringify({
      name: "x",
      lockfileVersion: 3,
      packages: {
        "": { name: "x", dependencies: deps },
        ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v }])),
      },
    });
  const scan = async (extra: Record<string, unknown> = {}) =>
    (await executeVulnerabilityScan(null, { project_path: dir, ...extra }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;

  it("scans a Ruby project from its Gemfile.lock", async () => {
    write("Gemfile", "source 'https://rubygems.org'\ngem 'rails'\n");
    write("Gemfile.lock", GEMFILE_LOCK);
    const result = await scan();
    expect(result.ecosystems_scanned).toEqual(["RubyGems"]);
    expect(result.total_vulnerable_packages).toBe(1);
    expect(result.vulnerable_packages[0]).toMatchObject({ package: "rails", current_version: "6.0.0", is_direct: true });
  });

  it("a Maven-only project is NOT COVERED, never 'run from your project root'", async () => {
    write("pom.xml", "<project/>");
    const result = await scan();
    const text = JSON.stringify(result);
    expect(text).toMatch(/NOT COVERED/);
    expect(text).toMatch(/pom\.xml/);
    expect(text).not.toMatch(/Run this tool from your project root/);
    // Audit 6.2.5 A-6: no "0 vulnerable" beside NOT COVERED when nothing was read at all.
    expect(result.total_vulnerable_packages).toBeNull();
    expect(result.by_severity).toBeNull();
  });

  it("a mixed repository scans what it can and lists every file it could not", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.15" } }));
    write("package-lock.json", npmLock({ lodash: "4.17.15" }));
    write("backend/pom.xml", "<project/>");
    write("svc/App.csproj", "<Project/>");
    write("android/build.gradle.kts", "");
    const result = await scan();
    expect(result.total_vulnerable_packages).toBe(1);
    expect(result.coverage.not_covered).toEqual(expect.arrayContaining([
      { path: "backend/pom.xml", ecosystem: "Maven" },
      { path: "svc/App.csproj", ecosystem: "NuGet" },
      { path: "android/build.gradle.kts", ecosystem: "Maven (Gradle)" },
    ]));
    expect(result.coverage.note).toMatch(/NOT COVERED: 3 manifest\/lockfiles/);
  });

  it("test-fixture lockfiles are counted, not scanned, unless asked for", async () => {
    write("package.json", JSON.stringify({ dependencies: { left: "1.0.0" } }));
    write("package-lock.json", npmLock({ left: "1.0.0" }));
    write("tests/conformance/cases/a/package-lock.json", npmLock({ lodash: "4.17.15" }));
    write("test/fixtures/b/Cargo.lock", "");
    const result = await scan();
    expect(result.total_dependencies_scanned).toBe(1);
    expect(result.coverage.not_scanned).toEqual({ test_fixture_lockfiles: 2, dirs: ["test", "tests"].sort() });
    const withFixtures = await scan({ include_test_fixtures: true });
    expect(withFixtures.total_vulnerable_packages).toBe(1);
    expect(withFixtures.coverage?.not_scanned).toBeUndefined();
  });

  it("a lockfile with merge-conflict markers is named, with that reason, not treated as missing", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "^4.17.0" } }));
    write("package-lock.json", `{\n<<<<<<< HEAD\n  "name": "x"\n=======\n  "name": "y"\n>>>>>>> branch\n}\n`);
    const read = resolveVersionSource(dir, "npm");
    expect(read.problems?.[0].error).toMatch(/merge-conflict markers/);
    const result = await scan();
    expect(result.coverage.unreadable_lockfiles[0]).toMatchObject({ path: "package-lock.json" });
    expect(result.coverage.unreadable_lockfiles[0].error).toMatch(/merge-conflict/);
    expect(JSON.stringify(result)).not.toMatch(/no lock file/i);
  });

  it("an unparseable lockfile says why", async () => {
    write("package-lock.json", "{ not json");
    const read = resolveVersionSource(dir, "npm");
    expect(read.problems?.[0]).toMatchObject({ file: path.join(dir, "package-lock.json") });
    expect(read.problems?.[0].error).toMatch(/invalid JSON/);
  });

  it("a valid lockfile of a project with no dependencies is not a problem", () => {
    write("package-lock.json", JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x" } } }));
    expect(resolveVersionSource(dir, "npm").problems).toBeUndefined();
  });
});
