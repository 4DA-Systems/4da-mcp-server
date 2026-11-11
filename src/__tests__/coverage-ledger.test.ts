// SPDX-License-Identifier: Apache-2.0
/**
 * What a scan did not read is always said (audit 2026-11-11, T2, T4, M10, M12).
 *
 * The scanner was accurate on every lockfile it opened (1,342 of 1,343
 * advisory matches) and reported projects as clean while skipping files:
 * - a lockfile .gitignore listed, and any lockfile in a dot-directory, was
 *   skipped with no trace ("5 dependencies, 0 vulnerable" beside a
 *   750-package backend/package-lock.json);
 * - two lockfiles in one directory: one was picked without a word;
 * - a manifest with no lockfile (exact pins, a binary bun.lockb) read clean
 *   with no caveat; environment.yml and setup.py went unmentioned;
 * - `pydantic>=2.0.0` read "pydantic unknown (direct): no known advisories";
 * - a UTF-16 requirements.txt gave 0 dependencies, a truncated Cargo.lock or
 *   pnpm-lock.yaml a fraction, with no notice.
 *
 * Each test here fails on 6.2.7 and on main before this change.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { cargoLockDamage, resolveVersionSource } from "../live/lockfile-parsers.js";
import { pnpmLockDamage } from "../live/js-lockfile-readers.js";
import { tomlLockDamage, unpinnedRequirements } from "../live/lockfile-parsers-pygo.js";
import { decodeText } from "../live/text-file.js";
import { discoveryNote, scanProjectTree, workspaceGlobMatches } from "../project-tree.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

/** Packages the OSV stub reports one HIGH advisory for. */
const VULNERABLE = new Set(["lodash", "django", "minimist", "smallvec"]);

describe("coverage ledger: what was not read is always said", () => {
  let dir: string;
  let priorOffline: string | undefined;
  /** Every (name, version) sent to OSV, in order. */
  let asked: Array<{ name: string; version?: string; ecosystem: string }>;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-ledger-"));
    asked = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version?: string }> };
        for (const q of queries) asked.push({ name: q.package.name, version: q.version, ecosystem: q.package.ecosystem });
        return new Response(JSON.stringify({ results: queries.map((q) => (VULNERABLE.has(q.package.name.toLowerCase()) ? { vulns: [{ id: `GHSA-${q.package.name.toLowerCase()}` }] } : {})) }), { status: 200 });
      }
      if (url.includes("/v1/vulns/")) {
        const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
        return new Response(JSON.stringify({ id, summary: id, database_specific: { severity: "HIGH" } }), { status: 200 });
      }
      // Fix-target checks ask OSV and the registries by package: no answer, which the scan tolerates.
      throw new TypeError(`fetch failed (${url})`);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const write = (rel: string, content: string | Buffer) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  };
  const npmLock = (deps: Record<string, string>) =>
    JSON.stringify({
      name: "x",
      lockfileVersion: 3,
      packages: {
        "": { name: "x", dependencies: deps },
        ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` }])),
      },
    });
  // force_refresh: the OSV answer cache is per test worker, and `asked` must show what THIS scan sent.
  const scan = async (extra: Record<string, unknown> = {}) =>
    (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true, ...extra }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
  const rels = () => scanProjectTree(dir).entries.map((e) => path.relative(dir, e.dir).replace(/\\/g, "/") || ".").sort();

  // ---------------------------------------------------------------------------
  // 1. gitignored lockfiles, dot-directories, gitignored and build-output directories
  // ---------------------------------------------------------------------------

  describe("lockfiles are labelled, never suppressed", () => {
    it("a lockfile .gitignore lists is scanned: the kairos-mvp layout no longer reads clean", async () => {
      write(".gitignore", "node_modules/\npackage-lock.json\nyarn.lock\n");
      write("package.json", JSON.stringify({ dependencies: { "left-pad": "1.3.0" } }));
      write("package-lock.json", npmLock({ "left-pad": "1.3.0" }));
      write("backend/package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
      write("backend/package-lock.json", npmLock({ lodash: "4.17.20" }));

      expect(rels()).toEqual([".", "backend"]);
      const result = await scan();
      expect(asked.map((q) => `${q.name}@${q.version}`).sort()).toEqual(["left-pad@1.3.0", "lodash@4.17.20"]);
      expect(result.total_dependencies_scanned).toBe(2);
      expect(result.total_vulnerable_packages).toBe(1);
      expect(result.vulnerable_packages[0]).toMatchObject({ package: "lodash", current_version: "4.17.20", source_dirs: ["backend"] });
      // Everything found was read, so nothing says "partial"; the detailed answer labels what .gitignore lists.
      expect(result.coverage).toBeUndefined();
      const detailed = await scan({ response_format: "detailed" });
      expect(detailed._meta.resolution.lockfiles).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ path: "backend/package-lock.json", gitignored: true }),
          expect.objectContaining({ path: "package-lock.json", gitignored: true }),
        ]),
      );
    });

    it("a dot-directory is an ordinary directory: .github/actions/* and .design-system are scanned", async () => {
      write("package.json", JSON.stringify({ dependencies: { "left-pad": "1.3.0" } }));
      write("package-lock.json", npmLock({ "left-pad": "1.3.0" }));
      write(".github/actions/deploy/package.json", JSON.stringify({ dependencies: { minimist: "1.2.5" } }));
      write(".github/actions/deploy/package-lock.json", npmLock({ minimist: "1.2.5" }));
      write(".design-system/package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
      write(".design-system/package-lock.json", npmLock({ lodash: "4.17.20" }));

      expect(rels()).toEqual([".", ".design-system", ".github/actions/deploy"]);
      const result = await scan();
      expect(result.total_vulnerable_packages).toBe(2);
      expect(result.vulnerable_packages.map((p: any) => `${p.package} in ${p.source_dirs.join(",")}`).sort()).toEqual([
        "lodash in .design-system",
        "minimist in .github/actions/deploy",
      ]);
    });

    it("a gitignored directory is not scanned, and every lockfile in it is listed by path with complete: false", async () => {
      write(".gitignore", "scratch/\n/vendor-tools\n");
      write("package.json", JSON.stringify({ dependencies: { "left-pad": "1.3.0" } }));
      write("package-lock.json", npmLock({ "left-pad": "1.3.0" }));
      write("scratch/clone/package-lock.json", npmLock({ lodash: "4.17.20" }));
      write("vendor-tools/a/b/Cargo.lock", '[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+x"\n');

      const { entries, discovery } = scanProjectTree(dir);
      expect(entries.map((e) => path.relative(dir, e.dir) || ".")).toEqual(["."]);
      expect(discovery.skipped.sort((a, b) => a.path.localeCompare(b.path))).toEqual([
        { path: "scratch/clone/package-lock.json", reason: "gitignored_directory" },
        { path: "vendor-tools/a/b/Cargo.lock", reason: "gitignored_directory" },
      ]);
      expect(discoveryNote(discovery)).toMatch(/^Partial scan: 2 lockfiles were found but NOT scanned \(in a directory \.gitignore excludes\): .*pass project_path to scan one of them\.$/);

      for (const format of ["concise", "detailed"]) {
        const result = await scan({ response_format: format });
        expect(result.total_vulnerable_packages).toBe(0);
        expect(result.coverage).toMatchObject({ complete: false, lockfiles_not_scanned: 2 });
        expect(result.coverage.not_scanned.lockfiles).toEqual(
          expect.arrayContaining([
            { path: "scratch/clone/package-lock.json", reason: "gitignored_directory" },
            { path: "vendor-tools/a/b/Cargo.lock", reason: "gitignored_directory" },
          ]),
        );
        expect(result.coverage.note).toMatch(/2 lockfiles were found but NOT scanned/);
      }
      // The advisories of an ignored scratch clone are not reported as this project's.
      expect([...new Set(asked.map((q) => q.name))]).toEqual(["left-pad"]);
    });

    it("installed code and build output stay unscanned; a lockfile directly in build/ is listed, one deep in node_modules is not", async () => {
      write("package.json", JSON.stringify({ dependencies: { "left-pad": "1.3.0" } }));
      write("package-lock.json", npmLock({ "left-pad": "1.3.0" }));
      write("node_modules/x/package-lock.json", npmLock({ lodash: "4.17.20" }));
      write(".venv/lib/site-packages/y/requirements.txt", "django==3.2.0\n");
      write("target/package/z/Cargo.lock", "");
      write(".claude/worktrees/agent-1/package-lock.json", npmLock({ lodash: "4.17.20" }));
      write("build/package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
      write("build/package-lock.json", npmLock({ lodash: "4.17.20" }));

      const { entries, discovery } = scanProjectTree(dir);
      expect(entries).toHaveLength(1);
      expect(discovery.skipped).toEqual([{ path: "build/package-lock.json", reason: "output_directory" }]);
      const result = await scan();
      expect(result.coverage.not_scanned.lockfiles).toEqual([{ path: "build/package-lock.json", reason: "output_directory" }]);
      expect(result.coverage.note).toMatch(/directly inside a build-output directory/);
    });

    it("nothing scanned at the root and a lockfile left out below: the totals are null, never 0", async () => {
      write(".gitignore", "clone/\n");
      write("clone/package-lock.json", npmLock({ lodash: "4.17.20" }));
      const result = await scan();
      expect(result.total_vulnerable_packages).toBeNull();
      expect(result.by_severity).toBeNull();
      expect(result.coverage.not_scanned.lockfiles).toEqual([{ path: "clone/package-lock.json", reason: "gitignored_directory" }]);
      expect(result.note).toMatch(/^Nothing was checked\. Partial scan: 1 lockfile was found but NOT scanned/);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. two lockfiles in one directory
  // ---------------------------------------------------------------------------

  describe("two lockfiles in one directory", () => {
    const yarnLock = (name: string, version: string) =>
      `# yarn lockfile v1\n\n${name}@^4.17.0:\n  version "${version}"\n  resolved "https://registry.yarnpkg.com/${name}/-/${name}-${version}.tgz#abc"\n`;

    it("says which was read and that the other exists and differs", async () => {
      write("package.json", JSON.stringify({ dependencies: { lodash: "^4.17.0" } }));
      write("package-lock.json", npmLock({ lodash: "4.17.21" }));
      write("yarn.lock", yarnLock("lodash", "4.17.20"));

      const read = resolveVersionSource(dir, "npm");
      expect(path.basename(read.source!)).toBe("package-lock.json");
      expect(read.problems).toEqual([expect.objectContaining({ file: path.join(dir, "yarn.lock"), conflict: true })]);
      expect(read.problems![0].error).toMatch(/package-lock\.json was read instead.*pins a different set: 1 package differ.*lodash 4\.17\.20 here, 4\.17\.21 in package-lock\.json/);

      const result = await scan();
      expect(result.coverage).toMatchObject({ complete: false });
      expect(result.coverage.conflicting_lockfiles).toEqual([expect.objectContaining({ path: "yarn.lock" })]);
      expect(result.coverage.note).toMatch(/^CONFLICT: 1 lockfile beside the one that was read was not used: yarn\.lock/);
      // Only the lockfile that was read is asked about.
      expect(asked.map((q) => `${q.name}@${q.version}`)).toEqual(["lodash@4.17.21"]);
    });

    it("two lockfiles that agree are not a problem", () => {
      write("package.json", JSON.stringify({ dependencies: { lodash: "^4.17.0" } }));
      write("package-lock.json", npmLock({ lodash: "4.17.21" }));
      write("yarn.lock", yarnLock("lodash", "4.17.21"));
      expect(resolveVersionSource(dir, "npm").problems).toBeUndefined();
    });

    it("a second lockfile that cannot be parsed is named: it could not be compared", () => {
      write("package-lock.json", npmLock({ lodash: "4.17.21" }));
      write("bun.lock", "{ this is not a lockfile");
      const problems = resolveVersionSource(dir, "npm").problems ?? [];
      expect(problems).toEqual([expect.objectContaining({ file: path.join(dir, "bun.lock"), conflict: true })]);
      expect(problems[0].error).toMatch(/could not be compared/);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. a manifest with no lockfile
  // ---------------------------------------------------------------------------

  describe("a manifest with no lockfile is never a clean result", () => {
    it("exact-pinned package.json: the pins are checked and the answer says the transitive tree was not resolved", async () => {
      write("package.json", JSON.stringify({ dependencies: { next: "15.5.29", react: "19.3.1", "react-dom": "19.3.1" } }));
      const result = await scan();
      expect(result.total_dependencies_scanned).toBe(3);
      expect(result.total_vulnerable_packages).toBe(0);
      expect(result.coverage).toMatchObject({ complete: false });
      expect(result.coverage.note).toMatch(/^NO LOCKFILE: package\.json has no lockfile, so only the 3 exact pins declared there were checked; the packages they depend on \(the transitive tree\) were not resolved and NOT checked: run npm install --package-lock-only/);
      expect(result.coverage.unresolved_manifests).toEqual([
        { manifest: "package.json", declared_ranges: 0, exact_pins_checked: 3, transitive_dependencies: "not resolved, not checked", fix: "npm install --package-lock-only in ." },
      ]);
    });

    it("Cargo.toml only: the same caveat", async () => {
      write("Cargo.toml", '[package]\nname = "fx"\nversion = "0.1.0"\n\n[dependencies]\nsmallvec = "=1.6.0"\nregex = "=1.5.4"\n');
      const result = await scan();
      expect(result.total_vulnerable_packages).toBe(1);
      expect(result.coverage.note).toMatch(/NO LOCKFILE: Cargo\.toml has no lockfile, so only the 2 exact pins declared there were checked.*run cargo generate-lockfile/);
    });

    it("a binary bun.lockb is named as unread, at the root and in a subdirectory", async () => {
      write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
      write("bun.lockb", Buffer.from([0x23, 0x21, 0x2f, 0x75, 0x00, 0x01, 0x02, 0xff]));
      write("app/package.json", JSON.stringify({ dependencies: { minimist: "1.2.5" } }));
      write("app/bun.lockb", Buffer.from([0x23, 0x21, 0x00, 0xff]));

      expect(rels()).toEqual([".", "app"]);
      const result = await scan();
      expect(result.coverage.unreadable_lockfiles.map((p: any) => p.path).sort()).toEqual(["app/bun.lockb", "bun.lockb"]);
      expect(result.coverage.unreadable_lockfiles[0].error).toMatch(/Bun's binary lockfile, which this server cannot read: run `bun install --save-text-lockfile`/);
      expect(result.coverage.note).toMatch(/^UNREADABLE: 2 lockfiles could not be read/);
      expect(result.coverage.note).toMatch(/NO LOCKFILE: .*only the 2 exact pins declared there were checked/);
    });

    it("a manifest no lockfile pins is listed; a workspace member of a lockfile above is not", async () => {
      write("package.json", JSON.stringify({ workspaces: ["packages/*"], dependencies: { "left-pad": "1.3.0" } }));
      write("package-lock.json", npmLock({ "left-pad": "1.3.0" }));
      write("packages/a/package.json", JSON.stringify({ dependencies: { lodash: "^4.17.0" } }));
      // kairos-mvp: a root lockfile, and a frontend/ with 22 dependencies that is no workspace of it.
      write("frontend/package.json", JSON.stringify({ dependencies: { react: "^18.2.0", vite: "^5.0.0" } }));
      write("services/api/Cargo.toml", '[package]\nname = "api"\n\n[dependencies]\nsmallvec = "1.6"\ntokio = { version = "1" }\n');
      write("services/ml/pyproject.toml", '[project]\nname = "ml"\ndependencies = ["Django==3.2.0", "requests>=2"]\n');
      write("docs/package.json", JSON.stringify({ name: "docs", type: "module" }));

      const { discovery } = scanProjectTree(dir);
      expect(discovery.unlockedManifests).toEqual([
        { path: "frontend/package.json", ecosystem: "npm", dependencies: 2 },
        { path: "services/api/Cargo.toml", ecosystem: "crates.io", dependencies: 2 },
        { path: "services/ml/pyproject.toml", ecosystem: "PyPI", dependencies: 2 },
      ]);
      const result = await scan();
      expect(result.coverage).toMatchObject({ complete: false, manifests_without_lockfile_count: 3 });
      expect(result.coverage.manifests_without_lockfile.map((m: any) => m.path)).toEqual(["frontend/package.json", "services/api/Cargo.toml", "services/ml/pyproject.toml"]);
      expect(result.coverage.note).toMatch(
        /3 manifests have no lockfile beside them and are no workspace member of one above \(frontend\/package\.json, services\/api\/Cargo\.toml, services\/ml\/pyproject\.toml\), so the dependencies they declare were not resolved and NOT checked/,
      );
    });

    it("workspace members are recognised per ecosystem: pnpm and Yarn globs, Cargo and uv members by name", () => {
      // pnpm: pnpm-workspace.yaml; a directory its patterns exclude is not a member.
      write("js/pnpm-workspace.yaml", "packages:\n  - 'apps/**'\n  - \"libs/*\"\n  - '!libs/legacy'\n");
      // A directory the lockfile lists under `importers:` is its own, whatever the patterns say.
      write("js/pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  tools/linked:\n    dependencies:\n      zx:\n        specifier: ^7\n        version: 7.2.3\n");
      write("js/tools/linked/package.json", JSON.stringify({ dependencies: { zx: "^7" } }));
      write("js/apps/web/admin/package.json", JSON.stringify({ dependencies: { react: "^18" } }));
      write("js/libs/ui/package.json", JSON.stringify({ dependencies: { react: "^18" } }));
      write("js/libs/legacy/package.json", JSON.stringify({ dependencies: { jquery: "^1" } }));
      write("js/scripts/package.json", JSON.stringify({ dependencies: { zx: "^7" } }));
      // npm: a `file:` link target is keyed by its path in package-lock.json, and resolved there.
      write("npm/package.json", JSON.stringify({ dependencies: { "local-lib": "file:./lib" } }));
      write(
        "npm/package-lock.json",
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { dependencies: { "local-lib": "file:./lib" } },
            lib: { name: "local-lib", version: "1.0.0", dependencies: { minimist: "1.2.5" } },
            "node_modules/local-lib": { resolved: "lib", link: true },
            "node_modules/minimist": { version: "1.2.5" },
          },
        }),
      );
      write("npm/lib/package.json", JSON.stringify({ name: "local-lib", dependencies: { minimist: "1.2.5" } }));
      write("npm/other/package.json", JSON.stringify({ name: "other", dependencies: { chalk: "^5" } }));
      // Yarn: `workspaces: { packages: [...] }`.
      write("yarn/package.json", JSON.stringify({ private: true, workspaces: { packages: ["packages/*"] } }));
      write("yarn/yarn.lock", "# yarn lockfile v1\n");
      write("yarn/packages/a/package.json", JSON.stringify({ dependencies: { lodash: "^4" } }));
      // Cargo: a member is a source-less package of the Cargo.lock; a crate the lockfile does not hold is on its own.
      write("rs/Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n');
      write("rs/Cargo.lock", '[[package]]\nname = "member"\nversion = "0.1.0"\ndependencies = [\n "serde",\n]\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n');
      write("rs/crates/member/Cargo.toml", '[package]\nname = "member"\n\n[dependencies]\nserde = "1"\n');
      write("rs/examples/standalone/Cargo.toml", '[package]\nname = "standalone"\n\n[dependencies]\ntokio = "1"\n');
      // uv: a workspace member is a [[package]] of the root uv.lock.
      write("py/uv.lock", 'version = 1\n\n[[package]]\nname = "svc-core"\nversion = "0.1.0"\nsource = { editable = "packages/core" }\n');
      write("py/packages/core/pyproject.toml", '[project]\nname = "svc_core"\ndependencies = ["httpx>=0.27"]\n');
      write("py/tools/other/pyproject.toml", '[project]\nname = "other"\ndependencies = ["click>=8"]\n');

      expect((scanProjectTree(dir).discovery.unlockedManifests ?? []).map((m) => m.path).sort()).toEqual([
        "js/libs/legacy/package.json",
        "js/scripts/package.json",
        "npm/other/package.json",
        "py/tools/other/pyproject.toml",
        "rs/examples/standalone/Cargo.toml",
      ]);
      expect(workspaceGlobMatches("packages/*", "packages/a")).toBe(true);
      expect(workspaceGlobMatches("packages/*", "packages/a/b")).toBe(false);
      expect(workspaceGlobMatches("apps/**", "apps/web/admin")).toBe(true);
      expect(workspaceGlobMatches("./tools/cli/", "tools/cli")).toBe(true);
      expect(workspaceGlobMatches("@scope/*-plugin", "@scope/a-plugin")).toBe(true);
      // A hostile pattern costs nothing: no regex is built from it.
      expect(workspaceGlobMatches(`${"**/".repeat(40)}x`, `${"a/".repeat(60)}y`)).toBe(false);
    });

    it("environment.yml, setup.py and pylock.toml are named as unread, also beside a lockfile that was read", async () => {
      write("pdm.lock", '[[package]]\nname = "django"\nversion = "3.2.0"\nsummary = "x"\n');
      write("environment.yml", "name: fx\ndependencies:\n  - python=3.11\n  - pip:\n      - requests==2.25.0\n");
      write("setup.py", 'from setuptools import setup\nsetup(name="fx", install_requires=["Django==3.2.0", "PyYAML==5.3.1"])\n');
      write("tools/setup.py", 'from setuptools import setup\nsetup(name="tools")\n');
      write("tools/pylock.toml", 'lock-version = "1.0"\n');

      const result = await scan();
      expect(result.total_vulnerable_packages).toBe(1);
      expect(result.coverage.not_covered).toEqual([
        { path: "environment.yml", ecosystem: "Conda (environment.yml is not read)" },
        { path: "setup.py", ecosystem: "PyPI (setup.py: install_requires is not read)" },
        // tools/setup.py declares no install_requires, so there is nothing of its to name.
        { path: "tools/pylock.toml", ecosystem: "PyPI (pylock.toml, PEP 751, is not read)" },
      ]);
      expect(result.coverage.note).toMatch(/NOT COVERED: 3 manifest\/lockfiles of ecosystems or formats this server does not read \(Conda, PyPI\): environment\.yml, setup\.py, tools\/pylock\.toml/);
    });

    it("pyproject.toml with no lockfile: its dependencies are named as not checked, with no advice to run a tool the project does not use", async () => {
      write("pyproject.toml", '[project]\nname = "fx"\nversion = "0.1.0"\ndependencies = ["Django==3.2.0", "requests==2.25.0"]\n');
      const result = await scan();
      expect(result.total_vulnerable_packages).toBeNull();
      expect(result.coverage.unpinned_requirements).toEqual([{ file: "pyproject.toml", count: 2, names: ["django", "requests"] }]);
      expect(result.coverage.note).toMatch(/NOT CHECKED \(no pinned version\): 2 requirements in pyproject\.toml/);
      expect(JSON.stringify(result)).not.toMatch(/poetry install/);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. requirements with no version
  // ---------------------------------------------------------------------------

  describe("a requirement with no pinned version is not checked, and says so", () => {
    it("pydantic>=2.0.0 reads NOT CHECKED, never 'no known advisories'", async () => {
      write("requirements.txt", "pydantic>=2.0.0\nrequests\nurllib3~=1.26.0\n");
      const result = await scan({ package: "pydantic" });
      expect(asked).toEqual([]);
      expect(result.package_note).toMatch(/^pydantic \(direct\) is declared but no lockfile or exact pin gives it a version in this project, so it was NOT CHECKED/);
      expect(result.package_note).not.toMatch(/no known advisories/);
      expect(result.total_vulnerable_packages).toBeNull();
      expect(result.coverage.unpinned_requirements).toEqual([{ file: "requirements.txt", count: 3, names: ["pydantic", "requests", "urllib3"] }]);
      expect(result.coverage.note).toMatch(/NOT CHECKED \(no pinned version\): 3 requirements in requirements\.txt name no exact version \(pydantic, requests, urllib3\), so there is no installed version to check/);
      // The file pins nothing, so the note must not say it "pins only the packages listed".
      expect(result.coverage.note).not.toMatch(/pins? only the packages listed/);
    });

    it("pins and ranges in one file: the pins are checked, the ranges are listed, and the 'pins only what it lists' note stays", async () => {
      write("requirements.txt", "django==3.2.0\npydantic>=2.0.0\n");
      const result = await scan();
      expect(asked.map((q) => `${q.name}@${q.version}`)).toEqual(["django@3.2.0"]);
      expect(result.total_vulnerable_packages).toBe(1);
      expect(result.coverage.unpinned_requirements).toEqual([{ file: "requirements.txt", count: 1, names: ["pydantic"] }]);
      expect(result.coverage.note).toMatch(/requirements\.txt pins only the packages listed/);
    });

    it("a name another file in the directory pins is not unpinned; a git or URL requirement is not checkable", () => {
      write("requirements.in", "flask\n");
      write("requirements.txt", "flask\nrequests>=2\nmypkg @ git+https://github.com/acme/mypkg.git@v1\n-e git+https://github.com/acme/tool.git#egg=acme-tool\nhttps://example.com/wheels/other-1.0-py3-none-any.whl\n");
      write("requirements-lock.txt", "flask==2.0.1\n");
      const read = resolveVersionSource(dir, "PyPI");
      expect(read.unpinned).toEqual([{ file: path.join(dir, "requirements.txt"), names: ["requests"] }]);
      expect(read.uncheckable?.map((u) => `${u.name}:${u.kind}`).sort()).toEqual(["acme-tool:git", "mypkg:git", "other:url"]);
      expect(unpinnedRequirements("a==1\nb>=2\nc\n./local/pkg\n").names).toEqual(["b", "c"]);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. damaged and oddly encoded files
  // ---------------------------------------------------------------------------

  describe("damaged or oddly encoded files are never read as less, silently", () => {
    const utf16le = (text: string, bom = true) => Buffer.concat([bom ? Buffer.from([0xff, 0xfe]) : Buffer.alloc(0), Buffer.from(text, "utf16le")]);

    it("decodes UTF-8 with a mark, UTF-16LE and UTF-16BE, with or without a mark", () => {
      const text = "Django==3.2.0\r\nrequests==2.25.0\r\n";
      const be = Buffer.from(text, "utf16le").swap16();
      expect(decodeText(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)]))).toBe(text);
      expect(decodeText(utf16le(text))).toBe(text);
      expect(decodeText(utf16le(text, false))).toBe(text);
      expect(decodeText(Buffer.concat([Buffer.from([0xfe, 0xff]), be]))).toBe(text);
      expect(decodeText(be)).toBe(text);
      expect(decodeText(Buffer.from(text))).toBe(text);
    });

    it("a UTF-16 requirements.txt (PowerShell 5 `pip freeze >`) is read: its pins reach OSV as direct dependencies", async () => {
      write("requirements.txt", utf16le("Django==3.2.0\r\nrequests==2.25.0\r\nurllib3==1.26.4\r\n"));
      const result = await scan();
      expect(asked.map((q) => `${q.name}@${q.version}`).sort()).toEqual(["django@3.2.0", "requests@2.25.0", "urllib3@1.26.4"]);
      expect(result.total_dependencies_scanned).toBe(3);
      expect(result.vulnerable_packages[0]).toMatchObject({ package: "django", is_direct: true });
    });

    it("a package-lock.json with a UTF-8 byte-order mark is read, not reported as invalid JSON", () => {
      write("package-lock.json", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(npmLock({ lodash: "4.17.20" }))]));
      const read = resolveVersionSource(dir, "npm");
      expect(read.instances).toEqual([{ name: "lodash", version: "4.17.20", dev: false }]);
      expect(read.problems).toBeUndefined();
    });

    const cargoPackage = (name: string, deps: string[] = []) =>
      `[[package]]\nname = "${name}"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${"a".repeat(64)}"\n${deps.length > 0 ? `dependencies = [\n${deps.map((d) => ` "${d}",`).join("\n")}\n]\n` : ""}\n`;
    const cargoLock = `# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3\n\n${cargoPackage("aho-corasick", ["memchr"])}${cargoPackage("app-helper", ["smallvec", "tokio"])}${cargoPackage("memchr")}${cargoPackage("smallvec")}${cargoPackage("tokio", ["memchr"])}`;

    it("a whole Cargo.lock is not damaged", () => {
      expect(cargoLockDamage(cargoLock)).toBeNull();
      write("Cargo.lock", cargoLock);
      expect(resolveVersionSource(dir, "crates.io").problems).toBeUndefined();
    });

    it("a Cargo.lock cut mid-line is reported as not fully read", async () => {
      const cut = cargoLock.slice(0, cargoLock.indexOf('name = "smallvec"') + 12);
      write("Cargo.toml", '[package]\nname = "fx"\n\n[dependencies]\nsmallvec = "1"\n');
      write("Cargo.lock", cut);
      const read = resolveVersionSource(dir, "crates.io");
      expect(read.instances.map((i) => i.name)).toEqual(["aho-corasick", "app-helper", "memchr"]);
      expect(read.problems).toEqual([expect.objectContaining({ file: path.join(dir, "Cargo.lock"), partial: true })]);
      expect(read.problems![0].error).toMatch(/it is truncated or damaged: line \d+ is not lockfile syntax; 1 \[\[package\]\] table has no name or version; 2 packages named as dependencies have no \[\[package\]\] table \(smallvec, tokio\)/);

      const result = await scan();
      expect(result.coverage).toMatchObject({ complete: false });
      expect(result.coverage.partial_lockfiles).toEqual([expect.objectContaining({ path: "Cargo.lock", skipped_entries: 3 })]);
      expect(result.coverage.note).toMatch(/^PARTIAL: 1 lockfile was NOT read to the end: Cargo\.lock \(it is truncated or damaged/);
    });

    it("a Cargo.lock cut cleanly between two tables is still caught: a dependency has no table", () => {
      const cut = cargoLock.slice(0, cargoLock.indexOf('[[package]]\nname = "smallvec"'));
      const damage = cargoLockDamage(cut);
      expect(damage?.reason).toMatch(/2 packages named as dependencies have no \[\[package\]\] table \(smallvec, tokio\)/);
      expect(damage?.missing).toBe(2);
    });

    const pnpmLock = [
      "lockfileVersion: '9.0'",
      "",
      "importers:",
      "",
      "  .:",
      "    dependencies:",
      "      express:",
      "        specifier: 4.17.1",
      "        version: 4.17.1",
      "      lodash:",
      "        specifier: 4.17.20",
      "        version: 4.17.20",
      "",
      "packages:",
      "",
      "  accepts@1.3.8:",
      "    resolution: {integrity: sha512-aaa}",
      "",
      "  express@4.17.1:",
      "    resolution: {integrity: sha512-bbb}",
      "",
      "  lodash@4.17.20:",
      "    resolution: {integrity: sha512-ccc}",
      "",
      "snapshots:",
      "",
      "  accepts@1.3.8: {}",
      "",
      "  express@4.17.1:",
      "    dependencies:",
      "      accepts: 1.3.8",
      "",
      "  lodash@4.17.20: {}",
      "",
    ].join("\n");

    it("a whole pnpm-lock.yaml is not damaged", () => {
      expect(pnpmLockDamage(pnpmLock)).toBeNull();
      write("pnpm-lock.yaml", pnpmLock);
      expect(resolveVersionSource(dir, "npm").problems).toBeUndefined();
    });

    it("a pnpm-lock.yaml cut inside `packages:` is reported as not fully read", async () => {
      const cut = pnpmLock.slice(0, pnpmLock.indexOf("  lodash@4.17.20:\n    resolution")) + "  lodash@4.17.20:\n    resolution: {integrity: sha512-cc";
      write("package.json", JSON.stringify({ dependencies: { express: "4.17.1", lodash: "4.17.20" } }));
      write("pnpm-lock.yaml", cut);
      const read = resolveVersionSource(dir, "npm");
      expect(read.problems).toEqual([expect.objectContaining({ file: path.join(dir, "pnpm-lock.yaml"), partial: true })]);
      expect(read.problems![0].error).toMatch(/it is truncated or damaged: line \d+ is not lockfile syntax; .*it has `packages:` but no `snapshots:` section/);
      const result = await scan();
      expect(result.coverage.partial_lockfiles).toEqual([expect.objectContaining({ path: "pnpm-lock.yaml" })]);
      expect(result.coverage.note).toMatch(/^PARTIAL: 1 lockfile was NOT read to the end: pnpm-lock\.yaml/);
    });

    it("a pnpm-lock.yaml cut cleanly after an entry is still caught: an importer's pin has no entry", () => {
      const cut = pnpmLock.slice(0, pnpmLock.indexOf("  lodash@4.17.20:\n    resolution"));
      write("pnpm-lock.yaml", cut);
      const problems = resolveVersionSource(dir, "npm").problems ?? [];
      expect(problems[0].error).toMatch(/1 version its importers pin has no `packages:` entry \(lodash@4\.17\.20\)/);
    });

    it("a poetry.lock or uv.lock cut mid-value is reported; a whole one, and a dynamic-version uv project, are not", () => {
      const whole = '[[package]]\nname = "django"\nversion = "3.2.0"\nfiles = [\n    {file = "Django-3.2-py3-none-any.whl", hash = "sha256:aa"},\n]\n\n[[package]]\nname = "sqlparse"\nversion = "0.4.1"\nfiles = [\n    {file = "sqlparse-0.4.1-py3-none-any.whl", hash = "sha256:bb"},\n]\n\n[metadata]\nlock-version = "2.1"\n';
      expect(tomlLockDamage(whole)).toBeNull();
      expect(tomlLockDamage('version = 1\n\n[[package]]\nname = "fx"\nsource = { editable = "." }\n\n[[package]]\nname = "django"\nversion = "3.2.0"\nsource = { registry = "https://pypi.org/simple" }\n')).toBeNull();
      expect(tomlLockDamage(whole.slice(0, whole.indexOf('{file = "sqlparse') + 20))?.reason).toMatch(/its last line ends inside a string/);
      expect(tomlLockDamage(whole.slice(0, whole.indexOf('name = "sqlparse"')))?.reason).toMatch(/1 \[\[package\]\] table has no name or version/);

      write("poetry.lock", whole.slice(0, whole.indexOf('{file = "sqlparse') + 20));
      const read = resolveVersionSource(dir, "PyPI");
      expect(read.instances.map((i) => i.name)).toEqual(["django", "sqlparse"]);
      expect(read.problems).toEqual([expect.objectContaining({ file: path.join(dir, "poetry.lock"), partial: true })]);
    });

    it("a yarn.lock whose last entry has no version is reported", () => {
      write("package.json", JSON.stringify({ dependencies: { lodash: "^4.17.0" } }));
      write("yarn.lock", '# yarn lockfile v1\n\nlodash@^4.17.0:\n  version "4.17.20"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz#abc"\n\nminimist@^1.2.0:\n  resol');
      const problems = resolveVersionSource(dir, "npm").problems ?? [];
      expect(problems).toEqual([expect.objectContaining({ partial: true, skipped: 1 })]);
      expect(problems[0].error).toMatch(/1 entry names a package but no version/);
    });
  });

  // ---------------------------------------------------------------------------
  // 7. git and URL dependencies, end to end
  // ---------------------------------------------------------------------------

  it("a git dependency is never asked about as the registry package of that name, and is listed as not checkable", async () => {
    write("package.json", JSON.stringify({ dependencies: { "bignumber.js": "git+ssh://git@github.com/acme/bignumber.js.git#v2.0.7", lodash: "4.17.20" } }));
    write(
      "package-lock.json",
      JSON.stringify({
        name: "x",
        lockfileVersion: 3,
        packages: {
          "": { name: "x", dependencies: { "bignumber.js": "git+ssh://git@github.com/acme/bignumber.js.git#v2.0.7", lodash: "4.17.20" } },
          "node_modules/bignumber.js": { version: "2.0.7", resolved: "git+ssh://git@github.com/acme/bignumber.js.git#aeb3e27dae0412de5c0494e9563a5f10c82cc7a9" },
          "node_modules/lodash": { version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
        },
      }),
    );
    const result = await scan({ package: "bignumber.js" });
    expect(asked.map((q) => q.name)).toEqual(["lodash"]);
    expect(result.coverage).toMatchObject({ complete: false, not_checkable_count: 1 });
    expect(result.coverage.not_checkable).toEqual([{ package: "bignumber.js", version: "2.0.7", source: "git", lockfile: "package-lock.json" }]);
    expect(result.coverage.note).toMatch(/NOT CHECKABLE: 1 dependency is installed from git, a URL or a local archive, not from the registry \(bignumber\.js\)/);
    expect(result.package_note).toMatch(/^bignumber\.js is installed from git \(package-lock\.json\), not from the registry.*NOT CHECKED/);
    // The location itself (it can carry credentials) is never echoed.
    expect(JSON.stringify(result)).not.toMatch(/git@github\.com|aeb3e27/);
  });
});
