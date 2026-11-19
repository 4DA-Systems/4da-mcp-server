// SPDX-License-Identifier: Apache-2.0
/**
 * What upgrade_planner puts in a registry URL, per ecosystem. Every request is recorded at the
 * HTTP boundary; the installed versions of the project are never in a registry URL, with the one
 * exception PyPI's API forces.
 *
 * npm: a parent's requirement on a transitive copy is read from the parent's whole-package
 * document (the one its release facts already come from), never from
 * `registry.npmjs.org/<parent>/<installed version>`. The one per-version npm request asks whether
 * a fix target above every release the document lists is published: an advisory's fixed version,
 * never an installed one.
 *
 * crates.io: the sparse index entry, by name only. Go: the proxy's version list and `@latest` by
 * name, and the go.mod of the fix target (`@v/<target>.mod`), never of the installed version.
 *
 * PyPI is the exception: a release's requirements are served per release only
 * (`/pypi/<name>/<version>/json`), so the installed version of a parent named by a uv.lock or a
 * compiled requirements file is part of that request.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { restampDepContext } from "../live/osv-scanner.js";
import type { ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import type { FourDADatabase } from "../db.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const noDb = null as unknown as FourDADatabase;

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const OSV = /^https:\/\/api\.osv\.dev\//;
const registryRequests = () => h.requests.filter((u) => !OSV.test(u));
const npmRequests = () => h.requests.filter((u) => u.startsWith("https://registry.npmjs.org/"));
const WHOLE_PACKAGE = /^https:\/\/registry\.npmjs\.org\/(?:@[^/]+%2F)?[^/]+$/i;

describe("npm: parent requirements come from the whole-package document", () => {
  function pnpmProject() {
    h.ADVISORIES.braces = [adv("GHSA-grv7-fg5c-xmjg", "braces", fixedIn("3.0.3"))];
    h.NPM = {
      chokidar: { latest: "3.5.3", versions: { "3.5.3": { dependencies: { braces: "~3.0.2" } } } },
      micromatch: { latest: "4.0.5", versions: { "4.0.5": { dependencies: { braces: "^3.0.2" } } } },
      braces: { latest: "3.0.3", versions: { "3.0.2": {}, "3.0.3": {} } },
    };
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { chokidar: "^3.5.3" } }));
    // pnpm records the resolved version of each dependency, not the parent's declared range.
    h.write("pnpm-lock.yaml", [
      "lockfileVersion: '6.0'", "", "dependencies:", "  chokidar:", "    specifier: ^3.5.3", "    version: 3.5.3", "", "packages:", "",
      "  /braces@3.0.2:", "    resolution: {integrity: sha512-x}", "",
      "  /chokidar@3.5.3:", "    resolution: {integrity: sha512-y}", "    dependencies:", "      braces: 3.0.2", "      micromatch: 4.0.5", "",
      "  /micromatch@4.0.5:", "    resolution: {integrity: sha512-z}", "    dependencies:", "      braces: 3.0.2", "",
    ].join("\n"));
  }

  it("a pnpm lockfile: the refresh is decided from the parents' requirements, and no installed version is in a registry URL", async () => {
    pnpmProject();
    const { step } = await h.plan();
    // Read, not inferred: chokidar "~3.0.2" and micromatch "^3.0.2" both admit 3.0.3.
    expect(step("braces")).toMatchObject({ action: "lockfile_refresh", targetVersion: "3.0.3", refreshCommands: [{ command: "pnpm update braces --depth Infinity" }] });
    expect(step("braces").refreshInferred).toBeUndefined();
    const urls = npmRequests();
    expect(urls).toContain("https://registry.npmjs.org/chokidar");
    expect(urls).toContain("https://registry.npmjs.org/micromatch");
    expect(urls.filter((u) => !WHOLE_PACKAGE.test(u))).toEqual([]);
    expect(registryRequests().join("\n")).not.toMatch(/3\.5\.3|4\.0\.5|3\.0\.2/);
  });

  it("a parent release the registry does not list leaves the requirement unread (no refresh on a guess)", async () => {
    pnpmProject();
    // The fix is on another major: nothing is inferred from semver, so an unread requirement decides nothing.
    h.ADVISORIES.braces = [adv("GHSA-grv7-fg5c-xmjg", "braces", fixedIn("4.0.0"))];
    h.NPM.braces.versions["4.0.0"] = {};
    h.NPM.chokidar.versions = { "3.5.2": { dependencies: { braces: "~3.0.2" } } };
    const { step } = await h.plan();
    expect(step("braces").action).not.toBe("lockfile_refresh");
    expect(npmRequests().filter((u) => !WHOLE_PACKAGE.test(u))).toEqual([]);
  });

  it("a package-lock project asks for whole-package documents only", async () => {
    h.ADVISORIES["body-parser"] = [adv("GHSA-qwcr-r2fm-qrc7", "body-parser", fixedIn("1.20.3"))];
    h.NPM = {
      express: { latest: "4.22.3", versions: { "4.17.1": { dependencies: { "body-parser": "1.19.0" } }, "4.22.3": { dependencies: { "body-parser": "~1.20.3" } } } },
      "body-parser": { latest: "1.20.3", versions: { "1.19.0": {}, "1.20.3": {} } },
    };
    h.npmProject({ express: "4.17.1" }, {}, { express: { version: "4.17.1", dependencies: { "body-parser": "1.19.0" } }, "body-parser": { version: "1.19.0" } });
    const { step } = await h.plan();
    expect(step("body-parser")).toMatchObject({ action: "upgrade_parent" });
    expect(npmRequests().filter((u) => !WHOLE_PACKAGE.test(u))).toEqual([]);
    expect(registryRequests().join("\n")).not.toMatch(/4\.17\.1|1\.19\.0/);
  });

  it("the one per-version request names a fix target the document does not list, never the installed version", async () => {
    h.ADVISORIES.minimist = [adv("GHSA-xvch-5gv4-984h", "minimist", fixedIn("1.2.6"))];
    // The document has not caught up with the advisory's fixed version: it is asked for by name.
    h.NPM = { minimist: { latest: "1.2.5", versions: { "1.2.5": {} } } };
    h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
    await h.plan();
    expect(npmRequests().filter((u) => !WHOLE_PACKAGE.test(u))).toEqual(["https://registry.npmjs.org/minimist/1.2.6"]);
    expect(registryRequests().join("\n")).not.toContain("1.2.5");
  });
});

describe("crates.io: the sparse index entry, by name only", () => {
  function cargoLock(packages: Array<{ name: string; version: string; deps?: string[]; root?: boolean }>) {
    return ["version = 4", "", ...packages.flatMap((p) => [
      "[[package]]", `name = "${p.name}"`, `version = "${p.version}"`,
      ...(p.root ? [] : ['source = "registry+https://github.com/rust-lang/crates.io-index"']),
      ...(p.deps && p.deps.length > 0 ? ["dependencies = [", ...p.deps.map((d) => ` "${d}",`), "]"] : []), "",
    ])].join("\n");
  }

  /** The scan as OSV.dev answers it, per version (no `cargo tree` runs here); the planner's own reads go through the stubbed fetch. */
  async function intelWithVulnerableMio() {
    const li = new LiveIntelligence(new Database(":memory:"));
    const scanOf = async (deps: ResolvedDependency[], projectPath: string): Promise<VulnerabilityScanResult> => {
      const vulnerabilities = deps
        .filter((d) => d.name === "mio" && d.version === "0.8.0")
        .map((d) => restampDepContext({
          package: "", currentVersion: "", ecosystem: "crates.io", isDev: false, isDirect: false, devScopeKnown: true,
          vulnId: "GHSA-r8w9-5wcg-vfj7", aliases: [], severity: "high", cvssScore: null, summary: "named pipe token", fixedVersion: "0.8.11",
          published: "2024-03-04T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: [],
        } as unknown as VulnerabilityEntry, d));
      return {
        scannedAt: new Date().toISOString(), projectPath, ecosystemsScanned: ["crates.io"], totalScanned: deps.length, totalVulnerable: 1,
        platformInactiveVulnerable: 0, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 }, vulnerabilities,
        cleanCount: deps.length - 1, scanDurationMs: 1, cached: false, offline: false,
      };
    };
    (li as unknown as { osvScanner: { scan: typeof scanOf } }).osvScanner = { scan: scanOf } as never;
    const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
    const { entries, discovery } = scanProjectTree(h.dir);
    li.initFromProjectTree(h.dir, treeResolutionGroups(entries), discovery);
    return li;
  }

  it("a transitive crate's refresh is decided from the parent's sparse entry; no installed version is in a URL", async () => {
    h.ADVISORIES.mio = [adv("GHSA-r8w9-5wcg-vfj7", "mio", [{ introduced: "0.7.2" }, { fixed: "0.8.11" }], "crates.io")];
    h.CRATES.tokio = [{ vers: "1.17.0", deps: [{ name: "mio", req: "^0.8.0" }] }];
    h.CRATES.mio = [{ vers: "0.8.0" }, { vers: "0.8.11" }];
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\ntokio = "1"\n');
    h.write("Cargo.lock", cargoLock([
      { name: "app", version: "0.1.0", deps: ["tokio"], root: true },
      { name: "tokio", version: "1.17.0", deps: ["mio"] },
      { name: "mio", version: "0.8.0" },
    ]));
    const plan = (await executeUpgradePlanner(noDb, { project_path: h.dir, max_recommendations: 50 }, await intelWithVulnerableMio())) as Record<string, any>;
    const mio = plan.recommendations.find((r: { package: string }) => r.package === "mio");
    expect(mio).toMatchObject({ action: "lockfile_refresh", targetVersion: "0.8.11", refreshCommands: [{ command: "cargo update -p mio@0.8.0 --precise 0.8.11" }] });
    const crates = registryRequests().filter((u) => u.includes("crates.io"));
    expect(crates).toContain("https://index.crates.io/to/ki/tokio");
    expect(crates.filter((u) => !/^https:\/\/index\.crates\.io\/[^@]+$/.test(u))).toEqual([]);
    expect(registryRequests().join("\n")).not.toMatch(/1\.17\.0|0\.8\.0/);
  });
});

describe("Go: the version list by name, and the go.mod of the fix target only", () => {
  it("a direct module's upgrade reads the target's go.mod, never the installed version's", async () => {
    h.write("go.mod", "module example.com/demo\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/text v0.3.2\n)\n");
    h.write("go.sum", "golang.org/x/text v0.3.2 h1:a=\ngolang.org/x/text v0.3.2/go.mod h1:b=\n");
    h.ADVISORIES["golang.org/x/text"] = [adv("GO-2020-0015", "golang.org/x/text", fixedIn("0.3.3"), "Go")];
    h.GO["golang.org/x/text"] = ["v0.3.2", "v0.3.3", "v0.3.8"];
    h.GOMOD["golang.org/x/text@v0.3.3"] = "";
    const { step } = await h.plan();
    expect(step("golang.org/x/text")).toMatchObject({ action: "upgrade_direct", targetVersion: "v0.3.3" });
    const go = registryRequests().filter((u) => u.startsWith("https://proxy.golang.org/"));
    expect(go).toContain("https://proxy.golang.org/golang.org/x/text/@v/list");
    expect(go).toContain("https://proxy.golang.org/golang.org/x/text/@v/v0.3.3.mod");
    expect(registryRequests().join("\n")).not.toContain("0.3.2");
  });
});

describe("PyPI: a parent's requirements are served per release, so its installed version is in the request", () => {
  it("uv.lock: the one request that names an installed version is the parent's release metadata", async () => {
    h.ADVISORIES.certifi = [adv("PYSEC-2023-135", "certifi", fixedIn("2023.7.22"), "PyPI")];
    h.PYPI = {
      certifi: { "2020.12.5": {}, "2023.7.22": {} },
      requests: { "2.25.0": { requiresDist: ["certifi (>=2017.4.17)"] } },
    };
    h.write("pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\nrequires-python = ">=3.8"\ndependencies = ["requests==2.25.0"]\n');
    h.write("uv.lock", [
      'version = 1\nrequires-python = ">=3.8"\n',
      '[[package]]\nname = "certifi"\nversion = "2020.12.5"\nsource = { registry = "https://pypi.org/simple" }\n',
      '[[package]]\nname = "requests"\nversion = "2.25.0"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "certifi" },\n]\n',
      '[[package]]\nname = "x"\nversion = "0.1.0"\nsource = { virtual = "." }\ndependencies = [\n    { name = "requests" },\n]\n\n[package.metadata]\nrequires-dist = [{ name = "requests", specifier = "==2.25.0" }]\n',
    ].join("\n"));
    const { step } = await h.plan();
    expect(step("certifi")).toMatchObject({ action: "lockfile_refresh" });
    const versioned = h.requests.filter((u) => /^https:\/\/pypi\.org\/pypi\/[^/]+\/[^/]+\/json$/.test(u));
    // uv.lock names the parent without its requirement, and PyPI has no document that lists every release's requirements.
    expect(versioned).toEqual(["https://pypi.org/pypi/requests/2.25.0/json"]);
    // The vulnerable copy's own installed version is never in a URL.
    expect(registryRequests().join("\n")).not.toContain("2020.12.5");
  });
});
