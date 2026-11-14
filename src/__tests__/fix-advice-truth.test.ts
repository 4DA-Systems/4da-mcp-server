// SPDX-License-Identifier: Apache-2.0
/**
 * Fix advice tells the truth (Wave 1, stream M1; audit 2026-11-11 M7, M8 and the a2 black-box
 * track's fix-advice rows):
 *
 * 1. One answer per finding: vulnerability_scan said "Upgrade zip 8.6.0 -> 9.0.5" for a transitive
 *    copy while upgrade_planner said docx-rs 0.4.22, its newest release, requires `^8.6.0`. The scan
 *    now carries the planner's verdict (refresh, parent upgrade, override or replace, blocked).
 * 2. No yanked or deprecated target: crypto-bigint 0.7.6 (yanked) was named for a crate not built
 *    on this host, because those rows were never checked.
 * 3. "breaking" is honest: "Force uuid to 11.1.1" under request (`^3.3.2`) read breaking: false.
 * 4. A dead installed line names the smallest safe release on a later line AND the newest.
 * 5. Python and Go transitive copies: the refresh command when every parent admits the fix,
 *    blocked upstream naming the parent when one does not (and the project's Python when that is
 *    what holds it back); Go indirect modules are raised with `go get`.
 * 6. The audit's two false "upgrade the parent" claims (navcal glob, victauri @azure/msal-node):
 *    the scan now says the planner's refresh too.
 *
 * Registry and OSV shapes are the real ones (registry.npmjs.org abbreviated documents,
 * index.crates.io sparse lines, pypi.org JSON, proxy.golang.org lists, api.osv.dev records); the
 * version lists are cut down to what decides each case.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { restampDepContext } from "../live/osv-scanner.js";
import type { OsvVulnerability, ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

type Ev = Record<string, string>;
const adv = (id: string, name: string, events: Ev[], ecosystem = "npm", severity = "HIGH"): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity },
  affected: [{ package: { name, ecosystem }, ranges: [{ type: ecosystem === "PyPI" ? "ECOSYSTEM" : "SEMVER", events }] }],
});
const fixedIn = (v: string): Ev[] => [{ introduced: "0" }, { fixed: v }];

let ADVISORIES: Record<string, OsvVulnerability[]> = {};
type NpmVersion = { deprecated?: string; dependencies?: Record<string, string> };
let NPM: Record<string, { versions: Record<string, NpmVersion>; latest: string }> = {};
/** index.crates.io: crate -> its sparse-index lines. */
let CRATES: Record<string, Array<{ vers: string; yanked?: boolean; deps?: Array<{ name: string; req: string; kind?: string }> }>> = {};
/** pypi.org: project -> release -> what the JSON API says of it. */
let PYPI: Record<string, Record<string, { requiresPython?: string; requiresDist?: string[]; yanked?: boolean }>> = {};
let GO: Record<string, string[]> = {};
/** proxy.golang.org: "module@vX" -> the go directive of that version's go.mod. */
let GOMOD: Record<string, string> = {};

const cmp = (a: string, b: string) => a.replace(/^v/, "").localeCompare(b.replace(/^v/, ""), undefined, { numeric: true });
const affects = (v: OsvVulnerability, version: string) => {
  const fixed = v.affected![0].ranges[0].events.find((e) => e.fixed)?.fixed;
  return fixed ? cmp(version, fixed) < 0 : true;
};

function sparsePath(name: string): string {
  const n = name.toLowerCase();
  return n.length <= 2 ? `${n.length}/${n}` : n.length === 3 ? `3/${n[0]}/${n}` : `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}

function stubNetwork() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (ADVISORIES[q.package.name] ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(ADVISORIES).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: ADVISORIES[q.package.name] ?? [] });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({}, 404);
      if (npm[2]) {
        const version = doc.versions[decodeURIComponent(npm[2])];
        return version ? json(version) : json({ error: "version not found" }, 404);
      }
      return json({ name, "dist-tags": { latest: doc.latest }, versions: doc.versions });
    }
    const crate = /^https:\/\/index\.crates\.io\/(.+)$/.exec(url);
    if (crate) {
      const name = Object.keys(CRATES).find((n) => sparsePath(n) === crate[1]);
      if (!name) return new Response("not found", { status: 404 });
      return new Response(CRATES[name].map((l) => JSON.stringify({ name, vers: l.vers, deps: (l.deps ?? []).map((d) => ({ kind: "normal", optional: false, ...d })), yanked: l.yanked === true })).join("\n"), { status: 200 });
    }
    const pypiOne = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/([^/]+)\/json$/.exec(url);
    if (pypiOne) {
      const release = PYPI[decodeURIComponent(pypiOne[1]).toLowerCase()]?.[decodeURIComponent(pypiOne[2])];
      return release ? json({ info: { requires_dist: release.requiresDist ?? null, requires_python: release.requiresPython ?? null } }) : json({}, 404);
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      const name = decodeURIComponent(pypi[1]).toLowerCase();
      const project = PYPI[name];
      if (!project) return json({}, 404);
      const versions = Object.keys(project).sort(cmp);
      const releases = Object.fromEntries(
        versions.map((v) => [v, [{ upload_time_iso_8601: "2024-01-01T00:00:00Z", yanked: project[v].yanked === true, requires_python: project[v].requiresPython ?? null }]]),
      );
      return json({ info: { name, version: versions[versions.length - 1], license: "", classifiers: [], summary: "", yanked: false, yanked_reason: null }, releases });
    }
    const goMod = /^https:\/\/proxy\.golang\.org\/(.+)\/@v\/(v[^/]+)\.mod$/.exec(url);
    if (goMod) {
      const directive = GOMOD[`${goMod[1]}@${goMod[2]}`];
      return directive ? new Response(`module ${goMod[1]}\n\ngo ${directive}\n`, { status: 200 }) : new Response("not found", { status: 404 });
    }
    const go = /^https:\/\/proxy\.golang\.org\/(.+)\/@v\/(list|v[^/]+\.info)$/.exec(url);
    if (go) {
      const versions = GO[go[1]];
      if (!versions) return new Response("not found", { status: 404 });
      if (go[2] === "list") return new Response(`${versions.join("\n")}\n`, { status: 200 });
      const version = go[2].replace(/\.info$/, "");
      return versions.includes(version) ? json({ Version: version, Time: "2024-01-01T00:00:00Z" }) : new Response("not found", { status: 404 });
    }
    return json({}, 404);
  });
}

let dir: string;
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-fix-truth-"));
  ADVISORIES = {};
  NPM = {};
  CRATES = {};
  PYPI = {};
  GO = {};
  GOMOD = {};
  stubNetwork();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

const write = (file: string, body: string) => {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), body);
};

type LockEntry = { version: string; dev?: boolean; dependencies?: Record<string, string> };
/** A package-lock v3 project: `direct` is declared; `tree` is every installed entry. */
function npmProject(direct: Record<string, string>, tree: Record<string, LockEntry>) {
  write("package.json", JSON.stringify({ name: "x", dependencies: direct }));
  const packages: Record<string, unknown> = { "": { name: "x", dependencies: direct } };
  for (const [n, e] of Object.entries(tree)) packages[`node_modules/${n}`] = e;
  write("package-lock.json", JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
}

async function live() {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

async function plan() {
  const result = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, await live())) as Record<string, any>;
  const step = (name: string) => result.recommendations.find((s: { package: string }) => s.package === name);
  return { result, step };
}

async function scan(format: "concise" | "detailed" = "concise") {
  return (await executeVulnerabilityScan(null, { project_path: dir, response_format: format }, await live())) as Record<string, any>;
}

const lineFor = (s: Record<string, any>, name: string, version: string) => (s.recommendations as string[]).find((r) => r.includes(`${name} ${version}`));

// ---------------------------------------------------------------------------
// 1 + 3: zip under docx-rs (4DA's own src-tauri)
// ---------------------------------------------------------------------------

/** Cargo.lock as cargo writes it: the root package has no source. */
function cargoLock(packages: Array<{ name: string; version: string; deps?: string[]; root?: boolean }>) {
  return [
    "version = 4",
    "",
    ...packages.flatMap((p) => [
      "[[package]]",
      `name = "${p.name}"`,
      `version = "${p.version}"`,
      ...(p.root ? [] : ['source = "registry+https://github.com/rust-lang/crates.io-index"']),
      ...(p.deps && p.deps.length > 0 ? ["dependencies = [", ...p.deps.map((d) => ` "${d}",`), "]"] : []),
      "",
    ]),
  ].join("\n");
}

describe("1. one answer per finding: a transitive copy carries the planner's verdict (zip under docx-rs, M8)", () => {
  function zipProject() {
    ADVISORIES.zip = [adv("GHSA-9hj8-73fh-9963", "zip", fixedIn("9.0.5"), "crates.io")];
    CRATES.zip = [{ vers: "8.6.0" }, { vers: "9.0.5" }, { vers: "9.5.1" }];
    CRATES["docx-rs"] = [{ vers: "0.4.22", deps: [{ name: "zip", req: "^8.6.0" }] }];
    write("Cargo.lock", cargoLock([
      { name: "app", version: "0.1.0", deps: ["docx-rs"], root: true },
      { name: "docx-rs", version: "0.4.22", deps: ["zip"] },
      { name: "zip", version: "8.6.0" },
    ]));
  }

  it("the planner: blocked upstream (docx-rs 0.4.22 is its newest release), override or replace, breaking across zip 9", async () => {
    zipProject();
    const { step } = await plan();
    const zip = step("zip");
    expect(zip).toMatchObject({ action: "override_or_replace", targetVersion: "9.0.5", scope: "transitive", breaking: true, fixPathChecked: "all_advisories" });
    const reasons = zip.reasons.join(" | ");
    expect(reasons).toMatch(/docx-rs 0\.4\.22 requires "\^8\.6\.0", and docx-rs 0\.4\.22 is already its latest release/);
    expect(reasons).toMatch(/Breaking: forcing zip from 8\.6\.0 to 9\.0\.5 crosses a major version of what its parent declares \(docx-rs 0\.4\.22 requires "\^8\.6\.0"\)/);
  });

  it("the scan says the same thing, never a bare 'Upgrade zip 8.6.0 → 9.0.5'", async () => {
    zipProject();
    const concise = await scan();
    const line = lineFor(concise, "zip", "8.6.0")!;
    expect(line).toMatch(/^Blocked upstream: zip 8\.6\.0 in \. \[1 high\] — 9\.0\.5 would resolve 1 CVE, but no parent release admits it, so it takes an override or replacing the parent \(breaking\): /);
    expect(line).toMatch(/docx-rs 0\.4\.22 is already its latest release/);
    expect(concise.recommendations.join("\n")).not.toMatch(/^Upgrade zip/m);
    expect(concise.vulnerable_packages.find((p: { package: string }) => p.package === "zip")).toMatchObject({ fixed_version: "9.0.5", is_direct: false, fix_action: "override_or_replace", fix_breaking: true });
    const detailed = await scan("detailed");
    expect(detailed.fix_targets["zip@8.6.0"]).toMatchObject({ target: "9.0.5", checked: "all_advisories", action: "override_or_replace", breaking: true });
  });
});

// ---------------------------------------------------------------------------
// 2: a yanked target for code this host does not build (crypto-bigint 0.7.6)
// ---------------------------------------------------------------------------

describe("2. a target is never a yanked release, on a crate this host does not build either (crypto-bigint 0.7.6)", () => {
  /** The scan stubbed as in scan-targets.test.ts: cargo tree is not run here, so the copy is marked not built on this host directly. */
  async function inactiveIntel() {
    ADVISORIES["crypto-bigint"] = [adv("RUSTSEC-2026-0387", "crypto-bigint", fixedIn("0.7.6"), "crates.io")];
    // crates.io, 2026-11-11: 0.7.0 to 0.7.8 are yanked; 0.7.9 is the first release a user can install.
    CRATES["crypto-bigint"] = ["0.5.5", "0.7.5", "0.7.6", "0.7.7", "0.7.8", "0.7.9", "0.7.11"].map((vers) => ({ vers, yanked: ["0.7.5", "0.7.6", "0.7.7", "0.7.8"].includes(vers) }));
    write("Cargo.lock", cargoLock([
      { name: "app", version: "0.1.0", deps: ["rsa"], root: true },
      { name: "rsa", version: "0.9.10", deps: ["crypto-bigint"] },
      { name: "crypto-bigint", version: "0.5.5" },
    ]));
    const li = new LiveIntelligence(new Database(":memory:"));
    const scanOf = async (deps: ResolvedDependency[], projectPath: string): Promise<VulnerabilityScanResult> => {
      const vulnerabilities = deps
        .filter((d) => d.name === "crypto-bigint")
        .map((d) =>
          restampDepContext(
            {
              package: "", currentVersion: "", ecosystem: "crates.io", isDev: false, isDirect: false, devScopeKnown: true,
              vulnId: "RUSTSEC-2026-0387", aliases: [], severity: "medium", cvssScore: null, summary: "timing", fixedVersion: "0.7.6",
              published: "2026-10-23T00:00:00Z", references: [], target: null, platformActive: false, sourceDirs: [],
            } as unknown as VulnerabilityEntry,
            d,
          ),
        )
        .map((v) => ({ ...v, platformActive: false }));
      return {
        scannedAt: new Date().toISOString(), projectPath, ecosystemsScanned: ["crates.io"], totalScanned: deps.length, totalVulnerable: 0,
        platformInactiveVulnerable: 1, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities,
        cleanCount: deps.length - 1, scanDurationMs: 1, cached: false, offline: false,
      };
    };
    (li as unknown as { osvScanner: { scan: typeof scanOf } }).osvScanner = { scan: scanOf } as never;
    const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
    const { entries, discovery } = scanProjectTree(dir);
    li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    return li;
  }

  it("upgrade_planner names 0.7.9 and says 0.7.6-0.7.8 are yanked", async () => {
    const result = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, await inactiveIntel())) as Record<string, any>;
    const row = result.recommendations.find((r: { package: string }) => r.package === "crypto-bigint");
    expect(row).toMatchObject({ action: "not_built_on_this_host", targetVersion: "0.7.9", fixPathChecked: "all_advisories", withheld: ["0.7.6", "0.7.7", "0.7.8"] });
    expect(row.reasons.join(" | ")).toMatch(/0\.7\.6, 0\.7\.7 and 0\.7\.8 are yanked on crates\.io; 0\.7\.9 is the smallest clean release/);
  });

  it("vulnerability_scan's platform-inactive row names 0.7.9 too, never the yanked 0.7.6", async () => {
    const detailed = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, await inactiveIntel())) as Record<string, any>;
    const row = detailed.platform_inactive_vulnerabilities.find((v: { package: string }) => v.package === "crypto-bigint");
    expect(row).toMatchObject({ fixed_version: "0.7.9", withheld: ["0.7.6", "0.7.7", "0.7.8"] });
  });
});

// ---------------------------------------------------------------------------
// 3: breaking is honest
// ---------------------------------------------------------------------------

describe("3. a forced version across a major of what the parent declares is breaking (uuid under request)", () => {
  function requestProject(fix: string) {
    ADVISORIES.uuid = [adv("GHSA-uuid-0000-0001", "uuid", fixedIn(fix))];
    NPM.uuid = { latest: "11.1.1", versions: { "3.4.0": {}, "3.4.1": {}, "11.1.1": {} } };
    // request is retired whole (its latest is deprecated): it will not move.
    NPM.request = { latest: "2.88.2", versions: { "2.88.2": { deprecated: "request has been deprecated", dependencies: { uuid: "^3.3.2" } } } };
    npmProject({ request: "^2.88.2" }, { request: { version: "2.88.2", dependencies: { uuid: "^3.3.2" } }, uuid: { version: "3.4.0" } });
  }

  it("Force uuid 3.4.0 -> 11.1.1: breaking, and why (request was written against uuid 3.x)", async () => {
    requestProject("11.1.1");
    const { step } = await plan();
    const uuid = step("uuid");
    expect(uuid).toMatchObject({ action: "override_or_replace", targetVersion: "11.1.1", breaking: true });
    expect(uuid.reasons.join(" | ")).toMatch(/Force uuid to 11\.1\.1: npm: add "overrides"/);
    expect(uuid.reasons.join(" | ")).toMatch(/Breaking: forcing uuid from 3\.4\.0 to 11\.1\.1 crosses a major version of what its parent declares \(request 2\.88\.2 requires "\^3\.3\.2"\); that parent was written against uuid 3\.x/);
    const concise = await scan();
    expect(concise.vulnerable_packages.find((p: { package: string }) => p.package === "uuid")).toMatchObject({ fix_action: "override_or_replace", fix_breaking: true });
  });

  it("a forced version inside the declared major is not called breaking", async () => {
    // request 2.88.2 requires ^3.3.2, which already admits 3.4.1: a refresh, nothing forced, nothing breaking.
    requestProject("3.4.1");
    const { step } = await plan();
    const uuid = step("uuid");
    expect(uuid).toMatchObject({ action: "lockfile_refresh", breaking: false });
    expect(uuid.reasons.join(" ")).not.toMatch(/Breaking:/);
  });

  it("a parent upgrade that needs a major upgrade of what the project declares is breaking", async () => {
    ADVISORIES.child = [adv("GHSA-chld-0000-0001", "child", fixedIn("1.0.1"))];
    NPM.child = { latest: "1.0.1", versions: { "1.0.0": {}, "1.0.1": {} } };
    NPM.parent = { latest: "2.0.0", versions: { "1.0.0": { dependencies: { child: "1.0.0" } }, "2.0.0": { dependencies: { child: "^1.0.1" } } } };
    npmProject({ parent: "^1.0.0" }, { parent: { version: "1.0.0", dependencies: { child: "1.0.0" } }, child: { version: "1.0.0" } });
    const { step } = await plan();
    const child = step("child");
    expect(child.action).toBe("upgrade_parent");
    expect(child.parentUpgrades[0]).toMatchObject({ parent: "parent", from: "1.0.0", to: "2.0.0", breaking: true });
    expect(child.breaking).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4: a dead installed line
// ---------------------------------------------------------------------------

describe("4. a dead installed line names the smallest safe release on a later line and the newest (jsonwebtoken 8.5.1)", () => {
  function jwtProject() {
    ADVISORIES.jsonwebtoken = [adv("GHSA-8cf7-32gw-wr33", "jsonwebtoken", fixedIn("9.0.0"))];
    NPM.jsonwebtoken = { latest: "9.0.3", versions: { "8.5.1": {}, "9.0.0": {}, "9.0.2": {}, "9.0.3": {} } };
    npmProject({ jsonwebtoken: "8.5.1" }, { jsonwebtoken: { version: "8.5.1" } });
  }

  it("upgrade_planner: 9.0.0 is the target, 9.0.3 the newest, and both are said", async () => {
    jwtProject();
    const { step } = await plan();
    const jwt = step("jsonwebtoken");
    expect(jwt).toMatchObject({ targetVersion: "9.0.0", latestVersion: "9.0.3", breaking: true });
    expect(jwt.reasons).toContain("No 8.x release clears every advisory: 9.0.0 is the smallest safe release, on the nearest later line that has one; 9.0.3 is the newest safe release");
  });

  it("vulnerability_scan: the same words, and fix_targets carries newest_safe", async () => {
    jwtProject();
    const detailed = await scan("detailed");
    expect(lineFor(detailed, "jsonwebtoken", "8.5.1")).toMatch(/no 8\.x release clears every advisory: 9\.0\.0 is the smallest safe release, on the nearest later line that has one; 9\.0\.3 is the newest safe release/);
    expect(detailed.fix_targets["jsonwebtoken@8.5.1"]).toMatchObject({ target: "9.0.0", newest_safe: "9.0.3" });
  });

  it("a fix on the installed line says nothing of the kind", async () => {
    ADVISORIES.lodash = [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21"))];
    NPM.lodash = { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } };
    npmProject({ lodash: "4.17.20" }, { lodash: { version: "4.17.20" } });
    const { step } = await plan();
    expect(step("lodash").reasons.join(" ")).not.toMatch(/release clears every advisory/);
  });
});

// ---------------------------------------------------------------------------
// 5: Python and Go transitive copies
// ---------------------------------------------------------------------------

describe("5. Python transitive copies: refresh when every parent admits, blocked upstream naming the parent when one does not", () => {
  function pythonRegistry() {
    ADVISORIES = {
      certifi: [adv("PYSEC-2023-135", "certifi", fixedIn("2023.7.22"), "PyPI")],
      idna: [adv("PYSEC-2024-60", "idna", fixedIn("3.7"), "PyPI")],
      sqlparse: [adv("GHSA-2m57-hf25-phgg", "sqlparse", fixedIn("0.6.0"), "PyPI")],
    };
    PYPI = {
      certifi: { "2020.12.5": {}, "2023.7.22": { requiresPython: ">=3.6" }, "2026.10.23": { requiresPython: ">=3.7" } },
      idna: { "2.10": {}, "3.7": { requiresPython: ">=3.5" } },
      sqlparse: { "0.4.1": {}, "0.5.5": { requiresPython: ">=3.8" }, "0.6.0": { requiresPython: ">=3.10" } },
      requests: {
        "2.25.0": { requiresDist: ["chardet (<4,>=3.0.2)", "idna (<3,>=2.5)", "certifi (>=2017.4.17)", "PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'"] },
        "2.34.2": { requiresDist: ["idna<4,>=2.5", "certifi>=2017.4.17"] },
      },
      django: { "3.2": { requiresDist: ["asgiref (<4,>=3.3.2)", "sqlparse (>=0.2.2)"] } },
    };
  }

  it("poetry.lock: `poetry update certifi`; idna blocked by requests 2.25.0 (whose 2.34.2 admits it); sqlparse held by the project's Python", async () => {
    pythonRegistry();
    write("pyproject.toml", '[tool.poetry]\nname = "x"\nversion = "0.1.0"\n\n[tool.poetry.dependencies]\npython = "^3.8"\nrequests = "2.25.0"\nDjango = "3.2"\n');
    write("poetry.lock", [
      '[[package]]\nname = "requests"\nversion = "2.25.0"\ndescription = ""\noptional = false\npython-versions = ">=3.6"\n\n[package.dependencies]\ncertifi = ">=2017.4.17"\nidna = ">=2.5,<3"\n',
      '[[package]]\nname = "django"\nversion = "3.2"\ndescription = ""\noptional = false\npython-versions = ">=3.6"\n\n[package.dependencies]\nsqlparse = ">=0.2.2"\n',
      '[[package]]\nname = "certifi"\nversion = "2020.12.5"\ndescription = ""\noptional = false\npython-versions = "*"\n',
      '[[package]]\nname = "idna"\nversion = "2.10"\ndescription = ""\noptional = false\npython-versions = "*"\n',
      '[[package]]\nname = "sqlparse"\nversion = "0.4.1"\ndescription = ""\noptional = false\npython-versions = ">=3.5"\n',
      '[metadata]\nlock-version = "2.0"\npython-versions = "^3.8"\ncontent-hash = "x"\n',
    ].join("\n"));
    const { step } = await plan();
    expect(step("certifi")).toMatchObject({ action: "lockfile_refresh", scope: "transitive", refreshCommands: [{ dir: ".", command: "poetry update certifi" }] });
    expect(step("certifi").reasons.join(" ")).toMatch(/every parent's declared requirement already admits 2023\.7\.22 \(requests 2\.25\.0 requires certifi ">=2017\.4\.17"\) \(a refresh resolves it to 2026\.10\.23\)/);
    expect(step("idna")).toMatchObject({ action: "waiting_on_upstream" });
    expect(step("idna").refreshCommands).toBeUndefined();
    expect(step("idna").reasons.join(" ")).toMatch(
      /blocked upstream: requests 2\.25\.0 requires idna ">=2\.5,<3", which excludes idna 3\.7, so a lockfile refresh cannot reach it: requests has to move first \(requests 2\.34\.2, its newest release, requires idna "<4,>=2\.5", which admits 3\.7\)/,
    );
    expect(step("sqlparse").reasons.join(" ")).toMatch(/held back by the project's Python support: every parent admits sqlparse 0\.6\.0 \(django 3\.2 requires sqlparse ">=0\.2\.2"\), but 0\.6\.0 requires Python ">=3\.10"/);
    expect(step("sqlparse").refreshCommands).toBeUndefined();
    // The scan says each one the same way.
    const concise = await scan();
    expect(lineFor(concise, "certifi", "2020.12.5")).toMatch(/^Refresh certifi 2020\.12\.5 → 2023\.7\.22 in \. with a lockfile refresh — .*`poetry update certifi` in \./);
    expect(lineFor(concise, "idna", "2.10")).toMatch(/^Waiting on upstream: idna 2\.10 .*requests has to move first/);
  });

  it("uv.lock: the parents' requirements come from PyPI; `uv lock --upgrade-package certifi`", async () => {
    pythonRegistry();
    write("pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\nrequires-python = ">=3.8"\ndependencies = ["requests==2.25.0"]\n');
    write("uv.lock", [
      'version = 1\nrequires-python = ">=3.8"\n',
      '[[package]]\nname = "certifi"\nversion = "2020.12.5"\nsource = { registry = "https://pypi.org/simple" }\n',
      '[[package]]\nname = "idna"\nversion = "2.10"\nsource = { registry = "https://pypi.org/simple" }\n',
      '[[package]]\nname = "requests"\nversion = "2.25.0"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "certifi" },\n    { name = "idna" },\n]\n',
      '[[package]]\nname = "x"\nversion = "0.1.0"\nsource = { virtual = "." }\ndependencies = [\n    { name = "requests" },\n]\n\n[package.metadata]\nrequires-dist = [{ name = "requests", specifier = "==2.25.0" }]\n',
    ].join("\n"));
    const { step } = await plan();
    expect(step("certifi")).toMatchObject({ action: "lockfile_refresh", refreshCommands: [{ dir: ".", command: "uv lock --upgrade-package certifi" }] });
    expect(step("idna").reasons.join(" ")).toMatch(/blocked upstream: requests 2\.25\.0 requires idna "<3,>=2\.5"/);
  });

  it("a requirement that cannot be read leaves the conservative label (no refresh on a guess)", async () => {
    pythonRegistry();
    delete PYPI.requests["2.25.0"];
    write("pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\nrequires-python = ">=3.8"\ndependencies = ["requests==2.25.0"]\n');
    write("uv.lock", [
      'version = 1\nrequires-python = ">=3.8"\n',
      '[[package]]\nname = "certifi"\nversion = "2020.12.5"\nsource = { registry = "https://pypi.org/simple" }\n',
      '[[package]]\nname = "requests"\nversion = "2.25.0"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "certifi" },\n]\n',
    ].join("\n"));
    const { step } = await plan();
    expect(step("certifi")).toMatchObject({ action: "waiting_on_upstream" });
    expect(step("certifi").refreshCommands).toBeUndefined();
  });

  /** uv.lock for a project on requests 2.25.0, with an optional [manifest] table. */
  function uvLock(manifest = "") {
    write("pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\nrequires-python = ">=3.8"\ndependencies = ["requests==2.25.0"]\n');
    write("uv.lock", [
      'version = 1\nrequires-python = ">=3.8"\n',
      ...(manifest ? [manifest] : []),
      '[[package]]\nname = "certifi"\nversion = "2020.12.5"\nsource = { registry = "https://pypi.org/simple" }\n',
      '[[package]]\nname = "requests"\nversion = "2.25.0"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "certifi" },\n]\n',
    ].join("\n"));
  }

  it("a uv [manifest] constraint on the package decides what a refresh reaches: no refresh is claimed from the parents", async () => {
    pythonRegistry();
    uvLock('[manifest]\nconstraints = [{ name = "certifi", specifier = "<2023" }]\n');
    const { step } = await plan();
    expect(step("certifi").action).not.toBe("lockfile_refresh");
    expect(JSON.stringify(step("certifi"))).not.toMatch(/uv lock --upgrade-package certifi/);
  });

  it("a [manifest] entry for another package changes nothing", async () => {
    pythonRegistry();
    uvLock('[manifest]\noverrides = [{ name = "urllib3", specifier = "<2" }]\n');
    const { step } = await plan();
    expect(step("certifi")).toMatchObject({ action: "lockfile_refresh" });
  });

  it("marker-gated requirements that disagree on the fix decide nothing (requires_dist)", async () => {
    pythonRegistry();
    // On Python >= 3.8 requests would exclude the fix; on older ones it admits it.
    PYPI.requests["2.25.0"].requiresDist = ['certifi>=2017.4.17 ; python_version < "3.8"', 'certifi<2023 ; python_version >= "3.8"'];
    uvLock();
    const { step } = await plan();
    expect(step("certifi").action).not.toBe("lockfile_refresh");
    expect(step("certifi").refreshCommands).toBeUndefined();
    expect(step("certifi").reasons.join(" ")).not.toMatch(/blocked upstream/);
  });

  it("marker-gated requirements that all admit the fix are still a refresh", async () => {
    pythonRegistry();
    PYPI.requests["2.25.0"].requiresDist = ['certifi>=2017.4.17 ; python_version < "3.8"', 'certifi>=2020 ; python_version >= "3.8"'];
    uvLock();
    const { step } = await plan();
    expect(step("certifi")).toMatchObject({ action: "lockfile_refresh" });
  });

  it("a poetry.lock array of marker-gated requirements that disagree decides nothing", async () => {
    pythonRegistry();
    write("pyproject.toml", '[tool.poetry]\nname = "x"\nversion = "0.1.0"\n\n[tool.poetry.dependencies]\npython = "^3.8"\nrequests = "2.25.0"\n');
    write("poetry.lock", [
      '[[package]]\nname = "requests"\nversion = "2.25.0"\ndescription = ""\noptional = false\npython-versions = ">=3.6"\n\n[package.dependencies]\ncertifi = [\n    {version = ">=2017.4.17", markers = "python_version < \\"3.8\\""},\n    {version = "<2023", markers = "python_version >= \\"3.8\\""},\n]\n',
      '[[package]]\nname = "certifi"\nversion = "2020.12.5"\ndescription = ""\noptional = false\npython-versions = "*"\n',
      '[metadata]\nlock-version = "2.0"\npython-versions = "^3.8"\ncontent-hash = "x"\n',
    ].join("\n"));
    const { step } = await plan();
    expect(step("certifi").action).not.toBe("lockfile_refresh");
    expect(JSON.stringify(step("certifi"))).not.toMatch(/poetry update certifi/);
  });
});

describe("review fixes: the version a verdict names is the checked one", () => {
  it("a transitive copy whose fix-path check did not finish names the checked target (lodash 4.18.1), never the withdrawn advisory fix (4.18.0)", async () => {
    const { formatScanResult } = await import("../tools/vulnerability-scan-format.js");
    const { TRANSITIVE_PENDING } = await import("../tools/fix-verdicts.js");
    const vuln = {
      package: "lodash", currentVersion: "4.17.20", ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: true,
      vulnId: "GHSA-35jh-r3h4-6jhm", aliases: [], severity: "high", cvssScore: 7.2, summary: "lodash", fixedVersion: "4.18.0",
      published: "2026-01-01T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: [dir],
    } as unknown as VulnerabilityEntry;
    const result = {
      scannedAt: new Date().toISOString(), projectPath: dir, ecosystemsScanned: ["npm"], totalScanned: 1, totalVulnerable: 1,
      platformInactiveVulnerable: 0, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 }, vulnerabilities: [vuln],
      cleanCount: 0, scanDurationMs: 1, cached: false, offline: false,
    } as unknown as VulnerabilityScanResult;
    const key = ["npm", "lodash", "4.17.20"].join("\u0000");
    // The target check finished: 4.18.0 is withdrawn, 4.18.1 the target.
    const clean = { target: "4.18.1", basis: "registry", floor: "4.18.0", floorAffectedBy: [], stillAffectedBy: [], unfixable: [], withheld: ["4.18.0"], withheldWhy: { "4.18.0": '4.18.0 is deprecated on npm ("Bad release")' } };
    // The planner's fix-path check did not: its step still holds the raw highest advisory fix.
    const pending = {
      package: "lodash", ecosystem: "npm", currentVersion: "4.17.20", targetVersion: "4.18.0", upgradeType: "minor", reasons: [TRANSITIVE_PENDING],
      breaking: false, scope: "transitive", action: "waiting_on_upstream", fixPathChecked: "installed_advisories_only",
    };
    const out = formatScanResult(result, undefined, {
      resolution: null, reResolvedThisCall: false, drift: [], includeDev: true,
      verifiedTargets: new Map([[key, clean as never]]), verdicts: new Map([[key, pending as never]]),
    });
    const line = out.recommendations.find((r: string) => r.includes("lodash 4.17.20"))!;
    expect(line).toMatch(/4\.18\.1 would resolve 1 CVE/);
    expect(line).not.toMatch(/4\.18\.0 would resolve/);
    expect(out.fix_targets["lodash@4.17.20"].target).toBe("4.18.1");
  });
});

describe("5. Go transitive modules: `go get module@v`, then `go mod tidy` (no requirement sets an upper bound)", () => {
  function goProject(extra = "") {
    write("go.mod", `module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n\nrequire (\n\tgolang.org/x/text v0.3.0 // indirect\n)\n${extra}`);
    write("go.sum", "github.com/gin-gonic/gin v1.9.1 h1:a=\ngithub.com/gin-gonic/gin v1.9.1/go.mod h1:b=\ngolang.org/x/text v0.3.0 h1:c=\ngolang.org/x/text v0.3.0/go.mod h1:d=\n");
    ADVISORIES["golang.org/x/text"] = [adv("GO-2021-0113", "golang.org/x/text", fixedIn("0.3.7"), "Go")];
    GO["golang.org/x/text"] = ["v0.3.0", "v0.3.7", "v0.3.8"];
    GO["github.com/gin-gonic/gin"] = ["v1.9.1"];
  }

  it("an indirect module is raised in go.mod with no parent moving", async () => {
    goProject();
    const { step } = await plan();
    const text = step("golang.org/x/text");
    expect(text).toMatchObject({ action: "lockfile_refresh", scope: "transitive", targetVersion: "v0.3.7", refreshCommands: [{ dir: ".", command: "go get golang.org/x/text@v0.3.7" }, { dir: ".", command: "go mod tidy" }] });
    // Two commands, never joined with `&&` (not a statement separator in Windows PowerShell 5.1).
    expect(JSON.stringify(text)).not.toMatch(/&&/);
    const concise = await scan();
    expect(lineFor(concise, "golang.org/x/text", "v0.3.0")).toMatch(/^Refresh golang\.org\/x\/text v0\.3\.0 → v0\.3\.7 .*`go get golang\.org\/x\/text@v0\.3\.7`, then `go mod tidy` in \./);
    const detailed = await scan("detailed");
    expect(detailed.fix_targets["golang.org/x/text@v0.3.0"].commands).toEqual([{ dir: ".", command: "go get golang.org/x/text@v0.3.7" }, { dir: ".", command: "go mod tidy" }]);
  });

  it("a fix that needs a newer Go says so (x/text v0.41.0 requires go >= 1.25.0)", async () => {
    goProject();
    GOMOD["golang.org/x/text@v0.3.7"] = "1.25.0";
    const { step } = await plan();
    expect(step("golang.org/x/text").reasons.join(" ")).toMatch(
      "golang.org/x/text v0.3.7 requires go >= 1.25.0 and go.mod says go 1.21, so go get also raises the go directive to 1.25.0 (a Go older than 1.25.0 with GOTOOLCHAIN=local refuses it: install Go 1.25.0 or later first)",
    );
  });

  it("a fix that needs no newer Go says nothing about the go directive", async () => {
    goProject();
    GOMOD["golang.org/x/text@v0.3.7"] = "1.17";
    const { step } = await plan();
    expect(step("golang.org/x/text").reasons.join(" ")).not.toMatch(/go directive/);
  });

  it("a module go.mod replaces is not raised that way", async () => {
    goProject("\nreplace golang.org/x/text => golang.org/x/text v0.3.0\n");
    const { step } = await plan();
    const text = step("golang.org/x/text");
    expect(text).toBeDefined();
    expect(text.action).not.toBe("lockfile_refresh");
    expect(JSON.stringify(text)).not.toMatch(/go get golang\.org\/x\/text/);
  });
});

// ---------------------------------------------------------------------------
// 6: the audit's two false parent claims, on the scan side too
// ---------------------------------------------------------------------------

describe("6. M7 regressions on the scan: the two false 'upgrade the parent' claims say the planner's refresh", () => {
  it("navcal: glob through sucrase through tailwindcss is `npm update sucrase`, no tailwindcss upgrade", async () => {
    ADVISORIES.glob = [adv("GHSA-3g3m-2fjr-6pw4", "glob", fixedIn("11.1.0"))];
    NPM.glob = { latest: "11.1.0", versions: { "10.3.10": {}, "10.5.0": {}, "11.0.0": {}, "11.1.0": {} } };
    NPM.tinyglobby = { latest: "0.2.15", versions: { "0.2.11": {}, "0.2.15": {} } }; // sucrase 3.35.1 narrowly ranges it (round 8, B6)
    NPM.sucrase = { latest: "3.35.1", versions: { "3.35.0": { dependencies: { glob: "^10.3.10" } }, "3.35.1": { dependencies: { tinyglobby: "^0.2.11" } } } };
    NPM.tailwindcss = { latest: "3.4.19", versions: { "3.4.18": { dependencies: { sucrase: "^3.35.0" } }, "3.4.19": { dependencies: { sucrase: "^3.35.1" } } } };
    npmProject({ tailwindcss: "^3.4.1" }, {
      tailwindcss: { version: "3.4.18", dependencies: { sucrase: "^3.35.0" } },
      sucrase: { version: "3.35.0", dependencies: { glob: "^10.3.10" } },
      glob: { version: "10.5.0" },
    });
    const concise = await scan();
    const line = lineFor(concise, "glob", "10.5.0")!;
    expect(line).toMatch(/^Refresh glob 10\.5\.0 → 11\.1\.0 in \. with a lockfile refresh — .*`npm update sucrase` in \./);
    expect(line).not.toMatch(/tailwindcss 3\.4\.19|upgrade tailwindcss|npm install/);
  });

  it("victauri: @azure/msal-node through @azure/identity through @vscode/vsce is `npm update @azure/identity`", async () => {
    ADVISORIES["@azure/msal-node"] = [adv("GHSA-msal-0000-0001", "@azure/msal-node", fixedIn("7.1.0"))];
    NPM["@azure/msal-node"] = { latest: "7.2.1", versions: { "5.2.2": {}, "7.1.0": {}, "7.2.1": {} } };
    NPM["@azure/identity"] = { latest: "4.14.1", versions: { "4.13.1": { dependencies: { "@azure/msal-node": "^5.1.0" } }, "4.14.1": { dependencies: { "@azure/msal-node": "^7.1.0" } } } };
    NPM["@vscode/vsce"] = { latest: "4.0.0", versions: { "3.9.1": { dependencies: { "@azure/identity": "^4.1.0" } }, "4.0.0": { dependencies: { "@azure/identity": "^4.14.1" } } } };
    npmProject({ "@vscode/vsce": "^3.9.1" }, {
      "@vscode/vsce": { version: "3.9.1", dependencies: { "@azure/identity": "^4.1.0" } },
      "@azure/identity": { version: "4.13.1", dependencies: { "@azure/msal-node": "^5.1.0" } },
      "@azure/msal-node": { version: "5.2.2" },
    });
    const concise = await scan();
    const line = lineFor(concise, "@azure/msal-node", "5.2.2")!;
    expect(line).toMatch(/^Refresh @azure\/msal-node 5\.2\.2 → 7\.1\.0 .*`npm update @azure\/identity` in \./);
    expect(line).not.toMatch(/@vscode\/vsce 4\.0\.0|a major upgrade|npm install/);
    expect(concise.vulnerable_packages.find((p: { package: string }) => p.package === "@azure/msal-node")).toMatchObject({ fix_action: "lockfile_refresh" });
  });
});
