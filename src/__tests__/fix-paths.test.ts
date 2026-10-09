// SPDX-License-Identifier: Apache-2.0
/**
 * Fix-path correctness (fix-path oracle, 2026-10-10): each recommendation was
 * applied to a copy of a public repo, re-resolved and re-scanned.
 *
 * - openssl 0.10.38 was sent to 0.10.79, which GHSA-phqj-4mhp-q6mq affects
 *   (0.10.50 up to 0.10.80). The right target is 0.10.80.
 * - minimist 1.2.5 (npm), braces 3.0.2 (pnpm) and mio 0.8.0 (Cargo) were
 *   "waiting on upstream", but every parent's requirement already admitted
 *   the fix and a lockfile refresh fixed each one.
 *
 * The advisory ranges, version lists and parent requirements below are the
 * real ones (api.osv.dev, registry.npmjs.org, index.crates.io, 2026-10-10).
 */

import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { advisoryAffects, advisoryRanges, smallestCleanVersion } from "../live/osv-ranges.js";
import { extractFixedVersion } from "../live/osv-scanner.js";
import { cargoReqAdmits, npmRangeAdmits } from "../live/range-satisfies.js";
import { cargoPrecisePrerequisites, type CratesSparse, type FixPathSources } from "../live/fix-paths.js";
import { bunParents, cargoParents, packageLockParents, pnpmParents, yarnParents } from "../live/lockfile-parents.js";
import type { FourDADatabase } from "../db.js";
import type { OsvVulnerability, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";

type Ev = { introduced?: string; fixed?: string; last_affected?: string };
const adv = (eco: string, name: string, id: string, ...ranges: Ev[][]): OsvVulnerability => ({
  id,
  affected: [{ package: { name, ecosystem: eco }, ranges: ranges.map((events) => ({ type: "SEMVER", events })) }],
});
const r = (introduced: string, fixed: string): Ev[] => [{ introduced }, { fixed }];

const OPENSSL: OsvVulnerability[] = [
  ["GHSA-34p9-f4q3-c4r7", "0", "0.9.0"], ["GHSA-3gxf-9r58-2ghg", "0.9.7", "0.10.48"], ["GHSA-4fcv-w3qc-ppgg", "0.10.39", "0.10.72"],
  ["GHSA-6hcf-g6gr-hhcr", "0.9.7", "0.10.48"], ["GHSA-8c75-8mhr-p7r9", "0.10.24", "0.10.78"], ["GHSA-9qwg-crg9-m2vc", "0.9.7", "0.10.48"],
  ["GHSA-ghm9-cr32-g9qj", "0.10.39", "0.10.78"], ["GHSA-hppc-g8h3-xhp3", "0.9.24", "0.10.78"], ["GHSA-phqj-4mhp-q6mq", "0.10.50", "0.10.80"],
  ["GHSA-pqf5-4pqq-29f5", "0.9.27", "0.10.78"], ["GHSA-q445-7m23-qrmw", "0", "0.10.66"], ["GHSA-rpmj-rpgj-qmpm", "0.10.0", "0.10.70"],
  ["GHSA-xcf7-rvmh-g6q4", "0.10.0", "0.10.55"], ["GHSA-xjxc-vfw2-cg96", "0.10.8", "0.10.9"], ["GHSA-xmgf-hq76-4vx2", "0.9.0", "0.10.78"],
  ["GHSA-xp3w-r5p5-63rr", "0.9.7", "0.10.79"], ["GHSA-xphf-cx8h-7q9g", "0.10.29", "0.10.60"], ["GHSA-xv59-967r-8726", "0.10.0", "0.10.79"],
  ["RUSTSEC-2023-0044", "0.0.0-0", "0.10.55"], ["RUSTSEC-2025-0022", "0.10.39", "0.10.72"],
].map(([id, i, f]) => adv("crates.io", "openssl", id, r(i, f)));
const OPENSSL_VERSIONS = [
  ...Array.from({ length: 44 }, (_, i) => `0.10.${i}`).filter((v) => v !== "0.10.17"),
  ...Array.from({ length: 37 }, (_, i) => `0.10.${i + 45}`),
];

const MIO = [adv("crates.io", "mio", "GHSA-r8w9-5wcg-vfj7", r("0.7.2", "0.8.11")), adv("crates.io", "mio", "GHSA-pf3p-x6qj-6j7q", r("0.7.0", "0.7.6"))];
const MIO_VERSIONS = Array.from({ length: 12 }, (_, i) => `0.8.${i}`);
const MINIMIST = [
  adv("npm", "minimist", "GHSA-vh95-rmgr-6w4m", r("0", "0.2.1"), r("1.0.0", "1.2.3")),
  adv("npm", "minimist", "GHSA-xvch-5gv4-984h", r("1.0.0", "1.2.6"), r("0", "0.2.4")),
];
const MINIMIST_VERSIONS = "0.0.10 0.1.0 0.2.0 0.2.4 1.0.0 1.1.0 1.2.0 1.2.3 1.2.4 1.2.5 1.2.6 1.2.7 1.2.8".split(" ");
const BRACES = [
  adv("npm", "braces", "GHSA-cwfw-4gq5-mrqx", r("2.2.0", "2.3.1")),
  adv("npm", "braces", "GHSA-grv7-fg5c-xmjg", r("0", "3.0.3")),
  adv("npm", "braces", "GHSA-vfj7-8cjw-p6xm", [{ introduced: "0" }, { last_affected: "3.0.3" }]),
];
const BRACES_VERSIONS = "2.3.1 2.3.2 3.0.0 3.0.1 3.0.2 3.0.3".split(" ");

/** The per-advisory fixes the scanner computes for an installed version (each advisory's own line). */
const affecting = (vulns: OsvVulnerability[], name: string, eco: string, installed: string) =>
  vulns.filter((v) => advisoryAffects(advisoryRanges(v, name, eco)!, installed, eco));
const fixesFor = (vulns: OsvVulnerability[], name: string, eco: string, installed: string) =>
  affecting(vulns, name, eco, installed)
    .map((v) => extractFixedVersion(v.affected, name, eco, installed))
    .filter((f): f is string => f !== null);

describe("range satisfaction", () => {
  it.each([
    ["^1.2.5", "1.2.8", true], ["^1.2.0", "1.2.6", true], ["^1.2.5", "2.0.0", false], ["~3.0.2", "3.0.3", true],
    ["~3.0.2", "3.1.0", false], ["^0.2.3", "0.2.9", true], ["^0.2.3", "0.3.0", false], ["^0.0.3", "0.0.4", false],
    [">=1.0.0 <1.2.6", "1.2.6", false], [">= 1.0.0", "3.0.0", true], ["1.2.x", "1.2.9", true], ["1.x || >=3", "3.1.0", true],
    ["1.2.5", "1.2.6", false], ["*", "9.9.9", true], ["", "1.0.0", true], ["1.0.0 - 1.2", "1.2.9", true], ["1.0.0 - 1.2", "1.3.0", false],
    ["^1.2.0", "1.3.0-beta.1", false], ["npm:^1.2.0", "1.2.7", true],
  ])("npm %s admits %s: %s", (range, version, expected) => {
    expect(npmRangeAdmits(range, version)).toBe(expected);
  });

  it.each([["github:user/repo", "1.0.0"], ["file:../x", "1.0.0"], ["latest", "1.0.0"], ["npm:other@^1.0.0", "1.0.0"], ["workspace:*", "1.0.0"]])(
    "npm %s is not a registry range (null)",
    (range, version) => {
      expect(npmRangeAdmits(range, version)).toBeNull();
    },
  );

  it.each([
    ["^0.8.0", "0.8.11", true], ["0.8", "0.8.11", true], ["0.8.0", "0.9.0", false], ["^0.10.29", "0.10.80", true],
    ["=0.8.0", "0.8.11", false], [">=0.10, <0.11", "0.10.80", true], ["~1.2", "1.3.0", false], ["*", "2.0.0", true], ["1", "1.9.0", true],
  ])("cargo %s admits %s: %s", (req, version, expected) => {
    expect(cargoReqAdmits(req, version)).toBe(expected);
  });
});

describe("smallestCleanVersion — a target no fixable advisory affects", () => {
  it("openssl 0.10.38 goes to 0.10.80, not 0.10.79 (GHSA-phqj-4mhp-q6mq affects 0.10.50..<0.10.80)", () => {
    const fixes = fixesFor(OPENSSL, "openssl", "crates.io", "0.10.38");
    expect(fixes).toContain("0.10.79");
    const advisories = OPENSSL.map((v) => advisoryRanges(v, "openssl", "crates.io")!);
    const fromRegistry = smallestCleanVersion({ ecosystem: "crates.io", fixes, advisories, published: OPENSSL_VERSIONS });
    expect(fromRegistry).toMatchObject({ target: "0.10.80", floor: "0.10.79", basis: "registry", floorAffectedBy: ["GHSA-phqj-4mhp-q6mq"], stillAffectedBy: [] });
    // Without a version list, the advisories' own fix events are the candidates.
    const fromFixes = smallestCleanVersion({ ecosystem: "crates.io", fixes, advisories, published: null });
    expect(fromFixes).toMatchObject({ target: "0.10.80", basis: "advisory_fixes" });
  });

  it("braces: an advisory no release fixes does not disqualify 3.0.3, and is reported", () => {
    const advisories = BRACES.map((v) => advisoryRanges(v, "braces", "npm")!);
    const clean = smallestCleanVersion({ ecosystem: "npm", fixes: ["3.0.3"], advisories, published: BRACES_VERSIONS });
    expect(clean).toMatchObject({ target: "3.0.3", stillAffectedBy: ["GHSA-vfj7-8cjw-p6xm"], unfixable: ["GHSA-vfj7-8cjw-p6xm"] });
  });

  it("a target on the installed line wins over a later one", () => {
    const advisories = MINIMIST.map((v) => advisoryRanges(v, "minimist", "npm")!);
    expect(smallestCleanVersion({ ecosystem: "npm", fixes: ["1.2.6"], advisories, published: MINIMIST_VERSIONS })?.target).toBe("1.2.6");
  });
});

describe("lockfile parents and their declared requirements", () => {
  it("package-lock v2: minimist 1.2.5 is pulled by mkdirp (^1.2.5) and rc (^1.2.0)", () => {
    const lock = {
      packages: {
        "": { name: "proshop", dependencies: { mkdirp: "^0.5.5" } },
        "node_modules/minimist": { version: "1.2.5" },
        "node_modules/mkdirp": { version: "0.5.5", dependencies: { minimist: "^1.2.5" } },
        "node_modules/rc": { version: "1.2.8", dependencies: { minimist: "^1.2.0" } },
        "node_modules/optimist": { version: "0.6.1", dependencies: { minimist: "~0.0.1" } },
        "node_modules/optimist/node_modules/minimist": { version: "0.0.10" },
      },
    };
    expect(packageLockParents(lock, "minimist", "1.2.5")).toEqual([
      { parent: "mkdirp", parentVersion: "0.5.5", range: "^1.2.5", local: false },
      { parent: "rc", parentVersion: "1.2.8", range: "^1.2.0", local: false },
    ]);
    expect(packageLockParents(lock, "minimist", "0.0.10")).toEqual([{ parent: "optimist", parentVersion: "0.6.1", range: "~0.0.1", local: false }]);
  });

  it("package-lock v1: requires + nested dependencies", () => {
    const lock = {
      dependencies: {
        minimist: { version: "1.2.5" },
        mkdirp: { version: "0.5.5", requires: { minimist: "^1.2.5" } },
      },
    };
    expect(packageLockParents(lock, "minimist", "1.2.5")).toEqual([{ parent: "mkdirp", parentVersion: "0.5.5", range: "^1.2.5", local: false }]);
  });

  it("pnpm v6: braces 3.0.2 is pulled by chokidar and micromatch; the lockfile records no range", () => {
    const lock = [
      "lockfileVersion: '6.0'",
      "",
      "packages:",
      "",
      "  /braces@3.0.2:",
      "    resolution: {integrity: sha512-x}",
      "",
      "  /chokidar@3.5.3:",
      "    dependencies:",
      "      anymatch: 3.1.3",
      "      braces: 3.0.2",
      "",
      "  /micromatch@4.0.5:",
      "    dependencies:",
      "      braces: 3.0.2",
      "      picomatch: 2.3.1",
      "",
    ].join("\n");
    expect(pnpmParents(lock, "braces", "3.0.2")).toEqual([
      { parent: "chokidar", parentVersion: "3.5.3", range: null, local: false },
      { parent: "micromatch", parentVersion: "4.0.5", range: null, local: false },
    ]);
  });

  it("Cargo.lock: mio 0.8.0 is pulled by tokio 1.17.0 (\"mio 0.8.0\" beside mio 0.7.14)", () => {
    const lock = [
      "[[package]]", 'name = "mio"', 'version = "0.7.14"', 'source = "registry+https://github.com/rust-lang/crates.io-index"', "",
      "[[package]]", 'name = "mio"', 'version = "0.8.0"', 'source = "registry+https://github.com/rust-lang/crates.io-index"', "",
      "[[package]]", 'name = "crossterm"', 'version = "0.22.1"', 'source = "registry+https://github.com/rust-lang/crates.io-index"', 'dependencies = [', ' "mio 0.7.14",', "]", "",
      "[[package]]", 'name = "tokio"', 'version = "1.17.0"', 'source = "registry+https://github.com/rust-lang/crates.io-index"', 'dependencies = [', ' "bytes",', ' "mio 0.8.0",', "]", "",
    ].join("\n");
    expect(cargoParents(lock, "mio", "0.8.0")).toEqual([{ parent: "tokio", parentVersion: "1.17.0", range: null, local: false }]);
  });

  it("yarn v1 and berry record each parent's range", () => {
    const v1 = [
      "# yarn lockfile v1", "",
      'braces@^3.0.2, braces@~3.0.2:', '  version "3.0.2"', "",
      "micromatch@^4.0.4:", '  version "4.0.5"', "  dependencies:", '    braces "^3.0.2"', '    picomatch "^2.3.1"', "",
    ].join("\n");
    expect(yarnParents(v1, "braces", "3.0.2")).toEqual([{ parent: "micromatch", parentVersion: "4.0.5", range: "^3.0.2", local: false }]);
    const berry = [
      "__metadata:", "  version: 6", "",
      '"braces@npm:^3.0.2, braces@npm:~3.0.2":', "  version: 3.0.2", "",
      '"chokidar@npm:^3.5.3":', "  version: 3.5.3", "  dependencies:", "    braces: ~3.0.2", "",
    ].join("\n");
    expect(yarnParents(berry, "braces", "3.0.2")).toEqual([{ parent: "chokidar", parentVersion: "3.5.3", range: "~3.0.2", local: false }]);
  });

  it("bun.lock records each parent's range", () => {
    const lock = {
      packages: {
        braces: ["braces@3.0.2", "", {}, "sha"],
        micromatch: ["micromatch@4.0.5", "", { dependencies: { braces: "^3.0.2" } }, "sha"],
      },
    };
    expect(bunParents(lock, "braces", "3.0.2")).toEqual([{ parent: "micromatch", parentVersion: "4.0.5", range: "^3.0.2", local: false }]);
  });
});

describe("cargo --precise prerequisites", () => {
  const lock = [
    ["nu", "0.1.0", null, ["openssl", "rstest"]],
    ["openssl", "0.10.38", "r", ["openssl-sys"]],
    ["openssl-sys", "0.9.72", "r", []],
    ["rstest", "0.12.0", "r", ["quote", "syn"]],
    ["quote", "1.0.15", "r", ["proc-macro2"]],
    ["proc-macro2", "1.0.36", "r", []],
    ["syn", "1.0.86", "r", ["quote", "proc-macro2"]],
  ]
    .map(([n, v, src, deps]) =>
      ["[[package]]", `name = "${n}"`, `version = "${v}"`, ...(src ? ['source = "registry+https://github.com/rust-lang/crates.io-index"'] : []),
        ...((deps as string[]).length ? ["dependencies = [", ...(deps as string[]).map((d) => ` "${d}",`), "]"] : []), ""].join("\n"))
    .join("\n");
  const sparseOf: Record<string, CratesSparse> = {
    openssl: { versions: ["0.10.38", "0.10.80"], reqs: { "0.10.80": { "openssl-sys": [{ req: "^0.9.117", optional: false }], "openssl-macros": [{ req: "^0.1.1", optional: false }], foreign: [{ req: "^0.3", optional: true }] } } },
    "openssl-sys": { versions: ["0.9.72", "0.9.117"], reqs: { "0.9.117": {} } },
    "openssl-macros": { versions: ["0.1.1"], reqs: { "0.1.1": { syn: [{ req: "^2", optional: false }], quote: [{ req: "^1", optional: false }] } } },
    syn: { versions: ["1.0.86", "2.0.119"], reqs: { "2.0.119": { quote: [{ req: "^1.0.35", optional: false }], "proc-macro2": [{ req: "^1.0.91", optional: false }] } } },
    quote: { versions: ["1.0.15", "1.0.47"], reqs: {} },
    "proc-macro2": { versions: ["1.0.36", "1.0.106"], reqs: {} },
  };
  const sources = { cratesSparse: async (name: string) => sparseOf[name] ?? null } as unknown as FixPathSources;

  it("names the locked crates outside openssl's own tree that 0.10.80 needs newer (nushell, 2026-10-10)", async () => {
    // openssl-sys moves with openssl (its own tree); quote and proc-macro2 are rstest's, so cargo keeps them.
    expect(await cargoPrecisePrerequisites(sources, lock, "openssl", "0.10.38", "0.10.80")).toEqual(["proc-macro2@1.0.36", "quote@1.0.15"]);
  });

  it("needs nothing when every requirement is already met", async () => {
    const plain = { cratesSparse: async () => ({ versions: ["0.8.11"], reqs: { "0.8.11": {} } }) } as unknown as FixPathSources;
    expect(await cargoPrecisePrerequisites(plain, lock, "openssl", "0.10.38", "0.8.11")).toEqual([]);
  });

  it("is unknown (null) when a registry record is missing", async () => {
    const none = { cratesSparse: async () => null } as unknown as FixPathSources;
    expect(await cargoPrecisePrerequisites(none, lock, "openssl", "0.10.38", "0.10.80")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// upgrade_planner end to end, over real lockfile shapes and a stubbed network
// ---------------------------------------------------------------------------

let root: string;
let npmDir: string;
let pnpmDir: string;
let cargoDir: string;
let pinnedDir: string;
let priorOffline: string | undefined;
const noDb = null as unknown as FourDADatabase;

function entry(over: Partial<VulnerabilityEntry>): VulnerabilityEntry {
  return {
    package: "x", currentVersion: "1.0.0", ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: true, vulnId: "GHSA-x",
    aliases: [], severity: "high", cvssScore: 7.5, summary: "advisory", fixedVersion: null, published: "2026-01-01T00:00:00Z",
    references: [], target: null, platformActive: true, sourceDirs: [], ...over,
  };
}

function entriesFor(vulns: OsvVulnerability[], name: string, eco: "npm" | "crates.io", installed: string, dir: string): VulnerabilityEntry[] {
  return affecting(vulns, name, eco, installed)
    .map((v) => entry({ package: name, ecosystem: eco, currentVersion: installed, vulnId: v.id, fixedVersion: extractFixedVersion(v.affected, name, eco, installed), sourceDirs: [dir] }));
}

const sparse = (versions: string[], reqs: Record<string, Record<string, string>> = {}) =>
  versions.map((vers) => JSON.stringify({ name: "x", vers, yanked: false, deps: Object.entries(reqs[vers] ?? {}).map(([name, req]) => ({ name, req, kind: "normal" })) })).join("\n");

function stubNetwork(): string[] {
  const calls: string[] = [];
  const advisories: Record<string, OsvVulnerability[]> = { openssl: OPENSSL, mio: MIO, minimist: MINIMIST, braces: BRACES, "left-pad": [] };
  const npmVersions: Record<string, string[]> = { minimist: MINIMIST_VERSIONS, braces: BRACES_VERSIONS };
  const npmDeps: Record<string, Record<string, string>> = { "chokidar/3.5.3": { braces: "~3.0.2" }, "micromatch/4.0.5": { braces: "^3.0.2" } };
  const crates: Record<string, string> = {
    "op/en/openssl": sparse(OPENSSL_VERSIONS),
    "3/m/mio": sparse(MIO_VERSIONS),
    "to/ki/tokio": sparse(["1.17.0"], { "1.17.0": { mio: "^0.8.0" } }),
    "na/ti/native-tls": sparse(["0.2.8"], { "0.2.8": { openssl: "^0.10.29" } }),
  };
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: advisories[q.package.name] ?? [] });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      if (npm[2]) return json({ dependencies: npmDeps[`${name}/${decodeURIComponent(npm[2])}`] ?? {} });
      return npmVersions[name] ? json({ versions: Object.fromEntries(npmVersions[name].map((v) => [v, {}])) }) : new Response("", { status: 404 });
    }
    const crate = /^https:\/\/index\.crates\.io\/(.+)$/.exec(url);
    if (crate && crates[crate[1]]) return new Response(crates[crate[1]], { status: 200 });
    return new Response("", { status: 404 });
  });
  return calls;
}

function intel(dir: string, language: string, deps: string[], scanEntries: VulnerabilityEntry[]): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  li.initFromDependencyGroups([{ dir, language, deps, devDeps: [] }]);
  const scan: VulnerabilityScanResult = {
    scannedAt: new Date().toISOString(), projectPath: dir, ecosystemsScanned: [], totalScanned: 20,
    totalVulnerable: new Set(scanEntries.map((e) => e.package)).size, platformInactiveVulnerable: 0,
    bySeverity: { critical: 0, high: scanEntries.length, medium: 0, low: 0, unknown: 0 }, vulnerabilities: scanEntries,
    cleanCount: 10, scanDurationMs: 1, cached: false, offline: false,
  };
  (li as unknown as { lastVulnScan: VulnerabilityScanResult }).lastVulnScan = scan;
  (li as unknown as { lastVulnScanIncludesDev: boolean }).lastVulnScanIncludesDev = true;
  return li;
}

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-fix-paths-"));
  npmDir = path.join(root, "proshop");
  pnpmDir = path.join(root, "taxonomy");
  cargoDir = path.join(root, "nushell");
  pinnedDir = path.join(root, "pinned");
  for (const d of [npmDir, pnpmDir, cargoDir, pinnedDir]) fs.mkdirSync(d);
  fs.writeFileSync(path.join(npmDir, "package.json"), JSON.stringify({ dependencies: { mkdirp: "^0.5.5" } }));
  fs.writeFileSync(
    path.join(npmDir, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 2,
      packages: {
        "": { dependencies: { mkdirp: "^0.5.5" } },
        "node_modules/minimist": { version: "1.2.5" },
        "node_modules/mkdirp": { version: "0.5.5", dependencies: { minimist: "^1.2.5" } },
        "node_modules/rc": { version: "1.2.8", dependencies: { minimist: "^1.2.0" } },
      },
    }),
  );
  fs.writeFileSync(path.join(pnpmDir, "package.json"), JSON.stringify({ dependencies: { chokidar: "^3.5.3" } }));
  fs.writeFileSync(
    path.join(pnpmDir, "pnpm-lock.yaml"),
    [
      "lockfileVersion: '6.0'", "", "dependencies:", "  chokidar:", "    specifier: ^3.5.3", "    version: 3.5.3", "", "packages:", "",
      "  /braces@3.0.2:", "    resolution: {integrity: sha512-x}", "",
      "  /chokidar@3.5.3:", "    dependencies:", "      braces: 3.0.2", "",
      "  /micromatch@4.0.5:", "    dependencies:", "      braces: 3.0.2", "",
    ].join("\n"),
  );
  const pkg = (name: string, version: string, deps: string[] = [], local = false) =>
    ["[[package]]", `name = "${name}"`, `version = "${version}"`, ...(local ? [] : ['source = "registry+https://github.com/rust-lang/crates.io-index"']),
      ...(deps.length ? ["dependencies = [", ...deps.map((d) => ` "${d}",`), "]"] : []), ""].join("\n");
  fs.writeFileSync(path.join(cargoDir, "Cargo.toml"), '[package]\nname = "nu"\nversion = "0.1.0"\n\n[dependencies]\ntokio = "1"\nnative-tls = "0.2"\n');
  fs.writeFileSync(
    path.join(cargoDir, "Cargo.lock"),
    [
      pkg("nu", "0.1.0", ["native-tls", "tokio"], true), pkg("mio", "0.7.14"), pkg("mio", "0.8.0"), pkg("crossterm", "0.22.1", ["mio 0.7.14"]),
      pkg("tokio", "1.17.0", ["mio 0.8.0"]), pkg("native-tls", "0.2.8", ["openssl"]), pkg("openssl", "0.10.38"),
    ].join("\n"),
  );
  // A parent that pins the vulnerable version exactly: a refresh cannot help.
  fs.writeFileSync(path.join(pinnedDir, "package.json"), JSON.stringify({ dependencies: { "left-pad": "1.0.0" } }));
  fs.writeFileSync(
    path.join(pinnedDir, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { "left-pad": "1.0.0" } },
        "node_modules/left-pad": { version: "1.0.0", dependencies: { minimist: "1.2.5" } },
        "node_modules/minimist": { version: "1.2.5" },
      },
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(root, { recursive: true, force: true });
});

describe("upgrade_planner — fix paths are verified against every advisory and the parents' requirements", () => {
  it("npm: minimist 1.2.5 is a lockfile refresh (mkdirp ^1.2.5, rc ^1.2.0 admit 1.2.8), not waiting on upstream", async () => {
    stubNetwork();
    const li = intel(npmDir, "javascript", ["mkdirp"], entriesFor(MINIMIST, "minimist", "npm", "1.2.5", npmDir));
    const plan = (await executeUpgradePlanner(noDb, { include_dev: true }, li)) as Record<string, any>;
    const step = plan.recommendations.find((s: { package: string }) => s.package === "minimist");
    expect(step).toMatchObject({ targetVersion: "1.2.6", action: "lockfile_refresh", fixPathChecked: "all_advisories", refreshCommands: [{ command: "npm update minimist" }] });
    expect(step.reasons.join(" ")).toMatch(/a refresh resolves it to 1\.2\.8/);
    expect(plan.lockfileRefreshes).toBe(1);
    expect(plan.waitingOnUpstream).toBe(0);
    expect(plan.summary).toMatch(/fixed by a lockfile refresh/);
  });

  it("pnpm: braces 3.0.2 is a lockfile refresh (chokidar ~3.0.2 and micromatch ^3.0.2 from the registry); the unfixable advisory is reported", async () => {
    const calls = stubNetwork();
    const li = intel(pnpmDir, "javascript", ["chokidar"], entriesFor(BRACES, "braces", "npm", "3.0.2", pnpmDir));
    const plan = (await executeUpgradePlanner(noDb, { include_dev: true }, li)) as Record<string, any>;
    const step = plan.recommendations.find((s: { package: string }) => s.package === "braces");
    expect(step).toMatchObject({ targetVersion: "3.0.3", action: "lockfile_refresh", refreshCommands: [{ command: "pnpm update braces" }] });
    expect(step.reasons.join(" ")).toMatch(/GHSA-vfj7-8cjw-p6xm also affects 3\.0\.3 and every newer release/);
    expect(calls).toContain("https://registry.npmjs.org/chokidar/3.5.3");
    expect(calls).toContain("https://registry.npmjs.org/micromatch/4.0.5");
  });

  it("Cargo: openssl 0.10.38 targets 0.10.80 (not the affected 0.10.79) and mio 0.8.0 is a precise cargo update", async () => {
    stubNetwork();
    const li = intel(cargoDir, "rust", ["tokio", "native-tls"], [
      ...entriesFor(OPENSSL, "openssl", "crates.io", "0.10.38", cargoDir),
      ...entriesFor(MIO, "mio", "crates.io", "0.8.0", cargoDir),
    ]);
    const plan = (await executeUpgradePlanner(noDb, { include_dev: true, max_recommendations: 50 }, li)) as Record<string, any>;
    const openssl = plan.recommendations.find((s: { package: string }) => s.package === "openssl");
    expect(openssl).toMatchObject({
      targetVersion: "0.10.80",
      action: "lockfile_refresh",
      refreshCommands: [{ command: "cargo update -p openssl@0.10.38 --precise 0.10.80" }],
    });
    expect(openssl.reasons.join(" ")).toMatch(/0\.10\.79, the highest per-advisory fix, is itself affected by GHSA-phqj-4mhp-q6mq/);
    const mio = plan.recommendations.find((s: { package: string }) => s.package === "mio");
    expect(mio).toMatchObject({ targetVersion: "0.8.11", action: "lockfile_refresh", refreshCommands: [{ command: "cargo update -p mio@0.8.0 --precise 0.8.11" }] });
  });

  it("a parent that pins the vulnerable version keeps waiting on upstream, and says which requirement blocks", async () => {
    stubNetwork();
    const li = intel(pinnedDir, "javascript", ["left-pad"], entriesFor(MINIMIST, "minimist", "npm", "1.2.5", pinnedDir));
    const plan = (await executeUpgradePlanner(noDb, { include_dev: true }, li)) as Record<string, any>;
    const step = plan.recommendations.find((s: { package: string }) => s.package === "minimist");
    expect(step.action).toBe("waiting_on_upstream");
    expect(step.reasons.join(" ")).toMatch(/left-pad 1\.0\.0 requires "1\.2\.5"/);
  });

  it("when OSV cannot be read, the target is labelled unverified instead of being trusted silently", async () => {
    vi.stubGlobal("fetch", async () => new Response("", { status: 503 }));
    const li = intel(cargoDir, "rust", ["tokio", "native-tls"], entriesFor(OPENSSL, "openssl", "crates.io", "0.10.38", cargoDir));
    const plan = (await executeUpgradePlanner(noDb, { include_dev: true }, li)) as Record<string, any>;
    const openssl = plan.recommendations.find((s: { package: string }) => s.package === "openssl");
    expect(openssl).toMatchObject({ targetVersion: "0.10.79", action: "waiting_on_upstream", fixPathChecked: "installed_advisories_only" });
    expect(plan.summary).toMatch(/checked only against the installed version's advisories/);
  });
});
