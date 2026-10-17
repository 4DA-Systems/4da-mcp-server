// SPDX-License-Identifier: Apache-2.0
/**
 * FX-H5 (4DA #976): never recommend a release its registry withdrew, with the
 * app's rule for what "withdrawn" means (live/withdrawn-releases.ts):
 * - the target walk skips excluded releases as it skips prereleases, and
 *   names the ones it passed (`withheld`);
 * - every way out withdrawn: no target, "No installable fix", never a
 *   withdrawn version, and that holds for an advisory's own line fix too;
 * - crates.io / PyPI yanked; npm deprecated only when a later, non-deprecated
 *   stable release is on the same caret line, and nothing when `latest` is
 *   deprecated (glob deprecates 160 of 168 versions: excluding them all sent
 *   glob 10.4.5 to 12.0.0);
 * - a registry that cannot be read leaves the old answer and says so.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { LiveCache } from "../live/cache.js";
import type { OsvVulnerability } from "../live/types.js";
import { installableFix, smallestCleanVersion, type AdvisoryRanges } from "../live/osv-ranges.js";
import { npmExcludedVersions, sayWithdrawn } from "../live/withdrawn-releases.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

// ---------------------------------------------------------------------------
// The npm rule
// ---------------------------------------------------------------------------

describe("which npm deprecations withdraw a release (the app's caret-line rule)", () => {
  const GLOB_NOTICE = "Old versions of glob are not supported, and contain widely publicized security vulnerabilities";

  it("lodash: 4.18.0 'Bad release' is withdrawn, because 4.18.1 is clean on 4.x", () => {
    expect(npmExcludedVersions({ "4.17.21": undefined, "4.18.0": "Bad release. Please use lodash@4.17.21 instead.", "4.18.1": undefined }, "4.18.1")).toEqual(["4.18.0"]);
  });

  it("glob: a whole-major notice withdraws nothing on 10.x, even with a clean 12.x", () => {
    const versions: Record<string, unknown> = { "10.4.5": GLOB_NOTICE, "10.5.0": GLOB_NOTICE, "11.0.0": GLOB_NOTICE, "12.0.0": undefined, "13.0.6": undefined };
    expect(npmExcludedVersions(versions, "13.0.6")).toEqual([]);
  });

  it("tar: 7.x deprecations below the clean 7.5.8 are withdrawn, the 6.x line's are not", () => {
    const notice = "Old versions of tar are not supported";
    const versions: Record<string, unknown> = { "6.2.0": notice, "6.2.1": notice, "7.0.0": notice, "7.5.7": notice, "7.5.8": undefined, "7.5.9-beta.1": undefined };
    expect(npmExcludedVersions(versions, "7.5.8")).toEqual(["7.0.0", "7.5.7"]);
  });

  it("a deprecated latest (the package retired whole) withdraws nothing", () => {
    expect(npmExcludedVersions({ "1.0.0": "use x", "1.0.1": undefined, "1.0.2": "retired" }, "1.0.2")).toEqual([]);
  });

  it("0.x lines are per minor; a prerelease is not a clean successor; `deprecated: true` counts", () => {
    expect(npmExcludedVersions({ "0.3.1": true, "0.3.2": undefined, "0.4.0": undefined }, "0.4.0")).toEqual(["0.3.1"]);
    expect(npmExcludedVersions({ "0.3.2": true, "0.4.0": undefined }, "0.4.0")).toEqual([]);
    expect(npmExcludedVersions({ "2.0.0": "bad", "2.0.1-rc.1": undefined, "3.0.0": undefined }, "3.0.0")).toEqual([]);
    expect(npmExcludedVersions({ "2.0.0": "", "2.0.1": undefined }, "2.0.1")).toEqual([]);
  });

  it("releases with the same reason are named once", () => {
    const why = { "7.5.3": '7.5.3 is deprecated on npm ("old")', "7.5.4": '7.5.4 is deprecated on npm ("old")', "0.3.17": "0.3.17 is yanked on crates.io" };
    expect(sayWithdrawn(["7.5.3", "7.5.4"], why, "npm")).toBe('7.5.3 and 7.5.4 are deprecated on npm ("old")');
    expect(sayWithdrawn(["0.3.17"], why, "crates.io")).toBe("0.3.17 is yanked on crates.io");
  });
});

// ---------------------------------------------------------------------------
// The target walk
// ---------------------------------------------------------------------------

const span = (introduced: string, fixed: string | null, lastAffected: string | null = null) => ({ introduced, fixed, lastAffected });
const ranges = (id: string, ...spans: ReturnType<typeof span>[]): AdvisoryRanges => ({ id, spans, versions: [] });

describe("smallestCleanVersion with excluded releases", () => {
  it("steps over a withdrawn fix to the next clean release, and names it", () => {
    const clean = smallestCleanVersion({ ecosystem: "npm", fixes: ["4.18.0"], advisories: [ranges("A", span("0", "4.18.0"))], published: ["4.17.21", "4.18.0", "4.18.1"], excluded: ["4.18.0"] });
    expect(clean).toMatchObject({ target: "4.18.1", withheld: ["4.18.0"], stillAffectedBy: [] });
  });

  it("every way out withdrawn: no target, and withheld names the withdrawn release", () => {
    const clean = smallestCleanVersion({ ecosystem: "crates.io", fixes: ["0.3.17"], advisories: [ranges("RUSTSEC-2023-0034", span("0", "0.3.17"))], published: ["0.3.17"], excluded: ["0.3.17"] });
    expect(clean).toMatchObject({ target: null, withheld: ["0.3.17"] });
  });

  it("a withdrawn release above the target is not withheld (tar 7.x above 6.2.1)", () => {
    const clean = smallestCleanVersion({ ecosystem: "npm", fixes: ["6.2.1"], advisories: [ranges("A", span("0", "6.2.1"))], published: ["6.2.1", "7.0.0", "7.5.8"], excluded: ["7.0.0"] });
    expect(clean).toMatchObject({ target: "6.2.1", withheld: [] });
  });

  it("without registry facts nothing changes", () => {
    const clean = smallestCleanVersion({ ecosystem: "npm", fixes: ["4.18.0"], advisories: [ranges("A", span("0", "4.18.0"))], published: null });
    expect(clean).toMatchObject({ target: "4.18.0", withheld: [] });
  });

  it("a line fix the registry withdrew becomes the next release that fixes that advisory, or none", () => {
    const advisories = [ranges("A", span("0", "3.0.3"))];
    expect(installableFix({ ecosystem: "npm", fix: "3.0.3", advisories, published: ["3.0.3", "3.0.4"], excluded: ["3.0.3"] })).toEqual({ fix: "3.0.4", withheld: ["3.0.3"] });
    expect(installableFix({ ecosystem: "npm", fix: "3.0.3", advisories, published: ["3.0.3"], excluded: ["3.0.3"] })).toEqual({ fix: null, withheld: ["3.0.3"] });
    expect(installableFix({ ecosystem: "npm", fix: "3.0.4", advisories, published: ["3.0.4"], excluded: ["3.0.3"] })).toEqual({ fix: "3.0.4", withheld: [] });
  });
});

// ---------------------------------------------------------------------------
// Through the tools, on stubbed registries
// ---------------------------------------------------------------------------

const adv = (id: string, name: string, ecosystem: string, events: Array<Record<string, string>>): OsvVulnerability => ({
  id,
  summary: `${name} advisory`,
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name, ecosystem }, ranges: [{ type: "SEMVER", events }] }],
});

let ADVISORIES: Record<string, OsvVulnerability[]> = {};
let NPM: Record<string, { versions: Record<string, { deprecated?: string }>; latest: string }> = {};
let CRATES: Record<string, Array<{ vers: string; yanked: boolean }>> = {};
let DOWN: string[] = [];

const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
function affects(v: OsvVulnerability, version: string): boolean {
  const ev = v.affected![0].ranges[0].events;
  const fixed = ev.find((e) => e.fixed)?.fixed;
  return fixed ? cmp(version, fixed) < 0 : true;
}

beforeEach(() => {
  vi.stubEnv("FOURDA_OFFLINE", "false");
  ADVISORIES = {};
  NPM = {};
  CRATES = {};
  DOWN = [];
  // One package name per scenario would hide it; each test starts from an empty registry cache instead.
  new LiveCache(null).invalidateAll();
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (DOWN.some((host) => url.includes(host))) return json({ error: "down" }, 503);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (ADVISORIES[q.package.name] ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const found = Object.values(ADVISORIES).flat().find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      return json({ vulns: ADVISORIES[(JSON.parse(String(init?.body)) as { package: { name: string } }).package.name] ?? [] });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)$/.exec(url);
    if (npm) {
      const doc = NPM[decodeURIComponent(npm[1])];
      if (!doc) return json({}, 404);
      const time = Object.fromEntries(Object.keys(doc.versions).map((v) => [v, "2024-01-01T00:00:00.000Z"]));
      return json({ name: npm[1], "dist-tags": { latest: doc.latest }, versions: doc.versions, time: { created: "2020-01-01T00:00:00.000Z", ...time } });
    }
    const sparse = /^https:\/\/index\.crates\.io\/(?:\d|[^/]{2}\/[^/]{2}|\d\/[^/])\/(.+)$/.exec(url);
    if (sparse && CRATES[sparse[1]]) return new Response(CRATES[sparse[1]].map((r) => JSON.stringify({ name: sparse[1], vers: r.vers, deps: [], yanked: r.yanked })).join("\n"));
    return json({}, 404);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

function npmProject(deps: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-fxh5-"));
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: deps }));
  const packages: Record<string, unknown> = { "": { name: "x", dependencies: deps } };
  for (const [n, v] of Object.entries(deps)) packages[`node_modules/${n}`] = { version: v };
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
  return dir;
}

function cargoProject(name: string, version: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-fxh5-"));
  fs.writeFileSync(path.join(dir, "Cargo.toml"), `[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\n${name} = "=${version}"\n`);
  fs.writeFileSync(
    path.join(dir, "Cargo.lock"),
    `version = 3\n\n[[package]]\nname = "x"\nversion = "0.1.0"\ndependencies = [\n "${name}",\n]\n\n[[package]]\nname = "${name}"\nversion = "${version}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`,
  );
  return dir;
}

const live = () => new LiveIntelligence(new Database(":memory:"));
const scan = async (dir: string, detailed = false) =>
  (await executeVulnerabilityScan(null, { project_path: dir, ...(detailed ? { response_format: "detailed" } : {}) }, live())) as Record<string, any>;
const plan = async (dir: string) => ((await executeUpgradePlanner(noDb, { project_path: dir }, live())) as { recommendations: Array<Record<string, any>> }).recommendations;

const GLOB_NOTICE = "Old versions of glob are not supported, and contain widely publicized security vulnerabilities";
function globShaped() {
  ADVISORIES.glob = [adv("GHSA-5j98-mcp5-4vw2", "glob", "npm", [{ introduced: "10.3.7" }, { fixed: "10.5.0" }])];
  NPM.glob = {
    latest: "13.0.6",
    versions: { "10.4.5": { deprecated: GLOB_NOTICE }, "10.5.0": { deprecated: GLOB_NOTICE }, "11.0.0": { deprecated: GLOB_NOTICE }, "12.0.0": {}, "13.0.6": {} },
  };
}
function lodashShaped() {
  ADVISORIES.lodash = [adv("GHSA-f23m-r3pf-42rh", "lodash", "npm", [{ introduced: "0" }, { fixed: "4.18.0" }])];
  NPM.lodash = { latest: "4.18.1", versions: { "4.17.20": {}, "4.18.0": { deprecated: "Bad release. Please use lodash@4.17.21 instead." }, "4.18.1": {} } };
}

describe("vulnerability_scan and upgrade_planner never name a withdrawn release", () => {
  it("glob 10.4.5 -> 10.5.0, not 12.0.0: a whole-major deprecation notice is not a withdrawal", async () => {
    globShaped();
    const dir = npmProject({ glob: "10.4.5" });
    const result = await scan(dir);
    expect(result.vulnerable_packages[0]).toMatchObject({ package: "glob", fixed_version: "10.5.0", fix_checked: "all_advisories" });
    expect(result.recommendations[0]).toMatch(/^Upgrade glob 10\.4\.5 → 10\.5\.0/);
    expect((await plan(dir)).find((r) => r.package === "glob")).toMatchObject({ targetVersion: "10.5.0", upgradeType: "minor" });
  });

  it("lodash: each finding's own fix is 4.18.1, never the deprecated 4.18.0, and says why", async () => {
    lodashShaped();
    const dir = npmProject({ lodash: "4.17.20" });
    const detailed = await scan(dir, true);
    expect(detailed.vulnerabilities[0]).toMatchObject({
      fixed_version: "4.18.1",
      withheld: ["4.18.0"],
      withheld_note: '4.18.0 is deprecated on npm ("Bad release. Please use lodash@4.17.21 instead."); 4.18.1 is the smallest release past it that fixes this advisory',
    });
    expect(detailed.fix_targets["lodash@4.17.20"]).toMatchObject({
      target: "4.18.1",
      withheld: ["4.18.0"],
      withheld_note: '4.18.0 is deprecated on npm ("Bad release. Please use lodash@4.17.21 instead."); 4.18.1 is the smallest clean release',
    });
    expect(JSON.stringify(detailed)).not.toMatch(/"fixed_version":"4\.18\.0"|→ 4\.18\.0/);
    const step = (await plan(dir)).find((r) => r.package === "lodash")!;
    expect(step).toMatchObject({ targetVersion: "4.18.1", withheld: ["4.18.0"] });
    expect(step.reasons).toContain('4.18.0 is deprecated on npm ("Bad release. Please use lodash@4.17.21 instead."); 4.18.1 is the smallest clean release');
  });

  it("crates.io: yanked h2 0.3.17 is passed for 0.3.18, in the finding and the target", async () => {
    ADVISORIES.h2 = [adv("RUSTSEC-2023-0034", "h2", "crates.io", [{ introduced: "0" }, { fixed: "0.3.17" }])];
    CRATES.h2 = [{ vers: "0.3.16", yanked: false }, { vers: "0.3.17", yanked: true }, { vers: "0.3.18", yanked: false }];
    const dir = cargoProject("h2", "0.3.16");
    const detailed = await scan(dir, true);
    expect(detailed.vulnerabilities[0]).toMatchObject({ fixed_version: "0.3.18", withheld: ["0.3.17"] });
    expect(detailed.fix_targets["h2@0.3.16"]).toMatchObject({ target: "0.3.18", withheld: ["0.3.17"], withheld_note: "0.3.17 is yanked on crates.io; 0.3.18 is the smallest clean release" });
  });

  it("every fixing release withdrawn: no target, 'No installable fix', never the withdrawn version", async () => {
    ADVISORIES.h2 = [adv("RUSTSEC-2023-0034", "h2", "crates.io", [{ introduced: "0" }, { fixed: "0.3.17" }])];
    CRATES.h2 = [{ vers: "0.3.16", yanked: false }, { vers: "0.3.17", yanked: true }];
    const dir = cargoProject("h2", "0.3.16");
    const detailed = await scan(dir, true);
    expect(detailed.vulnerabilities[0]).toMatchObject({ fixed_version: null, withheld: ["0.3.17"] });
    expect(detailed.fix_targets["h2@0.3.16"]).toMatchObject({ target: null, withheld: ["0.3.17"] });
    expect(detailed.recommendations[0]).toMatch(/No installable fix: 0\.3\.17 is yanked on crates\.io, and no later release is known to clear it/);
    expect(detailed.recommendations[0]).not.toMatch(/no fix version published|→ 0\.3\.17/);
    const step = (await plan(dir)).find((r) => r.package === "h2")!;
    expect(step).toMatchObject({ targetVersion: null, action: "no_fix_available", withheld: ["0.3.17"] });
    expect(step.reasons.join("\n")).toMatch(/No installable fix: 0\.3\.17 is yanked on crates\.io/);
    expect(step.upgradeCommands).toBeUndefined();
  });

  it("registry down: the advisory data's answer stands, and the tools say the registry was not read", async () => {
    lodashShaped();
    DOWN = ["registry.npmjs.org"];
    const dir = npmProject({ lodash: "4.17.20" });
    const detailed = await scan(dir, true);
    expect(detailed.fix_targets["lodash@4.17.20"].note).toMatch(/registry could not be read, so whether it yanked or deprecated this release was not checked/);
    const step = (await plan(dir)).find((r) => r.package === "lodash")!;
    expect(step.reasons.join("\n")).toMatch(/registry could not be read: whether it yanked or deprecated this release was not checked/);
  });
});

describe("dependency_check's smallest and newest safe release", () => {
  const check = (items: unknown[]) => executeDependencyCheck(null, { items }, live()) as Promise<{ results: Array<Record<string, any>> }>;

  it("glob ^10.4.5 has a safe release, 10.5.0, judged review (a whole-line notice), not 'no safe release'", async () => {
    globShaped();
    const r = (await check([{ ecosystem: "npm", package: "glob", from: "10.4.5", to: "^10.4.5" }])).results[0];
    expect(r).toMatchObject({ to: "10.5.0", verdict: "review" });
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "10.5.0", smallest_safe_upgrade: "10.5.0" });
    expect(r.signals.find((s: { id: string }) => s.id === "yanked_or_deprecated")).toMatchObject({ effect: "review", value: { withdrawn: false } });
  });

  it("lodash ^4.17.20 names the withdrawn 4.18.0 it steps over", async () => {
    lodashShaped();
    const r = (await check([{ ecosystem: "npm", package: "lodash", from: "4.17.20", to: "^4.17.20" }])).results[0];
    expect(r).toMatchObject({ to: "4.18.1" });
    expect(r.range_check).toMatchObject({ smallest_safe_upgrade: "4.18.1", withheld: ["4.18.0"] });
    expect(r.reason).toContain('4.18.0 is deprecated on npm ("Bad release. Please use lodash@4.17.21 instead."); 4.18.1 is the smallest clean release');
    // The withdrawn release itself, asked for directly: avoid.
    const direct = (await check([{ ecosystem: "npm", package: "lodash", to: "4.18.0" }])).results[0];
    expect(direct.verdict).toBe("avoid");
  });
});
