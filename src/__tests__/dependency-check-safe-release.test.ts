// SPDX-License-Identifier: Apache-2.0
/**
 * What dependency_check names as the release to write (audit 2026-11-11, M13). Three defects:
 *
 * 1. A prerelease named as the safe line. `litellm` 1.107.0 was correctly avoid (MAL-2026-2144),
 *    and the answer went on "Safe on 1.107.0's line: smallest 1.107.0.dev1, newest 1.107.0rc3".
 * 2. A bare PyPI version read as a range. `{Jinja2, "3.1"}` said proceed (to 3.1.6) while
 *    `"==3.1"` said avoid (3.1.0 has ten OSV ids); an agent then writes `Jinja2==3.1`.
 * 3. An avoid with nothing offered. Every Next.js 15 release exact-pins postcss 8.4.31, and
 *    `{next, "^15.0"}` said avoid and "No release in ^15.0 is free of known advisories", full stop.
 *
 * Registry and record shapes are the real ones (pypi.org, registry.npmjs.org, api.osv.dev,
 * 2026-11-11), cut down to what decides each case.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import { advisoryAffects, advisoryRanges } from "../live/osv-ranges.js";
import type { PackageReleaseIndex } from "../live/release-metadata.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { checkRange, describeReading, parseTarget, rangeNamesPrerelease } from "../tools/dependency-check-versions.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-11T00:00:00Z");
const DAY = 86_400_000;
const daysAgo = (n: number) => new Date(NOW.getTime() - n * DAY).toISOString();

interface NpmPkg {
  latest: string;
  versions: Record<string, { at: string; dependencies?: Record<string, string> }>;
}
let NPM: Record<string, NpmPkg>;
/** PyPI: name -> version -> upload time. */
let PYPI: Record<string, Record<string, string>>;
let OSV: OsvVulnerability[];

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const same = (a: string, b: string, eco: string) => (eco === "PyPI" ? a.toLowerCase() === b.toLowerCase() : a === b);
    const recordsFor = (name: string, eco: string) => OSV.filter((v) => v.affected?.some((a) => a.package?.ecosystem === eco && same(a.package.name, name, eco)));
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return json({
        results: queries.map((q) => ({
          vulns: recordsFor(q.package.name, q.package.ecosystem)
            .filter((v) => advisoryAffects(advisoryRanges(v, q.package.name, q.package.ecosystem)!, q.version, q.package.ecosystem))
            .map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" })),
        })),
      });
    }
    if (url.includes("/v1/vulns/")) {
      const found = OSV.find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string } };
      return json({ vulns: recordsFor(q.package.name, q.package.ecosystem) });
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      const name = Object.keys(PYPI).find((n) => n.toLowerCase() === decodeURIComponent(pypi[1]).toLowerCase());
      if (!name) return json({ message: "Not Found" }, 404);
      return json({ info: { name }, releases: Object.fromEntries(Object.entries(PYPI[name]).map(([v, at]) => [v, [{ upload_time_iso_8601: at, yanked: false }]])) });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({ error: "Not found" }, 404);
      return json({
        name,
        "dist-tags": { latest: doc.latest },
        versions: Object.fromEntries(Object.entries(doc.versions).map(([v, r]) => [v, { name, version: v, dependencies: r.dependencies ?? {} }])),
        time: { created: "2015-01-01T00:00:00.000Z", ...Object.fromEntries(Object.entries(doc.versions).map(([v, r]) => [v, r.at])) },
      });
    }
    return json({}, 404);
  });
}

let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  clearNpmDownloadsMemo();
  NPM = {};
  PYPI = {};
  OSV = [];
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

type Result = Record<string, any>;
const check = async (items: unknown[]) =>
  (await executeDependencyCheck(noDb, { items } as never, new LiveIntelligence(new Database(":memory:")), { now: NOW })) as unknown as { results: Result[] };
const pypiRecord = (id: string, name: string, extra: Record<string, unknown>, top: Partial<OsvVulnerability> = {}): OsvVulnerability =>
  ({ id, aliases: [], summary: `${name} advisory`, affected: [{ package: { name, ecosystem: "PyPI" }, ...extra }], ...top }) as unknown as OsvVulnerability;
const npmRecord = (id: string, name: string, events: Array<Record<string, string>>, severity: string): OsvVulnerability =>
  ({ id, aliases: [], summary: `${name} advisory`, database_specific: { severity }, affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events }] }] }) as unknown as OsvVulnerability;

// ---------------------------------------------------------------------------------------------
// 1. A prerelease is never the safe release, unless one was asked for
// ---------------------------------------------------------------------------------------------

describe("prereleases are not offered as the safe release", () => {
  /** litellm as PyPI lists it around 1.107.0: the release itself was removed; its dev and rc builds remain. */
  beforeEach(() => {
    PYPI.litellm = {
      "1.106.4": daysAgo(40),
      "1.106.5": daysAgo(30),
      "1.107.0.dev1": daysAgo(25),
      "1.107.0rc1": daysAgo(22),
      "1.107.0rc2": daysAgo(21),
      "1.107.0rc3": daysAgo(20),
      "1.108.0": daysAgo(10),
    };
    OSV.push(pypiRecord("MAL-2026-2144", "litellm", { versions: ["1.107.0"] }, { summary: "Malicious code in litellm (PyPI)" }));
  });

  it("litellm 1.107.0 is avoid, and no dev or rc build is named as safe on its line (it named 1.107.0.dev1 and 1.107.0rc3)", async () => {
    const [r] = (await check([{ ecosystem: "PyPI", package: "litellm", to: "1.107.0" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.reason).toContain("1.107.0 is affected by MAL-2026-2144 (critical)");
    expect(r.range_check).toMatchObject({
      basis: "same_line",
      range: "==1.107.*",
      releases_in_range: 0,
      prereleases_not_offered: 4,
      smallest_safe_in_range: null,
      newest_safe_in_range: null,
      safe_versions: [],
      newest_safe_outside_range: "1.108.0",
    });
    expect(r.reason).not.toMatch(/dev1|rc3/);
    expect(r.reason).toContain("No stable release on 1.107.0's line (==1.107.*): the 4 releases there are prereleases, and a prerelease is never offered as the safe release unless you ask for one. Newest safe release outside it: 1.108.0.");
  });

  it("a constraint that admits only prereleases picks none: unknown, with the stable release outside it", async () => {
    const [r] = (await check([{ ecosystem: "PyPI", package: "litellm", to: "1.107.*" }])).results;
    expect(r.verdict).toBe("unknown");
    expect(r.to).toBe("1.107.*");
    expect(r.reason).toBe(
      "No stable release of litellm matches ==1.107.*: the 4 releases it admits (1.107.0.dev1 to 1.107.0rc3) are prereleases, and a prerelease is never offered as the safe release. Ask for one by its exact version to have it judged. Newest safe release outside it: 1.108.0.",
    );
    expect(r.range_check).toMatchObject({ releases_in_range: 0, prereleases_not_offered: 4, smallest_safe_in_range: null });
  });

  it("asked for a prerelease, a prerelease may be offered: an exact rc, and a constraint that names one", async () => {
    OSV.push(pypiRecord("PYSEC-2026-9999", "litellm", { versions: ["1.107.0rc1"] }, { database_specific: { severity: "MODERATE" } }));
    const out = await check([
      { ecosystem: "PyPI", package: "litellm", to: "1.107.0rc1" },
      { ecosystem: "PyPI", package: "litellm", to: ">=1.107.0rc1,<1.107.0" },
    ]);
    expect(out.results[0].verdict).toBe("review");
    expect(out.results[0].range_check).toMatchObject({ basis: "same_line", smallest_safe_in_range: "1.107.0.dev1", newest_safe_in_range: "1.107.0rc3" });
    expect(out.results[1]).toMatchObject({ to: "1.107.0rc3", verdict: "proceed" });
    expect(out.results[1].range_check.prereleases_not_offered).toBeUndefined();
  });

  it("a stable line still offers its stable releases, never a prerelease beside them", async () => {
    PYPI.litellm["1.106.6rc1"] = daysAgo(28);
    OSV.push(pypiRecord("PYSEC-2026-1000", "litellm", { versions: ["1.106.4"] }, { database_specific: { severity: "HIGH" } }));
    const [r] = (await check([{ ecosystem: "PyPI", package: "litellm", to: "1.106.4" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "1.106.5", newest_safe_in_range: "1.106.5", releases_in_range: 2 });
    expect(r.range_check.prereleases_not_offered).toBeUndefined();
  });

  it("rangeNamesPrerelease: only a constraint that itself names one", () => {
    expect(rangeNamesPrerelease("PyPI", ">=1.107.0rc1")).toBe(true);
    expect(rangeNamesPrerelease("PyPI", "==1.107.0.dev1")).toBe(true);
    expect(rangeNamesPrerelease("PyPI", "==1.107.*")).toBe(false);
    expect(rangeNamesPrerelease("PyPI", "~=3.1")).toBe(false);
    expect(rangeNamesPrerelease("PyPI", ">=2,<3")).toBe(false);
    expect(rangeNamesPrerelease("npm", "^5.0.0-beta.1")).toBe(true);
    expect(rangeNamesPrerelease("npm", "7.x")).toBe(false);
    expect(rangeNamesPrerelease("npm", ">=7.5.11 <8")).toBe(false);
    expect(rangeNamesPrerelease("npm", "1.0.0 - 2.0.0")).toBe(false);
    expect(rangeNamesPrerelease("crates.io", "0.17")).toBe(false);
    expect(rangeNamesPrerelease("crates.io", "=1.0.0-rc.2")).toBe(true);
    expect(rangeNamesPrerelease("Go", "v2.0.0-rc.1")).toBe(true);
    expect(rangeNamesPrerelease("Go", "v0")).toBe(false);
  });

  it("checkRange: stable candidates only by default; prereleases counted, never listed", () => {
    const index: PackageReleaseIndex = {
      ecosystem: "npm",
      name: "pre-only",
      createdAt: null,
      releases: Object.fromEntries(
        ["1.0.0", "2.0.0-beta.1", "2.0.0-beta.2"].map((v) => [v, { version: v, publishedAt: null, trust: 0 as const, trustEvidence: "", installScripts: null, deprecated: null, withdrawn: null, dependencies: null }]),
      ),
    };
    const base = { ecosystem: "npm" as const, index, range: ">=2.0.0-beta.1 <3", basis: "requested" as const, advisories: [] };
    expect(checkRange(base)).toMatchObject({ releases_in_range: 0, prereleases_not_offered: 2, smallest_safe_in_range: null, safe_versions: [], newest_safe_outside_range: "1.0.0" });
    expect(checkRange({ ...base, allowPrerelease: true })).toMatchObject({ releases_in_range: 2, smallest_safe_in_range: "2.0.0-beta.1", newest_safe_in_range: "2.0.0-beta.2" });
  });
});

// ---------------------------------------------------------------------------------------------
// 2. How `to` is read, said in every answer
// ---------------------------------------------------------------------------------------------

describe("a bare version is read as its ecosystem reads it, and the answer says how", () => {
  beforeEach(() => {
    PYPI.Jinja2 = Object.fromEntries(["3.0.3", "3.1.0", "3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6"].map((v, i) => [v, daysAgo(900 - i * 60)]));
    OSV.push(
      pypiRecord("GHSA-h5c8-rqwp-cp95", "jinja2", { ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.1.3" }] }] }, { database_specific: { severity: "MODERATE" } }),
      pypiRecord("GHSA-cpwx-vrp4-4pq7", "jinja2", { ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.1.6" }] }] }, { database_specific: { severity: "HIGH" } }),
    );
    NPM.ws = { latest: "8.18.0", versions: Object.fromEntries(["7.5.9", "7.5.10", "7.5.13", "8.18.0"].map((v, i) => [v, { at: daysAgo(500 - i * 20) }])) };
  });

  it("PyPI: \"3.1\" is the release 3.1.0, the same answer as \"==3.1\" (it said proceed, for 3.1.6)", async () => {
    const out = await check([
      { ecosystem: "PyPI", package: "Jinja2", to: "3.1" },
      { ecosystem: "PyPI", package: "Jinja2", to: "==3.1" },
      { ecosystem: "PyPI", package: "Jinja2", to: "3.1.*" },
      { ecosystem: "PyPI", package: "Jinja2", to: "~=3.1.0" },
    ]);
    const [bare, pinned, star, compatible] = out.results;
    expect(bare).toMatchObject({ to: "3.1.0", to_requested: "3.1", verdict: "avoid" });
    expect(pinned).toMatchObject({ to: "3.1.0", to_requested: "==3.1", verdict: "avoid" });
    expect(bare.reason).toContain("3.1.0 is affected by 2 known advisories");
    expect(bare.reason).toContain("Safe on 3.1.0's line (==3.1.*): smallest 3.1.6, newest 3.1.6.");
    expect(bare.to_read_as).toBe('exact version: a bare "3.1" is the one release 3.1.0, as pip reads ==3.1; it is not the 3.1 series. For the series ask "3.1.*" or "~=3.1.0"');
    expect(pinned.to_read_as).toBe("exact version: this one release was judged");
    // Only constraint syntax is a range.
    expect(star).toMatchObject({ to: "3.1.6", to_requested: "3.1.*", verdict: "proceed" });
    expect(compatible).toMatchObject({ to: "3.1.6", verdict: "proceed" });
    expect(star.to_read_as).toMatch(/^range: "3\.1\.\*" is read as a PEP 440 specifier/);
  });

  it("PyPI: a bare version the index does not list is unknown, never a neighbouring release", async () => {
    const [r] = (await check([{ ecosystem: "PyPI", package: "Jinja2", to: "3.2" }])).results;
    expect(r.verdict).toBe("unknown");
    expect(r.to).toBe("3.2");
    expect(r.reason).toContain("Jinja2@3.2 is not a published version on PyPI");
  });

  it("npm: \"7\" and \"7.5\" are ranges, as package.json reads them, and say so; a full version is that release", async () => {
    const out = await check([
      { ecosystem: "npm", package: "ws", to: "7" },
      { ecosystem: "npm", package: "ws", to: "7.5" },
      { ecosystem: "npm", package: "ws", to: "7.5.10" },
    ]);
    expect(out.results[0]).toMatchObject({ to: "7.5.13", to_requested: "7" });
    expect(out.results[1]).toMatchObject({ to: "7.5.13", to_requested: "7.5" });
    expect(out.results[0].to_read_as).toMatch(/^range: npm reads "7" as a version range, as package\.json and "npm install <pkg>@<range>" do/);
    expect(out.results[2].to).toBe("7.5.10");
    expect(out.results[2].to_requested).toBeUndefined();
    expect(out.results[2].to_read_as).toMatch(/^exact version: 7\.5\.10 itself was judged/);
  });

  it("describeReading: each ecosystem's own reading, in words", () => {
    const read = (eco: Parameters<typeof parseTarget>[0], raw: string) => describeReading(eco, raw, parseTarget(eco, raw)!);
    expect(read("crates.io", "1")).toMatch(/^range: "1" is read as a Cargo requirement \(a bare "1" or "0\.17" is a caret requirement, as Cargo\.toml reads it\)/);
    expect(read("crates.io", "1.0.229")).toMatch(/^exact version: 1\.0\.229 itself was judged\. In Cargo\.toml a bare "1\.0\.229" is the caret requirement \^1\.0\.229/);
    expect(read("Go", "v1")).toMatch(/^range: "v1" is read as a version query \(a bare "v1" or "v1\.2" is a prefix, as "go get <module>@v1" reads it\)/);
    expect(read("Go", "v0.23.0")).toBe("exact version: v0.23.0 itself was judged");
    expect(read("PyPI", "3")).toMatch(/^exact version: a bare "3" is the one release 3\.0\.0, as pip reads ==3; it is not the 3 series/);
    expect(read("PyPI", "3.1.4")).toBe("exact version: this one release was judged");
    expect(read("npm", "latest")).toBe("latest: the newest stable release the registry has not withdrawn");
  });
});

// ---------------------------------------------------------------------------------------------
// 3. An avoid or review over a held dependency names it, its override, and the clean line outside
// ---------------------------------------------------------------------------------------------

describe("nothing in range is safe because of what the releases hold: Next.js 15 and postcss", () => {
  /** next as the registry lists it: every 15.x exact-pins postcss 8.4.31; 16.x moved past it. */
  function nextShape(severity: "MODERATE" | "HIGH") {
    NPM.next = {
      latest: "16.1.0",
      versions: {
        "15.4.0": { at: daysAgo(200), dependencies: { postcss: "8.4.31" } },
        "15.5.0": { at: daysAgo(120), dependencies: { postcss: "8.4.31" } },
        "15.5.29": { at: daysAgo(20), dependencies: { postcss: "8.4.31" } },
        "16.0.0": { at: daysAgo(60), dependencies: { postcss: "8.5.23" } },
        "16.1.0": { at: daysAgo(15), dependencies: { postcss: "8.5.23" } },
        // Published yesterday: clean, but inside the release-age hold, so not the alternative.
        "16.2.0": { at: daysAgo(1), dependencies: { postcss: "8.5.23" } },
      },
    };
    NPM.postcss = { latest: "8.5.23", versions: Object.fromEntries(["8.4.31", "8.5.10", "8.5.18", "8.5.23"].map((v, i) => [v, { at: daysAgo(700 - i * 100) }])) };
    OSV.push(
      npmRecord("GHSA-qx2v-qp2m-jg93", "postcss", [{ introduced: "0" }, { fixed: "8.5.10" }], "MODERATE"),
      npmRecord("GHSA-fxqj-rqcc-2cmp", "postcss", [{ introduced: "0" }, { fixed: "8.5.23" }], severity),
    );
  }

  it("a moderate held advisory: review, naming postcss, the override that clears it, and the clean release outside", async () => {
    nextShape("MODERATE");
    const [r] = (await check([{ ecosystem: "npm", package: "next", to: "^15.0" }])).results;
    expect(r).toMatchObject({ to: "15.5.29", verdict: "review" });
    expect(r.range_check.held_advice.dependencies).toEqual([
      { package: "postcss", installs: "8.4.31", advisories: ["GHSA-fxqj-rqcc-2cmp", "GHSA-qx2v-qp2m-jg93"], severity: "medium", fixed_in: "8.5.23" },
    ]);
    expect(r.range_check.newest_safe_outside_range).toBe("16.1.0");
    expect(r.reason).toContain("No release in ^15.0 is free of known advisories.");
    expect(r.reason).toContain("Only a low or moderate advisory on a dependency they install keeps them out: 15.5.29 holds postcss 8.4.31 (GHSA-fxqj-rqcc-2cmp, GHSA-qx2v-qp2m-jg93, medium).");
    expect(r.reason).toContain('To install 15.5.29 without it, override postcss to 8.5.23 (npm "overrides", pnpm "overrides", Yarn "resolutions")');
    expect(r.reason).toContain("Newest safe release outside it: 16.1.0.");
  });

  it("a high held advisory: still avoid, and no longer with nothing offered (it said only \"No release in ^15.0 is free of known advisories\")", async () => {
    nextShape("HIGH");
    const out = await check([
      { ecosystem: "npm", package: "next", to: "^15.0" },
      { ecosystem: "npm", package: "next", to: "15.x" },
      { ecosystem: "npm", package: "next", to: "15.5.29" },
    ]);
    for (const r of out.results) {
      expect(r).toMatchObject({ to: "15.5.29", verdict: "avoid" });
      expect(r.range_check.held_advice.dependencies).toEqual([
        { package: "postcss", installs: "8.4.31", advisories: ["GHSA-fxqj-rqcc-2cmp", "GHSA-qx2v-qp2m-jg93"], severity: "high", fixed_in: "8.5.23" },
      ]);
      expect(r.range_check.newest_safe_outside_range).toBe("16.1.0");
      expect(r.reason).toContain("What keeps them out is a dependency they install: 15.5.29 holds postcss 8.4.31 (GHSA-fxqj-rqcc-2cmp, GHSA-qx2v-qp2m-jg93, high). A high or critical advisory, so 15.5.29 as published stays avoid.");
      expect(r.reason).toContain("To install 15.5.29 without it, override postcss to 8.5.23");
      expect(r.reason).toContain("Newest safe release outside it: 16.1.0.");
    }
  });

  it("the clean line itself is proceed, and the release inside the age hold is not the alternative", async () => {
    nextShape("HIGH");
    const [r] = (await check([{ ecosystem: "npm", package: "next", to: "^16.0" }])).results;
    expect(r).toMatchObject({ to: "16.1.0", verdict: "proceed" });
  });

  it("the range answer is about the newest release whose only issue is a low or moderate held dependency", async () => {
    // 3.2.0, the newest, holds a child with a HIGH advisory; 3.1.0 holds one with a moderate advisory only.
    NPM.framework = {
      latest: "3.2.0",
      versions: {
        "3.0.0": { at: daysAgo(300), dependencies: { child: "1.0.0" } },
        "3.1.0": { at: daysAgo(200), dependencies: { child: "1.0.0" } },
        "3.2.0": { at: daysAgo(100), dependencies: { child: "1.1.0" } },
      },
    };
    NPM.child = { latest: "1.2.0", versions: Object.fromEntries(["1.0.0", "1.0.1", "1.1.0", "1.2.0"].map((v, i) => [v, { at: daysAgo(400 - i * 50) }])) };
    OSV.push(
      npmRecord("GHSA-chld-0000-0001", "child", [{ introduced: "0" }, { fixed: "1.0.1" }], "MODERATE"),
      npmRecord("GHSA-chld-0000-0002", "child", [{ introduced: "1.1.0" }, { fixed: "1.2.0" }], "HIGH"),
    );
    const [r] = (await check([{ ecosystem: "npm", package: "framework", to: "^3.0" }])).results;
    expect(r).toMatchObject({ to: "3.1.0", to_requested: "^3.0", verdict: "review" });
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: null, held_excluded: 3 });
    expect(r.range_check.held_advice.dependencies).toEqual([{ package: "child", installs: "1.0.0", advisories: ["GHSA-chld-0000-0001"], severity: "medium", fixed_in: "1.0.1" }]);
    expect(r.reason).toContain("3.1.0 holds child 1.0.0 (GHSA-chld-0000-0001, medium)");
    expect(r.reason).toContain("To install 3.1.0 without it, override child to 1.0.1");
    // With `from`, never a release at or below the installed one.
    const [up] = (await check([{ ecosystem: "npm", package: "framework", from: "3.1.0", to: "^3.0" }])).results;
    expect(up).toMatchObject({ to: "3.2.0", verdict: "avoid" });
  });
});
