// SPDX-License-Identifier: Apache-2.0
/**
 * Range events are read the way the OSV schema's evaluation reads them (sorted), an answer never
 * calls one release both affected and safe, and a closing event with no `introduced` is a cautious
 * reading that OSV.dev's own answer for a version overrules.
 *
 * - npm `derby`, GHSA-82jv-9wjw-pqh6: one range lists `introduced 4.0.0-beta1, fixed 4.0.0-beta.11`.
 *   In semver order the fix sorts BELOW its own start, so OSV.dev reads the range as open from
 *   4.0.0-beta1 and reports 4.0.0 and 4.2.3 affected. Paired in listed order the range was empty,
 *   and dependency_check said "4.2.3 is affected ... Safe on 4.x: smallest 4.0.0, newest 4.2.3".
 * - PyPI `lunasvg`, PYSEC-2025-128: `introduced 0, last_affected 3.0.0, last_affected 3.1.0`. OSV's
 *   evaluation gives the second closing event no effect (3.0.1 is not affected); read as "affected
 *   since the beginning up to 3.1.0", dependency_check held that reading against OSV.dev's answer
 *   and avoided 3.0.1.
 *
 * Records: api.osv.dev, read 2026-11-18, cut down to `affected`. The registries and OSV.dev are
 * stubbed at `fetch`; the batch answers are OSV.dev's per-version answers, written out here.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { confirmTargets, listConfirmed, unaccountedIds } from "../live/batch-confirm.js";
import type { FixPathSources, FixTargetResult } from "../live/fix-paths.js";
import type { AdvisoryQuery } from "../live/held-dependencies.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import { advisoriesAffecting, advisoryAffects, advisoryKnownToAffect, advisoryRanges, advisoryReading, collectAffectedSpans, smallestCleanVersion } from "../live/osv-ranges.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeDependencyCheck, runDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
type Ev = Record<string, string>;
const entry = (name: string, ecosystem: string, events: Ev[], versions?: string[]) => ({
  package: { name, ecosystem },
  ranges: [{ type: ecosystem === "PyPI" ? "ECOSYSTEM" : "SEMVER", events }],
  ...(versions ? { versions } : {}),
});

/** GHSA-82jv-9wjw-pqh6, as OSV.dev serves it: three affected entries, the third with its fix below its start. */
const DERBY = {
  id: "GHSA-82jv-9wjw-pqh6",
  summary: "Prototype pollution in derby",
  database_specific: { severity: "LOW" },
  affected: [
    entry("derby", "npm", [{ introduced: "0" }, { fixed: "2.3.2" }]),
    entry("derby", "npm", [{ introduced: "3.0.0" }, { fixed: "3.0.2" }]),
    entry("derby", "npm", [{ introduced: "4.0.0-beta1" }, { fixed: "4.0.0-beta.11" }]),
  ],
} as unknown as OsvVulnerability;
/** api.osv.dev /v1/query per version, 2026-11-18. */
const OSV_SAYS_DERBY: Record<string, boolean> = { "2.3.1": true, "2.3.2": false, "3.0.0": true, "3.0.1": true, "3.0.2": false, "3.5.0": false, "4.0.0": true, "4.2.3": true };

const LUNASVG = {
  id: "PYSEC-2025-128",
  summary: "lunasvg",
  database_specific: { severity: "HIGH" },
  affected: [entry("lunasvg", "PyPI", [{ introduced: "0" }, { last_affected: "3.0.0" }, { last_affected: "3.1.0" }])],
} as unknown as OsvVulnerability;

const TRYTON = {
  id: "PYSEC-2022-43170",
  affected: [
    entry("tryton", "PyPI", [
      { introduced: "5.0.0" }, { fixed: "5.0.12" }, { introduced: "6.0.0" }, { fixed: "6.0.5" }, { introduced: "6.2.0" }, { fixed: "6.2.2" }, { fixed: "6.2.6" }, { fixed: "6.0.16" }, { fixed: "5.0.46" },
    ]),
  ],
} as unknown as OsvVulnerability;

describe("events are evaluated sorted, as the OSV schema's algorithm evaluates them", () => {
  const derby = advisoryRanges(DERBY, "derby", "npm")!;

  it("derby: every version reads as OSV.dev answers it, 4.0.0 and 4.2.3 affected", () => {
    for (const [v, affected] of Object.entries(OSV_SAYS_DERBY)) {
      expect(advisoryAffects(derby, v, "npm"), v).toBe(affected);
      expect(advisoryKnownToAffect(derby, v, "npm"), v).toBe(affected);
    }
  });

  it("a fix sorted below its own start closes nothing and presumes nothing below it", () => {
    const spans = collectAffectedSpans(DERBY.affected, "derby", "npm");
    expect(spans).toEqual([
      { introduced: "0", fixed: "2.3.2", lastAffected: null },
      { introduced: "3.0.0", fixed: "3.0.2", lastAffected: null },
      { introduced: "4.0.0-beta1", fixed: null, lastAffected: null },
    ]);
  });

  it("events listed out of order pair as they sort", () => {
    const a = advisoryRanges({ id: "X", affected: [entry("p", "npm", [{ fixed: "2.0.0" }, { introduced: "1.0.0" }])] } as unknown as OsvVulnerability, "p", "npm")!;
    expect(a.spans).toEqual([{ introduced: "1.0.0", fixed: "2.0.0", lastAffected: null }]);
    for (const [v, affected] of [["0.5.0", false], ["1.0.0", true], ["1.9.9", true], ["2.0.0", false], ["3.0.0", false]] as Array<[string, boolean]>) {
      expect(advisoryAffects(a, v, "npm"), v).toBe(affected);
    }
  });

  it("an `introduced` inside an open span changes nothing: the span runs to the next closing event", () => {
    const a = advisoryRanges({ id: "X", affected: [entry("p", "npm", [{ introduced: "1.0.0" }, { introduced: "2.0.0" }, { fixed: "3.0.0" }])] } as unknown as OsvVulnerability, "p", "npm")!;
    expect(a.spans).toEqual([{ introduced: "1.0.0", fixed: "3.0.0", lastAffected: null }]);
    expect(advisoryAffects(a, "2.5.0", "npm")).toBe(true);
    expect(advisoryAffects(a, "4.0.0", "npm")).toBe(false);
  });

  it("the fix target for an old derby is the first release its ranges clear, and no 4.x release clears it", () => {
    const published = ["2.3.1", "2.3.2", "3.0.1", "3.0.2", "4.0.0", "4.2.3"];
    expect(smallestCleanVersion({ ecosystem: "npm", fixes: ["2.3.2"], advisories: [derby], published, installed: "2.3.1" })).toMatchObject({ target: "2.3.2", stillAffectedBy: [] });
    // From 4.0.0 nothing clears it: the advisory is reported as remaining, never passed over in silence.
    expect(smallestCleanVersion({ ecosystem: "npm", fixes: ["4.0.0-beta.11"], advisories: [derby], published, installed: "4.0.0" })).toMatchObject({
      stillAffectedBy: ["GHSA-82jv-9wjw-pqh6"],
      unfixable: ["GHSA-82jv-9wjw-pqh6"],
    });
  });
});

describe("a closing event with no `introduced`: cautious, and never held against OSV.dev's answer", () => {
  const lunasvg = advisoryRanges(LUNASVG, "lunasvg", "PyPI")!;
  const tryton = advisoryRanges(TRYTON, "tryton", "PyPI")!;

  it("lunasvg: 3.0.0 is affected; 3.0.1 to 3.1.0 only by the presumed reading", () => {
    expect(advisoryReading(lunasvg, "3.0.0", "PyPI")).toBe("affected");
    for (const v of ["3.0.1", "3.1.0"]) {
      expect(advisoryReading(lunasvg, v, "PyPI"), v).toBe("presumed");
      expect(advisoryKnownToAffect(lunasvg, v, "PyPI"), v).toBe(false);
      // Kept where nothing better is known: the release is not called clear of it.
      expect(advisoriesAffecting([lunasvg], v, "PyPI"), v).toEqual(["PYSEC-2025-128"]);
    }
    expect(advisoryReading(lunasvg, "3.2.0", "PyPI")).toBe("clear");
  });

  it("tryton: the three ranges are the known ones; the extra fixes only presume", () => {
    for (const v of ["5.0.0", "5.0.11", "6.0.4", "6.2.1"]) expect(advisoryReading(tryton, v, "PyPI"), v).toBe("affected");
    for (const v of ["2.4.15", "5.0.12", "6.0.5", "6.2.2"]) expect(advisoryReading(tryton, v, "PyPI"), v).toBe("presumed");
    for (const v of ["6.2.6", "7.0.0"]) expect(advisoryReading(tryton, v, "PyPI"), v).toBe("clear");
  });

  it("a lone `fixed` still reads as affected since the beginning", () => {
    const a = advisoryRanges({ id: "X", affected: [entry("p", "npm", [{ fixed: "2.1.0" }])] } as unknown as OsvVulnerability, "p", "npm")!;
    expect(a.spans).toEqual([{ introduced: "0", fixed: "2.1.0", lastAffected: null, presumed: true }]);
    expect(advisoryAffects(a, "2.0.0", "npm")).toBe(true);
    expect(advisoryAffects(a, "2.1.0", "npm")).toBe(false);
  });
});

describe("unaccountedIds: what OSV.dev names for a release and the list does not account for", () => {
  const derbyAsListed = { id: "GHSA-82jv-9wjw-pqh6", versions: [], spans: [{ introduced: "0", fixed: "2.3.2", lastAffected: null }, { introduced: "4.0.0-beta1", fixed: "4.0.0-beta.11", lastAffected: null }] };
  const notice = { id: "RUSTSEC-0000-0001", versions: [], spans: [{ introduced: "0", fixed: null, lastAffected: null }], maintenance: true };

  it("an id the list holds with ranges that do not reach the release is `misread`; one it lacks is `missing`", () => {
    expect(unaccountedIds([derbyAsListed], ["GHSA-82jv-9wjw-pqh6", "GHSA-none-none-none"], "4.2.3", "npm")).toEqual({ missing: ["GHSA-none-none-none"], misread: ["GHSA-82jv-9wjw-pqh6"] });
  });

  it("an id whose record has the release affected, an alias twin that has, and a maintenance notice are accounted for", () => {
    expect(unaccountedIds([derbyAsListed], ["GHSA-82jv-9wjw-pqh6"], "2.0.0", "npm")).toEqual({ missing: [], misread: [] });
    const twin = { id: "PYSEC-1", aliases: ["GHSA-82jv-9wjw-pqh6"], versions: ["4.2.3"], spans: [] };
    expect(unaccountedIds([derbyAsListed, twin], ["GHSA-82jv-9wjw-pqh6"], "4.2.3", "npm")).toEqual({ missing: [], misread: [] });
    expect(unaccountedIds([notice], ["RUSTSEC-0000-0001"], "9.9.9", "crates.io")).toEqual({ missing: [], misread: [] });
  });

  const answering = (ids: string[]): AdvisoryQuery =>
    (async (deps: Array<{ name: string; version: string | null; ecosystem: string }>) => ({
      vulnerabilities: deps.flatMap((d) => ids.map((vulnId) => ({ vulnId, package: d.name, ecosystem: d.ecosystem, currentVersion: d.version }))),
      offline: false,
    })) as unknown as AdvisoryQuery;

  it("confirmTargets: a target OSV.dev names a listed advisory against is not confirmed", async () => {
    const sources = { packageAdvisories: async () => [derbyAsListed] } as unknown as FixPathSources;
    const clean = { target: "4.2.3", basis: "registry", floor: "4.0.0-beta.11", floorAffectedBy: [], stillAffectedBy: [], unfixable: [], withheld: [] } as FixTargetResult;
    const out = (await confirmTargets(sources, answering(["GHSA-82jv-9wjw-pqh6"]), [{ key: "k", ecosystem: "npm", name: "derby", clean }], Date.now() + 5_000)).get("k");
    expect(out?.advisoriesUnread).toBe(true);
    expect(out?.unconfirmed).toMatch(/names GHSA-82jv-9wjw-pqh6 against it, which the ranges in derby's advisory list \(\/v1\/query\) do not show as affecting it/);
    // Named against it and acknowledged by the list's own reading: confirmed as before.
    const acknowledged = { ...clean, target: "2.0.0", stillAffectedBy: ["GHSA-82jv-9wjw-pqh6"] } as FixTargetResult;
    expect((await confirmTargets(sources, answering(["GHSA-82jv-9wjw-pqh6"]), [{ key: "k", ecosystem: "npm", name: "derby", clean: acknowledged }], Date.now() + 5_000)).get("k")).toBeUndefined();
  });

  it("listConfirmed: a list whose ranges OSV.dev's answer contradicts may not call releases clean", async () => {
    expect(await listConfirmed(answering(["GHSA-82jv-9wjw-pqh6"]), [derbyAsListed], "npm", "derby", ["4.2.3"], Date.now() + 5_000)).toBe(false);
    expect(await listConfirmed(answering(["GHSA-82jv-9wjw-pqh6"]), [derbyAsListed], "npm", "derby", ["2.0.0"], Date.now() + 5_000)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tool level
// ---------------------------------------------------------------------------

let NPM: Record<string, string[]>;
let PYPI: Record<string, string[]>;
let OSV: OsvVulnerability[];
/** OSV.dev's own answer: ids per "name@version". */
let BATCH: Record<string, string[]>;
let BATCH_DOWN: boolean;
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  clearNpmDownloadsMemo();
  NPM = {};
  PYPI = {};
  OSV = [];
  BATCH = {};
  BATCH_DOWN = false;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      if (BATCH_DOWN) return new Response("internal error", { status: 500 });
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (BATCH[`${q.package.name}@${q.version}`] ?? []).map((id) => ({ id, modified: "2026-11-01T00:00:00Z" })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const found = OSV.find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: OSV.filter((v) => v.affected?.some((a) => a.package?.name === q.package.name)) });
    }
    if (url.startsWith("https://api.npmjs.org/downloads/")) return json({ downloads: 50_000_000, package: "x" });
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      const versions = PYPI[decodeURIComponent(pypi[1])];
      if (!versions) return json({ message: "Not Found" }, 404);
      return json({ info: { name: pypi[1] }, releases: Object.fromEntries(versions.map((v) => [v, [{ upload_time_iso_8601: "2025-06-01T00:00:00Z", yanked: false }]])) });
    }
    const one = /^https:\/\/registry\.npmjs\.org\/([^/@][^/]*)\/([^/]+)$/.exec(url);
    if (one) return NPM[decodeURIComponent(one[1])]?.includes(decodeURIComponent(one[2])) ? json({ name: one[1], version: one[2], dependencies: {} }) : json({}, 404);
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const versions = NPM[name];
      if (!versions) return json({ error: "Not found" }, 404);
      return json({
        name,
        "dist-tags": { latest: versions[versions.length - 1] },
        versions: Object.fromEntries(versions.map((v) => [v, { name, version: v, dependencies: {} }])),
        time: { created: "2015-01-01T00:00:00.000Z", modified: "2025-06-01T00:00:00.000Z", ...Object.fromEntries(versions.map((v) => [v, "2025-01-01T00:00:00.000Z"])) },
      });
    }
    return json({}, 404);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const live = () => new LiveIntelligence(new Database(":memory:"));
const detailed = async (items: unknown[]) => (await executeDependencyCheck(noDb, { items, response_format: "detailed" } as never, live())).results as Array<Record<string, any>>;
const concise = async (items: unknown[]) => ((await runDependencyCheck(noDb, { items } as never, live())) as Record<string, any>).results as Array<Record<string, any>>;

function derbyOnNpm() {
  NPM.derby = ["2.3.1", "2.3.2", "3.0.1", "3.0.2", "4.0.0", "4.2.3"];
  OSV.push(DERBY);
  for (const [v, affected] of Object.entries(OSV_SAYS_DERBY)) if (affected) BATCH[`derby@${v}`] = ["GHSA-82jv-9wjw-pqh6"];
}

describe("dependency_check: one release is never both affected and safe", () => {
  it.each(["4.2.3", "4.x", "latest"])('{npm, derby, "%s"}: 4.2.3 is affected, and no 4.x release is named safe', async (to) => {
    derbyOnNpm();
    const [r] = await concise([{ ecosystem: "npm", package: "derby", to }]);
    expect(r).toMatchObject({ to: "4.2.3", verdict: "review", advisories: ["GHSA-82jv-9wjw-pqh6"] });
    expect(r.safe?.smallest).not.toBe("4.0.0");
    expect(r.safe?.newest).not.toBe("4.2.3");
    expect(r.reason).not.toMatch(/Safe (on|in) [^|]*newest 4\.2\.3/);
    expect(r.reason).toMatch(/No release (on 4\.2\.3's line \(4\.x\)|in 4\.x) is free of known advisories/);
  });

  it("the releases the advisory's ranges clear are still the safe ones", async () => {
    derbyOnNpm();
    const [r] = await detailed([{ ecosystem: "npm", package: "derby", to: "3.x" }]);
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "3.0.2", newest_safe_in_range: "3.0.2" });
  });

  it("OSV.dev names an advisory for a release the list's ranges do not reach: nothing is named safe from the list", async () => {
    NPM.demo = ["1.0.0", "1.5.0", "2.0.0", "2.1.0"];
    OSV.push({ id: "GHSA-demo-demo-demo", summary: "demo", database_specific: { severity: "MODERATE" }, affected: [entry("demo", "npm", [{ introduced: "1.0.0" }, { fixed: "1.5.0" }])] } as unknown as OsvVulnerability);
    BATCH = { "demo@1.0.0": ["GHSA-demo-demo-demo"], "demo@2.0.0": ["GHSA-demo-demo-demo"] };
    const [exact, range] = await concise([
      { ecosystem: "npm", package: "demo", to: "2.0.0" },
      { ecosystem: "npm", package: "demo", to: ">=2.0.0 <2.1.0" },
    ]);
    for (const r of [exact, range]) {
      expect(r).toMatchObject({ to: "2.0.0", verdict: "review", advisories: ["GHSA-demo-demo-demo"] });
      expect(r.safe).toBeUndefined();
      expect(r.reason).toMatch(/NOT CHECKED: OSV\.dev's batch query names GHSA-demo-demo-demo for demo 2\.0\.0, which the ranges in demo's advisory list \(\/v1\/query\) do not show as affecting it/);
      expect(r.reason).not.toMatch(/left out/);
    }
  });
});

describe("dependency_check: OSV.dev's answer for the exact version overrules a presumed reading", () => {
  beforeEach(() => {
    PYPI.lunasvg = ["3.0.0", "3.0.1", "3.1.0", "3.2.0"];
    OSV.push(LUNASVG);
    BATCH = { "lunasvg@3.0.0": ["PYSEC-2025-128"] };
  });

  it("lunasvg 3.0.1: OSV.dev names nothing against it, so it is not called affected", async () => {
    const [r] = await detailed([{ ecosystem: "PyPI", package: "lunasvg", to: "3.0.1" }]);
    expect(r.verdict).toBe("proceed");
    expect(r.reason).not.toMatch(/PYSEC-2025-128/);
  });

  it("lunasvg 3.0.0: OSV.dev names it, and it is avoided", async () => {
    const [r] = await detailed([{ ecosystem: "PyPI", package: "lunasvg", to: "3.0.0" }]);
    expect(r.verdict).toBe("avoid");
    expect(r.signals.find((s: { id: string }) => s.id === "advisories").value.affecting_to).toEqual(["PYSEC-2025-128"]);
  });

  it("with no answer from OSV.dev the cautious reading stands: 3.0.1 is unknown, and never named safe", async () => {
    BATCH_DOWN = true;
    const [r] = await detailed([{ ecosystem: "PyPI", package: "lunasvg", to: "3.0.1" }]);
    expect(r.verdict).toBe("unknown");
    const [range] = await detailed([{ ecosystem: "PyPI", package: "lunasvg", to: "==3.0.*" }]);
    expect(range.range_check).toBeUndefined();
    expect(range.verdict).not.toBe("proceed");
  });
});
