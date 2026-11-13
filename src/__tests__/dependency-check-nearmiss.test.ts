// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check and names one slip away from a popular package (audit 2026-11-11, M2).
 *
 * `expres`, `reactt` and `expresss` each said proceed on main: all three are on the registry, no
 * advisory names them, and the near-miss the server computed for them (express, react) was printed
 * only beside names npm had already taken down. Registry shapes and download counts are the real
 * ones (registry.npmjs.org, api.npmjs.org, 2026-11-11), cut down to what decides each case.
 *
 * The two bars this file holds (the plan's Y2): of at least 200 squat-shaped names none is
 * `proceed`, whatever the downloads API says or fails to say; and of the 1,822 bundled popular
 * names none is flagged, with the downloads API down and never asked.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { ESTABLISHED_WEEKLY_DOWNLOADS, LOW_WEEKLY_DOWNLOADS, nameCheckSignal, nearMissOf } from "../tools/dependency-check-nearmiss.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-11T00:00:00Z");
const DAY = 86_400_000;
const daysAgo = (n: number) => new Date(NOW.getTime() - n * DAY).toISOString();

interface Pkg {
  created: string;
  latest: string;
  /** version -> publish time and install scripts */
  versions: Record<string, { at: string; scripts?: Record<string, string> }>;
}
let NPM: Record<string, Pkg>;
/** Every other name is on the registry too, as an old one-release package. */
let ANY_PACKAGE: boolean;
/** Weekly downloads by name; a name absent here has no download record. */
let DOWNLOADS: Record<string, number>;
let DOWNLOADS_DOWN: boolean;
let downloadRequests: string[];

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
      return json({ results: queries.map(() => ({})) });
    }
    if (url === "https://api.osv.dev/v1/query") return json({ vulns: [] });
    const downloads = /^https:\/\/api\.npmjs\.org\/downloads\/point\/last-week\/(.+)$/.exec(url);
    if (downloads) {
      downloadRequests.push(url);
      if (DOWNLOADS_DOWN) return new Response("service unavailable", { status: 503 });
      const names = decodeURIComponent(downloads[1]).split(",");
      // The API's two forms: one name answers its count or 404; several answer one entry each, null for no record.
      if (names.length === 1) return names[0] in DOWNLOADS ? json({ downloads: DOWNLOADS[names[0]], package: names[0] }) : json({ error: `package ${names[0]} not found` }, 404);
      return json(Object.fromEntries(names.map((n) => [n, n in DOWNLOADS ? { downloads: DOWNLOADS[n], package: n } : null])));
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name] ?? (ANY_PACKAGE ? { created: "2015-03-01T00:00:00.000Z", latest: "1.0.0", versions: { "1.0.0": { at: "2015-03-01T00:00:00.000Z" } } } : null);
      if (!doc) return json({ error: "Not found" }, 404);
      return json({
        name,
        "dist-tags": { latest: doc.latest },
        versions: Object.fromEntries(Object.entries(doc.versions).map(([v, r]) => [v, { name, version: v, dependencies: {}, ...(r.scripts ? { scripts: r.scripts } : {}) }])),
        time: { created: doc.created, ...Object.fromEntries(Object.entries(doc.versions).map(([v, r]) => [v, r.at])) },
      });
    }
    return json({}, 404);
  });
}

let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  NPM = {};
  ANY_PACKAGE = false;
  DOWNLOADS = {};
  DOWNLOADS_DOWN = false;
  downloadRequests = [];
  clearNpmDownloadsMemo();
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

type Result = Record<string, any>;
const check = async (items: unknown[]) =>
  (await executeDependencyCheck(noDb, { items } as never, new LiveIntelligence(new Database(":memory:")), { now: NOW })) as unknown as { results: Result[]; _meta: Record<string, unknown> };
const nameCheck = (r: Result) => (r.signals as Array<{ id: string; value: any; effect: string; evidence: string }>).find((s) => s.id === "name_check");
const add = (name: string, to = "latest") => ({ ecosystem: "npm", package: name, to });

/** One release, published long ago: the shape of the three live names. */
const old = (name: string, created: string, version: string, scripts?: Record<string, string>) => {
  NPM[name] = { created, latest: version, versions: { [version]: { at: created, ...(scripts ? { scripts } : {}) } } };
};

// ---------------------------------------------------------------------------------------------
// The three names the audit found, with their real facts
// ---------------------------------------------------------------------------------------------

describe("a new dependency whose name is a near-miss of a popular package", () => {
  beforeEach(() => {
    old("expres", "2012-10-10T03:49:52.879Z", "0.0.5");
    old("reactt", "2016-02-08T08:37:22.279Z", "1.0.1");
    old("expresss", "2016-08-15T18:34:04.884Z", "0.0.0");
    Object.assign(DOWNLOADS, { expres: 5216, reactt: 10, expresss: 751, express: 195_493_804, react: 252_214_826 });
  });

  it("expres, reactt and expresss are review with \"did you mean\", never proceed (they said proceed)", async () => {
    const { results } = await check([add("expres"), add("reactt"), add("expresss")]);
    expect(results.map((r) => [r.package, r.verdict])).toEqual([["expres", "review"], ["reactt", "review"], ["expresss", "review"]]);
    expect(results[0].reason).toContain("name_check: expres is one character away from express, one of the most-used npm packages");
    expect(results[0].reason).toContain("it has 5,216 downloads a week (under 10,000), against 195,493,804 for express");
    expect(results[0].reason).toContain("Did you mean express?");
    expect(results[1].reason).toContain("Did you mean react?");
    expect(results[2].reason).toContain("Did you mean express?");
    expect(nameCheck(results[0])).toMatchObject({
      effect: "review",
      value: { near_miss_of: "express", closeness: "one_edit", weekly_downloads: 5216, downloads_lookup: "ok", popular_weekly_downloads: 195_493_804, install_scripts: [] },
    });
  });

  it("asks api.npmjs.org once, for the near-miss names and the packages they resemble, and for nothing else", async () => {
    old("left-pad", "2014-03-14T00:00:00.000Z", "1.3.0");
    await check([add("expres"), add("reactt"), add("left-pad"), add("express")]);
    expect(downloadRequests).toHaveLength(1);
    expect(decodeURIComponent(downloadRequests[0]).split("/").pop()!.split(",").sort()).toEqual(["expres", "express", "react", "reactt"]);
  });

  it("downloads that cannot be read never read as established: review, and the reason says the lookup failed", async () => {
    DOWNLOADS_DOWN = true;
    const [r] = (await check([add("expres")])).results;
    expect(r.verdict).toBe("review");
    expect(r.reason).toContain("its weekly downloads could not be read (api.npmjs.org answered HTTP 503), so nothing shows that anyone installs it");
    expect(r.reason).toContain("Did you mean express?");
    expect(nameCheck(r)!.value).toMatchObject({ weekly_downloads: null, downloads_lookup: "unreachable" });
  });

  it("a name npm has no download record for is review", async () => {
    delete DOWNLOADS.reactt;
    const [r] = (await check([add("reactt")])).results;
    expect(r.verdict).toBe("review");
    expect(r.reason).toContain("npm has no download record for it");
    expect(nameCheck(r)!.value).toMatchObject({ downloads_lookup: "no_data" });
  });

  it("an exact version and a constraint are checked the same way as latest", async () => {
    const { results } = await check([add("expres", "0.0.5"), add("expres", "0.x")]);
    expect(results.map((r) => r.verdict)).toEqual(["review", "review"]);
    for (const r of results) expect(r.reason).toContain("Did you mean express?");
  });

  it("a version the registry does not list is still a finding about the name, not just unknown", async () => {
    const [r] = (await check([add("expres", "9.9.9")])).results;
    expect(r.verdict).toBe("review");
    expect(r.reason).toContain("Did you mean express?");
    expect(r.reason).toContain("expres@9.9.9 is not a published version on npm");
  });

  it("a `from` alone does not make a name installed: the name is still checked (pre-publish audit S2)", async () => {
    // {expres, 0.0.5, from 0.0.5} and {reactt, latest, from 1.0.0} said proceed: `from` skipped the check.
    NPM.expres.versions["0.0.4"] = { at: "2012-10-01T00:00:00.000Z" };
    const [r] = (await check([{ ecosystem: "npm", package: "expres", from: "0.0.4", to: "0.0.5" }])).results;
    expect(nameCheck(r)).toBeDefined();
    expect(r.verdict).not.toBe("proceed");
    expect(r.reason).toContain("Did you mean express?");
  });

  it("a package this project's lockfiles already hold is not a new dependency: no name check, no downloads request", async () => {
    NPM.expres.versions["0.0.4"] = { at: "2012-10-01T00:00:00.000Z" };
    const live = new LiveIntelligence(new Database(":memory:"));
    vi.spyOn(live, "isInitialized").mockReturnValue(true);
    vi.spyOn(live, "getResolvedDeps").mockReturnValue([{ name: "expres", version: "0.0.4", ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [] }] as never);
    vi.spyOn(live, "getAuditDeps").mockReturnValue([]);
    const [r] = ((await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "expres", from: "0.0.4", to: "0.0.5" }] } as never, live, { now: NOW })) as unknown as { results: Result[] }).results;
    expect(nameCheck(r)).toBeUndefined();
    expect(r.reason).not.toContain("Did you mean");
    expect(downloadRequests).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------
// Established, typo traffic, strong evidence
// ---------------------------------------------------------------------------------------------

describe("what makes a near-miss name established, and what makes it avoid", () => {
  it("an established package is judged as its own: ttypescript (187,006 a week) is proceed, with an info line", async () => {
    expect(nearMissOf("ttypescript")).toEqual({ of: "typescript", closeness: "one_edit" });
    old("ttypescript", "2018-03-01T00:00:00.000Z", "1.5.15");
    Object.assign(DOWNLOADS, { ttypescript: 187_006, typescript: 417_015_344 });
    const [r] = (await check([add("ttypescript")])).results;
    expect(r.verdict).toBe("proceed");
    expect(nameCheck(r)).toMatchObject({ effect: "info" });
    expect(nameCheck(r)!.evidence).toContain("is established in its own right (187,006 downloads a week");
  });

  it("typo traffic: 13,444 a week against lodash's 202 million is under one thousandth, so review (loadsh)", async () => {
    expect(nearMissOf("loadsh")).toEqual({ of: "lodash", closeness: "one_edit" });
    old("loadsh", "2018-09-13T06:41:39.649Z", "0.0.4");
    Object.assign(DOWNLOADS, { loadsh: 13_444, lodash: 202_301_867 });
    const [r] = (await check([add("loadsh")])).results;
    expect(r.verdict).toBe("review");
    expect(r.reason).toContain("it has 13,444 downloads a week, under one thousandth of lodash's 202,301,867");
  });

  it("between 10,000 and 100,000 with the popular package's count unreadable: review, said so", () => {
    const s = nameCheckSignal({
      package: "loadsh",
      nearMiss: { of: "lodash", closeness: "one_edit" },
      downloads: { status: "ok", downloads: 13_444 },
      popularDownloads: { status: "unreachable", detail: "api.npmjs.org answered HTTP 503" },
      createdAt: "2018-09-13T06:41:39.649Z",
      installScripts: [],
      now: NOW,
    });
    expect(s.effect).toBe("review");
    expect(s.evidence).toContain("lodash's own count could not be read to compare");
  });

  it("the thresholds: under 10,000 is low; 100,000 or more is established whatever the popular count", () => {
    const at = (downloads: number, popular: number) =>
      nameCheckSignal({
        package: "expres",
        nearMiss: { of: "express", closeness: "one_edit" },
        downloads: { status: "ok", downloads },
        popularDownloads: { status: "ok", downloads: popular },
        createdAt: "2012-10-10T00:00:00.000Z",
        installScripts: [],
        now: NOW,
      }).effect;
    expect(at(LOW_WEEKLY_DOWNLOADS - 1, 1_000_000)).toBe("review");
    expect(at(LOW_WEEKLY_DOWNLOADS, 1_000_000)).toBe("info");
    expect(at(LOW_WEEKLY_DOWNLOADS, 900_000_000)).toBe("review");
    expect(at(ESTABLISHED_WEEKLY_DOWNLOADS - 1, 900_000_000)).toBe("review");
    expect(at(ESTABLISHED_WEEKLY_DOWNLOADS, 900_000_000)).toBe("info");
  });

  it("a very young package is review even with downloads (first published 40 days ago)", async () => {
    old("expresz", daysAgo(40), "1.0.0");
    expect(nearMissOf("expresz")?.of).toBe("express");
    Object.assign(DOWNLOADS, { expresz: 250_000, express: 195_493_804 });
    const [r] = (await check([add("expresz")])).results;
    expect(r.verdict).toBe("review");
    expect(r.reason).toContain("it was first published 40 days ago");
  });

  it("nobody installs it and it is days old: avoid", async () => {
    old("expresz", daysAgo(5), "1.0.0");
    Object.assign(DOWNLOADS, { expresz: 12, express: 195_493_804 });
    const [r] = (await check([add("expresz")])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.reason).toContain("name_check: expresz is one character away from express");
    expect(r.reason).toContain("where it is 5 days old");
    expect(r.reason).toContain("Do not install it. Did you mean express?");
  });

  it("nobody installs it and it runs install-time scripts: avoid", async () => {
    old("expresz", "2019-01-01T00:00:00.000Z", "1.0.0", { postinstall: "node setup.js" });
    Object.assign(DOWNLOADS, { expresz: 40, express: 195_493_804 });
    const [r] = (await check([add("expresz")])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.reason).toContain("where it runs install-time scripts (postinstall)");
    expect(nameCheck(r)!.value).toMatchObject({ install_scripts: ["postinstall"] });
  });

  it("avoid needs a count that was read: install scripts with the lookup down is review", async () => {
    old("expresz", "2019-01-01T00:00:00.000Z", "1.0.0", { postinstall: "node setup.js" });
    DOWNLOADS_DOWN = true;
    const [r] = (await check([add("expresz")])).results;
    expect(r.verdict).toBe("review");
  });
});

// ---------------------------------------------------------------------------------------------
// The two bars: 200 squat-shaped names, the whole popular list
// ---------------------------------------------------------------------------------------------

const POPULAR = new Set(POPULAR_NPM);

/**
 * Squat-shaped names, built the way squats are: from the first 70 unscoped popular names of five
 * characters or more, one character dropped, the last one doubled, two neighbours swapped, a
 * trailing `s`, and the `js` / `-js` / `.js` / `node-` affixes; plus the three the audit found live.
 */
function squatCorpus(): string[] {
  const out = new Set<string>(["expres", "reactt", "expresss"]);
  for (const p of POPULAR_NPM.filter((n) => !n.startsWith("@") && n.length >= 5).slice(0, 70)) {
    const mid = Math.floor(p.length / 2);
    for (const v of [
      p.slice(0, mid) + p.slice(mid + 1),
      p + p[p.length - 1],
      p.slice(0, 1) + p[2] + p[1] + p.slice(3),
      `${p}s`,
      `${p}js`,
      `${p}-js`,
      `${p}.js`,
      `node-${p}`,
    ]) {
      if (!POPULAR.has(v) && nearMissOf(v) !== null) out.add(v);
    }
  }
  return [...out];
}

async function verdictsOf(names: string[]): Promise<Result[]> {
  const results: Result[] = [];
  for (let i = 0; i < names.length; i += 25) results.push(...(await check(names.slice(i, i + 25).map((n) => add(n)))).results);
  return results;
}

describe("the squat-shaped corpus: none is proceed", () => {
  const corpus = squatCorpus();

  it("holds at least 200 names, none of them a popular name, each a near-miss of one", () => {
    expect(corpus.length).toBeGreaterThanOrEqual(200);
    for (const name of corpus) {
      expect(POPULAR.has(name), name).toBe(false);
      expect(nearMissOf(name), name).not.toBeNull();
    }
  });

  it.each([
    ["with a low download count", () => Object.assign(DOWNLOADS, Object.fromEntries(corpus.map((n, i) => [n, (i * 37) % 9000])), Object.fromEntries(POPULAR_NPM.map((n) => [n, 50_000_000])))],
    ["with no download record at all", () => Object.assign(DOWNLOADS, Object.fromEntries(POPULAR_NPM.map((n) => [n, 50_000_000])))],
    ["with the downloads API down", () => { DOWNLOADS_DOWN = true; }],
    ["with typo traffic of 60,000 a week against 100 million", () => Object.assign(DOWNLOADS, Object.fromEntries(corpus.map((n) => [n, 60_000])), Object.fromEntries(POPULAR_NPM.map((n) => [n, 100_000_000])))],
  ])("%s", async (_label, arrange) => {
    ANY_PACKAGE = true;
    arrange();
    const results = await verdictsOf(corpus);
    expect(results).toHaveLength(corpus.length);
    const proceed = results.filter((r) => r.verdict === "proceed" || r.verdict === "wait").map((r) => r.package);
    expect(proceed).toEqual([]);
    for (const r of results) {
      expect(["review", "avoid"], `${r.package}: ${r.verdict}`).toContain(r.verdict);
      expect(r.reason, r.package).toMatch(/Did you mean [@\w./-]+\?/);
    }
  });
});

describe("the popular list: none is flagged", () => {
  it("nearMissOf is null for every one of the 1,822 names", () => {
    expect(POPULAR_NPM.length).toBe(1822);
    expect(POPULAR_NPM.filter((n) => nearMissOf(n) !== null)).toEqual([]);
  });

  it("every popular name is proceed with no name check, the downloads API down and never asked", async () => {
    ANY_PACKAGE = true;
    DOWNLOADS_DOWN = true;
    const results = await verdictsOf([...POPULAR_NPM]);
    expect(results).toHaveLength(POPULAR_NPM.length);
    expect(results.filter((r) => nameCheck(r) !== undefined).map((r) => r.package)).toEqual([]);
    expect(results.filter((r) => r.verdict !== "proceed").map((r) => `${r.package}: ${r.verdict}`)).toEqual([]);
    expect(downloadRequests).toEqual([]);
  }, 120_000);

  it("a popular name that neighbours another popular one is never flagged (preact and react, chai and chalk)", async () => {
    ANY_PACKAGE = true;
    const { results } = await check([add("preact"), add("chai"), add("chalk")]);
    expect(results.map((r) => r.verdict)).toEqual(["proceed", "proceed", "proceed"]);
    expect(results.some((r) => nameCheck(r))).toBe(false);
  });
});
