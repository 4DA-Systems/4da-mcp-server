// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check must never hand an agent a harmful or absurd answer (audit 2026-11-10).
 *
 * Y2: a typo-squat npm took down (`lodahs` -> 0.0.1-security, MAL-2025-25502) said proceed.
 * Y3: `nx` latest said "Newest safe release outside it: 13.2.4" (2021, eleven majors back) because
 *     every 24.x exact-pins minimatch 10.2.5, which a moderate ReDoS affects.
 *
 * Record and registry shapes are the real ones (api.osv.dev, registry.npmjs.org, 2026-11-10), cut
 * down to what decides each case. The squat corpus is 43 names verified live that day: npm holds
 * each with a security placeholder and OSV.dev records it as malware.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { advisoryAffects, advisoryRanges } from "../live/osv-ranges.js";
import type { OsvVulnerability } from "../live/types.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { closestPopularNpm, editDistance } from "../tools/dependency-check-malicious.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-10T00:00:00Z");

interface Pkg {
  latest: string;
  /** version -> { published, dependencies } */
  versions: Record<string, { at: string; dependencies?: Record<string, string> }>;
  /** Releases the registry once had and no longer serves (in `time` only). */
  unpublished?: Record<string, string>;
}
let NPM: Record<string, Pkg>;
let OSV: OsvVulnerability[];
let OSV_PACKAGE_LIST_DOWN: boolean;

const range = (name: string, events: Array<Record<string, string>>) => [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events }] }];
const record = (id: string, name: string, events: Array<Record<string, string>>, extra: Partial<OsvVulnerability> = {}): OsvVulnerability =>
  ({ id, aliases: [], summary: `${name} advisory`, affected: range(name, events), ...extra }) as OsvVulnerability;

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const recordsFor = (name: string) => OSV.filter((v) => v.affected?.some((a) => a.package?.name === name));
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      // OSV's own per-version answer, by the same range reading OSV documents.
      return json({
        results: queries.map((q) => ({
          vulns: recordsFor(q.package.name)
            .filter((v) => advisoryAffects(advisoryRanges(v, q.package.name, "npm")!, q.version, "npm"))
            .map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" })),
        })),
      });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = OSV.find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      if (OSV_PACKAGE_LIST_DOWN) return new Response("unavailable", { status: 503 });
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: recordsFor(q.package.name) });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({ error: "Not found" }, 404);
      const versions = Object.fromEntries(Object.entries(doc.versions).map(([v, r]) => [v, { name, version: v, dependencies: r.dependencies ?? {} }]));
      const time = {
        created: "2015-01-01T00:00:00.000Z",
        ...Object.fromEntries(Object.entries(doc.versions).map(([v, r]) => [v, r.at])),
        ...(doc.unpublished ?? {}),
      };
      return json({ name, "dist-tags": { latest: doc.latest }, versions, time });
    }
    return json({}, 404);
  });
}

let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  NPM = {};
  OSV = [];
  OSV_PACKAGE_LIST_DOWN = false;
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const check = async (items: unknown[]) =>
  (await executeDependencyCheck(noDb, { items } as never, new LiveIntelligence(new Database(":memory:")), { now: NOW })) as { results: Array<Record<string, any>> };
const advisoriesOf = (r: Record<string, any>) => (r.signals as Array<{ id: string; value: any; effect: string; evidence: string }>).find((s) => s.id === "advisories");

// ---------------------------------------------------------------------------------------------
// Y2: names that are malware
// ---------------------------------------------------------------------------------------------

/** Taken down in 2025: only the placeholder is listed; a MAL record from "0" and the GHSA "is malware" record. */
const SQUATS_2025 = ["lodahs", "electorn", "loadyaml", "discordi.js", "axois", "axioss", "chalkk"];
/** The 2017 batch: the placeholder is `latest`, the malicious 1.0.x still listed, one GHSA "is malware" record (CWE-506). */
const SQUATS_2017 = [
  "crossenv", "babelcli", "d3.js", "fabric-js", "ffmepg", "gruntcli", "http-proxy.js", "jquery.js", "mongose", "mssql.js",
  "mssql-node", "mysqljs", "node-fabric", "node-opencv", "node-opensl", "node-openssl", "node-sqlite", "node-tkinter",
  "nodecaffe", "nodefabric", "nodeffmpeg", "nodemailer-js", "nodemailer.js", "nodemssql", "noderequest", "nodesass",
  "nodesqlite", "opencv.js", "openssl.js", "proxy.js", "shadowsock", "smb", "sqlite.js", "sqliter", "sqlserver", "tkinter",
];

function squat2025(name: string, n: number) {
  NPM[name] = { latest: "0.0.1-security", versions: { "0.0.1-security": { at: "2025-06-01T00:00:00.000Z" } }, unpublished: { "1.0.0": "2025-05-30T00:00:00.000Z" } };
  OSV.push(record(`MAL-2025-${20000 + n}`, name, [{ introduced: "0" }], { summary: `Malicious code in ${name} (npm)` }));
  OSV.push(record(`GHSA-squat-${n}`, name, [{ introduced: "0.0.1" }], { summary: `${name} is malware`, database_specific: { severity: "HIGH", cwe_ids: ["CWE-506"] } }));
}

function squat2017(name: string, n: number) {
  NPM[name] = {
    latest: "0.0.2-security",
    versions: {
      "0.0.1-security": { at: "2017-08-02T00:00:00.000Z" },
      "1.0.0": { at: "2017-07-19T00:00:00.000Z" },
      "0.0.2-security": { at: "2018-01-01T00:00:00.000Z" },
    },
    unpublished: { "1.0.1": "2017-07-20T00:00:00.000Z" },
  };
  OSV.push(record(`GHSA-2017-${n}`, name, [{ introduced: "0" }, { last_affected: "1.0.1" }], { summary: `${name} is malware`, database_specific: { severity: "HIGH", cwe_ids: ["CWE-506"] } }));
}

/** A real package with real releases; `malicious` lists hijacked releases (chalk 5.6.1, MAL-2025-46969 by version). */
function legit(name: string, latest: string, versions: string[], malicious: string[] = []) {
  NPM[name] = { latest, versions: Object.fromEntries(versions.map((v, i) => [v, { at: new Date(Date.UTC(2024, 0, 1 + i)).toISOString() }])) };
  if (malicious.length > 0) {
    OSV.push({ id: `MAL-${name}`, aliases: [], summary: `Malicious code in ${name} (npm)`, affected: [{ package: { name, ecosystem: "npm" }, versions: malicious }] } as unknown as OsvVulnerability);
  }
}

describe("Y2: a name npm took down as malware is never proceed", () => {
  it("the 43-name corpus: avoid for latest, a constraint and the placeholder itself", async () => {
    SQUATS_2025.forEach(squat2025);
    SQUATS_2017.forEach(squat2017);
    const names = [...SQUATS_2025, ...SQUATS_2017];
    expect(names).toHaveLength(43);
    for (const to of ["latest", "^1.0.0", "0.0.2-security"]) {
      const items = names.map((p) => ({ ecosystem: "npm", package: p, to: SQUATS_2025.includes(p) && to === "0.0.2-security" ? "0.0.1-security" : to }));
      for (let i = 0; i < items.length; i += 25) {
        const out = await check(items.slice(i, i + 25));
        for (const r of out.results) {
          expect(r.verdict, `${r.package} ${r.to_requested ?? r.to}: ${r.reason}`).toBe("avoid");
          expect(advisoriesOf(r)!.value.malicious_package).toBeDefined();
        }
      }
    }
  });

  it("lodahs: names the placeholder, the records and the package it imitates", async () => {
    squat2025("lodahs", 1);
    const [r] = (await check([{ ecosystem: "npm", package: "lodahs", to: "latest" }])).results;
    expect(r).toMatchObject({ to: "0.0.1-security", verdict: "avoid" });
    expect(r.reason).toMatch(/npm took lodahs down as malware and holds the name with an empty security placeholder \(0\.0\.1-security\); GHSA-squat-1, MAL-2025-20001 record it as a malicious package\. Do not install it\. Did you mean lodash\?/);
    expect(advisoriesOf(r)!.value.malicious_package).toEqual({ ids: ["GHSA-squat-1", "MAL-2025-20001"], taken_down: true, did_you_mean: "lodash" });
  });

  it("the placeholder alone is enough: avoid when OSV.dev's package list cannot be read", async () => {
    squat2025("electorn", 2);
    OSV_PACKAGE_LIST_DOWN = true;
    const [r] = (await check([{ ecosystem: "npm", package: "electorn", to: "latest" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.reason).toMatch(/empty security placeholder \(0\.0\.1-security\)\. Do not install it\. Did you mean electron\?/);
  });

  it("an installed placeholder being moved: avoid, and remove it", async () => {
    squat2017("crossenv", 3);
    const [r] = (await check([{ ecosystem: "npm", package: "crossenv", from: "0.0.2-security", to: "0.0.2-security" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.reason).toMatch(/Remove the installed crossenv@0\.0\.2-security as well\. Did you mean cross-env\?/);
  });

  it("a name the registry no longer has, with a malware record: avoid, not unknown", async () => {
    OSV.push(record("MAL-2026-1", "reqeusts-lib", [{ introduced: "0" }], { summary: "Malicious code in reqeusts-lib (npm)" }));
    const [r] = (await check([{ ecosystem: "npm", package: "reqeusts-lib", to: "1.0.0" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.reason).toMatch(/MAL-2026-1 records reqeusts-lib as a malicious package: the name itself/);
  });

  it("a name the registry does not have, with no record: still unknown, with a did-you-mean", async () => {
    const [r] = (await check([{ ecosystem: "npm", package: "expresss", to: "4.21.0" }])).results;
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toMatch(/check the name for a typo or a hallucinated package before adding it \(did you mean express\?\)/);
  });
});

describe("Y2: real packages are never avoided for being popular, or for one hijacked release", () => {
  beforeEach(() => {
    legit("lodash", "4.17.21", ["4.17.20", "4.17.21"]);
    legit("express", "5.1.0", ["4.21.2", "5.0.0", "5.1.0"]);
    legit("react", "19.2.0", ["18.3.1", "19.1.0", "19.2.0"]);
    // MAL-2025-46969 lists chalk 5.6.1 only (the September 2025 hijack); the release is gone from the registry.
    legit("chalk", "5.6.2", ["5.6.0", "5.6.2"], ["5.6.1"]);
    NPM.chalk.unpublished = { "5.6.1": "2025-09-08T00:00:00.000Z" };
    legit("debug", "4.4.3", ["4.4.1", "4.4.3"], ["4.4.2"]);
    NPM.debug.unpublished = { "4.4.2": "2025-09-08T00:00:00.000Z" };
  });

  it("latest of each is proceed; the hijacked release itself stays avoid", async () => {
    const out = await check([
      ...["lodash", "express", "react", "chalk", "debug"].map((p) => ({ ecosystem: "npm", package: p, to: "latest" })),
      { ecosystem: "npm", package: "chalk", to: "5.6.1" },
      { ecosystem: "npm", package: "debug", to: "4.4.2" },
    ]);
    const verdicts = Object.fromEntries(out.results.map((r) => [`${r.package}@${r.to}`, r.verdict]));
    expect(verdicts).toMatchObject({ "lodash@4.17.21": "proceed", "express@5.1.0": "proceed", "react@19.2.0": "proceed", "chalk@5.6.2": "proceed", "debug@4.4.3": "proceed" });
    expect(verdicts["chalk@5.6.1"]).toBe("avoid");
    expect(verdicts["debug@4.4.2"]).toBe("avoid");
    for (const r of out.results) expect(advisoriesOf(r)?.value?.malicious_package, `${r.package}@${r.to}`).toBeUndefined();
  });
});

describe("did you mean: the popular package a name is a near-miss of", () => {
  it("transpositions, dropped separators and affixes", () => {
    expect(closestPopularNpm("lodahs")).toBe("lodash");
    expect(closestPopularNpm("electorn")).toBe("electron");
    expect(closestPopularNpm("crossenv")).toBe("cross-env");
    expect(closestPopularNpm("babelcli")).toBe("babel-cli");
    expect(closestPopularNpm("mongose")).toBe("mongoose");
    expect(closestPopularNpm("nodesass")).toBe("node-sass");
    expect(closestPopularNpm("jquery.js")).toBe("jquery");
    expect(closestPopularNpm("nodemailer.js")).toBe("nodemailer");
    expect(closestPopularNpm("d3.js")).toBe("d3");
    expect(closestPopularNpm("axois")).toBe("axios");
  });

  it("no suggestion for a popular name itself, for short names, or for nothing close", () => {
    for (const name of POPULAR_NPM) expect(closestPopularNpm(name), name).toBeNull();
    expect(closestPopularNpm("smb")).toBeNull();
    expect(closestPopularNpm("loadyaml")).toBeNull();
    expect(closestPopularNpm("zzqx-internal-tool")).toBeNull();
  });

  it("the bundled list holds no name a malware record covers (fs, the npm placeholder, and two spam packages were left out)", () => {
    for (const bad of ["fs", "acertea", "anakjalanan", ...SQUATS_2025, ...SQUATS_2017]) expect(POPULAR_NPM, bad).not.toContain(bad);
  });

  it("edit distance counts an adjacent transposition as one edit and stops past the limit", () => {
    expect(editDistance("lodahs", "lodash", 2)).toBe(1);
    expect(editDistance("crossenv", "cross-env", 2)).toBe(1);
    expect(editDistance("abc", "abc", 2)).toBe(0);
    expect(editDistance("react", "preact", 2)).toBe(1);
    expect(editDistance("kitten", "sitting", 2)).toBe(3);
    expect(editDistance("a", "abcdef", 2)).toBe(3);
  });
});

// ---------------------------------------------------------------------------------------------
// Y3: no absurd steering for a moderate held advisory
// ---------------------------------------------------------------------------------------------

/** nx's shape on 2026-11-10: 13.2.4 holds nothing; 22.x pins minimatch 9.0.3; 23.x and 24.x pin 10.2.5. */
function nxShape(childSeverity = "MODERATE") {
  NPM.nx = {
    latest: "24.0.5",
    versions: {
      "13.2.4": { at: "2021-12-07T17:48:10.449Z" },
      "21.4.0": { at: "2025-08-20T00:00:00.000Z", dependencies: { minimatch: "9.0.3" } },
      "22.0.0": { at: "2025-10-22T16:24:27.142Z", dependencies: { minimatch: "9.0.3" } },
      "23.0.0": { at: "2026-06-16T16:06:46.654Z", dependencies: { minimatch: "10.2.5" } },
      "23.3.1": { at: "2026-10-23T18:57:04.844Z", dependencies: { minimatch: "10.2.5" } },
      "24.0.0": { at: "2026-10-23T20:52:24.258Z", dependencies: { minimatch: "10.2.5" } },
      "24.0.5": { at: "2026-11-06T20:23:54.269Z", dependencies: { minimatch: "10.2.5" } },
    },
  };
  NPM.minimatch = {
    latest: "11.0.1",
    versions: Object.fromEntries(["3.0.4", "9.0.3", "10.2.5", "11.0.1"].map((v) => [v, { at: "2025-01-01T00:00:00.000Z" }])),
  };
  // GHSA-g3hv-75wg-m249: introduced 7.0.0, fixed 11.0.1, MODERATE.
  OSV.push(record("GHSA-g3hv-75wg-m249", "minimatch", [{ introduced: "7.0.0" }, { fixed: "11.0.1" }], { database_specific: { severity: childSeverity } }));
}

describe("Y3: a moderate advisory a release holds never steers to a release years older", () => {
  it("nx latest: review naming minimatch, its advisory and the override; 13.2.4 is not offered", async () => {
    nxShape();
    const [r] = (await check([{ ecosystem: "npm", package: "nx", to: "latest" }])).results;
    expect(r).toMatchObject({ to: "24.0.5", verdict: "review" });
    expect(r.range_check.newest_safe_outside_range).toBeNull();
    expect(r.range_check.held_advice).toEqual({
      dependencies: [{ package: "minimatch", installs: "10.2.5", advisories: ["GHSA-g3hv-75wg-m249"], severity: "medium", fixed_in: "11.0.1" }],
      not_offered: { version: "13.2.4", published: "2021-12-07T17:48:10.449Z", reason: "11 majors below 24.0.5 and published 2021-12-07, more than 18 months ago" },
    });
    expect(r.reason).not.toMatch(/Newest safe release outside it/);
    expect(r.reason).toMatch(/24\.0\.5 holds minimatch 10\.2\.5 \(GHSA-g3hv-75wg-m249, medium\)/);
    expect(r.reason).toMatch(/13\.2\.4, the newest release clear of every advisory, is not offered: 11 majors below 24\.0\.5/);
    expect(r.reason).toMatch(/override minimatch to 11\.0\.1, a new major of minimatch: check that nx works with it \(npm "overrides", pnpm "overrides", Yarn "resolutions"\), or wait for a later nx release/);
  });

  it("a constraint (^24) reads the same", async () => {
    nxShape();
    const [r] = (await check([{ ecosystem: "npm", package: "nx", to: "^24.0.0" }])).results;
    expect(r.verdict).toBe("review");
    expect(r.range_check).toMatchObject({ basis: "requested", newest_safe_outside_range: null });
    expect(r.range_check.held_advice.not_offered.version).toBe("13.2.4");
  });

  it("a release one major back, recent and clean, is still offered", async () => {
    nxShape();
    NPM.nx.versions["23.3.1"].dependencies = { minimatch: "^11.0.1" }; // a wide range: not held
    const [r] = (await check([{ ecosystem: "npm", package: "nx", to: "latest" }])).results;
    expect(r.verdict).toBe("review");
    expect(r.range_check.newest_safe_outside_range).toBe("23.3.1");
    expect(r.range_check.held_advice.not_offered).toBeUndefined();
    expect(r.reason).toMatch(/Newest safe release outside it: 23\.3\.1\./);
  });

  it("a high held advisory stays avoid, and its alternatives are left as they were", async () => {
    nxShape("HIGH");
    const [r] = (await check([{ ecosystem: "npm", package: "nx", to: "latest" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.range_check.held_advice).toBeUndefined();
    expect(r.range_check.newest_safe_outside_range).toBe("13.2.4");
  });

  it("a release with its own high advisory stays avoid; the alternative is the newest release clear of its own advisories", async () => {
    nxShape();
    OSV.push(record("GHSA-nx21-high", "nx", [{ introduced: "21.0.0" }, { last_affected: "21.9.9" }], { database_specific: { severity: "HIGH" } }));
    const [r] = (await check([{ ecosystem: "npm", package: "nx", to: "21.4.0" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.range_check.newest_safe_outside_range).toBeNull();
    expect(r.range_check.held_advice).toMatchObject({ alternative: "24.0.5", not_offered: { version: "13.2.4" } });
    expect(r.reason).toMatch(/The newest release clear of nx's own advisories is 24\.0\.5, which holds minimatch 10\.2\.5 \(GHSA-g3hv-75wg-m249, medium\)/);
    expect(r.reason).toMatch(/To install 24\.0\.5 without it, override minimatch to 11\.0\.1/);
  });

  it("a malicious release stays avoid (nx 21.5.0-like: a MAL record on that release)", async () => {
    nxShape();
    NPM.nx.versions["21.5.0"] = { at: "2025-08-26T00:00:00.000Z" };
    OSV.push({ id: "MAL-2025-nx", aliases: [], summary: "Malicious code in nx (npm)", affected: [{ package: { name: "nx", ecosystem: "npm" }, versions: ["21.5.0"] }] } as unknown as OsvVulnerability);
    const out = await check([{ ecosystem: "npm", package: "nx", to: "21.5.0" }, { ecosystem: "npm", package: "nx", to: "latest" }]);
    expect(out.results[0].verdict).toBe("avoid");
    expect(out.results[0].reason).toMatch(/MAL-2025-nx \(critical\)/);
    // One hijacked release does not make the name malware.
    expect(out.results[1].verdict).toBe("review");
    expect(advisoriesOf(out.results[1])!.value.malicious_package).toBeUndefined();
  });
});
