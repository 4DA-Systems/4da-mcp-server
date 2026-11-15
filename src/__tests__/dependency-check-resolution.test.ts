// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check judges every release what the agent writes can install, and the worse verdict
 * stands (pre-publish round 10, W2):
 *
 * 1. A bare crates.io version is Cargo's caret requirement. `{smallvec, "1.6.0"}` was judged as an
 *    exact pin only: a Cargo.lock holding 1.6.0 keeps it, a fresh resolve installs the newest 1.x.
 * 2. npm installs its `latest` tag when the range admits it (npm-pick-manifest), not always the
 *    highest release; Yarn and pnpm can install the highest. Both are judged when they differ.
 * 3. crates.io reads `-` and `_` as one crate name: `{serde-json, "1.x"}` was unknown while
 *    `serde_json` was proceed. The published spelling comes from the registry's answer.
 *
 * Registry and record shapes are the real ones (crates.io API, index.crates.io, registry.npmjs.org,
 * api.osv.dev, 2026-11-15), cut down to what decides each case.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { LiveIntelligence } from "../live/index.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import { advisoryAffects, advisoryRanges } from "../live/osv-ranges.js";
import type { PackageReleaseIndex } from "../live/release-metadata.js";
import type { OsvVulnerability } from "../live/types.js";
import { crateSpellingReason, executeDependencyCheck, runDependencyCheck } from "../tools/dependency-check.js";
import { cargoBareVersion, npmPick, worseVerdict } from "../tools/dependency-check-resolution.js";
import type { FourDADatabase } from "../db.js";
import { callFindingKey } from "../call-budget.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-15T00:00:00Z");
const DAY = 86_400_000;
const daysAgo = (n: number) => new Date(NOW.getTime() - n * DAY).toISOString();

/** crates.io: the published name -> version -> publish time. */
let CRATES: Record<string, Record<string, string>>;
let NPM: Record<string, { latest: string; versions: Record<string, { at: string; deprecated?: string }> }>;
let OSV: OsvVulnerability[];
/** Every package name OSV.dev was asked about, as sent. */
let osvNames: string[];
/** Hosts or URL prefixes that fail (simulated outage). */
let down: string[];

/** crates.io and OSV.dev both fold `-`/`_` and case in a crate name (verified live 2026-11-15). */
const fold = (eco: string, name: string) => (eco === "crates.io" ? name.toLowerCase().replace(/_/g, "-") : name);
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (down.some((d) => url.startsWith(d))) throw new TypeError("fetch failed (simulated outage)");
    const recordsFor = (name: string, eco: string) => OSV.filter((v) => v.affected?.some((a) => a.package?.ecosystem === eco && fold(eco, a.package.name) === fold(eco, name)));
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      for (const q of queries) osvNames.push(q.package.name);
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
      osvNames.push(q.package.name);
      return json({ vulns: recordsFor(q.package.name, q.package.ecosystem) });
    }
    const crate = /^https:\/\/crates\.io\/api\/v1\/crates\/([^/?]+)(\/versions)?/.exec(url);
    if (crate) {
      const published = Object.keys(CRATES).find((n) => fold("crates.io", n) === fold("crates.io", decodeURIComponent(crate[1])));
      if (!published) return json({ errors: [{ detail: "Not Found" }] }, 404);
      const versions = Object.entries(CRATES[published])
        .sort(([a], [b]) => (a < b ? 1 : -1))
        .map(([num, at]) => ({ num, created_at: at, yanked: false, published_by: null, trustpub_data: null }));
      return crate[2]
        ? json({ versions, meta: { next_page: null } })
        : json({ crate: { id: published, name: published, created_at: "2018-01-01T00:00:00Z", num_versions: versions.length }, versions });
    }
    if (url.startsWith("https://index.crates.io/")) {
      // The index files a crate under its published spelling only (lowercased): `serde-json` is a 404.
      const file = url.split("/").pop()!;
      const published = Object.keys(CRATES).find((n) => n.toLowerCase() === file);
      if (!published) return new Response("", { status: 404 });
      return new Response(Object.keys(CRATES[published]).map((vers) => JSON.stringify({ name: published, vers, deps: [] })).join("\n"));
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({ error: "Not found" }, 404);
      return json({
        name,
        "dist-tags": { latest: doc.latest },
        versions: Object.fromEntries(Object.entries(doc.versions).map(([v, r]) => [v, { name, version: v, dependencies: {}, ...(r.deprecated ? { deprecated: r.deprecated } : {}) }])),
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
  CRATES = {};
  NPM = {};
  OSV = [];
  osvNames = [];
  down = [];
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

type Result = Record<string, any>;
function live(): LiveIntelligence {
  const l = new LiveIntelligence(new Database(":memory:"));
  // crates.io's one-request-a-second pacing, off for tests.
  (l as unknown as { cratesVersions: { minIntervalMs: number } }).cratesVersions.minIntervalMs = 0;
  return l;
}
const check = async (items: unknown[]) => (await executeDependencyCheck(noDb, { items } as never, live(), { now: NOW })) as unknown as { results: Result[]; summary: string };
const concise = async (items: unknown[]) => (await runDependencyCheck(noDb, { items } as never, live())) as unknown as { results: Result[] };
const rustsec = (id: string, name: string, events: Array<Record<string, string>>, severity = "CRITICAL"): OsvVulnerability =>
  ({ id, aliases: [], summary: `${name} advisory`, database_specific: { severity }, affected: [{ package: { name, ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events }] }] }) as unknown as OsvVulnerability;
const ghsa = (id: string, name: string, events: Array<Record<string, string>>, severity = "HIGH"): OsvVulnerability =>
  ({ id, aliases: [], summary: `${name} advisory`, database_specific: { severity }, affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events }] }] }) as unknown as OsvVulnerability;
const judged = (r: Result) => (r.resolution?.judged ?? []).map((j: { version: string; verdict: string }) => [j.version, j.verdict]);

// ---------------------------------------------------------------------------------------------
// 1. Cargo: a bare version is ^X
// ---------------------------------------------------------------------------------------------

describe("crates.io: a bare version is judged as the release and as the caret requirement Cargo reads", () => {
  beforeEach(() => {
    // smallvec as crates.io lists it: 1.6.0 has RUSTSEC-2021-0003 (fixed 1.6.1); 1.16.5 is the newest 1.x.
    CRATES.smallvec = { "1.5.1": daysAgo(2200), "1.6.0": daysAgo(2100), "1.6.1": daysAgo(2090), "1.15.1": daysAgo(200), "1.16.5": daysAgo(40) };
    OSV.push(rustsec("RUSTSEC-2021-0003", "smallvec", [{ introduced: "0.6.3" }, { fixed: "0.6.14" }, { introduced: "1.0.0" }, { fixed: "1.6.1" }]));
  });

  it('smallvec "1.6.0": avoid, says Cargo reads ^1.6.0, names 1.16.5 as what a fresh resolve installs and a safe pin', async () => {
    const [r] = (await check([{ ecosystem: "crates.io", package: "smallvec", to: "1.6.0" }])).results;
    expect(r).toMatchObject({ to: "1.6.0", to_requested: "1.6.0", verdict: "avoid" });
    expect(r.reason).toContain('Cargo reads a bare "1.6.0" as ^1.6.0: a Cargo.lock that already holds 1.6.0 keeps it');
    expect(r.reason).toContain("a fresh resolve (no Cargo.lock entry, or cargo update) installs 1.16.5, the newest release ^1.6.0 admits");
    expect(r.reason).toContain("RUSTSEC-2021-0003");
    expect(r.reason).toContain('Write "1.16.5"');
    expect(r.to_read_as).toMatch(/^Cargo requirement \^1\.6\.0/);
    expect(judged(r)).toEqual([
      ["1.6.0", "avoid"],
      ["1.16.5", "proceed"],
    ]);
    expect(r.range_check).toMatchObject({ range: "^1.6.0", basis: "requested", smallest_safe_in_range: "1.6.1", newest_safe_in_range: "1.16.5" });
  });

  it('"=1.6.0" stays one exact release: no caret reading, no second release judged', async () => {
    const [r] = (await check([{ ecosystem: "crates.io", package: "smallvec", to: "=1.6.0" }])).results;
    expect(r).toMatchObject({ to: "1.6.0", verdict: "avoid" });
    expect(r.resolution).toBeUndefined();
    expect(r.reason).not.toContain("Cargo reads a bare");
    expect(r.range_check).toMatchObject({ basis: "same_line", range: "1.x" });
  });

  it("an explicit range is unchanged: ^1.6 resolves to its newest release", async () => {
    const [r] = (await check([{ ecosystem: "crates.io", package: "smallvec", to: "^1.6" }])).results;
    expect(r).toMatchObject({ to: "1.16.5", verdict: "proceed" });
    expect(r.resolution).toBeUndefined();
  });

  it("a clean release whose newest compatible release is bad: avoid, with \"=X\" as the pin (a clean exact said proceed)", async () => {
    OSV.push(rustsec("RUSTSEC-2026-9001", "smallvec", [{ introduced: "1.16.0" }]));
    const [r] = (await check([{ ecosystem: "crates.io", package: "smallvec", to: "1.6.1" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(judged(r)).toEqual([
      ["1.6.1", "proceed"],
      ["1.16.5", "avoid"],
    ]);
    expect(r.reason).toContain('Write "=1.6.1" to require exactly 1.6.1 (proceed); as a bare "1.6.1", a fresh resolve installs 1.16.5 (avoid).');
    expect(r.resolution.judged[1].advisories).toEqual(["RUSTSEC-2026-9001"]);
  });

  it("G7: a bare version where the release and the newest compatible one are both clean is proceed", async () => {
    const out = await check([
      { ecosystem: "crates.io", package: "smallvec", to: "1.15.1" },
      { ecosystem: "crates.io", package: "smallvec", to: "1.16.5" },
    ]);
    expect(out.results.map((r) => r.verdict)).toEqual(["proceed", "proceed"]);
    expect(judged(out.results[0])).toEqual([
      ["1.15.1", "proceed"],
      ["1.16.5", "proceed"],
    ]);
    // The newest release itself: one release, nothing judged twice.
    expect(out.results[1].reason).toContain("1.16.5 is the newest release it admits, so a fresh resolve installs 1.16.5 as well.");
    expect(judged(out.results[1])).toEqual([["1.16.5", "proceed"]]);
    expect(out.summary).toMatch(/^2 checked: 2 proceed\./);
  });

  it("a young newest compatible release holds the bare version at wait; =X is the proceed pin", async () => {
    CRATES.smallvec["1.16.6"] = daysAgo(1);
    const [r] = (await check([{ ecosystem: "crates.io", package: "smallvec", to: "1.15.1" }])).results;
    expect(r.verdict).toBe("wait");
    expect(r.reason).toContain('Write "=1.15.1" to require exactly 1.15.1 (proceed)');
  });

  it("the concise answer carries what each release installs when, with its verdict", async () => {
    const [r] = (await concise([{ ecosystem: "crates.io", package: "smallvec", to: "1.6.0" }])).results;
    expect(r.resolution).toEqual({
      reads_as: "^1.6.0",
      judged: [
        { version: "1.6.0", installed_when: "a Cargo.lock already holds 1.6.0", verdict: "avoid", advisories: ["RUSTSEC-2021-0003"] },
        { version: "1.16.5", installed_when: "a fresh resolve (no Cargo.lock entry, or cargo update)", verdict: "proceed", advisories: [] },
      ],
    });
    expect(r.to_read_as).toMatch(/^Cargo requirement \^1\.6\.0/);
  });

  it("cargoBareVersion: only a bare full version; build metadata dropped as Cargo drops it", () => {
    expect(cargoBareVersion("1.6.0")).toBe("1.6.0");
    expect(cargoBareVersion("v1.6.0")).toBe("1.6.0");
    expect(cargoBareVersion("111.10.0+1.1.1g")).toBe("111.10.0");
    expect(cargoBareVersion("1.0.0-rc.2")).toBe("1.0.0-rc.2");
    for (const raw of ["=1.6.0", "==1.6.0", "^1.6.0", "1.6", "1", "latest", ">=1.6.0"]) expect(cargoBareVersion(raw)).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------
// 2. npm: npm's pick and the highest admitted release
// ---------------------------------------------------------------------------------------------

describe("npm: a range is judged at npm's pick and at the highest release it admits", () => {
  it("latest tag below the highest: npm installs latest, Yarn/pnpm the highest; an advisory on the highest makes it avoid", async () => {
    // bunyan's shape (2026-11-15): latest 1.8.15 while 2.0.5 is published.
    NPM.logpkg = { latest: "1.8.15", versions: { "1.8.14": { at: daysAgo(900) }, "1.8.15": { at: daysAgo(800) }, "2.0.5": { at: daysAgo(700) } } };
    OSV.push(ghsa("GHSA-test-0002-0005", "logpkg", [{ introduced: "2.0.0" }]));
    const [r] = (await check([{ ecosystem: "npm", package: "logpkg", to: ">=1.8.0" }])).results;
    expect(r).toMatchObject({ to: "1.8.15", to_requested: ">=1.8.0", verdict: "avoid" });
    expect(r.reason).toContain('npm installs 1.8.15 for ">=1.8.0" (its "latest" dist-tag, which the range admits); Yarn and pnpm can install 2.0.5, the highest release it admits.');
    expect(r.reason).toContain("GHSA-test-0002-0005");
    expect(r.reason).toContain("Pin exactly 1.8.15 (proceed): the range as written lets Yarn or pnpm install 2.0.5 (avoid).");
    expect(judged(r)).toEqual([
      ["1.8.15", "proceed"],
      ["2.0.5", "avoid"],
    ]);
  });

  it("both picks clean: proceed, with both named", async () => {
    NPM.logpkg = { latest: "1.8.15", versions: { "1.8.15": { at: daysAgo(800) }, "2.0.5": { at: daysAgo(700) } } };
    const [r] = (await check([{ ecosystem: "npm", package: "logpkg", to: "*" }])).results;
    expect(r.verdict).toBe("proceed");
    expect(judged(r)).toEqual([
      ["1.8.15", "proceed"],
      ["2.0.5", "proceed"],
    ]);
  });

  it("latest is the highest (the usual case): one release judged, as before", async () => {
    NPM.logpkg = { latest: "2.0.5", versions: { "1.8.15": { at: daysAgo(800) }, "2.0.5": { at: daysAgo(700) } } };
    const [r] = (await check([{ ecosystem: "npm", package: "logpkg", to: "*" }])).results;
    expect(r).toMatchObject({ to: "2.0.5", verdict: "proceed" });
    expect(r.resolution).toBeUndefined();
  });

  it("the highest is deprecated and latest is outside the range: npm takes the highest non-deprecated, the deprecated one is judged too", async () => {
    NPM.logpkg = {
      latest: "3.0.0",
      versions: { "2.0.0": { at: daysAgo(900) }, "2.1.0": { at: daysAgo(800), deprecated: "broken, use 2.0.0" }, "3.0.0": { at: daysAgo(100) } },
    };
    const [r] = (await check([{ ecosystem: "npm", package: "logpkg", to: "^2.0.0" }])).results;
    expect(r.to).toBe("2.0.0");
    expect(r.reason).toContain("the highest release it admits that is not deprecated");
    expect(r.verdict).not.toBe("proceed");
    expect(judged(r)[0]).toEqual(["2.0.0", "proceed"]);
    expect(judged(r)[1][0]).toBe("2.1.0");
  });

  it("npmPick follows npm-pick-manifest: latest when admitted and not deprecated, else highest non-deprecated, else highest", () => {
    const index = (latest: string, deprecated: string[], versions: string[]): PackageReleaseIndex => ({
      ecosystem: "npm",
      name: "x",
      createdAt: null,
      latest,
      releases: Object.fromEntries(
        versions.map((v) => [v, { version: v, publishedAt: null, trust: 0, trustEvidence: "", installScripts: null, deprecated: deprecated.includes(v) ? "old" : null, withdrawn: null, dependencies: null }]),
      ),
    });
    const all = ["1.0.0", "1.1.0", "1.2.0"];
    expect(npmPick(index("1.1.0", [], all), all)).toEqual({ version: "1.1.0", why: "latest" });
    expect(npmPick(index("1.1.0", ["1.1.0"], all), all)).toEqual({ version: "1.2.0", why: "not_deprecated" });
    expect(npmPick(index("9.0.0", ["1.2.0"], all), all)).toEqual({ version: "1.1.0", why: "not_deprecated" });
    expect(npmPick(index("9.0.0", all, all), all)).toEqual({ version: "1.2.0", why: "highest" });
    expect(worseVerdict("wait", "unknown")).toBe("unknown");
    expect(worseVerdict("proceed", "wait")).toBe("wait");
  });
});

// ---------------------------------------------------------------------------------------------
// 3. crates.io: `-` and `_` are one crate name
// ---------------------------------------------------------------------------------------------

describe("crates.io: a crate asked under another spelling is checked as published", () => {
  beforeEach(() => {
    CRATES.serde_json = { "1.0.153": daysAgo(60), "1.0.154": daysAgo(35) };
  });

  it("serde-json 1.x: checked as serde_json (it was unknown), OSV.dev asked under serde_json, and the answer says so", async () => {
    const [r] = (await check([{ ecosystem: "crates.io", package: "serde-json", to: "1.x" }])).results;
    expect(r).toMatchObject({ package: "serde_json", package_requested: "serde-json", to: "1.0.154", verdict: "proceed" });
    expect(r.reason).toMatch(/^serde-json is published as serde_json: crates\.io and Cargo read "-" and "_" in a crate name as the same crate/);
    expect(osvNames.length).toBeGreaterThan(0);
    // The batch query (the verdict) goes out under the published spelling only.
    expect(new Set(osvNames.filter((n) => n !== "serde-json"))).toEqual(new Set(["serde_json"]));
  });

  it("an exact version asked under another spelling (case too) reads the published name from crates.io", async () => {
    const out = await check([
      { ecosystem: "crates.io", package: "Serde-Json", to: "=1.0.154" },
      { ecosystem: "crates.io", package: "serde_json", to: "=1.0.154" },
    ]);
    expect(out.results.map((r) => [r.package, r.verdict])).toEqual([
      ["serde_json", "proceed"],
      ["serde_json", "proceed"],
    ]);
    expect(out.results[0].package_requested).toBe("Serde-Json");
    expect(out.results[1].package_requested).toBeUndefined();
  });

  it("an advisory filed under the published spelling reaches the other spelling: avoid", async () => {
    CRATES["openssl-src"] = { "111.10.0+1.1.1g": daysAgo(2000), "111.28.2+1.1.1w": daysAgo(400) };
    OSV.push(rustsec("RUSTSEC-2021-0057", "openssl-src", [{ introduced: "0.0.0-0" }, { fixed: "111.15.0" }], "HIGH"));
    const [r] = (await check([{ ecosystem: "crates.io", package: "openssl_src", to: "=111.10.0+1.1.1g" }])).results;
    expect(r).toMatchObject({ package: "openssl-src", package_requested: "openssl_src", verdict: "avoid" });
    expect(r.reason).toContain("RUSTSEC-2021-0057");
  });

  it("a finding read under the published spelling answers for the spelling asked (time budget, late answer)", () => {
    expect(callFindingKey("crates.io", "serde-json", "1.x")).toBe(callFindingKey("crates.io", "Serde_JSON", "1.x"));
    expect(callFindingKey("npm", "Foo_Bar", "1.0.0")).not.toBe(callFindingKey("npm", "foo-bar", "1.0.0"));
  });

  it("the published spelling cannot be read: unknown, never clean", async () => {
    // Only the crate lookup fails: the versions list still answers, the sparse index has no `serde-json`.
    vi.stubGlobal(
      "fetch",
      ((orig) => async (input: string | URL, init?: RequestInit) => {
        if (String(input) === "https://crates.io/api/v1/crates/serde-json") throw new TypeError("fetch failed (simulated outage)");
        return orig(input, init);
      })(globalThis.fetch as (input: string | URL, init?: RequestInit) => Promise<Response>),
    );
    const [r] = (await check([{ ecosystem: "crates.io", package: "serde-json", to: "=1.0.154" }])).results;
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toContain("published spelling could not be read");
  });
});

// ---------------------------------------------------------------------------------------------
// W10 (pre-publish round 10): a bare "X" / "X.Y" is a caret range too; crate spelling reasons
// ---------------------------------------------------------------------------------------------

describe("W10: a bare crates.io requirement short of X.Y.Z, and the reason a spelling was folded", () => {
  let dir: string | null = null;
  beforeEach(() => {
    CRATES.smallvec = { "1.5.1": daysAgo(2200), "1.6.0": daysAgo(2100), "1.6.1": daysAgo(2090), "1.15.1": daysAgo(200), "1.16.5": daysAgo(40) };
    OSV.push(rustsec("RUSTSEC-2021-0003", "smallvec", [{ introduced: "0.6.3" }, { fixed: "0.6.14" }, { introduced: "1.0.0" }, { fixed: "1.6.1" }]));
  });
  afterEach(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    dir = null;
  });
  /** A LiveIntelligence over a project whose Cargo.lock holds smallvec `locked`. */
  const withLock = (locked: string): LiveIntelligence => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-w10-cargo-"));
    fs.writeFileSync(path.join(dir, "Cargo.toml"), '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nsmallvec = "1.6"\n');
    fs.writeFileSync(path.join(dir, "Cargo.lock"), `version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["smallvec"]\n\n[[package]]\nname = "smallvec"\nversion = "${locked}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`);
    const l = live();
    const { entries, discovery } = scanProjectTree(dir);
    l.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    return l;
  };

  for (const to of ["1.6", "1"]) {
    it(`smallvec "${to}" with no lockfile: the range's verdict, and a note that a locked older release is kept`, async () => {
      const [r] = (await check([{ ecosystem: "crates.io", package: "smallvec", to }])).results;
      expect(r).toMatchObject({ to: "1.16.5", verdict: "proceed" });
      expect(r.reason).toContain(`Cargo reads a bare "${to}" as ^${to}, a caret range: a Cargo.lock that already holds a release in it keeps that release`);
      expect(r.reason).toMatch(/have a known advisory \(the smallest without one is 1\.6\.1\); a Cargo\.lock holding one keeps it/);
    });
  }

  it('smallvec "1.6" when the project\'s Cargo.lock holds 1.6.0: not proceed, and the locked release named with its advisory', async () => {
    const l = withLock("1.6.0");
    const [r] = ((await executeDependencyCheck(noDb, { items: [{ ecosystem: "crates.io", package: "smallvec", to: "1.6" }] } as never, l, { now: NOW })) as unknown as { results: Result[] }).results;
    expect(r.verdict).not.toBe("proceed");
    expect(r.verdict).toBe("avoid");
    expect(r.reason).toContain("1.6.0 in your Cargo.lock is affected by RUSTSEC-2021-0003");
    expect(judged(r)).toEqual([
      ["1.6.0", "avoid"],
      ["1.16.5", "proceed"],
    ]);
    expect(r.reason).toContain("cargo update -p smallvec");
  });

  it('smallvec "1.6" when the Cargo.lock holds a clean 1.15.1: proceed, the locked release judged', async () => {
    const l = withLock("1.15.1");
    const [r] = ((await executeDependencyCheck(noDb, { items: [{ ecosystem: "crates.io", package: "smallvec", to: "1.6" }] } as never, l, { now: NOW })) as unknown as { results: Result[] }).results;
    expect(r.verdict).toBe("proceed");
    expect(judged(r)[0]).toEqual(["1.15.1", "proceed"]);
  });

  it('"Smallvec" (case only) says letter case; "serde-json" says "-" and "_"; both differences say both', () => {
    expect(crateSpellingReason("Smallvec", "smallvec")).toBe("crates.io treats crate names that differ only in letter case as the same crate");
    expect(crateSpellingReason("serde-json", "serde_json")).toBe('crates.io and Cargo read "-" and "_" in a crate name as the same crate');
    expect(crateSpellingReason("Serde-Json", "serde_json")).toMatch(/letter case or in "-" against "_"/);
  });

  it('{crates.io, "Smallvec", "=1.6.0"}: the answer gives letter case as the reason', async () => {
    const [r] = (await check([{ ecosystem: "crates.io", package: "Smallvec", to: "=1.6.0" }])).results;
    expect(r.package).toBe("smallvec");
    expect(r.reason).toMatch(/^Smallvec is published as smallvec: crates\.io treats crate names that differ only in letter case as the same crate/);
    expect(r.reason).not.toContain('"-" and "_"');
  });
});
