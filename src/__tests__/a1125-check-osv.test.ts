// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish audit 2026-11-25, track C: dependency_check answers when OSV.dev or a registry answers
 * only in part. The registries and OSV.dev are stubbed with their real response shapes.
 *
 * C-1: querybatch answering `{}` for everything while /v1/query fails made lodash 4.17.20 `proceed`
 *      and cached it: a clean batch answer that could not be held against the package's own list is
 *      NOT CHECKED, and not kept.
 * C-2: a failed /v1/vulns read of the GHSA alias an ungraded record is graded by turned `avoid` into
 *      `review`: the grade was not read, so it counts as high, and the reason says so.
 * C-4: this server's own request limit for npm, PyPI and crates.io is named as such, with
 *      retry_after_seconds, never as "Registry could not be reached".
 * C-6: with no network every item is unknown and the summary leads NOT CHECKED; `_meta.offline_note`
 *      says FOURDA_OFFLINE is not set; a bare crate version claims no "newest release" it never read.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { LiveCache } from "../live/cache.js";
import { RateLimiter } from "../live/rate-limiter.js";
import { NpmPackumentReader } from "../live/npm-packument.js";
import { PypiReleasesReader } from "../live/pypi-releases.js";
import { CratesVersionsReader } from "../live/crates-versions.js";
import { advisoryAffects, advisoryRanges } from "../live/osv-ranges.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const NOW = Date.now();
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString();

let NPM: Record<string, string[]>;
let PYPI: Record<string, string[]>;
let CRATES: Record<string, string[]>;
let OSV: OsvVulnerability[];
/** querybatch answers `{}` for every release. */
let BATCH_EMPTY: boolean;
/** /v1/query (a package's advisory list) answers 503. */
let LIST_DOWN: boolean;
/** /v1/vulns/<id> ids answered 500. */
let VULNS_DOWN: (id: string) => boolean;
/** Every request fails as a dead network does. */
let DEAD: boolean;
let batches: number;

function record(id: string, ecosystem: string, name: string, events: Record<string, string>[], severity: string | null, extra: Partial<OsvVulnerability> = {}): OsvVulnerability {
  return {
    id,
    aliases: [],
    summary: `${name} advisory ${id}`,
    ...(severity ? { database_specific: { severity } } : {}),
    affected: [{ package: { name, ecosystem }, ranges: [{ type: ecosystem === "PyPI" ? "ECOSYSTEM" : "SEMVER", events }] }],
    ...extra,
  } as OsvVulnerability;
}

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (DEAD) throw new TypeError("fetch failed");
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const same = (a: string, b: string, eco: string) => (eco === "PyPI" ? a.toLowerCase() === b.toLowerCase() : a === b);
    const recordsFor = (name: string, eco: string) => OSV.filter((v) => v.affected?.some((a) => a.package?.ecosystem === eco && same(a.package.name, name, eco)));
    const affects = (v: OsvVulnerability, name: string, eco: string, version: string) => {
      const ranges = advisoryRanges(v, name, eco);
      return ranges ? advisoryAffects(ranges, version, eco) : false;
    };
    if (url.endsWith("/v1/querybatch")) {
      batches++;
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return json({
        results: queries.map((q) => {
          if (BATCH_EMPTY) return {};
          const ids = recordsFor(q.package.name, q.package.ecosystem).filter((v) => affects(v, q.package.name, q.package.ecosystem, q.version)).map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" }));
          return ids.length > 0 ? { vulns: ids } : {};
        }),
      });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      if (VULNS_DOWN(id)) return new Response("internal error", { status: 500 });
      const found = OSV.find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      if (LIST_DOWN) return new Response("unavailable", { status: 503 });
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string }; version?: string };
      const list = recordsFor(q.package.name, q.package.ecosystem);
      return json({ vulns: q.version ? list.filter((v) => affects(v, q.package.name, q.package.ecosystem, q.version!)) : list });
    }
    if (url.startsWith("https://api.npmjs.org/downloads/")) return json({ downloads: 50_000_000, package: "x" });
    const crate = /^https:\/\/crates\.io\/api\/v1\/crates\/([^/?]+)(\/versions)?/.exec(url);
    if (crate) {
      const name = decodeURIComponent(crate[1]);
      const versions = CRATES[name];
      if (!versions) return json({ errors: [{ detail: "Not Found" }] }, 404);
      const list = versions.map((num) => ({ num, created_at: daysAgo(300), yanked: false }));
      return crate[2] ? json({ versions: list, meta: { next_page: null } }) : json({ crate: { name, created_at: daysAgo(900), num_versions: list.length }, versions: list });
    }
    if (url.startsWith("https://index.crates.io/")) {
      const name = url.split("/").pop()!;
      const versions = CRATES[name];
      return versions ? new Response(versions.map((vers) => JSON.stringify({ name, vers, deps: [], yanked: false })).join("\n")) : new Response("", { status: 404 });
    }
    const pypiRelease = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/([^/]+)\/json$/.exec(url);
    if (pypiRelease) {
      const name = Object.keys(PYPI).find((n) => n.toLowerCase() === decodeURIComponent(pypiRelease[1]).toLowerCase());
      const version = decodeURIComponent(pypiRelease[2]);
      return name && PYPI[name].includes(version) ? json({ info: { name, version, requires_dist: null } }) : json({ message: "Not Found" }, 404);
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      const name = Object.keys(PYPI).find((n) => n.toLowerCase() === decodeURIComponent(pypi[1]).toLowerCase());
      if (!name) return json({ message: "Not Found" }, 404);
      return json({ info: { name }, releases: Object.fromEntries(PYPI[name].map((v) => [v, [{ upload_time_iso_8601: daysAgo(300), yanked: false }]])) });
    }
    const one = /^https:\/\/registry\.npmjs\.org\/([^/@][^/]*)\/([^/]+)$/.exec(url);
    if (one) {
      const name = decodeURIComponent(one[1]);
      const v = decodeURIComponent(one[2]);
      return NPM[name]?.includes(v) ? json({ name, version: v, dependencies: {} }) : json({}, 404);
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const versions = NPM[name];
      if (!versions) return json({ error: "Not found" }, 404);
      return json({
        name,
        "dist-tags": { latest: versions[versions.length - 1] },
        versions: Object.fromEntries(versions.map((v) => [v, { name, version: v, dependencies: {} }])),
        time: { created: "2015-01-01T00:00:00.000Z", modified: daysAgo(1), ...Object.fromEntries(versions.map((v) => [v, daysAgo(300)])) },
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
  NPM = { lodash: ["4.17.19", "4.17.20", "4.17.21"], ms: ["2.1.2", "2.1.3"] };
  PYPI = { Jinja2: ["3.1.2", "3.1.3"] };
  CRATES = { time: ["0.3.19", "0.3.20"] };
  OSV = [record("GHSA-35jh-r3h4-6jhm", "npm", "lodash", [{ introduced: "0" }, { fixed: "4.17.21" }], "HIGH")];
  BATCH_EMPTY = false;
  LIST_DOWN = false;
  VULNS_DOWN = () => false;
  DEAD = false;
  batches = 0;
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

type Answer = { summary: string; results: Array<Record<string, any>>; _meta: Record<string, any> };
const run = async (items: unknown[], li = new LiveIntelligence(new Database(":memory:"))) => (await executeDependencyCheck(noDb, { items, response_format: "detailed" } as never, li)) as unknown as Answer;

describe("C-1: a clean batch answer the package's own list could not confirm is NOT CHECKED", () => {
  const items = [
    { ecosystem: "npm", package: "lodash", to: "4.17.20" },
    { ecosystem: "npm", package: "ms", to: "2.1.3" },
  ];

  it("healthy: lodash 4.17.20 avoid, ms 2.1.3 proceed (an empty list confirms a clean answer)", async () => {
    const { results } = await run(items);
    expect(results.map((r) => r.verdict)).toEqual(["avoid", "proceed"]);
  });

  it("querybatch `{}` + /v1/query 503: no proceed, NOT CHECKED, and a later healthy call is not answered from it", async () => {
    BATCH_EMPTY = true;
    LIST_DOWN = true;
    const li = new LiveIntelligence(new Database(":memory:"));
    const first = await run(items, li);
    expect(first.results.map((r) => r.verdict)).toEqual(["unknown", "unknown"]);
    for (const r of first.results) expect(r.reason).toMatch(/NOT CHECKED: OSV\.dev's batch query named no advisory for .* own advisory list .* could not be read/);
    expect(first.summary).toMatch(/^NOT CHECKED/);
    BATCH_EMPTY = false;
    LIST_DOWN = false;
    const before = batches;
    const second = await run(items, li);
    expect(batches).toBeGreaterThan(before);
    expect(second.results.map((r) => r.verdict)).toEqual(["avoid", "proceed"]);
  });

  it("an advisory the batch names still stands when the list cannot be read", async () => {
    LIST_DOWN = true;
    const { results } = await run([{ ecosystem: "npm", package: "lodash", to: "4.17.20" }]);
    expect(results[0].verdict).toBe("avoid");
  });
});

describe("C-2: an advisory graded only through an alias that could not be read counts as high", () => {
  beforeEach(() => {
    // An ungraded PYSEC record whose GHSA alias carries the grade (the GHSA names another package, as Go's do).
    OSV.push(record("PYSEC-2024-1", "PyPI", "Jinja2", [{ introduced: "0" }, { fixed: "3.1.3" }], null, { aliases: ["GHSA-h5c8-rqwp-cp95"] }));
    OSV.push(record("GHSA-h5c8-rqwp-cp95", "PyPI", "jinja2-other", [{ introduced: "0" }], "HIGH", { aliases: ["PYSEC-2024-1"] }));
  });
  const item = [{ ecosystem: "PyPI", package: "Jinja2", to: "3.1.2" }];

  it("healthy: avoid, graded per the alias", async () => {
    const { results } = await run(item);
    expect(results[0].verdict).toBe("avoid");
    expect(results[0].reason).toMatch(/high, per GHSA-h5c8-rqwp-cp95/);
  });

  it("the alias read fails: still avoid, and the reason says the grade was not read", async () => {
    VULNS_DOWN = (id) => id.startsWith("GHSA-");
    const { results } = await run(item);
    expect(results[0].verdict).toBe("avoid");
    expect(results[0].reason).toMatch(/severity NOT CHECKED: .*GHSA-h5c8-rqwp-cp95 could not be read/);
  });

  it("an alias read that answers with a moderate grade is review, not avoid (no over-withholding)", async () => {
    OSV[OSV.length - 1] = record("GHSA-h5c8-rqwp-cp95", "PyPI", "jinja2-other", [{ introduced: "0" }], "MODERATE", { aliases: ["PYSEC-2024-1"] });
    const { results } = await run(item);
    expect(results[0].verdict).toBe("review");
  });
});

describe("C-4: this server's own request limit is named as such, with when to ask again", () => {
  const spent = (bucket: string) => {
    const limiter = new RateLimiter({ [bucket]: { maxPerMinute: 1 } });
    limiter.consume(bucket);
    return limiter;
  };
  const cache = () => new LiveCache(new Database(":memory:"));

  it("npm", async () => {
    const r = await new NpmPackumentReader(cache(), spent("npm")).getReleases("lodash");
    expect(r).toMatchObject({ status: "unreachable", ownLimit: { registry: "the npm registry" } });
    expect((r as { ownLimit: { retryAfterSeconds: number } }).ownLimit.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect((r as { detail: string }).detail).toMatch(/own request limit/);
  });

  it("PyPI: the release list and a release's requirements", async () => {
    const r = await new PypiReleasesReader(cache(), spent("pypi")).getReleases("Jinja2");
    expect(r).toMatchObject({ status: "unreachable", ownLimit: { registry: "PyPI" } });
    const q = await new PypiReleasesReader(cache(), spent("fixpath-registry")).getRequirements("Jinja2", "3.1.2");
    expect(q).toMatchObject({ status: "unreachable", ownLimit: { registry: "PyPI" } });
  });

  it("crates.io", async () => {
    const r = await new CratesVersionsReader(cache(), spent("crates"), 0).getReleases("time", []);
    expect(r).toMatchObject({ status: "unreachable", ownLimit: { registry: "crates.io" } });
    expect((r as { detail: string }).detail).not.toMatch(/crates\.io rate limit reached/);
  });

  it("not the limit: a registry failure is still worded as the registry's", async () => {
    DEAD = true;
    const r = await new NpmPackumentReader(cache(), new RateLimiter({ npm: { maxPerMinute: 10 } })).getReleases("lodash");
    expect(r).toMatchObject({ status: "unreachable" });
    expect((r as { ownLimit?: unknown }).ownLimit).toBeUndefined();
  });
});

describe("C-6: with no network the answer leads NOT CHECKED and claims nothing it did not read", () => {
  const items = [
    { ecosystem: "npm", package: "lodash", to: "4.17.20" },
    { ecosystem: "crates.io", package: "time", to: "0.3.20" },
    { ecosystem: "PyPI", package: "Jinja2", to: "3.1.2" },
  ];

  it("dead network, FOURDA_OFFLINE unset", async () => {
    DEAD = true;
    const a = await run(items);
    expect(a.results.map((r) => r.verdict)).toEqual(["unknown", "unknown", "unknown"]);
    expect(a.summary).toMatch(/^NOT CHECKED: none of the 3 items could be checked/);
    expect(a._meta.offline).toBe(true);
    expect(a._meta.offline_note).toMatch(/FOURDA_OFFLINE is not set/);
    expect(a.results[1].reason).not.toMatch(/is the newest release it admits/);
    expect(a.results[1].reason).toMatch(/could not be determined/);
  });

  it("FOURDA_OFFLINE set: the same lead, naming it", async () => {
    process.env.FOURDA_OFFLINE = "1";
    const a = await run(items);
    expect(a.summary).toMatch(/^NOT CHECKED: none of the 3 items could be checked \(live lookups are disabled \(FOURDA_OFFLINE\)\)/);
    expect(a._meta.offline_note).toMatch(/^Live lookups are disabled/);
  });

  it("healthy: no NOT CHECKED lead, no offline note, and the bare crate names its newest release", async () => {
    const a = await run(items);
    expect(a.summary).not.toMatch(/NOT CHECKED/);
    expect(a._meta.offline).toBe(false);
    expect(a._meta.offline_note).toBeUndefined();
    expect(a.results[1].reason).toMatch(/Cargo reads a bare "0\.3\.20" as \^0\.3\.20; 0\.3\.20 is the newest release it admits/);
  });
});
