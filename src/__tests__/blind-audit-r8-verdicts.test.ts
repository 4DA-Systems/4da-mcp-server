// SPDX-License-Identifier: Apache-2.0
/**
 * Verdict defects from the blind pre-publish audit of e3aba98 (round 8, 2026-11-15).
 *
 * The registries and OSV.dev are stubbed with their real response shapes; every test here fails
 * on e3aba98.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import { advisoryAffects, advisoryRanges } from "../live/osv-ranges.js";
import { isMalwareRecord } from "../live/malware.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeDependencyCheck, runDependencyCheck } from "../tools/dependency-check.js";
import { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const NOW = Date.now();
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString();

type Release = { deps?: Record<string, string>; at?: string };
type Doc = { versions: Record<string, Release>; latest?: string };
let NPM: Record<string, Doc>;
/** crates.io: name -> versions (all published 300 days ago). */
let CRATES: Record<string, string[]>;
/** PyPI: name -> versions. */
let PYPI: Record<string, string[]>;
let OSV: OsvVulnerability[];
/** querybatch: "ok", "empty" (a well-formed answer with every result `{}`), or names answered 500. */
let BATCH: "ok" | "empty" | ((names: string[]) => boolean);
/** npm names whose registry documents answer 500. */
let NPM_DOWN: Set<string>;

function record(id: string, ecosystem: string, name: string, ranges: Array<Record<string, string>[]>, severity: string, extra: Partial<OsvVulnerability> = {}): OsvVulnerability {
  return {
    id,
    aliases: [],
    summary: `${name} advisory ${id}`,
    database_specific: { severity },
    affected: [{ package: { name, ecosystem }, ranges: ranges.map((events) => ({ type: ecosystem === "PyPI" ? "ECOSYSTEM" : "SEMVER", events })) }],
    ...extra,
  } as OsvVulnerability;
}

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const same = (a: string, b: string, eco: string) =>
      eco === "PyPI" ? a.toLowerCase() === b.toLowerCase() : eco === "crates.io" ? a.replace(/-/g, "_") === b.replace(/-/g, "_") : a === b;
    const recordsFor = (name: string, eco: string) => OSV.filter((v) => v.affected?.some((a) => a.package?.ecosystem === eco && same(a.package.name, name, eco)));
    const affects = (v: OsvVulnerability, name: string, eco: string, version: string) => {
      const ranges = advisoryRanges(v, name, eco);
      return ranges ? advisoryAffects(ranges, version, eco) : false;
    };
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      if (typeof BATCH === "function" && BATCH(queries.map((q) => q.package.name))) return new Response("internal error", { status: 500 });
      return json({
        results: queries.map((q) => {
          if (BATCH === "empty") return {};
          const ids = recordsFor(q.package.name, q.package.ecosystem)
            .filter((v) => affects(v, q.package.name, q.package.ecosystem, q.version))
            .map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" }));
          return ids.length > 0 ? { vulns: ids } : {};
        }),
      });
    }
    if (url.includes("/v1/vulns/")) {
      const found = OSV.find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
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
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      const name = Object.keys(PYPI).find((n) => n.toLowerCase() === decodeURIComponent(pypi[1]).toLowerCase());
      if (!name) return json({ message: "Not Found" }, 404);
      return json({ info: { name }, releases: Object.fromEntries(PYPI[name].map((v) => [v, [{ upload_time_iso_8601: daysAgo(300), yanked: false }]])) });
    }
    const one = /^https:\/\/registry\.npmjs\.org\/([^/@][^/]*)\/([^/]+)$/.exec(url);
    if (one) {
      const name = decodeURIComponent(one[1]);
      if (NPM_DOWN.has(name)) return new Response("internal error", { status: 500 });
      const doc = NPM[name];
      const v = decodeURIComponent(one[2]);
      return doc?.versions[v] ? json({ name, version: v, dependencies: doc.versions[v].deps ?? {} }) : json({}, 404);
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      if (NPM_DOWN.has(name)) return new Response("internal error", { status: 500 });
      const doc = NPM[name];
      if (!doc) return json({ error: "Not found" }, 404);
      const versions = Object.keys(doc.versions);
      const latest = doc.latest ?? versions[versions.length - 1];
      return json({
        name,
        "dist-tags": { latest },
        versions: Object.fromEntries(versions.map((v) => [v, { name, version: v, dependencies: doc.versions[v].deps ?? {} }])),
        time: { created: "2015-01-01T00:00:00.000Z", modified: daysAgo(1), ...Object.fromEntries(versions.map((v) => [v, doc.versions[v].at ?? daysAgo(300)])) },
      });
    }
    return json({}, 404);
  });
}

let dir: string;
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  clearNpmDownloadsMemo();
  NPM = {};
  CRATES = {};
  PYPI = {};
  OSV = [];
  BATCH = "ok";
  NPM_DOWN = new Set();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-r8-"));
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

const live = () => new LiveIntelligence(new Database(":memory:"));
const check = async (items: unknown[], li: LiveIntelligence = live()) => (await executeDependencyCheck(noDb, { items } as never, li)).results as Array<Record<string, any>>;

/** minimist: GHSA-xvch-5gv4-984h (critical) affects <0.2.4 and >=1.0.0 <1.2.6. */
function minimist() {
  NPM.minimist = { versions: Object.fromEntries(["0.2.3", "0.2.4", "1.2.5", "1.2.6"].map((v) => [v, {}])) };
  OSV.push(record("GHSA-xvch-5gv4-984h", "npm", "minimist", [[{ introduced: "0" }, { fixed: "0.2.4" }], [{ introduced: "1.0.0" }, { fixed: "1.2.6" }]], "CRITICAL"));
}

describe("B2: a constraint is judged by the release the package manager installs", () => {
  it.each(["<1.2.6", "<=1.2.5", "1.2.5 || 0.2.4"])('{npm, minimist, "%s"} resolves to 1.2.5: avoid, and pin exactly 0.2.4', async (to) => {
    minimist();
    const [r] = await check([{ ecosystem: "npm", package: "minimist", to }]);
    expect(r).toMatchObject({ to: "1.2.5", to_requested: to, verdict: "avoid" });
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "0.2.4", newest_safe_in_range: "0.2.4" });
    expect(r.reason).toContain("Pin exactly 0.2.4; the range as written resolves to 1.2.5 (avoid).");
  });

  it('{crates.io, smallvec, "<1.6.1"} resolves to 1.6.0 (RUSTSEC-2021-0003): avoid, pin 0.6.14', async () => {
    CRATES.smallvec = ["0.6.13", "0.6.14", "1.5.0", "1.6.0", "1.6.1"];
    OSV.push(record("RUSTSEC-2021-0003", "crates.io", "smallvec", [[{ introduced: "0.6.3" }, { fixed: "0.6.14" }], [{ introduced: "1.0.0" }, { fixed: "1.6.1" }]], "CRITICAL"));
    const [r] = await check([{ ecosystem: "crates.io", package: "smallvec", to: "<1.6.1" }]);
    expect(r).toMatchObject({ to: "1.6.0", verdict: "avoid" });
    expect(r.reason).toContain("Pin exactly 0.6.14; the range as written resolves to 1.6.0 (avoid).");
    // Cargo's default (caret) reading: "1.5" admits 1.6.0 and 1.6.1, and installs 1.6.1.
    const [caret] = await check([{ ecosystem: "crates.io", package: "smallvec", to: "1.5" }]);
    expect(caret).toMatchObject({ to: "1.6.1", verdict: "proceed" });
  });

  it("PyPI: a comma is an AND, and pip installs the highest release the specifiers admit", async () => {
    PYPI.jinja2 = ["2.10.0", "2.11.2", "2.11.3", "3.0.0"];
    OSV.push(record("PYSEC-2021-66", "PyPI", "jinja2", [[{ introduced: "2.11.0" }, { fixed: "2.11.3" }]], "HIGH"));
    const [r] = await check([{ ecosystem: "PyPI", package: "jinja2", to: ">=2.10,<2.11.3" }]);
    expect(r).toMatchObject({ to: "2.11.2", verdict: "avoid" });
    expect(r.reason).toContain("Pin exactly 2.10.0; the range as written resolves to 2.11.2 (avoid).");
    const [ok] = await check([{ ecosystem: "PyPI", package: "jinja2", to: "~=2.11" }]);
    expect(ok).toMatchObject({ to: "2.11.3", verdict: "proceed" });
  });

  it("the concise form keeps the safe exact pins beside the avoid", async () => {
    minimist();
    const out = (await runDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "minimist", to: "<1.2.6" }] } as never, live())) as Record<string, any>;
    expect(out.results[0]).toMatchObject({ to: "1.2.5", verdict: "avoid", safe: { smallest: "0.2.4", newest: "0.2.4" } });
  });
});

/** RUSTSEC-2025-0147 and its GHSA twin, as OSV.dev serves them (read 2026-11-15). */
function evmUnits(): OsvVulnerability[] {
  return [
    {
      id: "GHSA-6662-54xr-8423",
      summary: "`evm-units` was removed from crates.io for malicious code",
      details: "It appeared to be attempting to steal cryptocurrency.",
      aliases: ["RUSTSEC-2025-0147"],
      database_specific: { cwe_ids: [], severity: "CRITICAL", github_reviewed: true },
      affected: [{ package: { name: "evm-units", ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }],
    },
    {
      id: "RUSTSEC-2025-0147",
      summary: "`evm-units` was removed from crates.io for malicious code",
      details: "It appeared to be attempting to steal cryptocurrency.",
      aliases: ["GHSA-6662-54xr-8423"],
      database_specific: { license: "CC0-1.0" },
      affected: [
        {
          package: { name: "evm-units", ecosystem: "crates.io" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0.0.0-0" }] }],
          database_specific: { categories: ["malicious"], cvss: null, informational: null },
        },
      ],
    },
  ] as unknown as OsvVulnerability[];
}

describe("B3: a malware crate no longer on crates.io is avoid, labelled malware", () => {
  it("RustSec's `categories: [\"malicious\"]` and \"removed from crates.io for malicious code\" are malware records", () => {
    const [ghsa, rustsec] = evmUnits();
    expect(isMalwareRecord(rustsec)).toBe(true);
    expect(isMalwareRecord(ghsa)).toBe(true);
    expect(isMalwareRecord({ id: "RUSTSEC-2020-0001", summary: "x", affected: [{ database_specific: { categories: ["memory-corruption"] } }] })).toBe(false);
  });

  it.each(["latest", "0.1.0", "^0.1"])("{crates.io, evm-units, %s}: avoid with malicious_package", async (to) => {
    OSV.push(...evmUnits());
    const [r] = await check([{ ecosystem: "crates.io", package: "evm-units", to }]);
    expect(r.verdict).toBe("avoid");
    const advisories = r.signals.find((s: { id: string }) => s.id === "advisories");
    expect(advisories.value.malicious_package.ids).toEqual(["GHSA-6662-54xr-8423", "RUSTSEC-2025-0147"]);
    expect(r.reason).toMatch(/malicious package/);
  });

  it("a name the registry does not have, with an advisory OSV.dev lists against every release, is never a bare unknown", async () => {
    OSV.push(record("GHSA-gone-0000-0001", "npm", "gone-pkg", [[{ introduced: "0" }]], "HIGH"));
    const [r] = await check([{ ecosystem: "npm", package: "gone-pkg", to: "latest" }]);
    expect(r.verdict).not.toBe("unknown");
    expect(r.verdict).not.toBe("proceed");
    expect(r.reason).toContain("GHSA-gone-0000-0001");
  });
});

/** express: 4.17.1 has its own advisory; 4.20.0 exact-pins an affected qs; 4.22.3 holds a clean one. */
function express() {
  NPM.qs = { versions: { "6.11.0": {}, "6.16.0": {} } };
  NPM.express = {
    versions: {
      "4.17.1": { deps: { qs: "6.7.0" } },
      "4.20.0": { deps: { qs: "6.11.0" } },
      "4.22.3": { deps: { qs: "6.16.0" } },
    },
  };
  NPM.qs.versions["6.7.0"] = {};
  OSV.push(
    record("GHSA-expr-0000-0001", "npm", "express", [[{ introduced: "0" }, { fixed: "4.20.0" }]], "HIGH"),
    record("GHSA-qsqs-0000-0001", "npm", "qs", [[{ introduced: "0" }, { fixed: "6.16.0" }]], "HIGH"),
  );
}

describe("B7: a well-formed but empty batch answer never overrides the advisories already known", () => {
  it("express 4.17.1 and smallvec 1.6.0 stay avoid when every querybatch result is {}", async () => {
    express();
    CRATES.smallvec = ["0.6.14", "1.6.0", "1.6.1"];
    OSV.push(record("RUSTSEC-2021-0003", "crates.io", "smallvec", [[{ introduced: "1.0.0" }, { fixed: "1.6.1" }]], "CRITICAL"));
    BATCH = "empty";
    const [ex, sv] = await check([
      { ecosystem: "npm", package: "express", to: "4.17.1" },
      { ecosystem: "crates.io", package: "smallvec", to: "1.6.0" },
    ]);
    expect(ex.verdict).toBe("avoid");
    expect(ex.reason).toContain("GHSA-expr-0000-0001");
    expect(sv.verdict).toBe("avoid");
    expect(sv.reason).toContain("RUSTSEC-2021-0003");
  });

  it("a release its list calls clean is NOT CHECKED, never proceed, when the batch contradicts the list elsewhere", async () => {
    express();
    BATCH = "empty";
    const [r] = await check([{ ecosystem: "npm", package: "express", to: "4.22.3" }]);
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toMatch(/NOT CHECKED/);
  });

  it('{express, "4.x"} names no safe release from an empty batch answer, and a later healthy call is not answered from it', async () => {
    express();
    const li = live();
    BATCH = "empty";
    const [bad] = await check([{ ecosystem: "npm", package: "express", to: "4.x" }], li);
    expect(bad.verdict).not.toBe("proceed");
    expect(bad.range_check?.smallest_safe_in_range ?? null).toBeNull();
    expect(bad.reason).not.toMatch(/Safe in 4\.x/);
    BATCH = "ok";
    const [good] = await check([{ ecosystem: "npm", package: "express", to: "4.x" }], li);
    expect(good).toMatchObject({ to: "4.22.3", verdict: "proceed" });
    expect(good.range_check).toMatchObject({ smallest_safe_in_range: "4.22.3", newest_safe_in_range: "4.22.3" });
    const [pinned] = await check([{ ecosystem: "npm", package: "express", to: "4.20.0" }], li);
    expect(pinned.verdict).toBe("avoid");
  });
});

