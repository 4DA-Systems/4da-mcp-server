// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check for PyPI and Go, and constraint (range) checks on every
 * ecosystem — offline, against responses recorded from the live registries
 * and OSV.dev on 2026-10-11 (fixtures/dependency-check/recorded/), plus small
 * synthetic modules for cases no stable real package shows (a retraction, a
 * yank, `+incompatible`).
 *
 * The OSV oracle tests are the point: for every recorded release, the
 * constraint check's "safe" set (computed locally from each advisory's
 * affected ranges) must equal the set OSV.dev itself returned no advisory
 * for when asked about that exact version (`querybatch`, recorded).
 *
 * Origin: the G7 agent evaluation (2026-10-11). "Pin ws 7.x" produced
 * ws 7.5.10 and "pin body-parser 1.x" 1.20.3, both affected; PyPI and Go adds
 * never called a tool because dependency_check took npm and crates.io only.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { checkRange, lineOf, parseTarget, pep440SpecAdmits, rangeAdmits } from "../tools/dependency-check-versions.js";
import { parseRetractions, pseudoVersionTime } from "../live/go-releases.js";
import { projectPypiProject } from "../live/pypi-releases.js";
import { advisoryRanges } from "../live/osv-ranges.js";
import type { PackageReleaseIndex } from "../live/release-metadata.js";
import type { OsvVulnerability } from "../live/types.js";
import type { FourDADatabase } from "../db.js";

const dir = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "dependency-check", "recorded");
const read = (f: string) => readFileSync(join(dir, f), "utf8");
const fixture = <T = unknown>(f: string) => JSON.parse(read(f)) as T;
const noDb = null as unknown as FourDADatabase;
/** A day after recording: ws 7.5.13, Jinja2 3.1.6 and x/net v0.60.0 are older than 3 days; x/net v0.61.0 is not. */
const NOW = new Date("2026-10-12T00:00:00Z");
const DAY = 86_400_000;
const daysAgo = (n: number) => new Date(NOW.getTime() - n * DAY).toISOString();

type Osv = OsvVulnerability[];
interface Pkg {
  osv: Osv;
  /** OSV's own per-version answer (querybatch), by version. */
  batch: Record<string, string[]>;
}

interface Router {
  npm: Record<string, unknown>;
  pypi: Record<string, unknown>;
  go: Record<string, { list: string; info: Record<string, { Version: string; Time: string }>; mod?: string }>;
  osv: Record<string, Pkg>;
  down: string[];
  requests: string[];
}
let router: Router;
let priorOffline: string | undefined;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

const osvKey = (ecosystem: string, name: string) => `${ecosystem}:${ecosystem === "PyPI" ? name.toLowerCase() : name}`;

function route(url: string, init?: RequestInit): Response {
  const u = new URL(url);
  if (router.down.includes(u.hostname)) throw new TypeError("fetch failed (simulated outage)");
  if (u.hostname === "registry.npmjs.org") {
    const doc = router.npm[decodeURIComponent(u.pathname.slice(1))];
    return doc ? json(doc) : json({ error: "Not found" }, 404);
  }
  if (u.hostname === "pypi.org") {
    const m = /^\/pypi\/([^/]+)\/json$/.exec(u.pathname);
    const doc = m ? router.pypi[decodeURIComponent(m[1])] : null;
    return doc ? json(doc) : json({ message: "Not Found" }, 404);
  }
  if (u.hostname === "proxy.golang.org") {
    const m = /^\/(.+)\/@(v\/list|latest|v\/(.+)\.(info|mod))$/.exec(u.pathname);
    const mod = m ? router.go[m[1]] : null;
    if (!m || !mod) return new Response("not found", { status: 404 });
    if (m[2] === "v/list") return new Response(mod.list);
    if (m[2] === "latest") return new Response("not found", { status: 404 });
    if (m[4] === "info") return mod.info[m[3]] ? json(mod.info[m[3]]) : new Response("not found", { status: 404 });
    return mod.mod !== undefined ? new Response(mod.mod) : new Response("not found", { status: 404 });
  }
  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/query") {
    const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string } };
    return json({ vulns: router.osv[osvKey(q.package.ecosystem, q.package.name)]?.osv ?? [] });
  }
  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
    const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
    return json({
      results: queries.map((q) => {
        const pkg = router.osv[osvKey(q.package.ecosystem, q.package.name)];
        if (pkg && !(q.version in pkg.batch)) throw new Error(`no recorded OSV answer for ${q.package.name}@${q.version}`);
        return { vulns: (pkg?.batch[q.version] ?? []).map((id) => ({ id, modified: "2026-10-01T00:00:00Z" })) };
      }),
    });
  }
  if (u.hostname === "api.osv.dev" && u.pathname.startsWith("/v1/vulns/")) {
    const id = decodeURIComponent(u.pathname.slice("/v1/vulns/".length));
    const hit = Object.values(router.osv).flatMap((p) => p.osv).find((v) => v.id === id);
    return hit ? json(hit) : json({}, 404);
  }
  throw new Error(`unrouted request in test: ${url}`);
}

const XNET_LIST = read("go-xnet-list.txt");

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
});
afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

beforeEach(() => {
  router = {
    npm: { ws: fixture("npm-ws.json") },
    pypi: {
      jinja2: fixture("pypi-jinja2.json"),
      yanky: {
        info: { name: "yanky" },
        releases: {
          "1.0.0": [{ upload_time_iso_8601: daysAgo(400), yanked: false }],
          "1.0.1": [{ upload_time_iso_8601: daysAgo(300), yanked: true, yanked_reason: "broken wheel" }],
          "1.1.0": [{ upload_time_iso_8601: daysAgo(1), yanked: false }],
          "1.2.0": [],
        },
      },
    },
    go: {
      "golang.org/x/net": { list: XNET_LIST, info: fixture("go-xnet-info.json"), mod: read("go-xnet-newest.mod") },
      "example.com/retracted": {
        list: "v1.0.0\nv1.1.0\nv1.2.0\n",
        info: {
          "v1.0.0": { Version: "v1.0.0", Time: daysAgo(300) },
          "v1.1.0": { Version: "v1.1.0", Time: daysAgo(200) },
          "v1.2.0": { Version: "v1.2.0", Time: daysAgo(100) },
          "v0.0.0-20240102150405-abcdef123456": { Version: "v0.0.0-20240102150405-abcdef123456", Time: "2024-01-02T15:04:05Z" },
        },
        mod: "module example.com/retracted\n\ngo 1.22\n\nretract v1.1.0 // data loss on upgrade\n",
      },
      "github.com/old/lib": {
        list: "v1.0.0\nv2.0.0+incompatible\n",
        info: { "v2.0.0+incompatible": { Version: "v2.0.0+incompatible", Time: daysAgo(900) } },
        mod: "module github.com/old/lib\n",
      },
    },
    osv: {
      "npm:ws": { osv: fixture("osv-npm-ws.json"), batch: fixture("osvbatch-npm-ws.json") },
      "PyPI:jinja2": { osv: fixture("osv-pypi-jinja2.json"), batch: fixture("osvbatch-pypi-jinja2.json") },
      "Go:golang.org/x/net": { osv: fixture("osv-go-xnet.json"), batch: fixture("osvbatch-go-xnet.json") },
    },
    down: [],
    requests: [],
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      router.requests.push(url);
      return route(url, init);
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

async function check(items: unknown[]) {
  const live = new LiveIntelligence(new Database(":memory:"));
  return executeDependencyCheck(noDb, { items }, live, { now: NOW });
}

type Result = Awaited<ReturnType<typeof check>>["results"][number];
const signal = (r: Result, id: string) => r.signals.find((s) => s.id === id)!;

describe("constraint checks: the G7 pin tasks", () => {
  it('"pin ws 7.x" -> 7.5.10 is affected, 7.5.11 is the smallest safe release, the verdict is for the newest safe one', async () => {
    const r = (await check([{ ecosystem: "npm", package: "ws", to: "7.x" }])).results[0];
    expect(r).toMatchObject({ to: "7.5.13", to_requested: "7.x", verdict: "proceed" });
    expect(r.range_check).toMatchObject({
      range: "7.x",
      basis: "requested",
      smallest_safe_in_range: "7.5.11",
      newest_safe_in_range: "7.5.13",
      safe_versions: ["7.5.11", "7.5.12", "7.5.13"],
    });
    expect(r.range_check!.safe_versions).not.toContain("7.5.10");
    expect(r.reason).toContain("smallest 7.5.11");
  });

  it("an exact 7.5.10 is avoid, and the reason names the safe releases on its line", async () => {
    const r = (await check([{ ecosystem: "npm", package: "ws", to: "7.5.10" }])).results[0];
    expect(r.verdict).toBe("avoid");
    expect(signal(r, "advisories").value).toMatchObject({ affecting_to: ["GHSA-96hv-2xvq-fx4p"] });
    expect(r.range_check).toMatchObject({ range: "7.x", basis: "same_line", smallest_safe_in_range: "7.5.11" });
    expect(r.reason).toMatch(/Safe on 7\.5\.10's line \(7\.x\): smallest 7\.5\.11, newest 7\.5\.13/);
  });

  it("with `from`, a constraint picks the smallest safe upgrade, not the newest", async () => {
    const r = (await check([{ ecosystem: "npm", package: "ws", from: "7.4.6", to: "^7.4.6" }])).results[0];
    expect(r).toMatchObject({ to: "7.5.11", verdict: "proceed" });
    expect(r.range_check!.smallest_safe_upgrade).toBe("7.5.11");
  });

  it("a constraint nothing satisfies is unknown and says so", async () => {
    const r = (await check([{ ecosystem: "npm", package: "ws", to: "^9.0.0" }])).results[0];
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toContain("No published, non-withdrawn release of ws matches ^9.0.0");
  });

  it("a line with no safe release says which advisories affect all of it, and the newest safe release outside it", async () => {
    const r = (await check([{ ecosystem: "npm", package: "ws", to: "8.17.x" }])).results[0];
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: null, newest_safe_in_range: null });
    expect(r.range_check!.affecting_all).toEqual(expect.arrayContaining(["GHSA-58qx-3vcg-4xpx", "GHSA-96hv-2xvq-fx4p"]));
    expect(r.range_check!.newest_safe_outside_range).toBe("7.5.13");
    expect(r.verdict).toBe("avoid");
  });
});

describe("OSV oracle: the local range evaluation agrees with OSV's own per-version answers", () => {
  const cases: Array<{ eco: "npm" | "PyPI" | "Go"; name: string; osv: string; batch: string; index: () => PackageReleaseIndex; range: string }> = [
    {
      eco: "npm",
      name: "ws",
      osv: "osv-npm-ws.json",
      batch: "osvbatch-npm-ws.json",
      range: ">=7.0.0",
      index: () => ({
        ecosystem: "npm",
        name: "ws",
        createdAt: null,
        releases: Object.fromEntries(Object.keys(fixture<{ versions: object }>("npm-ws.json").versions).map((v) => [v, rec(v)])),
      }),
    },
    { eco: "PyPI", name: "jinja2", osv: "osv-pypi-jinja2.json", batch: "osvbatch-pypi-jinja2.json", range: ">=3.0", index: () => projectPypiProject("jinja2", fixture("pypi-jinja2.json")) },
    {
      eco: "Go",
      name: "golang.org/x/net",
      osv: "osv-go-xnet.json",
      batch: "osvbatch-go-xnet.json",
      range: "v0",
      index: () => ({
        ecosystem: "Go",
        name: "golang.org/x/net",
        createdAt: null,
        releases: Object.fromEntries(XNET_LIST.split("\n").filter(Boolean).map((v) => [v.trim(), rec(v.trim())])),
      }),
    },
  ];
  for (const c of cases) {
    it(`${c.eco} ${c.name}: safe set == versions OSV reports no advisory for`, () => {
      const advisories = fixture<Osv>(c.osv).map((v) => advisoryRanges(v, c.name, c.eco)).filter((a) => a !== null);
      const batch = fixture<Record<string, string[]>>(c.batch);
      const index = c.index();
      const rc = checkRange({ ecosystem: c.eco, index, range: c.range, basis: "requested", advisories });
      const all = Object.keys(index.releases).filter((v) => rangeAdmits(c.eco, c.range, v) && !/[a-z]/i.test(v.replace(/^v/, "")));
      const osvSafe = all.filter((v) => batch[v] !== undefined && batch[v].length === 0).sort();
      expect(all.length).toBeGreaterThan(10);
      // checkRange keeps at most 8 safe versions; compare the full count and the ends.
      expect(rc.releases_in_range - rc.vulnerable_in_range).toBe(osvSafe.length);
      for (const v of rc.safe_versions) expect(batch[v], `${c.name}@${v}`).toEqual([]);
      expect(osvSafe).toContain(rc.smallest_safe_in_range);
    });
  }
});

describe("PyPI", () => {
  it('"Jinja2 ==3.1.*" -> 3.1.6 (the only safe 3.1 release), proceed; npm-only signals say not applicable', async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "Jinja2", to: "3.1.*" }])).results[0];
    expect(r).toMatchObject({ to: "3.1.6", to_requested: "3.1.*", verdict: "proceed" });
    expect(r.range_check).toMatchObject({ range: "==3.1.*", smallest_safe_in_range: "3.1.6", vulnerable_in_range: 6 });
    for (const id of ["publish_trust", "install_script_added", "new_dependencies"]) {
      expect(signal(r, id)).toMatchObject({ value: "not_applicable", effect: "info" });
      expect(signal(r, id).evidence).toMatch(/not applicable/);
    }
    expect(signal(r, "release_age")).toMatchObject({ effect: "proceed", value: { published_at: "2025-03-05T20:05:00.369721Z" } });
  });

  it("~=3.1, a bare 3.1 (no such release: the 3.1 series) and ==3.1.4 all resolve on the PEP 440 line", async () => {
    const out = await check([
      { ecosystem: "PyPI", package: "jinja2", to: "~=3.1" },
      { ecosystem: "PyPI", package: "jinja2", to: "3.1" },
      { ecosystem: "PyPI", package: "jinja2", to: "==3.1.4" },
    ]);
    expect(out.results[0]).toMatchObject({ to: "3.1.6", verdict: "proceed" });
    expect(out.results[1]).toMatchObject({ to: "3.1.6", to_requested: "3.1", verdict: "proceed" });
    expect(out.results[2].to).toBe("3.1.4");
    expect(["avoid", "review"]).toContain(out.results[2].verdict);
    expect(out.results[2].range_check).toMatchObject({ basis: "same_line", range: "==3.1.*", smallest_safe_in_range: "3.1.6" });
    expect(out.results[2].reason).toContain("smallest 3.1.6");
  });

  it("with `from`, upgrade within the series gets the smallest fix and lists what it fixes", async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "jinja2", from: "3.1.2", to: "3.1.*" }])).results[0];
    expect(r).toMatchObject({ to: "3.1.6", verdict: "proceed" });
    expect((signal(r, "advisories").value as { fixed_by_this_change: string[] }).fixed_by_this_change.length).toBe(10);
    expect(signal(r, "upgrade_type").value).toBe("patch");
  });

  it("a yanked release is avoid; a constraint skips it, and holds back a release under 3 days old", async () => {
    const out = await check([
      { ecosystem: "PyPI", package: "yanky", to: "1.0.1" },
      { ecosystem: "PyPI", package: "yanky", to: "1.*" },
      { ecosystem: "PyPI", package: "yanky", to: "1.1.0" },
      { ecosystem: "PyPI", package: "yanky", to: "1.2.0" },
    ]);
    expect(out.results[0].verdict).toBe("avoid");
    expect(signal(out.results[0], "yanked_or_deprecated").evidence).toContain("yanked");
    expect(out.results[1]).toMatchObject({ to: "1.0.0", verdict: "proceed" });
    expect(out.results[1].range_check!.safe_versions).toEqual(["1.0.0", "1.1.0"]);
    expect(out.results[2].verdict).toBe("wait");
    // A release with no files cannot be installed.
    expect(out.results[3]).toMatchObject({ verdict: "unknown" });
    expect(out.results[3].reason).toContain("not a published version");
  });

  it("a missing package is unknown, never proceed", async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "reqeusts", to: "2.31.0" }])).results[0];
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toMatch(/not on PyPI.*hallucinated/);
  });
});

describe("Go", () => {
  it('"golang.org/x/net v0" -> v0.60.0: the newest safe release is under the 3-day hold, so the one before it', async () => {
    const r = (await check([{ ecosystem: "Go", package: "golang.org/x/net", to: "v0" }])).results[0];
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "v0.60.0", newest_safe_in_range: "v0.61.0" });
    expect(r).toMatchObject({ to: "v0.60.0", to_requested: "v0", verdict: "proceed" });
    expect(signal(r, "release_age")).toMatchObject({ effect: "proceed", value: { published_at: "2026-10-08T17:22:58Z" } });
    expect(signal(r, "publish_trust")).toMatchObject({ value: "not_applicable", effect: "info" });
    expect(signal(r, "install_script_added").evidence).toMatch(/Go runs no package code/);
  });

  it("an exact version without its `v` is read as the module version; affected -> safe releases on the module's line", async () => {
    const r = (await check([{ ecosystem: "Go", package: "golang.org/x/net", to: "0.23.0" }])).results[0];
    expect(r.to).toBe("v0.23.0");
    expect(["avoid", "review"]).toContain(r.verdict);
    expect(r.range_check).toMatchObject({ range: "v0", basis: "same_line", smallest_safe_in_range: "v0.60.0" });
    expect(signal(r, "release_age").value).toMatchObject({ published_at: "2024-04-03T17:30:20Z" });
  });

  it("a retracted version is avoid with the go.mod rationale; a constraint skips it", async () => {
    const out = await check([
      { ecosystem: "Go", package: "example.com/retracted", to: "v1.1.0" },
      { ecosystem: "Go", package: "example.com/retracted", from: "v1.0.0", to: "v1" },
    ]);
    expect(out.results[0].verdict).toBe("avoid");
    expect(signal(out.results[0], "yanked_or_deprecated").evidence).toContain("retracted");
    expect(out.results[1]).toMatchObject({ to: "v1.2.0", verdict: "proceed" });
  });

  it("`+incompatible`: v2.0.0 resolves to the release the proxy lists; a missing /v2 module path is named", async () => {
    router.osv["Go:golang.org/x/net"].batch["v2.0.0"] = [];
    const out = await check([
      { ecosystem: "Go", package: "github.com/old/lib", to: "v2.0.0" },
      { ecosystem: "Go", package: "golang.org/x/net", to: "v2.0.0" },
    ]);
    expect(out.results[0]).toMatchObject({ to: "v2.0.0+incompatible", verdict: "proceed" });
    expect(out.results[1].verdict).toBe("unknown");
    expect(out.results[1].reason).toContain("Go major 2 is a different module: golang.org/x/net/v2");
  });

  it("a pseudo-version is dated from the proxy and judged like a release", async () => {
    const r = (await check([{ ecosystem: "Go", package: "example.com/retracted", to: "v0.0.0-20240102150405-abcdef123456" }])).results[0];
    expect(r.verdict).toBe("proceed");
    expect(signal(r, "release_age").value).toMatchObject({ published_at: "2024-01-02T15:04:05Z" });
  });

  it("an unresolvable module path is unknown", async () => {
    const r = (await check([{ ecosystem: "Go", package: "github.com/nobody/nothing", to: "v1.0.0" }])).results[0];
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toContain("not a module the Go proxy can resolve");
  });
});

describe("privacy and honesty", () => {
  it("npm and PyPI registry requests never carry a version; Go reads .info only for the versions judged", async () => {
    await check([
      { ecosystem: "npm", package: "ws", to: "7.x" },
      { ecosystem: "PyPI", package: "jinja2", to: "3.1.4" },
      { ecosystem: "Go", package: "golang.org/x/net", to: "v0.23.0" },
    ]);
    const registry = router.requests.filter((u) => /registry\.npmjs\.org|pypi\.org/.test(u));
    expect(registry.length).toBeGreaterThan(0);
    for (const u of registry) expect(u).not.toMatch(/\d+\.\d+\.\d+/);
    const goInfo = router.requests.filter((u) => u.endsWith(".info")).map((u) => /@v\/(.+)\.info$/.exec(u)![1]);
    expect(goInfo).toEqual(["v0.23.0"]);
  });

  it("OSV down: a constraint names no safe version and the verdict is unknown, never proceed", async () => {
    router.down = ["api.osv.dev"];
    const r = (await check([{ ecosystem: "npm", package: "ws", to: "7.x" }])).results[0];
    expect(r.range_check).toBeUndefined();
    expect(r.verdict).toBe("unknown");
    expect(r.to).toBe("7.5.13");
  });

  it("rejects what is neither a version nor a constraint, per ecosystem", async () => {
    await expect(check([{ ecosystem: "PyPI", package: "jinja2", to: "^3.1" }])).rejects.toThrow(/PyPI version constraint/);
    await expect(check([{ ecosystem: "Go", package: "golang.org/x/net", to: "newest" }])).rejects.toThrow(/Go version constraint/);
    await expect(check([{ ecosystem: "npm", package: "ws", to: "7.5.11", from: "7.x" }])).rejects.toThrow(/from must be an exact version/);
  });

  it("accepts ecosystem names in any case", async () => {
    const r = (await check([{ ecosystem: "pypi", package: "jinja2", to: "3.1.6" }])).results[0];
    expect(r).toMatchObject({ ecosystem: "PyPI", verdict: "proceed" });
  });
});

describe("version and constraint parsing", () => {
  it("PEP 440 specifiers", () => {
    expect(pep440SpecAdmits("==3.1.*", "3.1.6")).toBe(true);
    expect(pep440SpecAdmits("==3.1.*", "3.10.0")).toBe(false);
    expect(pep440SpecAdmits("~=3.1", "3.9")).toBe(true);
    expect(pep440SpecAdmits("~=3.1", "4.0")).toBe(false);
    expect(pep440SpecAdmits("~=3.1.2", "3.1.9")).toBe(true);
    expect(pep440SpecAdmits("~=3.1.2", "3.2.0")).toBe(false);
    expect(pep440SpecAdmits(">=2,<3", "2.31.0")).toBe(true);
    expect(pep440SpecAdmits(">=2,<3", "3.0")).toBe(false);
    expect(pep440SpecAdmits("!=2.0.*,>=1.5", "2.0.3")).toBe(false);
    expect(pep440SpecAdmits("==4.2.16", "4.2.16")).toBe(true);
    expect(pep440SpecAdmits("^3.1", "3.1")).toBeNull();
  });

  it("targets: exact, latest, constraint, and PyPI's two-part ambiguity", () => {
    expect(parseTarget("npm", "7.5.10")).toEqual({ kind: "exact", version: "7.5.10" });
    expect(parseTarget("crates.io", "=0.17.8")).toEqual({ kind: "exact", version: "0.17.8" });
    expect(parseTarget("crates.io", "0.17")).toEqual({ kind: "range", range: "0.17" });
    expect(parseTarget("npm", "LATEST")).toEqual({ kind: "latest" });
    expect(parseTarget("PyPI", "==2.0")).toEqual({ kind: "exact", version: "2.0" });
    expect(parseTarget("PyPI", "2.0")).toEqual({ kind: "exact_or_series", version: "2.0", range: "==2.0.*" });
    expect(parseTarget("PyPI", "3.1.x")).toEqual({ kind: "range", range: "==3.1.*" });
    expect(parseTarget("Go", "1.2.3")).toEqual({ kind: "exact", version: "v1.2.3" });
    expect(parseTarget("Go", "v2.0.0+incompatible")).toEqual({ kind: "exact", version: "v2.0.0+incompatible" });
    expect(parseTarget("Go", "v1")).toEqual({ kind: "range", range: "v1" });
    expect(parseTarget("npm", "not a version")).toBeNull();
  });

  it("Go constraints read over `v`-less semver; lines per ecosystem", () => {
    expect(rangeAdmits("Go", "v1", "v1.9.1")).toBe(true);
    expect(rangeAdmits("Go", "v1", "v2.0.0+incompatible")).toBe(false);
    expect(rangeAdmits("Go", ">=v0.23.0, <v0.30.0", "v0.29.0")).toBe(true);
    expect(rangeAdmits("crates.io", "0.17.x", "0.17.14")).toBe(true);
    expect(lineOf("npm", "7.5.10")).toBe("7.x");
    expect(lineOf("crates.io", "0.17.8")).toBe("0.17.x");
    expect(lineOf("PyPI", "4.2.16")).toBe("==4.2.*");
    expect(lineOf("Go", "v0.23.0")).toBe("v0");
  });

  it("go.mod retractions and pseudo-version times", () => {
    expect(
      parseRetractions("module x\nretract v1.0.0 // oops\nretract (\n\t[v1.1.0, v1.1.5] // bad range\n\tv1.2.0\n)\n"),
    ).toEqual([
      { low: "v1.0.0", high: "v1.0.0", rationale: "oops" },
      { low: "v1.1.0", high: "v1.1.5", rationale: "bad range" },
      { low: "v1.2.0", high: "v1.2.0", rationale: null },
    ]);
    expect(pseudoVersionTime("v0.0.0-20240102150405-abcdef123456")).toBe("2024-01-02T15:04:05Z");
    expect(pseudoVersionTime("v1.2.4-0.20240102150405-abcdef123456")).toBe("2024-01-02T15:04:05Z");
    expect(pseudoVersionTime("v1.2.3")).toBeNull();
  });
});

function rec(version: string) {
  return { version, publishedAt: null, trust: 0 as const, trustEvidence: "", installScripts: null, deprecated: null, withdrawn: null, dependencies: null };
}
