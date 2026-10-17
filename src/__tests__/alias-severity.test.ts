// SPDX-License-Identifier: Apache-2.0
/**
 * One advisory, one severity, in every tool (review of 6.2.5 M6, 2026-10-18).
 *
 * Go's vulnerability database rates nothing: golang.org/x/net v0.20.0 has
 * GO-2024-3333, which is GHSA-w32m-9786-jp63, rated HIGH, and OSV returns
 * only the GO record for the module (the GHSA names golang.org/x/net/html).
 * The first fix graded it from the alias inside dependency_check only, so
 * dependency_check said `avoid` ("high, per GHSA-w32m-9786-jp63") while
 * vulnerability_scan graded the same record unknown. The scanner now grades
 * it, so every tool reads the same entry, with `severityFrom`.
 *
 * Records recorded from OSV.dev on 2026-10-17.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { MAX_ALIAS_LOOKUPS, OsvScanner, type AdvisorySource } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import type { FourDADatabase } from "../db.js";
import type { OsvVulnerability, ResolvedDependency } from "../live/types.js";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "dependency-check", "recorded");
const read = (f: string) => fs.readFileSync(path.join(dir, f), "utf8");
const fixture = <T = unknown>(f: string) => JSON.parse(read(f)) as T;
const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-10-12T00:00:00Z");

const GO_3333 = fixture<OsvVulnerability>("osv-GO-2024-3333.json");
const GHSA_W32M = fixture<OsvVulnerability>("osv-GHSA-w32m-9786-jp63.json");

let records: Map<string, OsvVulnerability | "fail">;
let priorOffline: string | undefined;
let project: string;

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function route(url: string, init?: RequestInit): Response {
  const u = new URL(url);
  if (u.hostname === "proxy.golang.org") {
    const m = /^\/(.+)\/@(v\/list|latest|v\/(.+)\.(info|mod))$/.exec(u.pathname);
    if (!m || m[1] !== "golang.org/x/net") return new Response("not found", { status: 404 });
    if (m[2] === "v/list") return new Response(read("go-xnet-list.txt"));
    if (m[2] === "latest") return new Response("not found", { status: 404 });
    const info = fixture<Record<string, unknown>>("go-xnet-info.json");
    if (m[4] === "info") return info[m[3]] ? json(info[m[3]]) : new Response("not found", { status: 404 });
    return new Response(read("go-xnet-newest.mod"));
  }
  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
    const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ version: string }> };
    return json({ results: queries.map((q) => ({ vulns: q.version === "v0.20.0" || q.version === "0.20.0" ? [{ id: "GO-2024-3333", modified: "2026-10-01T00:00:00Z" }] : [] })) });
  }
  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/query") return json({ vulns: [GO_3333] });
  if (u.hostname === "api.osv.dev" && u.pathname.startsWith("/v1/vulns/")) {
    const hit = records.get(decodeURIComponent(u.pathname.slice("/v1/vulns/".length)));
    if (hit === "fail") return json({ error: "unavailable" }, 503);
    return hit ? json(hit) : json({}, 404);
  }
  throw new TypeError(`fetch failed (unrouted in test: ${url})`);
}

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  project = fs.mkdtempSync(path.join(os.tmpdir(), "4da-alias-sev-"));
  fs.writeFileSync(path.join(project, "go.mod"), "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/net v0.20.0\n");
  fs.writeFileSync(path.join(project, "go.sum"), "golang.org/x/net v0.20.0 h1:fixture=\ngolang.org/x/net v0.20.0/go.mod h1:fixture=\n");
});
afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(project, { recursive: true, force: true });
});
beforeEach(() => {
  delete process.env.FOURDA_OFFLINE;
  records = new Map<string, OsvVulnerability | "fail">([
    ["GO-2024-3333", GO_3333],
    ["GHSA-w32m-9786-jp63", GHSA_W32M],
  ]);
  // Records are cached for 24 h in the server cache: each case starts without one.
  new LiveCache(null).invalidateSource("osv");
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => route(url, init)));
});
afterEach(() => vi.unstubAllGlobals());

const live = () => new LiveIntelligence(new Database(":memory:"));

describe("every tool grades GO-2024-3333 HIGH, per GHSA-w32m-9786-jp63", () => {
  it("dependency_check: avoid", async () => {
    const out = await executeDependencyCheck(noDb, { items: [{ ecosystem: "Go", package: "golang.org/x/net", to: "v0.20.0" }] }, live(), { now: NOW });
    const r = out.results[0];
    expect(r.verdict).toBe("avoid");
    expect(r.signals.find((s) => s.id === "advisories")!.evidence).toMatch(/GO-2024-3333 \(high, per GHSA-w32m-9786-jp63\)/);
  });

  it("vulnerability_scan: high, with severity_from, and no unknown left", async () => {
    const scan = (await executeVulnerabilityScan(null, { project_path: project, response_format: "detailed" }, live())) as Record<string, any>;
    const row = scan.vulnerabilities.find((v: { vuln_id: string }) => v.vuln_id === "GO-2024-3333");
    expect(row).toMatchObject({ advisory_severity: "high", severity_from: "GHSA-w32m-9786-jp63" });
    expect(scan.advisory_by_severity.unknown).toBe(0);
    expect(scan._meta.alias_severity).toEqual({ rated_from_alias: 1, unresolved: [], ungraded: [] });
    const concise = (await executeVulnerabilityScan(null, { project_path: project }, live())) as Record<string, any>;
    expect(concise.vulnerable_packages[0]).toMatchObject({ package: "golang.org/x/net", severity_from: "GHSA-w32m-9786-jp63" });
  });

  it("dependency_health: weighted as high, and says the grade came from the alias", async () => {
    const li = live();
    li.initFromDependencyGroups([{ dir: project, language: "go", deps: ["golang.org/x/net"], devDeps: [] }]);
    li.fetchRegistryHealth = async () => [];
    const health = await executeDependencyHealth(noDb, {}, li);
    expect(health.vulnerabilitySummary).toEqual({ critical: 0, high: 1, medium: 0, low: 0 });
    expect(health.aliasSeverity).toEqual({ rated: 1, unresolved: [], ungraded: [], reason: null });
  });

  it("no answer for the alias: unknown everywhere, listed as unresolved, and dependency_check says review", async () => {
    records.set("GHSA-w32m-9786-jp63", "fail");
    const out = await executeDependencyCheck(noDb, { items: [{ ecosystem: "Go", package: "golang.org/x/net", to: "v0.20.0" }] }, live(), { now: NOW });
    expect(out.results[0].verdict).toBe("review");
    const scan = (await executeVulnerabilityScan(null, { project_path: project, response_format: "detailed" }, live())) as Record<string, any>;
    expect(scan._meta.alias_severity.unresolved).toEqual(["GHSA-w32m-9786-jp63"]);
    expect(scan._meta.alias_severity.ungraded).toEqual(["GO-2024-3333"]);
    expect(scan._meta.alias_severity.note).toMatch(/Unknown is not clean/);
  });
});

describe("the scanner's alias lookup: the source, the budget, the cap", () => {
  const dep = (name: string): ResolvedDependency =>
    ({ name, version: "v1.0.0", ecosystem: "Go", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [] }) as ResolvedDependency;
  const goRecord = (id: string, ghsa: string): OsvVulnerability => ({ id, aliases: [ghsa], summary: id }) as unknown as OsvVulnerability;
  const ghsaRecord = (id: string): OsvVulnerability => ({ id, database_specific: { severity: "HIGH" } }) as unknown as OsvVulnerability;
  const scanner = (source: AdvisorySource, aliasBudgetMs?: number) =>
    new OsvScanner(new LiveCache(new Database(":memory:")), new RateLimiter(DEFAULT_RATE_LIMITS), source, { aliasBudgetMs });

  it("a pinned (non-network) source answers from its own records: no request leaves the process", async () => {
    const details = vi.fn(async (ids: string[]) => new Map(ids.map((id) => [id, id.startsWith("GO-") ? goRecord(id, "GHSA-aaaa-bbbb-cccc") : ghsaRecord(id)])));
    const source: AdvisorySource = { network: false, query: async () => ({ ids: [["GO-1"]], failure: null }), details };
    const result = await scanner(source).scan([dep("example.com/a")], "x");
    expect(result.vulnerabilities[0]).toMatchObject({ severity: "high", severityFrom: "GHSA-aaaa-bbbb-cccc" });
    expect(details).toHaveBeenLastCalledWith(["GHSA-aaaa-bbbb-cccc"]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("FOURDA_OFFLINE with a network source: nothing is fetched, and the record says why it stays unknown", async () => {
    process.env.FOURDA_OFFLINE = "true";
    const details = vi.fn(async (ids: string[]) => new Map(ids.map((id) => [id, goRecord(id, "GHSA-aaaa-bbbb-cccc")])));
    const source: AdvisorySource = { network: true, query: async () => ({ ids: [["GO-1"]], failure: null }), details };
    const result = await scanner(source).scan([dep("example.com/a")], "x");
    expect(details).toHaveBeenCalledTimes(1); // the record itself, not the alias
    expect(result.vulnerabilities[0].severity).toBe("unknown");
    expect(result.aliasSeverity).toEqual({ rated: 0, unresolved: ["GHSA-aaaa-bbbb-cccc"], ungraded: ["GO-1"], reason: expect.stringMatching(/FOURDA_OFFLINE/) });
  });

  it("past the time budget the records stay unknown, said so", async () => {
    let call = 0;
    const source: AdvisorySource = {
      network: false,
      query: async () => ({ ids: [["GO-1"]], failure: null }),
      details: (ids) => (call++ === 0 ? Promise.resolve(new Map(ids.map((id) => [id, goRecord(id, "GHSA-aaaa-bbbb-cccc")]))) : new Promise(() => {})),
    };
    const result = await scanner(source, 50).scan([dep("example.com/a")], "x");
    expect(result.vulnerabilities[0].severity).toBe("unknown");
    expect(result.aliasSeverity).toEqual({ rated: 0, unresolved: ["GHSA-aaaa-bbbb-cccc"], ungraded: ["GO-1"], reason: expect.stringMatching(/did not arrive within 0.05 s/) });
  });

  it(`at most ${MAX_ALIAS_LOOKUPS} aliases are read; the rest are listed as unresolved, not dropped`, async () => {
    const n = MAX_ALIAS_LOOKUPS + 10;
    const deps = Array.from({ length: n }, (_, i) => dep(`example.com/m${i}`));
    const asked: string[][] = [];
    const source: AdvisorySource = {
      network: false,
      query: async () => ({ ids: deps.map((_, i) => [`GO-${i}`]), failure: null }),
      details: async (ids) => {
        asked.push(ids);
        return new Map(ids.map((id) => [id, id.startsWith("GO-") ? goRecord(id, `GHSA-${id.slice(3).padStart(4, "0")}-xxxx-yyyy`) : ghsaRecord(id)]));
      },
    };
    const result = await scanner(source).scan(deps, "x");
    expect(asked[1]).toHaveLength(MAX_ALIAS_LOOKUPS);
    expect(result.aliasSeverity?.rated).toBe(MAX_ALIAS_LOOKUPS);
    expect(result.aliasSeverity?.unresolved).toHaveLength(10);
    expect(result.aliasSeverity?.ungraded).toHaveLength(10);
    expect(result.aliasSeverity?.reason).toMatch(new RegExp(`more than ${MAX_ALIAS_LOOKUPS} aliases`));
  });
});

/**
 * Umbrella records name several GHSAs (RUSTSEC-2020-0014 lists 8; the first
 * fix took the FIRST one, so the grade depended on alias order). The shared
 * rule, which the 4DA app implements identically: the highest grade among
 * every GHSA alias that could be read; on a tie the smallest id; an alias
 * that could not be read never lowers the grade and is listed as unresolved.
 */
describe("an unrated record with several GHSA aliases takes the highest readable grade", () => {
  const sev = (label: string) => ({ database_specific: { severity: label } });
  const aliasRecords: Record<string, object> = {
    "GHSA-aaaa-0000-0001": sev("MODERATE"),
    "GHSA-bbbb-0000-0002": sev("CRITICAL"),
    "GHSA-cccc-0000-0003": sev("HIGH"),
    "GHSA-dddd-0000-0004": sev("HIGH"),
  };
  const run = async (aliases: string[], readable = (_id: string) => true) => {
    const source: AdvisorySource = {
      network: false,
      query: async () => ({ ids: [["RUSTSEC-2099-0001"]], failure: null }),
      details: async (ids) =>
        new Map(
          ids.flatMap((id): Array<[string, OsvVulnerability]> =>
            id === "RUSTSEC-2099-0001"
              ? [[id, { id, aliases, summary: "umbrella" } as unknown as OsvVulnerability]]
              : readable(id) && aliasRecords[id] ? [[id, { id, ...aliasRecords[id] } as unknown as OsvVulnerability]] : [],
          ),
        ),
    };
    const s = new OsvScanner(new LiveCache(new Database(":memory:")), new RateLimiter(DEFAULT_RATE_LIMITS), source);
    const d = { name: "x", version: "1.0.0", ecosystem: "crates.io", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [] } as ResolvedDependency;
    return s.scan([d], "x");
  };

  it.each([
    [["GHSA-aaaa-0000-0001", "GHSA-bbbb-0000-0002", "GHSA-cccc-0000-0003"]],
    [["GHSA-cccc-0000-0003", "GHSA-aaaa-0000-0001", "GHSA-bbbb-0000-0002"]],
    [["CVE-2099-1", "GHSA-bbbb-0000-0002", "GHSA-cccc-0000-0003", "GHSA-aaaa-0000-0001"]],
  ])("medium / critical / high gives critical, whatever the order (%j)", async (aliases) => {
    const r = await run(aliases);
    expect(r.vulnerabilities[0]).toMatchObject({ severity: "critical", severityFrom: "GHSA-bbbb-0000-0002" });
    expect(r.aliasSeverity).toEqual({ rated: 1, unresolved: [], ungraded: [], reason: null });
  });

  it("a tie goes to the smallest GHSA id", async () => {
    for (const aliases of [["GHSA-dddd-0000-0004", "GHSA-cccc-0000-0003"], ["GHSA-cccc-0000-0003", "GHSA-dddd-0000-0004"]]) {
      expect((await run(aliases)).vulnerabilities[0]).toMatchObject({ severity: "high", severityFrom: "GHSA-cccc-0000-0003" });
    }
  });

  it("an unreadable alias does not lower the grade, and is listed as unresolved", async () => {
    const r = await run(["GHSA-bbbb-0000-0002", "GHSA-cccc-0000-0003"], (id) => id !== "GHSA-bbbb-0000-0002");
    expect(r.vulnerabilities[0]).toMatchObject({ severity: "high", severityFrom: "GHSA-cccc-0000-0003" });
    expect(r.aliasSeverity).toEqual({ rated: 1, unresolved: ["GHSA-bbbb-0000-0002"], ungraded: [], reason: expect.stringMatching(/could not be read/) });
  });

  it("gradeFromAliases: the rule on its own, with every alias consulted", async () => {
    const { gradeFromAliases } = await import("../live/osv-scanner.js");
    const read = new Map([["GHSA-b", "critical"], ["GHSA-c", "high"], ["GHSA-u", "unknown"]] as const);
    expect(gradeFromAliases(["GHSA-c", "GHSA-x", "GHSA-b", "GHSA-u"], read)).toEqual({
      severity: "critical",
      from: "GHSA-b",
      consulted: [
        { id: "GHSA-b", grade: "critical" },
        { id: "GHSA-c", grade: "high" },
        { id: "GHSA-u", grade: "unknown" },
        { id: "GHSA-x", grade: "unreadable" },
      ],
    });
    expect(gradeFromAliases(["GHSA-x"], read)).toMatchObject({ severity: "unknown", from: null });
  });
});
