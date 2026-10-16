// SPDX-License-Identifier: Apache-2.0
/**
 * Readiness audit M6 (2026-10-16): Go advisories usually carry no severity.
 * golang.org/x/net v0.20.0 has GO-2024-3333, which is GHSA-w32m-9786-jp63,
 * rated HIGH; OSV returns only the GO record for the module (the GHSA names
 * golang.org/x/net/html), so dependency_check said `review`, not `avoid`.
 * A record with no severity now takes its GHSA alias's, read with
 * GET /v1/vulns/<id> (cached, bounded). No answer leaves it unknown: the
 * verdict stays `review`, never a proceed.
 *
 * Records recorded from OSV.dev on 2026-10-17.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { aliasSeverities } from "../tools/dependency-check-alias-severity.js";
import type { FourDADatabase } from "../db.js";
import type { OsvVulnerability, VulnerabilityEntry } from "../live/types.js";

const dir = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "dependency-check", "recorded");
const read = (f: string) => readFileSync(join(dir, f), "utf8");
const fixture = <T = unknown>(f: string) => JSON.parse(read(f)) as T;
const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-10-12T00:00:00Z");

const GO_3333 = fixture<OsvVulnerability>("osv-GO-2024-3333.json");
const GHSA_W32M = fixture<OsvVulnerability>("osv-GHSA-w32m-9786-jp63.json");

let records: Map<string, OsvVulnerability | "fail">;
let vulnFetches: string[];
let priorOffline: string | undefined;

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
    return json({ results: queries.map((q) => ({ vulns: q.version === "v0.20.0" ? [{ id: "GO-2024-3333", modified: "2026-10-01T00:00:00Z" }] : [] })) });
  }
  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/query") return json({ vulns: [GO_3333] });
  if (u.hostname === "api.osv.dev" && u.pathname.startsWith("/v1/vulns/")) {
    const id = decodeURIComponent(u.pathname.slice("/v1/vulns/".length));
    vulnFetches.push(id);
    const hit = records.get(id);
    if (hit === "fail") return json({ error: "unavailable" }, 503);
    return hit ? json(hit) : json({}, 404);
  }
  throw new Error(`unrouted request in test: ${url}`);
}

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
});
afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});
beforeEach(() => {
  records = new Map<string, OsvVulnerability | "fail">([
    ["GO-2024-3333", GO_3333],
    ["GHSA-w32m-9786-jp63", GHSA_W32M],
  ]);
  vulnFetches = [];
  // The alias reader shares the server cache: each case starts without a cached record.
  new LiveCache(null).invalidateSource("osv");
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => route(url, init)));
});
afterEach(() => vi.unstubAllGlobals());

async function checkXnet() {
  const live = new LiveIntelligence(new Database(":memory:"));
  const out = await executeDependencyCheck(noDb, { items: [{ ecosystem: "Go", package: "golang.org/x/net", to: "v0.20.0" }] }, live, { now: NOW });
  return out.results[0];
}

describe("dependency_check: a Go record with no severity takes its GHSA alias's (M6)", () => {
  it("golang.org/x/net v0.20.0 is avoid: GO-2024-3333 is HIGH via GHSA-w32m-9786-jp63", async () => {
    const r = await checkXnet();
    expect(r.verdict).toBe("avoid");
    const advisories = r.signals.find((s) => s.id === "advisories")!;
    expect(advisories.effect).toBe("avoid");
    expect(advisories.evidence).toMatch(/GO-2024-3333 \(high, per GHSA-w32m-9786-jp63\)/);
  });

  it("no answer for the alias: severity stays unknown and the verdict stays review, never proceed", async () => {
    records.set("GHSA-w32m-9786-jp63", "fail");
    const r = await checkXnet();
    expect(r.verdict).toBe("review");
    expect(r.signals.find((s) => s.id === "advisories")!.evidence).toMatch(/GO-2024-3333 \(unknown\)/);
  });
});

describe("aliasSeverities", () => {
  const entry = (vulnId: string, aliases: string[], severity: VulnerabilityEntry["severity"] = "unknown") =>
    ({ vulnId, aliases, severity, summary: vulnId, package: "golang.org/x/net", ecosystem: "Go", currentVersion: "v0.20.0" }) as VulnerabilityEntry;

  it("asks only for GHSA aliases of records with no severity", async () => {
    const details = vi.fn(async (ids: string[]) => new Map(ids.map((id) => [id, { id, database_specific: { severity: "HIGH" } } as unknown as OsvVulnerability])));
    const got = await aliasSeverities([entry("GO-1", ["CVE-1", "GHSA-aaaa-bbbb-cccc"]), entry("GO-2", ["CVE-2"]), entry("GO-3", ["GHSA-dddd-eeee-ffff"], "medium")], details);
    expect(details).toHaveBeenCalledWith(["GHSA-aaaa-bbbb-cccc"]);
    expect(got.get("GO-1")).toEqual({ severity: "high", from: "GHSA-aaaa-bbbb-cccc" });
    expect(got.has("GO-2")).toBe(false);
    expect(got.has("GO-3")).toBe(false);
  });

  it("is bounded: at most 25 alias records per call", async () => {
    const details = vi.fn(async () => new Map<string, OsvVulnerability>());
    await aliasSeverities(Array.from({ length: 40 }, (_, i) => entry(`GO-${i}`, [`GHSA-${String(i).padStart(4, "0")}-xxxx-yyyy`])), details);
    expect((details.mock.calls[0] as unknown[])[0]).toHaveLength(25);
  });

  it("a GHSA alias that is itself unrated changes nothing", async () => {
    const details = vi.fn(async (ids: string[]) => new Map(ids.map((id) => [id, { id } as OsvVulnerability])));
    expect((await aliasSeverities([entry("GO-1", ["GHSA-aaaa-bbbb-cccc"])], details)).size).toBe(0);
  });
});
