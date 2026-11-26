// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish audit 2026-11-25, C-5: `github.com/Sirupsen/logrus` v1.0.6 answered proceed while the
 * same code under `github.com/sirupsen/logrus` is avoid (GO-2025-4188): OSV.dev keys the advisory
 * under the lower-case path only. A Go path with upper-case letters whose release reads clean is
 * asked once more under its lower-case path; advisories there make it review, named.
 *
 * Release data: golang.org/x/net's recorded proxy answers, served under a made-up upper-case path.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "dependency-check", "recorded");
const read = (f: string) => fs.readFileSync(path.join(dir, f), "utf8");
const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-10-12T00:00:00Z");
const UPPER = "github.com/Zqxorg/logz";
const LOWER = "github.com/zqxorg/logz";
const VERSION = "v0.17.0";

const RECORD = {
  id: "GO-2025-9999",
  aliases: [],
  summary: "logz advisory",
  affected: [{ package: { name: LOWER, ecosystem: "Go" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.99.0" }] }] }],
};

/** Whether OSV.dev holds the advisory under the lower-case path; "fail": the lower-case query answers 500. */
let lowerHas: boolean | "fail";
let batches: Array<string[]>;

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function route(url: string, init?: RequestInit): Response {
  const u = new URL(url);
  if (u.hostname === "proxy.golang.org") {
    const m = /^\/(.+)\/@(v\/list|latest|v\/(.+)\.(info|mod))$/.exec(u.pathname);
    if (!m || m[1] !== "github.com/!zqxorg/logz") return new Response("not found", { status: 404 });
    if (m[2] === "v/list") return new Response(read("go-xnet-list.txt"));
    if (m[2] === "latest") return new Response("not found", { status: 404 });
    const info = JSON.parse(read("go-xnet-info.json")) as Record<string, unknown>;
    if (m[4] === "info") return info[m[3]] ? json(info[m[3]]) : new Response("not found", { status: 404 });
    return new Response(`module ${UPPER}\n\ngo 1.20\n`);
  }
  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
    const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
    batches.push(queries.map((q) => q.package.name));
    if (lowerHas === "fail" && queries.some((q) => q.package.name === LOWER)) return json({ error: "unavailable" }, 500);
    return json({ results: queries.map((q) => (q.package.name === LOWER && lowerHas === true ? { vulns: [{ id: RECORD.id, modified: "2026-10-01T00:00:00Z" }] } : {})) });
  }
  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/query") {
    const q = JSON.parse(String(init?.body)) as { package: { name: string } };
    return json({ vulns: q.package.name === LOWER && lowerHas === true ? [RECORD] : [] });
  }
  if (u.hostname === "api.osv.dev" && u.pathname.startsWith("/v1/vulns/")) {
    return decodeURIComponent(u.pathname.slice("/v1/vulns/".length)) === RECORD.id ? json(RECORD) : json({}, 404);
  }
  throw new TypeError(`fetch failed (unrouted in test: ${url})`);
}

let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  lowerHas = true;
  batches = [];
  new LiveCache(null).invalidateSource("osv");
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => route(url, init)));
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const check = async () => (await executeDependencyCheck(noDb, { items: [{ ecosystem: "Go", package: UPPER, to: VERSION }] }, new LiveIntelligence(new Database(":memory:")), { now: NOW })).results[0];

describe("C-5: an upper-case Go path is held against its lower-case path's advisories", () => {
  it("clean under the upper-case path, an advisory under the lower-case one: review, naming both", async () => {
    const r = await check();
    expect(r.verdict).toBe("review");
    const s = r.signals.find((x) => x.id === "module_path_case")!;
    expect(s).toMatchObject({ effect: "review", value: { module: LOWER, advisories: [RECORD.id] } });
    expect(r.reason).toContain(`module_path_case: OSV.dev lists no advisory under ${UPPER}, but the same module under its lower-case path ${LOWER} has one for ${VERSION}: ${RECORD.id}`);
    // One extra batch request, for the lower-case path only.
    expect(batches.filter((b) => b.includes(LOWER))).toEqual([[LOWER]]);
  });

  it("no advisory under the lower-case path either: proceed, with no extra signal", async () => {
    lowerHas = false;
    const r = await check();
    expect(r.verdict).toBe("proceed");
    expect(r.signals.some((x) => x.id === "module_path_case")).toBe(false);
  });

  it("the lower-case query fails: unknown, never proceed", async () => {
    lowerHas = "fail";
    const r = await check();
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toMatch(/module_path_case: .* could not be checked/);
  });
});
