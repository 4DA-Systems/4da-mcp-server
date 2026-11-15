// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_planner counted NOT CHECKED rows (OSV.dev gave no answer, risk "unknown") as
 * "vulnerable with no fixed release yet" (pre-publish round 10, W8). An unchecked dependency is
 * neither vulnerable nor clean: it is counted only as NOT CHECKED.
 *
 * Stubs copied from blind-audit-r7-verdicts.test.ts (real OSV.dev and npm response shapes).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const NOW = Date.now();
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString();

type Release = { deps?: Record<string, string>; at?: string; deprecated?: string };
type Doc = { versions: Record<string, Release>; latest?: string; unpublished?: Record<string, string>; repository?: unknown };
let NPM: Record<string, Doc>;
let OSV: OsvVulnerability[];
/** querybatch: "ok", "500" (every request), or a predicate on a request's package names that answers 500. */
let BATCH: "ok" | "500" | ((names: string[]) => boolean);
/** /v1/vulns/{id} ids that never answer (the request hangs until aborted). */
let HANG_DETAIL: Set<string>;
/** querybatch pages: a query for one of these names is cut after its first advisory, and its second page fails. */
let PAGE2_FAILS: Set<string>;
/** Every request body sent to api.osv.dev. */
const OSV_BODIES: string[] = [];

const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
function affects(v: OsvVulnerability, name: string, version: string): boolean {
  return (v.affected ?? []).some((a) => {
    if (a.package?.name !== name) return false;
    const listed = (a as { versions?: string[] }).versions;
    if (Array.isArray(listed) && listed.includes(version)) return true;
    for (const r of a.ranges ?? []) {
      const intro = r.events.find((e) => e.introduced)?.introduced ?? "0";
      const fixed = r.events.find((e) => e.fixed)?.fixed;
      if (cmp(version, intro) >= 0 && (!fixed || cmp(version, fixed) < 0)) return true;
    }
    return false;
  });
}

const adv = (id: string, name: string, fixed: string, severity: string, extra: Partial<OsvVulnerability> = {}): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity },
  affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed }] }] }],
  ...extra,
});

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.includes("api.osv.dev") && init?.body) OSV_BODIES.push(String(init.body));
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string; page_token?: string }> };
      const names = queries.map((q) => q.package.name);
      if (BATCH === "500" || (typeof BATCH === "function" && BATCH(names))) return new Response("internal error", { status: 500 });
      if (queries.some((q) => q.page_token)) return new Response("internal error", { status: 500 });
      return json({
        results: queries.map((q) => {
          const ids = OSV.filter((v) => affects(v, q.package.name, q.version)).map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" }));
          if (PAGE2_FAILS.has(q.package.name) && ids.length > 0) return { vulns: ids.slice(0, 1), next_page_token: "page-2" };
          return ids.length > 0 ? { vulns: ids } : {};
        }),
      });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      if (HANG_DETAIL.has(id)) {
        return new Promise<Response>((_, reject) => {
          init?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("This operation was aborted"), { name: "AbortError" })));
        });
      }
      const found = OSV.find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string }; version?: string };
      const list = OSV.filter((v) => (v.affected ?? []).some((a) => a.package?.name === q.package.name));
      return json({ vulns: q.version ? list.filter((v) => affects(v, q.package.name, q.version!)) : list });
    }
    if (url.startsWith("https://api.npmjs.org/downloads/")) return json({ downloads: 50_000_000, package: "x" });
    const one = /^https:\/\/registry\.npmjs\.org\/([^/@][^/]*)\/([^/]+)$/.exec(url);
    if (one) {
      const doc = NPM[decodeURIComponent(one[1])];
      const v = decodeURIComponent(one[2]);
      return doc?.versions[v] ? json({ name: one[1], version: v, dependencies: doc.versions[v].deps ?? {} }) : json({}, 404);
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({ error: "Not found" }, 404);
      const versions = Object.keys(doc.versions);
      const latest = doc.latest ?? versions[versions.length - 1];
      const repo = doc.repository !== undefined ? { repository: doc.repository } : {};
      return json({
        name,
        "dist-tags": { latest },
        ...repo,
        versions: Object.fromEntries(
          versions.map((v) => [
            v,
            { name, version: v, dependencies: doc.versions[v].deps ?? {}, ...(doc.versions[v].deprecated ? { deprecated: doc.versions[v].deprecated } : {}), ...repo },
          ]),
        ),
        time: {
          created: "2015-01-01T00:00:00.000Z",
          modified: daysAgo(1),
          ...Object.fromEntries(versions.map((v) => [v, doc.versions[v].at ?? daysAgo(300)])),
          ...(doc.unpublished ?? {}),
        },
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
  OSV = [];
  BATCH = "ok";
  HANG_DETAIL = new Set();
  PAGE2_FAILS = new Set();
  OSV_BODIES.length = 0;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-r10w8-"));
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.FOURDA_CALL_BUDGET_MS;
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

/** A project of npm packages: `direct` declared, `lock` every installed copy (lockfile path -> version and dependencies). */
function project(direct: Record<string, string>, lock: Record<string, { version: string; dependencies?: Record<string, string> }>) {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: direct }));
  const packages: Record<string, unknown> = { "": { name: "x", dependencies: direct } };
  for (const [p, v] of Object.entries(lock)) packages[p] = v;
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
}
async function liveFor(): Promise<LiveIntelligence> {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  vi.spyOn(li, "getProjectRoot").mockReturnValue(dir);
  return li;
}
const plan = async (params: Record<string, unknown> = {}) =>
  (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50, ...params }, await liveFor())) as Record<string, any>;
const scan = async (params: Record<string, unknown> = {}) => (await executeVulnerabilityScan(null, { project_path: dir, ...params }, await liveFor())) as Record<string, any>;
const health = async (params: Record<string, unknown> = {}) => (await executeDependencyHealth(null, { project_path: dir, ...params }, await liveFor())) as Record<string, any>;

/**
 * express: vulnerable with a fix. lodash: vulnerable, no advisory names a fix. Both answered.
 * left-pad and is-odd: up to date; OSV.dev's answer for each is cut after page 1 and page 2 fails,
 * so the scanner marks only those two unanswered (a partial OSV.dev answer).
 */
function mixed() {
  OSV.push(adv("GHSA-ex00-0000-0001", "express", "4.19.2", "HIGH"));
  OSV.push({ ...adv("GHSA-lo00-0000-0001", "lodash", "9.9.9", "HIGH"), affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }] });
  for (const name of ["left-pad", "is-odd"]) {
    OSV.push(adv(`GHSA-${name}-0001`, name, "99.0.0", "LOW"), adv(`GHSA-${name}-0002`, name, "99.0.0", "LOW"));
    PAGE2_FAILS.add(name);
  }
  NPM.express = { versions: { "4.16.4": {}, "4.19.2": {} } };
  NPM.lodash = { versions: { "4.17.21": {} } };
  NPM["left-pad"] = { versions: { "1.3.0": {} } };
  NPM["is-odd"] = { versions: { "3.0.1": {} } };
  project(
    { express: "4.16.4", lodash: "4.17.21", "left-pad": "1.3.0", "is-odd": "3.0.1" },
    {
      "node_modules/express": { version: "4.16.4" },
      "node_modules/lodash": { version: "4.17.21" },
      "node_modules/left-pad": { version: "1.3.0" },
      "node_modules/is-odd": { version: "3.0.1" },
    },
  );
}

type Row = { package: string; action: string; risk: string; targetVersion: string | null };
const row = (r: Record<string, any>, name: string) => (r.recommendations as Row[]).find((x) => x.package === name)!;

describe("W8: NOT CHECKED rows are never counted as vulnerable with no fixed release", () => {
  it("partial OSV.dev answer: only lodash is 'no fixed release yet'; left-pad and is-odd are NOT CHECKED, never vulnerable", async () => {
    mixed();
    const r = await plan();
    expect(r.vulnerabilityCoverage).toMatchObject({ checked_dependencies: 2, unchecked_dependencies: 2 });
    expect(row(r, "lodash")).toMatchObject({ action: "no_fix_available", risk: "high" });
    for (const name of ["left-pad", "is-odd"]) expect(row(r, name)).toMatchObject({ action: "not_checked", risk: "unknown", targetVersion: null });
    expect(r.summary).toContain(". 1 vulnerable with no fixed release yet.");
    expect(r.summary).toContain(". 2 NOT CHECKED: OSV.dev gave no answer for them");
    expect(r.summary).toMatch(/Planned over 2 vulnerable packages/);
    expect(r.waitingOnUpstream).toBe(0);
    // Never counted as clean either.
    expect(r.vulnerabilityDataAvailable).toBe(false);
    expect(r.summary).not.toMatch(/nothing to upgrade/);
  });

  it("vulnerability_scan and dependency_health count the same two as unchecked, never as vulnerable", async () => {
    mixed();
    const s = await scan();
    expect(s.coverage).toMatchObject({ complete: false, unchecked_dependencies: 2, checked_dependencies: 2 });
    expect(s.found_in_checked_dependencies.vulnerable_packages).toBe(2);
    expect((s.vulnerable_packages as Array<{ package: string }>).map((v) => v.package).sort()).toEqual(["express", "lodash"]);
    const h = await health();
    expect(h.vulnerabilityCoverage).toMatchObject({ unchecked_dependencies: 2 });
    expect(h.healthScore).toBeNull();
    expect(h.summary).toMatch(/at least 2 vulnerable packages/);
    expect(h.summary).not.toMatch(/ 4 vulnerable/);
  });

  it("offline from a partly filled cache: the uncached dependency is NOT CHECKED, not 'no fixed release yet'", async () => {
    OSV.push({ ...adv("GHSA-lo00-0000-0001", "lodash", "9.9.9", "HIGH"), affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }] });
    NPM.lodash = { versions: { "4.17.21": {} } };
    NPM["left-pad"] = { versions: { "1.3.0": {} } };
    project({ lodash: "4.17.21" }, { "node_modules/lodash": { version: "4.17.21" } });
    const db = new Database(":memory:");
    const liveOn = async () => {
      const li = new LiveIntelligence(db);
      const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
      const { entries, discovery } = scanProjectTree(dir);
      li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
      vi.spyOn(li, "getProjectRoot").mockReturnValue(dir);
      return li;
    };
    await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, await liveOn());
    project({ lodash: "4.17.21", "left-pad": "1.3.0" }, { "node_modules/lodash": { version: "4.17.21" }, "node_modules/left-pad": { version: "1.3.0" } });
    process.env.FOURDA_OFFLINE = "1";
    const r = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, await liveOn())) as Record<string, any>;
    expect(r.vulnerabilityCoverage).toMatchObject({ unchecked_dependencies: 1 });
    expect(row(r, "lodash")).toMatchObject({ action: "no_fix_available" });
    expect(row(r, "left-pad")).toMatchObject({ action: "not_checked", risk: "unknown" });
    expect(r.summary).toContain(". 1 vulnerable with no fixed release yet.");
    expect(r.summary).toContain(". 1 NOT CHECKED: OSV.dev gave no answer for it,");
  });

  it("the whole scan does not finish in the call: no row is 'vulnerable with no fixed release yet'", async () => {
    mixed();
    const li = await liveFor();
    vi.spyOn(li, "ensureVulnerabilities").mockResolvedValue(null as never);
    vi.spyOn(li, "getVulnerabilities").mockReturnValue(null as never);
    const r = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, li)) as Record<string, any>;
    for (const name of ["lodash", "left-pad", "is-odd"]) expect(row(r, name)).toMatchObject({ action: "not_checked", risk: "unknown" });
    expect(r.summary).not.toMatch(/vulnerable with no fixed release/);
    expect(r.summary).toMatch(/NOT CHECKED/);
  });
});
