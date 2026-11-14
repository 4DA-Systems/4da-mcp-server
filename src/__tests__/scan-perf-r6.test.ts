// SPDX-License-Identifier: Apache-2.0
/**
 * Blind audit round 6 (pre-publish, 60c9edc against 6.2.7, js-nest-npm3, 1,889 dependencies):
 *
 * - a fully cached vulnerability_scan took 3.7 s and `ping` waited 3.6 s for it: every parent
 *   lookup re-read, re-parsed and re-walked the whole lockfile (lockfile-parents.ts). At 107,000
 *   lockfile entries `ping` waited 20.8 s;
 * - a second scan in the same process re-sent 92 querybatch and 90 /v1/query requests: the fix
 *   confirmations went out one release per request, used up the 60-a-minute query budget, waited
 *   for tokens past their deadline and were asked again next time; concurrent checks of one release
 *   each asked for it;
 * - transitive rows came back with no fix_action and no marker;
 * - for a package the registry does not have, "latest" reached OSV.dev as a version.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";

// Every read of a file is counted, so a test can hold the lockfile to one read.
const reads = vi.hoisted(() => new Map<string, number>());
vi.mock("node:fs", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:fs")>();
  const readFileSync = ((file: unknown, ...rest: unknown[]) => {
    reads.set(String(file), (reads.get(String(file)) ?? 0) + 1);
    return (real.readFileSync as (...a: unknown[]) => unknown)(file, ...rest);
  }) as typeof real.readFileSync;
  return { ...real, default: { ...real, readFileSync }, readFileSync };
});
const fs = await import("node:fs");

const { LiveCache } = await import("../live/cache.js");
const { LiveIntelligence } = await import("../live/index.js");
const { OsvScanner, OsvHttpSource } = await import("../live/osv-scanner.js");
const { RateLimiter } = await import("../live/rate-limiter.js");
const { clearLockfileParentCache, prepareLockfileParents, readLockfileParents } = await import("../live/lockfile-parents.js");
const { batchAnswer, isConcreteVersion, listConfirmed } = await import("../live/batch-confirm.js");
const { executeVulnerabilityScan } = await import("../tools/vulnerability-scan.js");
const { yieldIfDue } = await import("../live/yield-point.js");
import type { OsvVulnerability, ResolvedDependency, VulnerabilityScanResult } from "../live/types.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const dep = (name: string, version = "1.0.0"): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [],
});

type Ev = Record<string, string>;
const adv = (id: string, name: string, fixed: string): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed }] as Ev[] }] }],
});
const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
const affects = (v: OsvVulnerability, version: string) => cmp(version, v.affected![0].ranges[0].events.find((e) => e.fixed)!.fixed!) < 0;

let ADVISORIES: Record<string, OsvVulnerability[]> = {};
let NPM: Record<string, { versions: Record<string, { dependencies?: Record<string, string> }>; latest: string }> = {};
let REQUESTS: Array<{ url: string; body: string }> = [];

function stubNetwork(delayMs = 0) {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const body = typeof init?.body === "string" ? init.body : "";
    REQUESTS.push({ url, body });
    if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
    const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(body) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (ADVISORIES[q.package.name] ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(ADVISORIES).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(body) as { package: { name: string } };
      return json({ vulns: ADVISORIES[q.package.name] ?? [] });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      const doc = NPM[decodeURIComponent(npm[1])];
      if (!doc) return json({}, 404);
      if (npm[2]) {
        const version = doc.versions[decodeURIComponent(npm[2])];
        return version ? json(version) : json({}, 404);
      }
      return json({ name: decodeURIComponent(npm[1]), "dist-tags": { latest: doc.latest }, versions: doc.versions });
    }
    return json({}, 404);
  });
}

let dir: string;
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-r6-perf-"));
  ADVISORIES = {};
  NPM = {};
  REQUESTS = [];
  reads.clear();
  clearLockfileParentCache();
  stubNetwork();
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

type LockEntry = { version: string; dependencies?: Record<string, string> };
function project(direct: Record<string, string>, tree: Record<string, LockEntry>) {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: direct }));
  const packages: Record<string, unknown> = { "": { name: "x", dependencies: direct } };
  for (const [n, e] of Object.entries(tree)) packages[`node_modules/${n}`] = e;
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
}

async function live() {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

/** Three parents, each pulling in a vulnerable transitive copy whose fix its range admits. */
function threeTransitives() {
  const tree: Record<string, LockEntry> = {};
  const direct: Record<string, string> = {};
  for (const i of [1, 2, 3]) {
    direct[`parent${i}`] = "^1.0.0";
    tree[`parent${i}`] = { version: "1.0.0", dependencies: { [`child${i}`]: "^1.0.0" } };
    tree[`child${i}`] = { version: "1.0.0" };
    ADVISORIES[`child${i}`] = [adv(`GHSA-c${i}c${i}-c${i}c${i}-c${i}c${i}`, `child${i}`, "1.0.1")];
    NPM[`child${i}`] = { versions: { "1.0.0": {}, "1.0.1": {} }, latest: "1.0.1" };
    NPM[`parent${i}`] = { versions: { "1.0.0": { dependencies: { [`child${i}`]: "^1.0.0" } } }, latest: "1.0.0" };
  }
  project(direct, tree);
}

describe("a lockfile is read once for its parents, however many lookups ask", () => {
  it("lookups for many packages read and parse the file once; a rewrite is read again", async () => {
    threeTransitives();
    const lock = path.join(dir, "package-lock.json");
    for (let round = 0; round < 3; round++) {
      for (const name of ["child1", "child2", "child3", "parent1", "parent2", "parent3", "nothing"]) readLockfileParents(lock, name, "1.0.0");
    }
    await prepareLockfileParents(lock);
    expect(reads.get(lock)).toBe(1);
    expect(readLockfileParents(lock, "child2", "1.0.0")!.edges).toEqual([{ parent: "parent2", parentVersion: "1.0.0", range: "^1.0.0", local: false }]);

    // A changed lockfile (another size) is read again and answers from its new content.
    const content = JSON.parse(fs.readFileSync(lock, "utf-8"));
    content.packages["node_modules/parent2"].dependencies.child2 = "~1.0.0";
    content.packages["node_modules/extra"] = { version: "9.9.9" };
    fs.writeFileSync(lock, JSON.stringify(content));
    reads.clear();
    expect(readLockfileParents(lock, "child2", "1.0.0")!.edges[0].range).toBe("~1.0.0");
    expect(reads.get(lock)).toBe(1);
  });

  it("a whole vulnerability_scan reads the lockfile for parents once, and a second scan does not read it for them again", async () => {
    threeTransitives();
    const li = await live();
    const lock = path.join(dir, "package-lock.json");
    reads.clear();
    await executeVulnerabilityScan(noDb, { response_format: "detailed" }, li);
    // Once for the dependency set's re-check is not counted here: the scan reads its versions
    // through its own resolution (unchanged lockfile: no read), and the parents once.
    const first = reads.get(lock) ?? 0;
    expect(first).toBeLessThanOrEqual(1);
    reads.clear();
    await executeVulnerabilityScan(noDb, { response_format: "detailed" }, li);
    expect(reads.get(lock) ?? 0).toBe(0);
  });

  it("building the index of a large lockfile lets timers run while it builds", async () => {
    const packages: Record<string, unknown> = { "": { name: "big", dependencies: {} as Record<string, string> } };
    for (let i = 0; i < 40_000; i++) {
      packages[`node_modules/p${i}`] = { version: "1.0.0", dependencies: { [`p${(i + 1) % 40_000}`]: "^1.0.0", [`p${(i + 7) % 40_000}`]: "^1.0.0" } };
    }
    const lock = path.join(dir, "package-lock.json");
    fs.writeFileSync(lock, JSON.stringify({ name: "big", lockfileVersion: 3, packages }));
    let ticks = 0;
    const timer = setInterval(() => ticks++, 1);
    const index = await prepareLockfileParents(lock);
    clearInterval(timer);
    expect(index!.parents("p5", "1.0.0").map((e) => e.parent).sort()).toEqual(["p4", "p39998"].sort());
    // The build gave the event loop back between steps (it yields every 2,000 entries).
    expect(ticks).toBeGreaterThan(3);
  });
});

describe("the event loop is given back during long cached work", () => {
  it("concurrent workers that are due share one turn, and a timer runs between turns", async () => {
    let fired = 0;
    const timer = setInterval(() => fired++, 0);
    const busyUntil = Date.now() + 200;
    const worker = async () => {
      while (Date.now() < busyUntil) {
        const spin = performance.now() + 2;
        while (performance.now() < spin);
        await yieldIfDue();
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
    clearInterval(timer);
    expect(fired).toBeGreaterThan(4);
  });
});

describe("OSV.dev queries: asked once, together", () => {
  it("many small confirmations at once go out in one querybatch request, within the query budget", async () => {
    ADVISORIES["pkg-3"] = [adv("GHSA-pkg3-pkg3-pkg3", "pkg-3", "1.0.1")];
    const limiter = new RateLimiter({ osv: { maxPerMinute: 60 } });
    const source = new OsvHttpSource(new LiveCache(new Database(":memory:")), limiter, 200);
    const answers = await Promise.all(Array.from({ length: 80 }, (_, i) => source.query([dep(`pkg-${i}`)])));
    expect(REQUESTS.filter((r) => r.url.endsWith("/v1/querybatch"))).toHaveLength(1);
    // Every caller has its own answer: none unanswered, none mixed up.
    expect(answers.every((a) => a.failure === null && Array.isArray(a.ids[0]))).toBe(true);
    expect(answers[3].ids[0]).toEqual(["GHSA-pkg3-pkg3-pkg3"]);
    expect(answers[4].ids[0]).toEqual([]);
  });

  it("a release several checks ask about at once is asked once, and the second scan of it asks nothing", async () => {
    ADVISORIES.lodash = [adv("GHSA-aaaa-bbbb-cccc", "lodash", "4.17.21")];
    stubNetwork(15);
    const scanner = new OsvScanner(new LiveCache(new Database(":memory:")), new RateLimiter({ osv: { maxPerMinute: 60 } }));
    const results = await Promise.all(Array.from({ length: 6 }, () => scanner.scan([dep("lodash", "4.17.20")], "dependency_check")));
    expect(results.every((r) => r.vulnerabilities.length === 1 && !r.offline)).toBe(true);
    expect(REQUESTS.filter((r) => r.url.endsWith("/v1/querybatch"))).toHaveLength(1);
    expect(REQUESTS.filter((r) => r.url.includes("/v1/vulns/"))).toHaveLength(1);
    REQUESTS = [];
    await scanner.scan([dep("lodash", "4.17.20")], "dependency_check");
    expect(REQUESTS).toEqual([]);
  });

  it("one failed answer shared by waiting callers leaves each of them unanswered, never clean", async () => {
    vi.stubGlobal("fetch", async () => new Response("down", { status: 503 }));
    const source = new OsvHttpSource(new LiveCache(new Database(":memory:")), new RateLimiter({ osv: { maxPerMinute: 60 } }), 200);
    const answers = await Promise.all([source.query([dep("a")]), source.query([dep("b")])]);
    for (const a of answers) {
      expect(a.ids).toEqual([null]);
      expect(a.failure).toBeTruthy();
    }
  });
});

describe("a second vulnerability_scan in the same process asks the network nothing", () => {
  it("fix targets, their confirmations and the fix-path verdicts all come from what the first scan cached", async () => {
    threeTransitives();
    const li = await live();
    const first = (await executeVulnerabilityScan(noDb, { response_format: "detailed" }, li)) as { fix_targets: Record<string, { action?: string }> };
    expect(REQUESTS.length).toBeGreaterThan(0);
    expect(first.fix_targets["child1@1.0.0"].action).toBe("lockfile_refresh");
    REQUESTS = [];
    const second = (await executeVulnerabilityScan(noDb, { response_format: "detailed" }, li)) as { fix_targets: Record<string, { action?: string }> };
    expect(REQUESTS.map((r) => r.url)).toEqual([]);
    expect(second.fix_targets).toEqual(first.fix_targets);
  });
});

describe("every vulnerable transitive row says how it is fixed, or plainly that it was not determined", () => {
  it("a transitive copy whose fix path did not finish carries action not_checked with why, in fix_targets and the concise row", async () => {
    const { formatScanResult } = await import("../tools/vulnerability-scan-format.js");
    const { conciseScanResult } = await import("../tools/vulnerability-scan-concise.js");
    const { TRANSITIVE_PENDING } = await import("../tools/fix-verdicts.js");
    const vuln = {
      package: "tar", currentVersion: "6.1.0", ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: true,
      vulnId: "GHSA-r6q2-hw4h-h46w", aliases: [], severity: "high", cvssScore: 7.5, summary: "tar", fixedVersion: "6.2.1",
      published: "2026-01-01T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: [dir],
    };
    const result = {
      scannedAt: new Date().toISOString(), projectPath: dir, ecosystemsScanned: ["npm"], totalScanned: 1, totalVulnerable: 1,
      platformInactiveVulnerable: 0, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 }, vulnerabilities: [vuln],
      cleanCount: 0, scanDurationMs: 1, cached: false, offline: false,
    } as unknown as VulnerabilityScanResult;
    const key = ["npm", "tar", "6.1.0"].join("\u0000");
    const pending = {
      package: "tar", ecosystem: "npm", currentVersion: "6.1.0", targetVersion: "6.2.1", upgradeType: "minor", reasons: [TRANSITIVE_PENDING],
      breaking: false, scope: "transitive", action: "waiting_on_upstream",
    };
    for (const verdicts of [new Map([[key, pending as never]]), new Map()]) {
      const full = formatScanResult(result, undefined, { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true, verdicts });
      const target = full.fix_targets["tar@6.1.0"] as { action?: string; action_note?: string };
      expect(target.action).toBe("not_checked");
      expect(target.action_note).toMatch(/^NOT CHECKED/);
      const row = (conciseScanResult(full) as unknown as { vulnerable_packages: Array<{ package: string; fix_action?: string; fix_action_note?: string }> }).vulnerable_packages.find((p) => p.package === "tar")!;
      expect(row.fix_action).toBe("not_checked");
      expect(row.fix_action_note).toMatch(/^NOT CHECKED/);
    }
    // No advisory names a fixed release: said as such, still with why.
    const noFix = { ...result, vulnerabilities: [{ ...vuln, fixedVersion: null }] } as unknown as VulnerabilityScanResult;
    const full = formatScanResult(noFix, undefined, { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true, verdicts: new Map([[key, { ...pending, targetVersion: null, action: "no_fix_available" } as never]]) });
    expect(full.fix_targets["tar@6.1.0"]).toMatchObject({ target: null, action: "no_fix_available", action_note: expect.stringMatching(/No release fixes/) });
  });
});

describe("only a concrete release is ever asked about or confirmed", () => {
  it('"latest", a range or nothing is not sent to OSV.dev, and is never confirmed', async () => {
    expect(isConcreteVersion("4.17.21")).toBe(true);
    expect(isConcreteVersion("v0.23.0")).toBe(true);
    for (const v of ["latest", "", "^1.2.0", "*", "next"]) expect(isConcreteVersion(v)).toBe(false);
    const asked: ResolvedDependency[][] = [];
    const query = async (deps: ResolvedDependency[]) => {
      asked.push(deps);
      return { vulnerabilities: [], offline: false } as unknown as VulnerabilityScanResult;
    };
    const answer = await batchAnswer(query, [{ ecosystem: "npm", name: "no-such-package-x", version: "latest" }], Date.now() + 1_000);
    expect(asked).toEqual([]);
    expect(answer.read).toBe(true);
    expect(await listConfirmed(query, [], "npm", "no-such-package-x", ["latest"], Date.now() + 1_000)).toBe(false);
    expect(asked).toEqual([]);
  });
});
