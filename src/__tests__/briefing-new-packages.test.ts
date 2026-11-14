// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know and the packages a task adds (audit 2026-11-11, M14).
 *
 * `{ task: "add the lodahs package" }` came back safe_to_delegate: the briefing only asked which
 * of the project's own dependencies the task names, and `lodahs` (a name npm took down as
 * malware, MAL-2025-25502) is not one of them. The briefing now runs dependency_check's
 * name-level checks on what a task adds.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import type { OsvVulnerability, ResolvedDependency, VulnerabilityScanResult } from "../live/types.js";
import { detectNewPackages } from "../tools/briefing-new-packages.js";
import { executeWhatShouldIKnow, type BriefingLiveIntel } from "../tools/what-should-i-know.js";

const dep = (name: string, version: string, ecosystem: ResolvedDependency["ecosystem"] = "npm"): ResolvedDependency => ({
  name,
  version,
  ecosystem,
  isDev: false,
  isDirect: true,
  devScopeKnown: true,
  target: null,
  platformActive: true,
  sourceDirs: ["d:/proj"],
});
const DEPS = [dep("express", "5.1.0"), dep("lodash", "4.17.21"), dep("serde", "1.0.229", "crates.io")];

describe("detectNewPackages: the names a task is about to add", () => {
  const names = (task: string, deps: ResolvedDependency[] = DEPS) => detectNewPackages(task, deps).map((p) => `${p.ecosystem}:${p.name}`);

  it.each([
    ["add the lodahs package", ["npm:lodahs"]],
    ["Add the `lodahs` package to the API", ["npm:lodahs"]],
    ["install lodahs", ["npm:lodahs"]],
    ["npm install lodahs expres", ["npm:lodahs", "npm:expres"]],
    ["run `pnpm add -D reactt` in the web app", ["npm:reactt"]],
    ["yarn add left-pad@1.3.0 and wire it in", ["npm:left-pad"]],
    ["add a dependency on left-pad", ["npm:left-pad"]],
    ["use the left-pad library for padding", ["npm:left-pad"]],
    ["add package lodahs and expres", ["npm:lodahs", "npm:expres"]],
    ["Add `expres` and set up a basic server", ["npm:expres"]],
    ["add expres to package.json", ["npm:expres"]],
    ["pip install reqeusts", ["PyPI:reqeusts"]],
    ["uv add httpx==0.27.0", ["PyPI:httpx"]],
    ["cargo add serde_jsn", ["crates.io:serde_jsn"]],
    ["add the tokio crate", ["crates.io:tokio"]],
    ["go get github.com/labstack/echo/v4", ["Go:github.com/labstack/echo/v4"]],
    ["install @scope/some-pkg", ["npm:@scope/some-pkg"]],
  ])("%s", (task, expected) => {
    expect(names(task)).toEqual(expected);
  });

  it.each([
    "add tests to the auth package",
    "add error handling to the parser",
    "add routes to the app",
    "add logging and retry around the upload",
    "fix the login bug",
    "upgrade lodash to 4.17.21",
    "add express middleware for auth",
    "run npm install and then the tests",
    "npm install in the frontend folder",
    "use the latest version of the package",
    "add a new dependency",
    "install dependencies",
    "add the missing dependency",
    "refactor the module loader to use async imports",
  ])("names nothing: %s", (task) => {
    expect(names(task)).toEqual([]);
  });

  it("a package the project already has is not a new one, and at most three are read", () => {
    expect(names("add the lodash package")).toEqual([]);
    expect(names("npm install lodash lodahs")).toEqual(["npm:lodahs"]);
    expect(names("npm install aaa bbb ccc ddd eee")).toHaveLength(3);
  });

  it("prose without a manager word takes the project's ecosystem", () => {
    const rust = [dep("serde", "1.0.229", "crates.io"), dep("tokio", "1.40.0", "crates.io")];
    expect(names("add the anyhow dependency", rust)).toEqual(["crates.io:anyhow"]);
    expect(names("add the anyhow dependency", [])).toEqual(["npm:anyhow"]);
  });
});

// ---------------------------------------------------------------------------------------------
// The briefing, over stubbed registries and OSV
// ---------------------------------------------------------------------------------------------

interface Pkg {
  created?: string;
  latest: string;
  versions: Record<string, string>;
  unpublished?: Record<string, string>;
}
let NPM: Record<string, Pkg>;
let OSV: OsvVulnerability[];
let DOWNLOADS: Record<string, number>;
let REGISTRY_DOWN: boolean;
/** Every URL the briefing fetched, to prove a word was never looked up. */
let ASKED: string[];

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    ASKED.push(url);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    // OSV answers by ecosystem and name, as the real one does.
    const recordsFor = (name: string, ecosystem?: string) => OSV.filter((v) => v.affected?.some((a) => a.package?.name === name && (!ecosystem || a.package?.ecosystem === ecosystem)));
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: recordsFor(q.package.name, q.package.ecosystem).map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const found = OSV.find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string } };
      return json({ vulns: recordsFor(q.package.name, q.package.ecosystem) });
    }
    const downloads = /^https:\/\/api\.npmjs\.org\/downloads\/point\/last-week\/(.+)$/.exec(url);
    if (downloads) {
      const asked = decodeURIComponent(downloads[1]).split(",");
      if (asked.length === 1) return asked[0] in DOWNLOADS ? json({ downloads: DOWNLOADS[asked[0]], package: asked[0] }) : json({ error: "not found" }, 404);
      return json(Object.fromEntries(asked.map((n) => [n, n in DOWNLOADS ? { downloads: DOWNLOADS[n], package: n } : null])));
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      if (REGISTRY_DOWN) return new Response("bad gateway", { status: 502 });
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({ error: "Not found" }, 404);
      return json({
        name,
        "dist-tags": { latest: doc.latest },
        versions: Object.fromEntries(Object.keys(doc.versions).map((v) => [v, { name, version: v, dependencies: {} }])),
        time: { created: doc.created ?? "2015-01-01T00:00:00.000Z", ...doc.versions, ...(doc.unpublished ?? {}) },
      });
    }
    return json({}, 404);
  });
}

function createDb(): FourDADatabase {
  const raw = new Database(":memory:");
  const instance = Object.create(FourDADatabase.prototype) as FourDADatabase;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (instance as any).db = raw;
  return instance;
}

const READY_SCAN: VulnerabilityScanResult = {
  scannedAt: new Date().toISOString(),
  projectPath: "d:/proj",
  ecosystemsScanned: ["npm"],
  totalScanned: 3,
  totalVulnerable: 0,
  platformInactiveVulnerable: 0,
  bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  vulnerabilities: [],
  cleanCount: 3,
  scanDurationMs: 5,
  cached: false,
  offline: false,
};

/** The project's scan state under the test's control; registry and OSV lookups through the real live layer. */
function intel(scan: VulnerabilityScanResult | null = READY_SCAN, over: Partial<BriefingLiveIntel> = {}): BriefingLiveIntel {
  const live = new LiveIntelligence(new Database(":memory:"));
  return {
    isEnabled: () => true,
    getProjectRoot: () => "d:/proj",
    ensureVulnerabilities: async () => scan,
    getVulnerabilities: () => scan,
    getResolvedDeps: () => DEPS,
    getAuditDeps: () => [],
    getReleaseSources: () => live.getReleaseSources(),
    getFixPathSources: () => live.getFixPathSources(),
    queryAdvisories: (deps) => live.queryAdvisories(deps),
    ...over,
  };
}

let db: FourDADatabase;
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  clearNpmDownloadsMemo();
  db = createDb();
  REGISTRY_DOWN = false;
  ASKED = [];
  DOWNLOADS = { express: 195_493_804, expres: 5216, lodash: 202_301_867 };
  NPM = {
    // npm took it down: only the security placeholder is listed.
    lodahs: { latest: "0.0.1-security", versions: { "0.0.1-security": "2025-06-01T00:00:00.000Z" }, unpublished: { "1.0.0": "2025-05-30T00:00:00.000Z" } },
    expres: { created: "2012-10-10T03:49:52.879Z", latest: "0.0.5", versions: { "0.0.5": "2012-10-10T03:49:52.879Z" } },
    "left-pad": { latest: "1.3.0", versions: { "1.2.0": "2017-01-01T00:00:00.000Z", "1.3.0": "2018-04-01T00:00:00.000Z" } },
  };
  OSV = [
    { id: "MAL-2025-25502", aliases: [], summary: "Malicious code in lodahs (npm)", affected: [{ package: { name: "lodahs", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }] } as unknown as OsvVulnerability,
  ];
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

describe("what_should_i_know: a task that adds a package", () => {
  it("\"add the lodahs package\" is human_only: the name is malware (it said safe_to_delegate)", async () => {
    const r = await executeWhatShouldIKnow(db, { task: "add the lodahs package" }, intel());
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason).toContain("The task adds lodahs (a malware name, avoid: did you mean lodash?). Do not install it:");
    expect(r.delegation_assessment.reason).toContain("npm took lodahs down as malware");
    expect(r.new_packages).toMatchObject([{ name: "lodahs", ecosystem: "npm", verdict: "avoid", malicious: true, did_you_mean: "lodash", latest: "0.0.1-security" }]);
    expect(r.summary).toContain("Task adds lodahs (a malware name, avoid: did you mean lodash?)");
    expect(r.summary).toContain("Delegation: human_only.");
  });

  it("a project with more Python than npm: a bare name PyPI lacks is checked on npm too, and its malware is found (blind audit replay 2026-11-14)", async () => {
    const mixed = [dep("lodash", "4.17.21"), dep("requests", "2.32.3", "PyPI"), dep("urllib3", "2.2.2", "PyPI"), dep("idna", "3.7", "PyPI")];
    expect(detectNewPackages("add the lodahs package", mixed)).toEqual([{ name: "lodahs", ecosystem: "PyPI", alternatives: ["npm"] }]);
    const r = await executeWhatShouldIKnow(db, { task: "add the lodahs package" }, intel(READY_SCAN, { getResolvedDeps: () => mixed }));
    expect(r.new_packages).toMatchObject([{ name: "lodahs", ecosystem: "npm", verdict: "avoid", malicious: true }]);
    expect(r.new_packages?.[0]).not.toHaveProperty("alternatives");
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it("a stated ecosystem is never second-guessed: \"pip install lodahs\" stays PyPI", () => {
    const mixed = [dep("lodash", "4.17.21"), dep("requests", "2.32.3", "PyPI")];
    expect(detectNewPackages("pip install lodahs", mixed)).toEqual([{ name: "lodahs", ecosystem: "PyPI" }]);
  });

  it("the same when the project scan is not ready: a malware name is never \"unknown\"", async () => {
    const r = await executeWhatShouldIKnow(db, { task: "add the lodahs package" }, intel(null));
    expect(r.scan_status).toBe("unavailable");
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it("a near-miss of a popular package is review_needed, with the name it likely meant", async () => {
    const r = await executeWhatShouldIKnow(db, { task: "npm install expres" }, intel());
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toContain("the task adds expres (review: did you mean express?), which dependency_check does not clear");
    expect(r.new_packages).toMatchObject([{ name: "expres", verdict: "review", malicious: false, did_you_mean: "express", name_finding: "review" }]);
    // And with no ready scan the finding still stands, beside the note that the rest is unreviewed.
    const cold = await executeWhatShouldIKnow(db, { task: "npm install expres" }, intel(null));
    expect(cold.delegation_assessment.level).toBe("review_needed");
    expect(cold.delegation_assessment.reason).toContain("did you mean express?");
    expect(cold.delegation_assessment.reason).toContain("Vulnerability scan unavailable");
  });

  it("a name the registry does not have is review_needed (a private package, a typo, or a hallucinated name)", async () => {
    const r = await executeWhatShouldIKnow(db, { task: "add the frobnicate-internal package" }, intel());
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.new_packages).toMatchObject([{ name: "frobnicate-internal", verdict: "unknown", malicious: false }]);
    expect(r.new_packages![0].reason).toContain("is not on the public npm registry");
  });

  it("a clean new package changes nothing: safe_to_delegate, and it is listed as proceed", async () => {
    const r = await executeWhatShouldIKnow(db, { task: "add the left-pad package" }, intel());
    expect(r.new_packages).toMatchObject([{ name: "left-pad", verdict: "proceed", latest: "1.3.0", malicious: false, name_finding: null }]);
    expect(r.delegation_assessment.level).toBe("safe_to_delegate");
  });

  it("a check that cannot run is never safe: registry down, lookups disabled, or no registry access in the session", async () => {
    REGISTRY_DOWN = true;
    const down = await executeWhatShouldIKnow(db, { task: "add the left-pad package" }, intel());
    expect(down.new_packages).toMatchObject([{ name: "left-pad", verdict: "unknown" }]);
    expect(down.delegation_assessment.level).toBe("review_needed");

    REGISTRY_DOWN = false;
    const offline = await executeWhatShouldIKnow(db, { task: "add the left-pad package" }, intel(READY_SCAN, { isEnabled: () => false }));
    expect(offline.new_packages).toMatchObject([{ name: "left-pad", verdict: "unknown" }]);
    expect(offline.new_packages![0].reason).toContain("live lookups are disabled");
    expect(offline.delegation_assessment.level).not.toBe("safe_to_delegate");

    const bare = await executeWhatShouldIKnow(db, { task: "add the left-pad package" }, intel(READY_SCAN, { getReleaseSources: undefined }));
    expect(bare.new_packages).toMatchObject([{ name: "left-pad", verdict: "unknown" }]);
    expect(bare.delegation_assessment.level).toBe("review_needed");
  });

  it("a task that adds nothing has no new_packages field and is judged as before", async () => {
    const r = await executeWhatShouldIKnow(db, { task: "add error handling to the parser" }, intel());
    expect(r.new_packages).toBeUndefined();
    expect(r.delegation_assessment.level).toBe("safe_to_delegate");
  });
});

// ---------------------------------------------------------------------------------------------
// Round 5 audits: malware added to a Python project, swapped in, or added with no package word
// ---------------------------------------------------------------------------------------------

const PY = [dep("requests", "2.32.3", "PyPI")];
const mal = (name: string, ecosystem: string, id: string) =>
  ({ id, aliases: [], summary: `Malicious code in ${name} (${ecosystem})`, affected: [{ package: { name, ecosystem }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }] }) as unknown as OsvVulnerability;

describe("round 5: a task that adds malware is never safe_to_delegate", () => {
  beforeEach(() => {
    OSV.push(
      mal("ctx", "PyPI", "MAL-2022-ctx"),
      mal("extrahtml", "PyPI", "MAL-2024-extrahtml"),
      mal("logger-libs", "PyPI", "MAL-2024-logger-libs"),
      mal("flatmap-stream", "npm", "MAL-2018-flatmap-stream"),
    );
    NPM["flatmap-stream"] = { latest: "0.0.1-security", versions: { "0.0.1-security": "2018-11-26T00:00:00.000Z" } };
  });

  it.each(["add ctx", "add ctx to requirements.txt", "add extrahtml to requirements.txt", "add logger-libs", "add extrahtml and ctx"])(
    "a PyPI project: %s is human_only (it was safe_to_delegate with no new package)",
    async (task) => {
      const r = await executeWhatShouldIKnow(db, { task }, intel(READY_SCAN, { getResolvedDeps: () => PY }));
      expect(r.delegation_assessment.level).toBe("human_only");
      expect(r.new_packages?.length).toBeGreaterThan(0);
      expect(r.new_packages!.every((p) => p.ecosystem === "PyPI" && p.verdict === "avoid" && p.malicious)).toBe(true);
    },
  );

  it.each([
    ["replace lodash with lodahs", "lodahs", "human_only"],
    ["swap express for expres", "expres", "review_needed"],
    ["add flatmap-stream", "flatmap-stream", "human_only"],
  ])("an npm project: %s brings %s in and is %s (it was safe_to_delegate with new_packages [])", async (task, name, level) => {
    const r = await executeWhatShouldIKnow(db, { task }, intel());
    expect(r.new_packages).toMatchObject([{ name, ecosystem: "npm" }]);
    expect(r.new_packages![0].verdict).not.toBe("proceed");
    expect(r.delegation_assessment.level).toBe(level);
  });

  it.each([
    ["replace lodash with lodahs", ["npm:lodahs"]],
    ["swap express for expres", ["npm:expres"]],
    ["swap out express for expres", ["npm:expres"]],
    ["switch from lodash to lodahs", ["npm:lodahs"]],
    ["migrate to dayjs", ["npm:dayjs"]],
    ["add flatmap-stream", ["npm:flatmap-stream"]],
    ["add ctx to the dependencies", ["npm:ctx"]],
    ["add ctx as a dev dependency", ["npm:ctx"]],
  ])("reads what comes in: %s", (task, expected) => {
    expect(detectNewPackages(task, DEPS).map((p) => `${p.ecosystem}:${p.name}`)).toEqual(expected);
  });

  it.each([
    "install steps",
    "add routes to the app",
    "add memoization to the parser",
    "add caching to the client",
    "add a footer to the page",
    "import json and parse the file",
    "add scripts to package.json",
    "replace the for loop with map",
    "move the helper to utils",
  ])("everyday English names nothing to look up: %s", (task) => {
    expect(detectNewPackages(task, PY)).toEqual([]);
    expect(detectNewPackages(task, DEPS)).toEqual([]);
  });

  it('"install zqx omega risk": zqx is a name, omega and risk are words and are never looked up', async () => {
    expect(detectNewPackages("install zqx omega risk", PY).map((p) => p.name)).toEqual(["zqx"]);
    await executeWhatShouldIKnow(db, { task: "install steps" }, intel(READY_SCAN, { getResolvedDeps: () => PY }));
    await executeWhatShouldIKnow(db, { task: "install zqx omega risk" }, intel());
    expect(ASKED.some((u) => /\/(?:steps|risk|omega)(?:$|[/?])/.test(u) || /"name":"(?:steps|risk|omega)"/.test(u))).toBe(false);
  });

  it("a bare name no registry has and no malware record covers was prose: dropped, the task judged as before", async () => {
    // "add frobnicator" with nothing else saying it is a package: the registry has no such name.
    expect(detectNewPackages("add frobnicator", DEPS)).toMatchObject([{ name: "frobnicator", ecosystem: "npm", weak: true }]);
    const r = await executeWhatShouldIKnow(db, { task: "add frobnicator" }, intel());
    expect(r.new_packages).toBeUndefined();
    expect(r.delegation_assessment.level).toBe("safe_to_delegate");
    // Said to be a package, the same name is still reported as one the registry does not have.
    const said = await executeWhatShouldIKnow(db, { task: "add frobnicator to package.json" }, intel());
    expect(said.new_packages).toMatchObject([{ name: "frobnicator", verdict: "unknown" }]);
    expect(said.delegation_assessment.level).toBe("review_needed");
    // And a check that could not run is never dropped as prose.
    REGISTRY_DOWN = true;
    const down = await executeWhatShouldIKnow(db, { task: "add frobnicator" }, intel());
    expect(down.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});
