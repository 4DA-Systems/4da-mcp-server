// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know reads a task clause by clause (pre-publish audit of 5d709ff).
 *
 * Each of these came back with a package or a version unchecked:
 * - "bring in rustdecimal" in an npm project: safe_to_delegate; crates.io's rustdecimal is malware.
 * - "pull in node-ipc 10.1.1", "bring in ua-parser-js 0.7.29", "we need node-ipc 10.1.1": the
 *   version was never tied to the name, and the malicious releases were not flagged.
 * - "add express, ctx", "add lodash 4.17.21 and crossenv", "add chalk 5.6.2 and electorn": a comma,
 *   or a version after the first name, ended the list, and the second package was never checked.
 * - "replace request with axios 0.21.0" (and swap / migrate), "pull in event-stream 3.3.6": the
 *   version was dropped, and the summary said "Task adds axios (proceed)".
 * - `add "dbg": "npm:debug@4.4.2" to package.json`: "Task adds dbg (proceed), npm (proceed)".
 * - "upgrade lodash to 4.17.21 and add express 4.x": the 4.x could be tied to lodash.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import type { OsvVulnerability, ResolvedDependency, VulnerabilityScanResult } from "../live/types.js";
import { detectNewPackages } from "../tools/briefing-new-packages.js";
import { readTaskVersions } from "../tools/briefing-requested-versions.js";
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
/** An npm project that has request and an older lodash. */
const NPM_PROJECT = [dep("react", "18.2.0"), dep("request", "2.88.2"), dep("lodash", "4.17.20")];
/** package.json + package-lock.json + requirements.txt. */
const MIXED = [dep("react", "18.2.0"), dep("lodash", "4.17.20"), dep("requests", "2.32.3", "PyPI")];
const RUST = [dep("serde", "1.0.200", "crates.io"), dep("tokio", "1.40.0", "crates.io")];

const show = (task: string, deps: ResolvedDependency[]) => ({
  added: detectNewPackages(task, deps).map((p) => `${p.ecosystem}:${p.name}${p.version ? `@${p.version}` : ""}`),
  requested: readTaskVersions(task, deps).requested.map((r) => `${r.ecosystem}:${r.name}@${r.to}`),
});

describe("the clause reader: every item of a list, and each version bound to the name before it", () => {
  it.each([
    // "bring in / pull in / need" with a version read like "add X@V".
    ["pull in node-ipc 10.1.1", ["npm:node-ipc@10.1.1"], ["npm:node-ipc@10.1.1"]],
    ["bring in ua-parser-js 0.7.29", ["npm:ua-parser-js@0.7.29"], ["npm:ua-parser-js@0.7.29"]],
    ["we need node-ipc 10.1.1", ["npm:node-ipc@10.1.1"], ["npm:node-ipc@10.1.1"]],
    ["pull in event-stream 3.3.6", ["npm:event-stream@3.3.6"], ["npm:event-stream@3.3.6"]],
    ["bring in event-stream at version 3.3.6", ["npm:event-stream@3.3.6"], ["npm:event-stream@3.3.6"]],
    // Lists: a comma, "and", "&", "+" or "plus", with or without versions.
    ["add express, ctx", ["npm:express", "npm:ctx"], []],
    ["add lodash-es 4.17.21 and crossenv", ["npm:lodash-es@4.17.21", "npm:crossenv"], ["npm:lodash-es@4.17.21"]],
    ["add chalk 5.6.2 and electorn", ["npm:chalk@5.6.2", "npm:electorn"], ["npm:chalk@5.6.2"]],
    ["add left-pad, chalk and electorn", ["npm:left-pad", "npm:chalk", "npm:electorn"], []],
    ["add left-pad, chalk, and electorn", ["npm:left-pad", "npm:chalk", "npm:electorn"], []],
    ["add left-pad & electorn", ["npm:left-pad", "npm:electorn"], []],
    ["add left-pad + electorn", ["npm:left-pad", "npm:electorn"], []],
    ["add left-pad plus electorn", ["npm:left-pad", "npm:electorn"], []],
    ["add left-pad 1.3.0, chalk 5.6.2 & electorn", ["npm:left-pad@1.3.0", "npm:chalk@5.6.2", "npm:electorn"], ["npm:left-pad@1.3.0", "npm:chalk@5.6.2"]],
    ["add left-pad@1.3.0, chalk@5.6.2 and electorn", ["npm:left-pad@1.3.0", "npm:chalk@5.6.2", "npm:electorn"], ["npm:left-pad@1.3.0", "npm:chalk@5.6.2"]],
    ["add the lodahs package and the expres package", ["npm:lodahs", "npm:expres"], []],
    ["add a1, a2, a3, a4 and a5", ["npm:a1", "npm:a2", "npm:a3", "npm:a4", "npm:a5"], []],
    // Swaps: what comes in, at the version written.
    ["replace request with axios 0.21.0", ["npm:axios@0.21.0"], ["npm:axios@0.21.0"]],
    ["swap request for axios 0.21.0", ["npm:axios@0.21.0"], ["npm:axios@0.21.0"]],
    ["migrate from request to axios 0.21.0", ["npm:axios@0.21.0"], ["npm:axios@0.21.0"]],
    ["switch from request to axios@0.21.0", ["npm:axios@0.21.0"], ["npm:axios@0.21.0"]],
    // The version of what goes out is not one the task writes.
    ["replace request 2.88.2 with axios 1.7.0", ["npm:axios@1.7.0"], ["npm:axios@1.7.0"]],
    // Manifest entries written into the task.
    ['add "dbg": "npm:debug@4.4.2" to package.json', ["npm:debug@4.4.2"], ["npm:debug@4.4.2"]],
    ["add 'dbg': 'npm:debug@^4.4.0' to package.json", ["npm:debug@^4.4.0"], ["npm:debug@^4.4.0"]],
    ['add "left-pad": "^1.2.3" to package.json', ["npm:left-pad@^1.2.3"], ["npm:left-pad@^1.2.3"]],
    ['add "@types/node": "20.1.0" to devDependencies', ["npm:@types/node@20.1.0"], ["npm:@types/node@20.1.0"]],
    ["add requests==2.19.0 to requirements.txt", ["PyPI:requests@2.19.0"], ["PyPI:requests@2.19.0"]],
    // Versions in the right clause.
    ["upgrade lodash to 4.17.21 and add express 4.x", ["npm:express@4.x"], ["npm:lodash@4.17.21", "npm:express@4.x"]],
    ["add express 4.x, then upgrade lodash to 4.17.21", ["npm:express@4.x"], ["npm:express@4.x", "npm:lodash@4.17.21"]],
  ])("an npm project: %s", (task, added, requested) => {
    expect(show(task, NPM_PROJECT)).toEqual({ added, requested });
  });

  it.each([
    ['add serde_json = "1.0.120" to Cargo.toml', ["crates.io:serde_json@1.0.120"], ["crates.io:serde_json@1.0.120"]],
    ['add smallvec = { version = "0.6.9", features = ["union"] } to Cargo.toml', ["crates.io:smallvec@0.6.9"], ["crates.io:smallvec@0.6.9"]],
    ["add anyhow 1 and thiserror 2 to Cargo.toml", ["crates.io:anyhow@1", "crates.io:thiserror@2"], ["crates.io:anyhow@1", "crates.io:thiserror@2"]],
    ["bring in rustdecimal", ["crates.io:rustdecimal"], []],
  ])("a Rust project: %s", (task, added, requested) => {
    expect(show(task, RUST)).toEqual({ added, requested });
  });

  it("an alias spec never makes `npm` (or the alias key) a package", () => {
    for (const task of ['add "dbg": "npm:debug@4.4.2" to package.json', '"dbg": "npm:debug@4.4.2"', "npm install dbg@npm:debug@4.4.2"]) {
      const names = detectNewPackages(task, NPM_PROJECT).map((p) => p.name);
      expect(names).not.toContain("npm");
      expect(names).not.toContain("dbg");
    }
  });

  it.each([
    // A manifest's own fields are not dependencies.
    ['set "version": "2.0.0" in package.json', []],
    ['set "node": ">=20" under engines in package.json', []],
    ['set edition = "2021" and rust-version = "1.80" in Cargo.toml', []],
    // A number in prose after "use" or "need" is not a release; a setting is not a package.
    ['set timeout = "30" in the config', []],
  ])("not a dependency version: %s", (task, requested) => {
    expect(readTaskVersions(task, NPM_PROJECT).requested.map((r) => `${r.name}@${r.to}`)).toEqual(requested);
    expect(detectNewPackages(task, NPM_PROJECT)).toEqual([]);
  });

  it.each([
    "add tests",
    "add logging to the handler",
    "add tests, logging and retries",
    "add error handling, then update the docs",
    "add routes to the app and update the docs",
    "add memoization and caching to the client",
    "we need better error messages, then a release",
    "pull in the latest main",
    "bring in the changes from main",
    "replace the for loop with map",
    "move the helper to utils",
    "add a footer, a header and a sidebar",
  ])("ordinary work still names nothing: %s", (task) => {
    for (const deps of [NPM_PROJECT, MIXED, RUST]) {
      expect(detectNewPackages(task, deps)).toEqual([]);
      expect(readTaskVersions(task, deps).requested).toEqual([]);
    }
  });

  it("a clause break or a new verb ends the list", () => {
    expect(show("install omega-flag-beta and set lodash to 4.17.21", NPM_PROJECT)).toEqual({ added: ["npm:omega-flag-beta"], requested: ["npm:lodash@4.17.21"] });
    expect(show("add left-pad; write tests for it", NPM_PROJECT).added).toEqual(["npm:left-pad"]);
    expect(show("add left-pad. Then run the build", NPM_PROJECT).added).toEqual(["npm:left-pad"]);
    expect(show("add left-pad and bring in chalk", NPM_PROJECT).added).toEqual(["npm:left-pad", "npm:chalk"]);
  });
});

// ---------------------------------------------------------------------------------------------
// The briefing, over stubbed registries and OSV.dev
// ---------------------------------------------------------------------------------------------

interface Pkg {
  latest: string;
  versions: string[];
}
let NPM: Record<string, Pkg>;
let OSV: OsvVulnerability[];
/** Every URL the briefing fetched (with its body), to prove what was and was not looked up. */
let ASKED: string[];

const cmp = (a: string, b: string) => {
  const pa = a.split(/[.-]/).map((x) => Number.parseInt(x, 10) || 0);
  const pb = b.split(/[.-]/).map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
};
/** Whether an OSV record affects a release: its explicit versions, or a SEMVER range. */
const affects = (v: OsvVulnerability, name: string, ecosystem: string, version: string) =>
  (v.affected ?? []).some((a) => {
    if (a.package?.name !== name || a.package?.ecosystem !== ecosystem) return false;
    if (a.versions?.includes(version)) return true;
    return (a.ranges ?? []).some((r) => {
      const intro = r.events.find((e) => "introduced" in e)?.introduced ?? "0";
      const fixed = r.events.find((e) => "fixed" in e)?.fixed;
      return (intro === "0" || cmp(version, intro) >= 0) && (!fixed || cmp(version, fixed) < 0);
    });
  });

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    ASKED.push(init?.body ? `${url} ${String(init.body)}` : url);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: OSV.filter((v) => affects(v, q.package.name, q.package.ecosystem, q.version)).map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const found = OSV.find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string } };
      return json({ vulns: OSV.filter((v) => v.affected?.some((a) => a.package?.name === q.package.name && a.package?.ecosystem === q.package.ecosystem)) });
    }
    if (url.startsWith("https://api.npmjs.org/downloads/")) return json({ error: "not found" }, 404);
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({ error: "Not found" }, 404);
      return json({
        name,
        "dist-tags": { latest: doc.latest },
        versions: Object.fromEntries(doc.versions.map((v) => [v, { name, version: v, dependencies: {} }])),
        time: { created: "2015-01-01T00:00:00.000Z", ...Object.fromEntries(doc.versions.map((v, i) => [v, new Date(Date.UTC(2016, 0, 1 + i)).toISOString()])) },
      });
    }
    return json({ errors: [{ detail: "Not Found" }] }, 404);
  });
}

const advisory = (id: string, name: string, severity: string, affected: { versions?: string[]; fixed?: string }, ecosystem = "npm", malware = false) =>
  ({
    id,
    aliases: [],
    summary: malware ? `Malicious code in ${name} (${ecosystem})` : `${name} advisory`,
    database_specific: { severity },
    affected: [
      {
        package: { name, ecosystem },
        ...(affected.versions ? { versions: affected.versions } : {}),
        ranges: affected.versions ? [] : [{ type: "SEMVER", events: [{ introduced: "0" }, ...(affected.fixed ? [{ fixed: affected.fixed }] : [])] }],
      },
    ],
  }) as unknown as OsvVulnerability;

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

function intel(deps: ResolvedDependency[], over: Partial<BriefingLiveIntel> = {}): BriefingLiveIntel {
  const live = new LiveIntelligence(new Database(":memory:"));
  return {
    isEnabled: () => true,
    getProjectRoot: () => "d:/proj",
    ensureVulnerabilities: async () => READY_SCAN,
    getVulnerabilities: () => READY_SCAN,
    getResolvedDeps: () => deps,
    getAuditDeps: () => [],
    getReleaseSources: () => live.getReleaseSources(),
    getFixPathSources: () => live.getFixPathSources(),
    queryAdvisories: (d) => live.queryAdvisories(d),
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
  ASKED = [];
  NPM = {
    "node-ipc": { latest: "12.0.0", versions: ["9.2.1", "10.1.0", "10.1.1", "10.1.2", "11.0.0", "12.0.0"] },
    "ua-parser-js": { latest: "1.0.40", versions: ["0.7.28", "0.7.29", "0.7.30", "1.0.40"] },
    "event-stream": { latest: "4.0.1", versions: ["3.3.4", "3.3.6", "4.0.0", "4.0.1"] },
    axios: { latest: "1.7.0", versions: ["0.21.0", "0.21.1", "0.21.2", "1.7.0"] },
    debug: { latest: "4.4.3", versions: ["4.4.0", "4.4.1", "4.4.2", "4.4.3"] },
    lodash: { latest: "4.18.1", versions: ["4.17.20", "4.17.21", "4.18.1"] },
    express: { latest: "5.1.0", versions: ["4.21.2", "5.1.0"] },
    chalk: { latest: "5.6.2", versions: ["5.6.1", "5.6.2"] },
    "left-pad": { latest: "1.3.0", versions: ["1.2.0", "1.3.0"] },
    ctx: { latest: "0.2.6", versions: ["0.2.6"] },
    // npm took both down: only the security placeholder is listed.
    crossenv: { latest: "0.0.1-security", versions: ["0.0.1-security"] },
    electorn: { latest: "0.0.1-security", versions: ["0.0.1-security"] },
  };
  OSV = [
    advisory("GHSA-97m3-w2cp-4xx6", "node-ipc", "CRITICAL", { versions: ["10.1.1", "10.1.2"] }),
    advisory("GHSA-pjwm-rvh2-c87w", "ua-parser-js", "CRITICAL", { versions: ["0.7.29"] }),
    advisory("GHSA-mh6f-8j2x-4483", "event-stream", "CRITICAL", { versions: ["3.3.6"] }),
    advisory("GHSA-4w2v-q235-vp99", "axios", "HIGH", { fixed: "0.21.1" }),
    advisory("MAL-2025-debug-4.4.2", "debug", "CRITICAL", { versions: ["4.4.2"] }, "npm", true),
    advisory("MAL-2017-crossenv", "crossenv", "CRITICAL", {}, "npm", true),
    advisory("MAL-2023-electorn", "electorn", "CRITICAL", {}, "npm", true),
    advisory("GHSA-4g82-3jcr-q52w", "ctx", "CRITICAL", {}, "PyPI", true),
    advisory("GHSA-7pwq-f4pq-78gm", "rustdecimal", "CRITICAL", {}, "crates.io", true),
  ];
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const brief = (task: string, deps: ResolvedDependency[] = NPM_PROJECT, over: Partial<BriefingLiveIntel> = {}) => executeWhatShouldIKnow(db, { task }, intel(deps, over));

describe("what_should_i_know: the audit's phrasings (all came back with something unchecked)", () => {
  it('"bring in rustdecimal" in an npm project: crates.io\'s malware is found, though npm has no such name (it was safe_to_delegate)', async () => {
    const r = await brief("bring in rustdecimal");
    expect(r.new_packages).toMatchObject([{ name: "rustdecimal", ecosystem: "crates.io", malicious: true, verdict: "avoid", also_checked: [{ ecosystem: "npm", verdict: "not_found" }] }]);
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it.each([
    ["pull in node-ipc 10.1.1", "node-ipc", "10.1.1", "GHSA-97m3-w2cp-4xx6"],
    ["we need node-ipc 10.1.1", "node-ipc", "10.1.1", "GHSA-97m3-w2cp-4xx6"],
    ["bring in ua-parser-js 0.7.29", "ua-parser-js", "0.7.29", "GHSA-pjwm-rvh2-c87w"],
    ["pull in event-stream 3.3.6", "event-stream", "3.3.6", "GHSA-mh6f-8j2x-4483"],
  ])("%s: the malicious release is judged and is human_only (it was not tied to the name)", async (task, name, version, id) => {
    const r = await brief(task);
    expect(r.requested_versions).toMatchObject([{ name, to: version, verdict: "avoid", critical: [id] }]);
    expect(r.new_packages).toMatchObject([{ name, version, verdict: "avoid", latest: null }]);
    expect(r.summary).toContain(`Task adds ${name} ${version} (avoid)`);
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason).toContain(id);
  });

  it.each([
    ["add express, ctx", MIXED, "ctx"],
    ["add lodash-es 4.17.21 and crossenv", NPM_PROJECT, "crossenv"],
    ["add chalk 5.6.2 and electorn", NPM_PROJECT, "electorn"],
    ["add left-pad, chalk and electorn", NPM_PROJECT, "electorn"],
    ["add left-pad & electorn", NPM_PROJECT, "electorn"],
    ["add left-pad + electorn", NPM_PROJECT, "electorn"],
    ["add left-pad plus electorn", NPM_PROJECT, "electorn"],
    ["add left-pad 1.3.0, chalk 5.6.2 & electorn", NPM_PROJECT, "electorn"],
  ])("%s: the later package is checked, and its malware is human_only (it was never checked)", async (task, deps, bad) => {
    NPM["lodash-es"] = { latest: "4.17.21", versions: ["4.17.21"] };
    const r = await brief(task, deps);
    expect(r.new_packages?.find((p) => p.name === bad)).toMatchObject({ malicious: true, verdict: "avoid" });
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it.each(["replace request with axios 0.21.0", "swap request for axios 0.21.0", "migrate from request to axios 0.21.0"])(
    '%s: axios is judged at 0.21.0, avoid (it said "Task adds axios (proceed)")',
    async (task) => {
      const r = await brief(task);
      expect(r.new_packages).toMatchObject([{ name: "axios", version: "0.21.0", verdict: "avoid" }]);
      expect(r.requested_versions).toMatchObject([{ name: "axios", to: "0.21.0", verdict: "avoid" }]);
      expect(r.summary).toContain("Task adds axios 0.21.0 (avoid)");
      expect(r.summary).not.toContain("(proceed)");
      expect(r.delegation_assessment.level).toBe("review_needed");
      expect(r.delegation_assessment.reason).toContain("axios 0.21.0 is avoid");
    },
  );

  it('add "dbg": "npm:debug@4.4.2" to package.json: debug 4.4.2 is judged, and neither dbg nor npm is a package (it said "Task adds dbg (proceed), npm (proceed)")', async () => {
    const r = await brief('add "dbg": "npm:debug@4.4.2" to package.json');
    expect(r.new_packages?.map((p) => p.name)).toEqual(["debug"]);
    expect(r.new_packages).toMatchObject([{ name: "debug", version: "4.4.2", verdict: "avoid" }]);
    expect(r.requested_versions).toMatchObject([{ name: "debug", to: "4.4.2", verdict: "avoid" }]);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(r.summary).not.toMatch(/\bnpm \(|\bdbg \(/);
    expect(ASKED.some((u) => u === "https://registry.npmjs.org/npm" || u === "https://registry.npmjs.org/dbg")).toBe(false);
  });

  it('"upgrade lodash to 4.17.21 and add express 4.x": each version is its own package\'s', async () => {
    const r = await brief("upgrade lodash to 4.17.21 and add express 4.x");
    expect(r.requested_versions?.map((v) => `${v.name}@${v.to}`)).toEqual(["lodash@4.17.21", "express@4.x"]);
  });

  it("a clean list stays safe_to_delegate, every item checked", async () => {
    const r = await brief("add left-pad 1.3.0, chalk 5.6.2 and express 5.1.0");
    expect(r.new_packages?.map((p) => `${p.name}@${p.version}=${p.verdict}`)).toEqual(["left-pad@1.3.0=proceed", "chalk@5.6.2=proceed", "express@5.1.0=proceed"]);
    expect(r.delegation_assessment.level).toBe("safe_to_delegate");
  });

  it("what a swap takes out is not judged as written: replacing request 2.88.2 is no reason to review", async () => {
    const r = await brief("replace request 2.88.2 with axios 1.7.0");
    expect(r.requested_versions?.map((v) => v.name)).toEqual(["axios"]);
    expect(r.delegation_assessment.level).toBe("safe_to_delegate");
  });
});

describe("what was already right stays right", () => {
  it.each([
    ["add the lodahs package", "human_only"],
    ["add tests", "safe_to_delegate"],
    ["add logging to the handler", "safe_to_delegate"],
    ["add error handling, then update the docs", "safe_to_delegate"],
    ["add tests, logging and retries", "safe_to_delegate"],
    ["upgrade lodash to 4.17.21", "safe_to_delegate"],
    ["add the left-pad package", "safe_to_delegate"],
  ] as const)("%s: %s", async (task, level) => {
    NPM.lodahs = { latest: "0.0.1-security", versions: ["0.0.1-security"] };
    OSV.push(advisory("MAL-2025-25502", "lodahs", "CRITICAL", {}, "npm", true));
    const r = await brief(task);
    expect(r.delegation_assessment.level).toBe(level);
  });

  it("a word that is prose is looked up nowhere, and a bare name no registry has is still dropped", async () => {
    await brief("add tests, logging and retries");
    expect(ASKED.some((u) => /tests|logging|retries/.test(u))).toBe(false);
    const r = await brief("add frobnicator");
    expect(r.new_packages).toBeUndefined();
    expect(r.delegation_assessment.level).toBe("safe_to_delegate");
  });

  it("a private name in a list is looked up nowhere, in any ecosystem; the public ones still are", async () => {
    const r = await brief("add left-pad, acme-vault and electorn", NPM_PROJECT, {
      privateReason: (_eco: string, name: string) => (name.toLowerCase() === "acme-vault" ? "private by .npmrc @acme registry" : null),
    });
    expect(ASKED.some((u) => u.includes("acme-vault"))).toBe(false);
    // left-pad is a bare name that comes back clean, so it is dropped as before; electorn is malware.
    expect(r.new_packages?.map((p) => p.name)).toEqual(["electorn"]);
    expect(ASKED.some((u) => u === "https://registry.npmjs.org/left-pad")).toBe(true);
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it("a private name the project's registries do not have is never sent to the other ecosystems either", async () => {
    await brief("bring in acme-vault", NPM_PROJECT, { privateReason: (_e: string, n: string) => (n === "acme-vault" ? "private by .npmrc" : null) });
    expect(ASKED.some((u) => u.includes("acme-vault"))).toBe(false);
  });
});
