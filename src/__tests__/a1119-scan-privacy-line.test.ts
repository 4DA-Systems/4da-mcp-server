// SPDX-License-Identifier: Apache-2.0
/**
 * vulnerability_scan's `_meta.privacy` describes the call it is in: it names every host the
 * call's lookups went to (OSV.dev for the scan, and the registries the fix-target checks read),
 * and says nothing was sent when nothing was. It used to read "Only public package names and
 * versions were sent, to OSV.dev" on every answer: beside registry requests, on an answer served
 * whole from the cache, and on a scan of nothing.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

/** Every host a request went to, in order. */
let contacted: string[] = [];

/** OSV.dev and the npm registry, answering for lodash 4.17.15 (one advisory, fixed in 4.17.21). */
function stubNetwork() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    contacted.push(url.host);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const record = {
      id: "GHSA-p6mc-m468-83gw",
      summary: "Prototype Pollution in lodash",
      database_specific: { severity: "HIGH" },
      affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
    };
    if (url.host === "api.osv.dev" && url.pathname === "/v1/querybatch") {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => (q.package.name === "lodash" && q.version === "4.17.15" ? { vulns: [{ id: record.id }] } : {})) });
    }
    if (url.host === "api.osv.dev" && url.pathname.startsWith("/v1/vulns/")) return json(record);
    if (url.host === "api.osv.dev" && url.pathname === "/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: q.package.name === "lodash" ? [record] : [] });
    }
    if (url.host === "registry.npmjs.org") {
      const name = decodeURIComponent(url.pathname.split("/")[1] ?? "");
      if (name === "lodash") return json({ name, "dist-tags": { latest: "4.17.21" }, versions: { "4.17.15": {}, "4.17.21": {} } });
      return json({}, 404);
    }
    return json({}, 404);
  });
}

let dir: string;
let priorOffline: string | undefined;

function project(deps: Record<string, string>) {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", dependencies: deps }));
  const packages: Record<string, unknown> = { "": { name: "x", version: "1.0.0", dependencies: deps } };
  for (const [name, version] of Object.entries(deps)) packages[`node_modules/${name}`] = { version };
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
}

function intel(deps: string[]): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  li.initFromDependencyGroups([{ dir, language: "javascript", deps, devDeps: [] }]);
  li.fetchRegistryHealth = async () => [];
  return li;
}

const privacyOf = (out: unknown) => String((out as { _meta: { privacy: string } })._meta.privacy);

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-privacy-line-"));
  contacted = [];
  stubNetwork();
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("vulnerability_scan _meta.privacy names where this call's lookups went", () => {
  it("a scan with a vulnerable package: every host a request went to is named, the registry included", async () => {
    project({ lodash: "4.17.15", "left-pad": "1.3.0" });
    const out = await executeVulnerabilityScan(null, { project_path: dir }, intel(["lodash", "left-pad"]));
    const privacy = privacyOf(out);
    const hosts = [...new Set(contacted)];
    expect(hosts).toContain("api.osv.dev");
    expect(hosts).toContain("registry.npmjs.org");
    for (const host of hosts) expect(privacy, `${host} was contacted and is not named`).toContain(host);
    // The old sentence named OSV.dev as the only destination.
    expect(privacy).not.toMatch(/Only public package names and versions were sent, to OSV\.dev/);
    expect(privacy).toMatch(/a private package's name was never sent/);
    // The detailed answer carries the same sentence.
    const detailed = await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, intel(["lodash", "left-pad"]));
    for (const host of hosts) expect(privacyOf(detailed)).toContain(host);
  });

  it("a clean scan asks OSV.dev only, and says so", async () => {
    project({ "left-pad": "1.3.0" });
    const out = await executeVulnerabilityScan(null, { project_path: dir }, intel(["left-pad"]));
    expect([...new Set(contacted)]).toEqual(["api.osv.dev"]);
    const privacy = privacyOf(out);
    expect(privacy).toContain("api.osv.dev");
    expect(privacy).not.toContain("registry.npmjs.org");
    expect(privacy).not.toMatch(/Nothing was sent/);
  });

  it("the same clean scan again is served from the cache: nothing was sent, and the line says nothing was", async () => {
    project({ "left-pad": "1.3.0" });
    const li = intel(["left-pad"]);
    await executeVulnerabilityScan(null, { project_path: dir }, li);
    contacted = [];
    const again = await executeVulnerabilityScan(null, { project_path: dir }, li);
    expect(contacted).toEqual([]);
    const privacy = privacyOf(again);
    expect(privacy).toMatch(/^Nothing was sent in this call: every answer was read from the local advisory cache/);
    expect(privacy).not.toMatch(/were sent/);
    expect(privacy).toMatch(/a private package's name was never sent/);
  });

  it("a project with nothing to scan: nothing was sent, and the line says nothing was", async () => {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", version: "1.0.0" } } }));
    const li = new LiveIntelligence(new Database(":memory:"));
    const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
    const { entries, discovery } = scanProjectTree(dir);
    li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    const out = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, li)) as Record<string, any>;
    expect(contacted).toEqual([]);
    if (out._meta) {
      expect(out.total_dependencies_scanned).toBe(0);
      expect(privacyOf(out)).toMatch(/^Nothing was sent in this call: no dependency was scanned/);
      expect(privacyOf(out)).not.toMatch(/were sent/);
    } else {
      // No scan answer at all (nothing resolved): then no privacy claim is made either.
      expect(JSON.stringify(out)).not.toMatch(/were sent/);
    }
  });

  it("offline: nothing is sent and the line says so, as before", async () => {
    project({ "left-pad": "1.3.0" });
    const li = intel(["left-pad"]);
    await executeVulnerabilityScan(null, { project_path: dir }, li);
    contacted = [];
    process.env.FOURDA_OFFLINE = "true";
    const offline = new LiveIntelligence(new Database(":memory:"));
    offline.initFromDependencyGroups([{ dir, language: "javascript", deps: ["left-pad"], devDeps: [] }]);
    const out = (await executeVulnerabilityScan(null, { project_path: dir }, offline)) as Record<string, any>;
    expect(contacted).toEqual([]);
    expect(JSON.stringify(out)).not.toMatch(/were sent to/);
    if (out._meta?.privacy) expect(out._meta.privacy).toMatch(/^Nothing was sent: live lookups are off/);
  });
});
