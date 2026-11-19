// SPDX-License-Identifier: Apache-2.0
/**
 * Inside a tool call, an answer that names the hosts it contacted names the ones its requests
 * were sent to (call-budget.ts recordedCallHosts, filled where requests are made, redirect hops
 * included), and says nothing was sent when none was. Outside a call nothing is recorded and the
 * tools derive their hosts as before.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { noteCallHost, recordedCallHosts, runWithCallBudget } from "../call-budget.js";
import { LiveIntelligence } from "../live/index.js";
import { fetchLoopbackJson } from "../live/loopback-http.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { checkSources, executeDependencyCheck } from "../tools/dependency-check.js";
import { impactSources } from "../tools/upgrade-impact.js";
import type { FourDADatabase } from "../db.js";

const fixtureDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "dependency-check");
const axios = JSON.parse(fs.readFileSync(path.join(fixtureDir, "npm-axios.json"), "utf8"));
const noDb = null as unknown as FourDADatabase;
const inCall = <T>(work: () => Promise<T>) => runWithCallBudget(Date.now(), work);

let contacted: string[] = [];
let dir: string;
let priorOffline: string | undefined;

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** OSV.dev, npm and a local Ollama: lodash 4.17.15 has one advisory (fixed in 4.17.21). */
function stubNetwork() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    contacted.push(url.host);
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
      if (name === "axios") return json(axios);
      return json({}, 404);
    }
    if (url.host === "localhost:11434") return json({ ok: true });
    return json({}, 404);
  });
}

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
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-wire-hosts-"));
  contacted = [];
  stubNetwork();
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("the record itself", () => {
  it("is null outside a call, empty in a call that sent nothing, and holds loopback requests too", async () => {
    expect(recordedCallHosts()).toBeNull();
    expect(await inCall(async () => recordedCallHosts())).toEqual([]);
    const hosts = await inCall(async () => {
      await fetchLoopbackJson("http://localhost:11434/api/tags");
      return recordedCallHosts();
    });
    expect(hosts).toEqual(["localhost:11434"]);
  });
});

describe("vulnerability_scan _meta.privacy inside a call", () => {
  it("names exactly the hosts the call's requests went to", async () => {
    project({ lodash: "4.17.15", "left-pad": "1.3.0" });
    const out = await inCall(() => executeVulnerabilityScan(null, { project_path: dir }, intel(["lodash", "left-pad"])));
    const hosts = [...new Set(contacted)].sort();
    expect(hosts).toContain("registry.npmjs.org");
    const privacy = privacyOf(out);
    for (const host of hosts) expect(privacy).toContain(host);
    expect(privacy).not.toMatch(/less whatever the local cache still held/);
    expect(privacy).toMatch(/a private package's name was never sent/);
  });

  it("answered from the caches: nothing was sent, though the fix checks ran (the derivation would name their hosts)", async () => {
    project({ lodash: "4.17.15" });
    const li = intel(["lodash"]);
    await executeVulnerabilityScan(null, { project_path: dir }, li);
    contacted = [];
    const again = await inCall(() => executeVulnerabilityScan(null, { project_path: dir }, li));
    expect(contacted).toEqual([]);
    expect(privacyOf(again)).toMatch(/^Nothing was sent in this call/);
    // Outside a call the same answer keeps today's derivation: the most that may have been asked.
    const outside = await executeVulnerabilityScan(null, { project_path: dir }, li);
    expect(contacted).toEqual([]);
    expect(privacyOf(outside)).toMatch(/the fix-target checks looked up the 1 vulnerable package .* on api\.osv\.dev and registry\.npmjs\.org, less whatever the local cache still held/);
  });
});

describe("dependency_check _meta.sources", () => {
  it("inside a call: the hosts this call asked, and only those", async () => {
    const live = new LiveIntelligence(new Database(":memory:"));
    const first = await inCall(() => executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "axios", to: "1.x" }] }, live));
    expect(first._meta.sources).toEqual([...new Set(contacted)].sort());
    expect(first._meta.sources).toContain("registry.npmjs.org");
    expect(first._meta.sources).not.toContain("proxy.golang.org");
    // Again, with the caches warm: what this call asked, not what the first one did.
    contacted = [];
    const again = await inCall(() => executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "axios", to: "1.x" }] }, live));
    expect(again._meta.sources).toEqual([...new Set(contacted)].sort());
    expect(again._meta.sources).not.toContain("api.osv.dev");
  });

  it("a call that sent nothing (offline): no sources, and a note that nothing was sent", async () => {
    process.env.FOURDA_OFFLINE = "true";
    const live = new LiveIntelligence(new Database(":memory:"));
    const out = await inCall(() => executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "axios", to: "1.x" }] }, live));
    expect(contacted).toEqual([]);
    expect(out._meta.sources).toEqual([]);
    expect((out._meta as { sources_note?: string }).sources_note).toMatch(/^Nothing was sent in this call/);
  });

  it("outside a call: every host the tool may ask, as before", () => {
    expect(checkSources().sources).toEqual(["registry.npmjs.org", "api.npmjs.org", "crates.io", "index.crates.io", "pypi.org", "proxy.golang.org", "osv.dev"]);
  });
});

describe("upgrade_impact _meta.sources and privacy", () => {
  it("inside a call the record wins over the first hops, redirect hosts included", async () => {
    const meta = await inCall(async () => {
      noteCallHost("crates.io");
      noteCallHost("static.crates.io");
      noteCallHost("api.osv.dev");
      return impactSources(new Set(["crates.io", "api.osv.dev"]));
    });
    expect(meta.sources).toEqual(["api.osv.dev", "crates.io", "static.crates.io"]);
    expect(meta.privacy).toMatch(/^Only the package's own registry and OSV\.dev were contacted/);
  });

  it("a call that sent nothing says nothing was sent", async () => {
    const meta = await inCall(async () => impactSources(new Set()));
    expect(meta.sources).toEqual([]);
    expect(meta.privacy).toMatch(/^Nothing was sent in this call/);
  });

  it("outside a call the first hops stand, GitHub named when it was asked", () => {
    const meta = impactSources(new Set(["registry.npmjs.org", "api.osv.dev", "api.github.com"]));
    expect(meta.sources).toEqual(["api.github.com", "api.osv.dev", "registry.npmjs.org"]);
    expect(meta.privacy).toMatch(/GitHub for release notes/);
  });
});
