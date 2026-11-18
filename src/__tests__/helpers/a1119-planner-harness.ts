// SPDX-License-Identifier: Apache-2.0
/**
 * A project on disk and the network at the HTTP boundary, for the upgrade_planner fix-path tests:
 * api.osv.dev (querybatch, /v1/vulns, /v1/query), registry.npmjs.org (abbreviated document and one
 * version), index.crates.io (sparse lines), pypi.org (project and one release) and
 * proxy.golang.org (list, .info, .mod). Shapes are the real ones; a test fills in the few releases
 * that decide its case. Every URL asked is recorded, and a host can be made unreachable.
 */

import { vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../../live/index.js";
import { advisoryAffects, advisoryRanges } from "../../live/osv-ranges.js";
import type { OsvVulnerability } from "../../live/types.js";
import { executeUpgradePlanner } from "../../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../../tools/vulnerability-scan.js";
import type { FourDADatabase } from "../../db.js";

const noDb = null as unknown as FourDADatabase;

export type Ev = Record<string, string>;
export type NpmVersion = { deprecated?: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> };
export type LockEntry = { version: string; dev?: boolean; dependencies?: Record<string, string> };

/** An OSV record with one range for one package. */
export const adv = (id: string, name: string, events: Ev[], ecosystem = "npm", severity = "HIGH"): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity },
  affected: [{ package: { name, ecosystem }, ranges: [{ type: ecosystem === "PyPI" ? "ECOSYSTEM" : "SEMVER", events }] }],
});
export const fixedIn = (v: string): Ev[] => [{ introduced: "0" }, { fixed: v }];

function sparsePath(name: string): string {
  const n = name.toLowerCase();
  return n.length <= 2 ? `${n.length}/${n}` : n.length === 3 ? `3/${n[0]}/${n}` : `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}

export interface Harness {
  dir: string;
  ADVISORIES: Record<string, OsvVulnerability[]>;
  NPM: Record<string, { versions: Record<string, NpmVersion>; latest: string }>;
  CRATES: Record<string, Array<{ vers: string; yanked?: boolean; deps?: Array<{ name: string; req: string; kind?: string; target?: string }> }>>;
  PYPI: Record<string, Record<string, { requiresPython?: string; requiresDist?: string[]; yanked?: boolean }>>;
  GO: Record<string, string[]>;
  /** "module@vX" -> the go directive of that version's go.mod. */
  GOMOD: Record<string, string>;
  /** Hosts that refuse every connection (the registry is unreachable). */
  down: Set<string>;
  /** Every URL asked, in order. */
  requests: string[];
  write(file: string, body: string): void;
  /** A package-lock v3 project: `direct` / `devDirect` are declared; `tree` is every installed entry, keyed by its lockfile path under node_modules/. */
  npmProject(direct: Record<string, string>, devDirect: Record<string, string>, tree: Record<string, LockEntry>): void;
  live(): Promise<LiveIntelligence>;
  plan(params?: Record<string, unknown>): Promise<{ result: Record<string, any>; step: (name: string, version?: string) => Record<string, any> }>;
  scan(params?: Record<string, unknown>): Promise<Record<string, any>>;
  dispose(): void;
}

export function createHarness(): Harness {
  const priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-planner-"));
  const h: Harness = {
    dir,
    ADVISORIES: {},
    NPM: {},
    CRATES: {},
    PYPI: {},
    GO: {},
    GOMOD: {},
    down: new Set(),
    requests: [],
    write(file, body) {
      fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
      fs.writeFileSync(path.join(dir, file), body);
    },
    npmProject(direct, devDirect, tree) {
      const root = { name: "x", version: "1.0.0", dependencies: direct, devDependencies: devDirect };
      h.write("package.json", JSON.stringify(root));
      const packages: Record<string, unknown> = { "": root };
      for (const [where, e] of Object.entries(tree)) packages[`node_modules/${where}`] = e;
      h.write("package-lock.json", JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
    },
    async live() {
      const li = new LiveIntelligence(new Database(":memory:"));
      const { scanProjectTree, treeResolutionGroups } = await import("../../project-tree.js");
      const { entries, discovery } = scanProjectTree(dir);
      li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
      return li;
    },
    async plan(params = {}) {
      const result = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50, ...params }, await h.live())) as Record<string, any>;
      const step = (name: string, version?: string) =>
        result.recommendations.find((s: { package: string; currentVersion: string }) => s.package === name && (!version || s.currentVersion === version));
      return { result, step };
    },
    async scan(params = {}) {
      return (await executeVulnerabilityScan(null, { project_path: dir, ...params }, await h.live())) as Record<string, any>;
    },
    dispose() {
      vi.unstubAllGlobals();
      if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
      else process.env.FOURDA_OFFLINE = priorOffline;
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };

  const affects = (v: OsvVulnerability, name: string, version: string) => {
    const eco = v.affected![0].package!.ecosystem;
    const ranges = advisoryRanges(v, name, eco);
    return ranges ? advisoryAffects(ranges, version.replace(/^v/, ""), eco) : false;
  };

  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    h.requests.push(url);
    if (h.down.has(new URL(url).hostname)) throw new TypeError("fetch failed");
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (h.ADVISORIES[q.package.name] ?? []).filter((v) => affects(v, q.package.name, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(h.ADVISORIES).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: h.ADVISORIES[q.package.name] ?? [] });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = h.NPM[name];
      if (!doc) return json({}, 404);
      if (npm[2]) {
        const version = doc.versions[decodeURIComponent(npm[2])];
        return version ? json(version) : json({ error: "version not found" }, 404);
      }
      return json({ name, "dist-tags": { latest: doc.latest }, versions: doc.versions });
    }
    const crate = /^https:\/\/index\.crates\.io\/(.+)$/.exec(url);
    if (crate) {
      const name = Object.keys(h.CRATES).find((n) => sparsePath(n) === crate[1]);
      if (!name) return new Response("not found", { status: 404 });
      return new Response(h.CRATES[name].map((l) => JSON.stringify({ name, vers: l.vers, deps: (l.deps ?? []).map((d) => ({ kind: "normal", optional: false, ...d })), yanked: l.yanked === true })).join("\n"), { status: 200 });
    }
    const pypiOne = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/([^/]+)\/json$/.exec(url);
    if (pypiOne) {
      const release = h.PYPI[decodeURIComponent(pypiOne[1]).toLowerCase()]?.[decodeURIComponent(pypiOne[2])];
      return release ? json({ info: { requires_dist: release.requiresDist ?? null, requires_python: release.requiresPython ?? null } }) : json({}, 404);
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      const name = decodeURIComponent(pypi[1]).toLowerCase();
      const project = h.PYPI[name];
      if (!project) return json({}, 404);
      const versions = Object.keys(project).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
      const releases = Object.fromEntries(
        versions.map((v) => [v, [{ upload_time_iso_8601: "2024-01-01T00:00:00Z", yanked: project[v].yanked === true, requires_python: project[v].requiresPython ?? null }]]),
      );
      return json({ info: { name, version: versions[versions.length - 1], license: "", classifiers: [], summary: "", yanked: false, yanked_reason: null }, releases });
    }
    const goMod = /^https:\/\/proxy\.golang\.org\/(.+)\/@v\/(v[^/]+)\.mod$/.exec(url);
    if (goMod) {
      const directive = h.GOMOD[`${goMod[1]}@${goMod[2]}`];
      return directive ? new Response(`module ${goMod[1]}\n\ngo ${directive}\n`, { status: 200 }) : new Response("not found", { status: 404 });
    }
    const go = /^https:\/\/proxy\.golang\.org\/(.+)\/@v\/(list|v[^/]+\.info)$/.exec(url);
    if (go) {
      const versions = h.GO[go[1]];
      if (!versions) return new Response("not found", { status: 404 });
      if (go[2] === "list") return new Response(`${versions.join("\n")}\n`, { status: 200 });
      const version = go[2].replace(/\.info$/, "");
      return versions.includes(version) ? json({ Version: version, Time: "2024-01-01T00:00:00Z" }) : new Response("not found", { status: 404 });
    }
    return json({}, 404);
  });
  return h;
}
