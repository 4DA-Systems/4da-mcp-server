// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know over stubbed registries and OSV.dev: npm packuments and OSV records held in
 * memory, every request recorded. Shared by the briefing suites that drive the whole tool.
 */

import { vi } from "vitest";
import Database from "better-sqlite3";
import { FourDADatabase } from "../../db.js";
import { LiveIntelligence } from "../../live/index.js";
import type { OsvVulnerability, ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../../live/types.js";
import type { BriefingLiveIntel } from "../../tools/what-should-i-know.js";

export interface StubPkg {
  latest: string;
  versions: string[];
}

export interface Stub {
  npm: Record<string, StubPkg>;
  osv: OsvVulnerability[];
  /** Every URL fetched (with its body). */
  asked: string[];
}

export const dep = (name: string, version: string, ecosystem: ResolvedDependency["ecosystem"] = "npm", isDirect = true): ResolvedDependency => ({
  name,
  version,
  ecosystem,
  isDev: false,
  isDirect,
  devScopeKnown: true,
  target: null,
  platformActive: true,
  sourceDirs: ["d:/proj"],
});

const cmp = (a: string, b: string) => {
  const pa = a.split(/[.-]/).map((x) => Number.parseInt(x, 10) || 0);
  const pb = b.split(/[.-]/).map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
};

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

/** Installs the fetch stub over `stub` (read at call time, so tests may change it). */
export function installFetchStub(stub: Stub): void {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    stub.asked.push(init?.body ? `${url} ${String(init.body)}` : url);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: stub.osv.filter((v) => affects(v, q.package.name, q.package.ecosystem, q.version)).map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const found = stub.osv.find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string } };
      return json({ vulns: stub.osv.filter((v) => v.affected?.some((a) => a.package?.name === q.package.name && a.package?.ecosystem === q.package.ecosystem)) });
    }
    if (url.startsWith("https://api.npmjs.org/downloads/")) return json({ error: "not found" }, 404);
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = stub.npm[name];
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

export const advisory = (id: string, name: string, severity: string, affected: { versions?: string[]; fixed?: string }, ecosystem = "npm", malware = false, summary?: string) =>
  ({
    id,
    aliases: [],
    summary: summary ?? (malware ? `Malicious code in ${name} (${ecosystem})` : `${name} advisory`),
    database_specific: { severity },
    affected: [
      {
        package: { name, ecosystem },
        ...(affected.versions ? { versions: affected.versions } : {}),
        ranges: affected.versions ? [] : [{ type: "SEMVER", events: [{ introduced: "0" }, ...(affected.fixed ? [{ fixed: affected.fixed }] : [])] }],
      },
    ],
  }) as unknown as OsvVulnerability;

export function memoryDb(): FourDADatabase {
  const raw = new Database(":memory:");
  const instance = Object.create(FourDADatabase.prototype) as FourDADatabase;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (instance as any).db = raw;
  return instance;
}

export function readyScan(vulnerabilities: VulnerabilityEntry[] = []): VulnerabilityScanResult {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const e of vulnerabilities) bySeverity[e.severity]++;
  return {
    scannedAt: new Date().toISOString(),
    projectPath: "d:/proj",
    ecosystemsScanned: ["npm"],
    totalScanned: 3,
    totalVulnerable: new Set(vulnerabilities.map((v) => v.package)).size,
    platformInactiveVulnerable: 0,
    bySeverity,
    vulnerabilities,
    cleanCount: 3,
    scanDurationMs: 5,
    cached: false,
    offline: false,
  };
}

/** A live layer over the stubbed network, for a project with `deps`. */
export function stubIntel(deps: ResolvedDependency[], over: Partial<BriefingLiveIntel> = {}, scan: VulnerabilityScanResult = readyScan()): BriefingLiveIntel {
  const live = new LiveIntelligence(new Database(":memory:"));
  return {
    isEnabled: () => true,
    getProjectRoot: () => "d:/proj",
    ensureVulnerabilities: async () => scan,
    getVulnerabilities: () => scan,
    getResolvedDeps: () => deps,
    getAuditDeps: () => [],
    getReleaseSources: () => live.getReleaseSources(),
    getFixPathSources: () => live.getFixPathSources(),
    queryAdvisories: (d) => live.queryAdvisories(d),
    ...over,
  };
}
