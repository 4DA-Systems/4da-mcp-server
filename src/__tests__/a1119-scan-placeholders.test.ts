// SPDX-License-Identifier: Apache-2.0
/**
 * An installed copy at npm's security-placeholder version (`0.0.N-security`) of a name a
 * malicious-package record covers is never counted clean and never passed over in silence: it is
 * listed in its own bucket with the step (remove the dependency). Any other advisory on such a
 * version is reported as for any other package.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { LiveIntelligence } from "../live/index.js";
import { OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import type { ResolvedDependency } from "../live/types.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

const dep = (name: string, version: string, extra: Partial<ResolvedDependency> = {}): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [], ...extra,
});

/** The records OSV.dev holds, by id. */
const RECORDS: Record<string, Record<string, unknown>> = {
  "MAL-2025-21003": { id: "MAL-2025-21003", summary: "Malicious code in fs (npm)", affected: [{ package: { name: "fs", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }] },
  // GitHub's record of an npm takedown: no MAL- id, malware by CWE-506.
  "GHSA-c2m4-w5hm-vqjw": { id: "GHSA-c2m4-w5hm-vqjw", summary: "crossenv is malware", aliases: ["CVE-2017-16074"], database_specific: { severity: "CRITICAL", cwe_ids: ["CWE-506"] } },
  // An ordinary vulnerability record.
  "GHSA-real-vuln-0001": { id: "GHSA-real-vuln-0001", summary: "Prototype pollution in holder", database_specific: { severity: "HIGH", cwe_ids: ["CWE-1321"] } },
};

/** OSV stub: `idsFor(name, version)` are the advisories of one copy; nothing else is reachable. */
function stubOsv(idsFor: (name: string, version: string) => string[]) {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return new Response(JSON.stringify({ results: queries.map((q) => ({ vulns: idsFor(q.package.name, q.version).map((id) => ({ id })) })) }), { status: 200 });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
      return RECORDS[id] ? new Response(JSON.stringify(RECORDS[id]), { status: 200 }) : new Response("{}", { status: 404 });
    }
    throw new TypeError(`fetch failed (${url})`);
  });
}

const ADVISORIES = (name: string, version: string): string[] =>
  name === "fs" ? ["MAL-2025-21003"] : name === "crossenv" ? ["GHSA-c2m4-w5hm-vqjw"] : name === "holder" && version === "0.0.1-security" ? ["GHSA-real-vuln-0001"] : [];

function scanner(): OsvScanner {
  const cache = new LiveCache(new Database(":memory:"));
  const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the scanner: a placeholder copy of a name taken down as malware", () => {
  it("is listed as a security placeholder with its records, and is not counted clean", async () => {
    stubOsv(ADVISORIES);
    const result = await scanner().scan([dep("fs", "0.0.1-security", { sourceDirs: ["/proj"] }), dep("left-pad", "1.3.0")], "/proj");
    expect(result.securityPlaceholders).toEqual([
      { ecosystem: "npm", package: "fs", version: "0.0.1-security", ids: ["MAL-2025-21003"], isDirect: true, isDev: false, devScopeKnown: true, sourceDirs: ["/proj"] },
    ]);
    // Not a vulnerability row (the placeholder is not the malware), and not one of the clean ones.
    expect(result.vulnerabilities).toEqual([]);
    expect(result.totalVulnerable).toBe(0);
    expect(result.cleanCount).toBe(1);
  });

  it("counts a GitHub malware record (no MAL- id) the same way", async () => {
    stubOsv(ADVISORIES);
    const result = await scanner().scan([dep("crossenv", "0.0.2-security")], "/proj");
    expect(result.securityPlaceholders?.map((p) => `${p.package}@${p.version}:${p.ids.join(",")}`)).toEqual(["crossenv@0.0.2-security:GHSA-c2m4-w5hm-vqjw"]);
    expect(result.vulnerabilities).toEqual([]);
    expect(result.cleanCount).toBe(0);
  });

  it("answers the same from the cache", async () => {
    stubOsv(ADVISORIES);
    const s = scanner();
    await s.scan([dep("fs", "0.0.1-security")], "/proj");
    const cached = await s.scan([dep("fs", "0.0.1-security")], "/proj");
    expect(cached.cached).toBe(true);
    expect(cached.securityPlaceholders?.map((p) => p.package)).toEqual(["fs"]);
    expect(cached.cleanCount).toBe(0);
  });

  it("an advisory that is not a malware record is reported on such a version as on any other", async () => {
    stubOsv(ADVISORIES);
    const result = await scanner().scan([dep("holder", "0.0.1-security")], "/proj");
    expect(result.vulnerabilities.map((v) => `${v.package}@${v.currentVersion}:${v.vulnId}:${v.severity}`)).toEqual(["holder@0.0.1-security:GHSA-real-vuln-0001:high"]);
    expect(result.securityPlaceholders).toBeUndefined();
    expect(result.totalVulnerable).toBe(1);
    expect(result.cleanCount).toBe(0);
  });

  it("a real release of the name stays installed malware, critical", async () => {
    stubOsv(ADVISORIES);
    const result = await scanner().scan([dep("fs", "0.0.2"), dep("fs", "1.0.0-security")], "/proj");
    expect(result.vulnerabilities.map((v) => `${v.currentVersion}:${v.severity}:${v.malware}`).sort()).toEqual(["0.0.2:critical:true", "1.0.0-security:critical:true"]);
    expect(result.securityPlaceholders).toBeUndefined();
  });

  it("a scan with no such copy carries no placeholder list", async () => {
    stubOsv(() => []);
    const result = await scanner().scan([dep("left-pad", "1.3.0")], "/proj");
    expect(result.securityPlaceholders).toBeUndefined();
    expect(result.cleanCount).toBe(1);
  });
});

describe("vulnerability_scan: the placeholder is said, with the step", () => {
  let dir: string;
  let priorOffline: string | undefined;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-placeholder-"));
    const deps = { fs: "0.0.1-security", "left-pad": "1.3.0" };
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", dependencies: deps }));
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: "x",
        lockfileVersion: 3,
        packages: {
          "": { name: "x", version: "1.0.0", dependencies: deps },
          "node_modules/fs": { version: "0.0.1-security" },
          "node_modules/left-pad": { version: "1.3.0" },
        },
      }),
    );
    stubOsv(ADVISORIES);
  });

  afterEach(() => {
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function intel(): LiveIntelligence {
    const li = new LiveIntelligence(new Database(":memory:"));
    li.initFromDependencyGroups([{ dir, language: "javascript", deps: ["fs", "left-pad"], devDeps: [] }]);
    li.fetchRegistryHealth = async () => [];
    return li;
  }

  it("concise: its own bucket, the summary line, the recommendation and the planner-facing action all say remove", async () => {
    const out = (await executeVulnerabilityScan(null, { project_path: dir }, intel())) as Record<string, any>;
    expect(out.security_placeholders).toEqual({
      count: 1,
      packages: [
        {
          package: "fs",
          current_version: "0.0.1-security",
          ecosystem: "npm",
          advisories: ["MAL-2025-21003"],
          is_direct: true,
          source_dirs: ["."],
          action: "remove_dependency",
          note: expect.stringMatching(/^fs was taken down from npm as malware \(MAL-2025-21003\)\. The installed fs 0\.0\.1-security claims to be npm's empty security placeholder.*Remove the dependency/),
        },
      ],
    });
    expect(Object.keys(out)[0]).toBe("summary");
    expect(out.summary).toMatch(/1 npm security placeholder is installed \(fs@0\.0\.1-security\)/);
    expect(out.summary).toMatch(/remove/i);
    expect(out.recommendations[0]).toMatch(/^Remove fs 0\.0\.1-security in \. /);
    // Not a vulnerability row, and never one of the clean dependencies.
    expect(out.vulnerable_packages).toEqual([]);
    expect(out.total_vulnerable_packages).toBe(0);
    expect(out.total_dependencies_scanned).toBe(2);
    const text = JSON.stringify(out);
    expect(text).not.toMatch(/no known advisories/);
  });

  it("detailed: the bucket, fix_targets with the planner's remove action, and one fewer clean dependency", async () => {
    const out = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, intel())) as Record<string, any>;
    expect(out.security_placeholders).toHaveLength(1);
    expect(out.security_placeholders[0]).toMatchObject({ package: "fs", current_version: "0.0.1-security", advisories: ["MAL-2025-21003"], action: "remove_dependency" });
    expect(out.fix_targets["fs@0.0.1-security"]).toMatchObject({ target: null, action: "remove_dependency" });
    expect(out.fix_targets["fs@0.0.1-security"].action_note).toMatch(/Remove the dependency/);
    expect(out.clean_dependencies).toBe(1);
    expect(out.vulnerabilities).toEqual([]);
  });

  it("asked about by name, it is not answered with \"no known advisories\"", async () => {
    const out = (await executeVulnerabilityScan(null, { project_path: dir, package: "fs" }, intel())) as Record<string, any>;
    expect(out.package_note).toMatch(/fs 0\.0\.1-security \(direct\): an npm security placeholder/);
    expect(out.package_note).not.toMatch(/no known advisories/);
    expect(out.security_placeholders.count).toBe(1);
    // Another package's question does not carry it.
    const other = (await executeVulnerabilityScan(null, { project_path: dir, package: "left-pad" }, intel())) as Record<string, any>;
    expect(other.security_placeholders).toBeUndefined();
    expect(other.package_note).toBe("left-pad 1.3.0 (direct): no known advisories.");
  });

  it("a severity filter never hides it", async () => {
    const out = (await executeVulnerabilityScan(null, { project_path: dir, severity_filter: "critical" }, intel())) as Record<string, any>;
    expect(out.security_placeholders.count).toBe(1);
  });
});
