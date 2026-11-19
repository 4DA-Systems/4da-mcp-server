// SPDX-License-Identifier: Apache-2.0
/**
 * Shared by the a1119-readers-*.test.ts suites: lockfile fixtures copied to a
 * temporary project, OSV.dev stubbed at the HTTP boundary with real record
 * shapes, and a scan of that project.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { vi } from "vitest";
import { LiveIntelligence } from "../../live/index.js";
import { advisoryAffects, advisoryRanges } from "../../live/osv-ranges.js";
import type { OsvVulnerability } from "../../live/types.js";
import { executeVulnerabilityScan } from "../../tools/vulnerability-scan.js";

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "test-fixtures", "a1119-readers");

/** A copy of test-fixtures/a1119-readers/<name> in a fresh temporary directory. */
export function fixtureProject(name: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `4da-a1119-${name}-`));
  fs.cpSync(path.join(FIXTURES, name), dir, { recursive: true });
  return dir;
}

/** An empty temporary project; `files` are written into it (paths relative, `/`-separated). */
export function tempProject(files: Record<string, string> = {}): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-"));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

export function removeProject(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

/** One npm advisory: affected from `introduced` (default 0) up to, not including, `fixed`. */
export function npmAdvisory(id: string, name: string, fixed: string, severity = "HIGH", introduced = "0"): OsvVulnerability {
  return {
    id,
    aliases: [],
    summary: `${name} advisory ${id}`,
    database_specific: { severity },
    affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced }, { fixed }] }] }],
  } as OsvVulnerability;
}

/** An npm registry document, cut down: the versions it lists and its `latest` tag. */
export type NpmDoc = { latest: string; versions: Record<string, { dependencies?: Record<string, string>; deprecated?: string }> };

/**
 * OSV.dev answering from `records`; registry.npmjs.org from `npm` (abbreviated
 * documents); every other registry answers 404 (nothing is known about any
 * release). Returns the names OSV.dev was asked about.
 */
export function stubOsv(records: OsvVulnerability[], npm: Record<string, NpmDoc> = {}): { asked: string[] } {
  const asked: string[] = [];
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const matching = (name: string, ecosystem: string, version?: string) =>
    records.filter((v) => {
      if (!v.affected?.some((a) => a.package?.ecosystem === ecosystem && a.package.name === name)) return false;
      if (version === undefined) return true;
      const ranges = advisoryRanges(v, name, ecosystem);
      return ranges ? advisoryAffects(ranges, version, ecosystem) : false;
    });
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      for (const q of queries) asked.push(`${q.package.name}@${q.version}`);
      return json({
        results: queries.map((q) => {
          const ids = matching(q.package.name, q.package.ecosystem, q.version).map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" }));
          return ids.length > 0 ? { vulns: ids } : {};
        }),
      });
    }
    if (url.includes("/v1/vulns/")) {
      const found = records.find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string }; version?: string };
      return json({ vulns: matching(q.package.name, q.package.ecosystem, q.version) });
    }
    const registry = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    const doc = registry ? npm[decodeURIComponent(registry[1])] : undefined;
    if (registry && doc) {
      if (registry[2]) return json(doc.versions[decodeURIComponent(registry[2])] ?? {});
      return json({ name: decodeURIComponent(registry[1]), "dist-tags": { latest: doc.latest }, versions: doc.versions, time: {} });
    }
    return json({}, 404);
  });
  return { asked };
}

export type ScanAnswer = Record<string, any>;

/** vulnerability_scan of `dir`, detailed, on a live layer of its own. */
export async function scanProject(dir: string, extra: Record<string, unknown> = {}): Promise<ScanAnswer> {
  return (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed", ...extra }, new LiveIntelligence(new Database(":memory:")))) as ScanAnswer;
}

/** `name@version` of every vulnerable package the answer lists, sorted. */
export function vulnerableCopies(answer: ScanAnswer): string[] {
  const rows = (answer.vulnerable_packages ?? answer.vulnerabilities ?? []) as Array<{ package: string; current_version: string }>;
  return [...new Set(rows.map((r) => `${r.package}@${r.current_version}`))].sort();
}
