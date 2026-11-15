// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish round 10, W16, item 1: mocha 10.8.2's serialize-javascript row said "the releases of a
 * parent could not be read; NOT CHECKED: every mocha release from 12.0.0 to 12.0.3 ... exact-pins or
 * narrowly ranges a dependency with a known advisory" while fixPathChecked was "all_advisories".
 * Those releases were read and judged affected through a WIDE range (glob "^13.0.0"). The text now
 * says what happened; an exact pin is still called one.
 *
 * Registry and OSV shapes are the real ones; mocha's release list is cut down to the ones that decide it.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const adv = (id: string, name: string, fixed: string): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed }] }] }],
});
const ADVISORIES: Record<string, OsvVulnerability[]> = {
  "serialize-javascript": [adv("GHSA-5c6j-r48x-rmvq", "serialize-javascript", "7.0.3")],
  // Stands in for an advisory against every glob 13.x the range admits.
  glob: [adv("GHSA-glob-0000-0000", "glob", "14.0.0")],
};
type Doc = { latest: string; versions: Record<string, { dependencies?: Record<string, string> }> };
let NPM: Record<string, Doc>;
function registry(globSpec: string) {
  const mocha = (s: string, g?: string) => ({ dependencies: { "serialize-javascript": s, ...(g ? { glob: g } : {}) } });
  NPM = {
    mocha: {
      latest: "12.0.3",
      versions: {
        "10.8.2": mocha("^6.0.2", "^8.1.0"),
        "11.7.5": mocha("^6.0.2", "^10.4.5"),
        "12.0.0": mocha("^7.0.3", globSpec),
        "12.0.1": mocha("^7.0.3", globSpec),
        "12.0.2": mocha("^7.0.3", globSpec),
        "12.0.3": mocha("^7.0.3", globSpec),
      },
    },
    "serialize-javascript": { latest: "7.0.3", versions: { "6.0.2": {}, "7.0.3": {} } },
    glob: { latest: "13.0.7", versions: { "8.1.0": {}, "10.4.5": {}, "13.0.0": {}, "13.0.7": {} } },
  };
}

const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
const affects = (v: OsvVulnerability, version: string) => cmp(version, v.affected![0].ranges[0].events.find((e) => e.fixed)!.fixed!) < 0;

let dir: string;
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-held-wording-"));
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (ADVISORIES[q.package.name] ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const found = Object.values(ADVISORIES).flat().find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: ADVISORIES[q.package.name] ?? [] });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)$/.exec(url);
    if (npm) {
      const doc = NPM[decodeURIComponent(npm[1])];
      return doc ? json({ name: decodeURIComponent(npm[1]), "dist-tags": { latest: doc.latest }, versions: doc.versions }) : json({}, 404);
    }
    return json({}, 404);
  });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", devDependencies: { mocha: "10.8.2" } }));
  fs.writeFileSync(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      name: "x",
      lockfileVersion: 3,
      packages: {
        "": { name: "x", devDependencies: { mocha: "10.8.2" } },
        "node_modules/mocha": { version: "10.8.2", dev: true, dependencies: { "serialize-javascript": "^6.0.2", glob: "^8.1.0" } },
        "node_modules/serialize-javascript": { version: "6.0.2", dev: true },
        "node_modules/glob": { version: "8.1.0", dev: true },
      },
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

async function serializeRow() {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  const result = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, li)) as Record<string, any>;
  return result.recommendations.find((r: { package: string }) => r.package === "serialize-javascript") as Record<string, any>;
}

describe("a parent whose releases were read and judged affected is not 'could not be read' (round 10, W16)", () => {
  it("mocha 12.x holds a wide glob range whose newest admitted release is affected: said so, checked, never NOT CHECKED", async () => {
    registry("^13.0.0");
    const row = await serializeRow();
    const text = row.reasons.join(" ");
    expect(row.fixPathChecked).toBe("all_advisories");
    expect(text).not.toMatch(/could not be read/);
    expect(text).not.toMatch(/NOT CHECKED/);
    expect(text).not.toMatch(/exact-pins or narrowly ranges/);
    expect(text).toMatch(/every parent release that admits a clean version brings in an affected dependency/);
    expect(text).toMatch(
      /every mocha release from 12\.0\.0 to 12\.0\.3 that admits a clean serialize-javascript holds a dependency range whose newest admitted release is affected \(12\.0\.0 requires glob "\^13\.0\.0", whose newest admitted release 13\.0\.7 is affected \(GHSA-glob-0000-0000\)\)/,
    );
  });

  it("a real exact pin is still called an exact pin", async () => {
    registry("13.0.7");
    const row = await serializeRow();
    const text = row.reasons.join(" ");
    expect(text).not.toMatch(/NOT CHECKED|could not be read/);
    expect(text).toMatch(/every mocha release from 12\.0\.0 to 12\.0\.3 that admits a clean serialize-javascript exact-pins a dependency with a known advisory \(12\.0\.0 exact-pins glob 13\.0\.7 \(GHSA-glob-0000-0000\)\)/);
  });
});
