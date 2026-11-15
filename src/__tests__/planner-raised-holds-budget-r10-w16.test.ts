// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish round 10, W16, item 4: the held checks of a release reconcileDirectTargets raises a
 * direct row to were awaited one row at a time inside the write loop, each allowed 5 s and none
 * bounded by the planner's `budgetMs`, so "nothing is written once the budget has run out" did not
 * hold. They now run together, within what is left of the budget; a row whose check did not
 * finish is NOT CHECKED (its target withheld downstream), never clean.
 *
 * Registry and OSV shapes are the real ones; express's requirements are its real ones, cut down.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import type { OsvVulnerability } from "../live/types.js";

const adv = (id: string, name: string, fixed: string): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed }] }] }],
});

const ADVISORIES: Record<string, OsvVulnerability[]> = {
  "path-to-regexp": [adv("GHSA-9wv6-86v2-598j", "path-to-regexp", "0.1.10"), adv("GHSA-rhx6-c78j-4q9w", "path-to-regexp", "0.1.12")],
  express: [adv("GHSA-qw6h-vgh9-j6wx", "express", "4.20.0")],
};
const NPM: Record<string, { latest: string; versions: Record<string, { dependencies?: Record<string, string> }> }> = {
  "path-to-regexp": { latest: "0.1.12", versions: { "0.1.7": {}, "0.1.10": {}, "0.1.12": {} } },
  express: {
    latest: "4.22.0",
    versions: {
      "4.16.4": { dependencies: { "path-to-regexp": "0.1.7" } },
      "4.20.0": { dependencies: { "path-to-regexp": "0.1.10" } },
      "4.22.0": { dependencies: { "path-to-regexp": "~0.1.12" } },
    },
  },
};

const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
const affects = (v: OsvVulnerability, version: string) => cmp(version, v.affected![0].ranges[0].events.find((e) => e.fixed)!.fixed!) < 0;

let dir: string;
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-raised-holds-"));
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
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: { express: "4.16.4" } }));
  fs.writeFileSync(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      name: "x",
      lockfileVersion: 3,
      packages: {
        "": { name: "x", dependencies: { express: "4.16.4" } },
        "node_modules/express": { version: "4.16.4", dependencies: { "path-to-regexp": "0.1.7" } },
        "node_modules/path-to-regexp": { version: "0.1.7" },
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

/** express 4.20.0 (own row) is raised to 4.22.0 for path-to-regexp's lever; `slowMs` delays every registry read after the first. */
async function reconcile(budgetMs: number, slowMs: number) {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  const sources = li.getFixPathSources()!;
  const facts = sources.releaseFacts.bind(sources);
  let reads = 0;
  sources.releaseFacts = async (...a: Parameters<typeof facts>) => {
    if (reads++ > 0) await new Promise((r) => setTimeout(r, slowMs));
    return facts(...a);
  };
  const { reconcileDirectTargets } = await import("../tools/upgrade-planner-fixpaths.js");
  const row = { package: "express", ecosystem: "npm", currentVersion: "4.16.4", targetVersion: "4.20.0", upgradeType: "minor" as const, reasons: [] as string[], breaking: false, scope: "direct" as const, action: "upgrade_direct" } as Record<string, any>;
  const pinned = {
    package: "path-to-regexp", ecosystem: "npm", currentVersion: "0.1.7", targetVersion: "0.1.12", upgradeType: "patch" as const, reasons: [] as string[], breaking: false, scope: "transitive" as const,
    action: "upgrade_parent", parentUpgrades: [{ parent: "express", from: "4.16.4", to: "4.22.0", breaking: false, levers: [{ name: "express", version: "4.16.4", to: "4.22.0", breaking: false }] }],
  };
  const started = Date.now();
  await reconcileDirectTargets([row as never, pinned as never], [{ step: row as never, fixes: ["4.20.0"], sourceDirs: [dir] }], li, budgetMs);
  return { row, elapsed: Date.now() - started };
}

describe("held checks of a raised planner target run within the planner's budget (round 10, W16)", () => {
  it("a slow registry: the call returns within its budget and the raised row is NOT CHECKED, never clean", async () => {
    const { row, elapsed } = await reconcile(800, 3_000);
    expect(row.targetVersion).toBe("4.22.0");
    expect(elapsed).toBeLessThan(2_000);
    expect(row.fixPathChecked).toBe("installed_advisories_only");
    expect(row.reasons.join(" ")).toMatch(/whether the dependencies 4\.22\.0 holds are affected was NOT CHECKED \(the planner's time budget ran out before it finished\)/);
    // Nothing is written after the budget: the late lookup's answer never lands.
    const before = JSON.stringify(row);
    await new Promise((r) => setTimeout(r, 3_200));
    expect(JSON.stringify(row)).toBe(before);
  }, 10_000);

  it("a registry that answers in time: the raised release's held dependencies are judged and it is checked against every advisory", async () => {
    const { row } = await reconcile(4_000, 0);
    expect(row.targetVersion).toBe("4.22.0");
    expect(row.fixPathChecked).toBe("all_advisories");
    expect(row.reasons.join(" ")).not.toMatch(/NOT CHECKED/);
  });
});
