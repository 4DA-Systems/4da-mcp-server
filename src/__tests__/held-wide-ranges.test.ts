// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish round 10, W13: a release is not clean when installing it necessarily installs an
 * affected dependency, whatever shape the spec has.
 *
 * - mocha 10.6.0 to 10.8.2 require serialize-javascript "^6.0.2" and every 6.x is affected
 *   (GHSA-5c6j-r48x-rmvq, fixed 7.0.3). Wide ranges were dropped as "a refresh reaches a clean
 *   release", so upgrade_impact named 10.6.0 the first clean release and dependency_check said
 *   proceed for 10.6.0 and for "^10".
 * - An npm alias ("es": "npm:event-stream@3.3.6") installs the aliased package; it read as nothing.
 * - react-native 1000.0.0 (deprecated, "accidentally published") was `safe.newest` for
 *   ">=0.80.0" and "*" while the same answer judged it avoid.
 *
 * The shapes are the registry's and OSV's; the release lists are cut down to the ones that decide it.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { heldSpecsOf, npmAliasTarget } from "../live/held-dependencies.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradeImpact } from "../tools/upgrade-impact.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

const adv = (id: string, name: string, fixed: string, severity: string): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity },
  affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed }] }] }],
});

const ADVISORIES: Record<string, OsvVulnerability[]> = {
  "serialize-javascript": [adv("GHSA-5c6j-r48x-rmvq", "serialize-javascript", "7.0.3", "HIGH"), adv("GHSA-qj8w-gfj5-8c6v", "serialize-javascript", "7.0.5", "MODERATE")],
  // Stands in for the event-stream 3.3.6 compromise: every release below the stub's "fixed" is affected.
  "event-stream": [adv("GHSA-mh6f-8j2x-4483", "event-stream", "4.0.0", "CRITICAL")],
  debug: [adv("GHSA-gxpj-cx7g-858c", "debug", "4.3.1", "LOW")],
};

type VersionDoc = { dependencies?: Record<string, string>; deprecated?: string };
let NPM: Record<string, { latest: string; versions: Record<string, VersionDoc> }>;

function registry() {
  const serialize = (spec: string) => ({ dependencies: { "serialize-javascript": spec, debug: "^4.3.1" } });
  NPM = {
    mocha: {
      latest: "11.0.0",
      versions: {
        "9.2.2": serialize("6.0.0"),
        "10.2.0": serialize("6.0.0"),
        "10.5.2": serialize("6.0.0"),
        "10.6.0": serialize("^6.0.2"),
        "10.8.2": serialize("^6.0.2"),
        // Stands in for a release whose wide range does reach a clean release.
        "11.0.0": serialize("^7.0.5"),
      },
    },
    "serialize-javascript": { latest: "7.0.5", versions: Object.fromEntries(["6.0.0", "6.0.1", "6.0.2", "7.0.3", "7.0.5"].map((v) => [v, {}])) },
    // A wide range whose newest admitted release is clean, though older ones are not: brings nothing.
    debug: { latest: "4.3.6", versions: Object.fromEntries(["4.3.0", "4.3.1", "4.3.6"].map((v) => [v, {}])) },
    "event-stream": { latest: "4.0.1", versions: Object.fromEntries(["3.3.6", "4.0.1"].map((v) => [v, {}])) },
    aliaser: {
      latest: "2.0.0",
      versions: {
        "1.0.0": { dependencies: { es: "npm:event-stream@3.3.6" } },
        "2.0.0": { dependencies: { es: "npm:event-stream@^4.0.1" } },
      },
    },
    "react-native": {
      latest: "0.88.1",
      versions: {
        "0.80.0": {},
        "0.88.1": {},
        "1000.0.0": { deprecated: "This version was accidentally published. Please use a 0.x release." },
      },
    },
  };
}

const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
const affects = (v: OsvVulnerability, version: string) => cmp(version, v.affected![0].ranges[0].events.find((e) => e.fixed)!.fixed!) < 0;

function stubNetwork() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (ADVISORIES[q.package.name] ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(ADVISORIES).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string }; version?: string };
      const all = ADVISORIES[q.package.name] ?? [];
      return json({ vulns: q.version ? all.filter((v) => affects(v, q.version!)) : all });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({}, 404);
      const time = Object.fromEntries([["created", "2015-01-01T00:00:00.000Z"], ...Object.keys(doc.versions).map((v) => [v, "2025-01-01T00:00:00.000Z"])]);
      return json({ name, "dist-tags": { latest: doc.latest }, versions: doc.versions, time });
    }
    if (/^https:\/\/registry\.npmjs\.org\/[^/]+\/[^/]+$/.test(url)) return json({}, 404);
    return json({}, 404);
  });
}

let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  registry();
  stubNetwork();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const check = async (items: unknown[]) =>
  (await executeDependencyCheck(noDb, { items } as never, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
const advisoriesOf = (r: { signals: Array<{ id: string; value: any; effect: string; evidence: string }> }) => r.signals.find((s) => s.id === "advisories") as { value: any; effect: string; evidence: string };
const impact = async (from: string, to: string) =>
  (await executeUpgradeImpact(noDb, { ecosystem: "npm", package: "mocha", from_version: from, to_version: to }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;

describe("a wide range with no clean admitted release is held (round 10, W13)", () => {
  it("upgrade_impact mocha 9.2.2 -> 10.2.0 names no 10.x release clean: 10.6.0's \"^6.0.2\" admits only affected releases", async () => {
    const r = await impact("9.2.2", "10.2.0");
    expect(r.first_clean_release ?? null).not.toBe("10.6.0");
    expect(r.first_clean_release ?? null).toBeNull();
    expect(r.summary).not.toMatch(/10\.6\.0 is the first later release/);
  });

  it("dependency_check mocha 10.6.0 is avoid and names serialize-javascript's range", async () => {
    const r = (await check([{ ecosystem: "npm", package: "mocha", to: "10.6.0" }])).results[0];
    expect(r.verdict).toBe("avoid");
    const a = advisoriesOf(r);
    const held = a.value.held_dependencies_affected.map((d: { package: string; installs: string }) => `${d.package}@${d.installs}`);
    expect(held).toEqual(["serialize-javascript@6.0.2"]);
    expect(a.evidence).toMatch(/serialize-javascript "\^6\.0\.2", whose newest admitted release 6\.0\.2 is affected/);
  });

  it("dependency_check mocha \"^10\" names no safe release; \"^11\" names 11.0.0, whose wide ranges reach clean releases", async () => {
    const ten = (await check([{ ecosystem: "npm", package: "mocha", to: "^10" }])).results[0];
    expect(ten.verdict).not.toBe("proceed");
    expect(ten.range_check.smallest_safe_in_range).toBeNull();
    expect(ten.range_check.newest_safe_in_range).toBeNull();
    expect(ten.safe?.smallest ?? null).toBeNull();
    const eleven = (await check([{ ecosystem: "npm", package: "mocha", to: "^11" }])).results[0];
    expect(eleven.verdict).toBe("proceed");
    expect(eleven.range_check.smallest_safe_in_range).toBe("11.0.0");
  });

  it("fails closed: a wide range whose releases cannot be read leaves the release NOT CHECKED, never proceed", async () => {
    delete (NPM as Record<string, unknown>)["serialize-javascript"];
    const r = (await check([{ ecosystem: "npm", package: "mocha", to: "11.0.0" }])).results[0];
    expect(r.verdict).toBe("unknown");
    expect(advisoriesOf(r).effect).toBe("unknown");
  });
});

describe("an npm alias is judged as the package it installs (round 10, W13)", () => {
  it("npmAliasTarget and heldSpecsOf read `npm:<name>@<spec>`", () => {
    expect(npmAliasTarget("npm:event-stream@3.3.6")).toEqual({ name: "event-stream", spec: "3.3.6" });
    expect(npmAliasTarget("npm:@scope/pkg@^1.2.0")).toEqual({ name: "@scope/pkg", spec: "^1.2.0" });
    expect(npmAliasTarget("npm:left-pad")).toEqual({ name: "left-pad", spec: "*" });
    expect(npmAliasTarget("^1.2.0")).toBeNull();
    expect(heldSpecsOf({ es: "npm:event-stream@3.3.6" })).toEqual({ "event-stream": "3.3.6" });
    // An exact pin wins over a range on the same package: a refresh never moves a pin.
    expect(heldSpecsOf({ "event-stream": "^4.0.1", es: "npm:event-stream@3.3.6" })).toEqual({ "event-stream": "3.3.6" });
    expect(heldSpecsOf({ bad: "npm:event-stream@latest" })).toEqual({});
  });

  it("dependency_check on a release whose alias pins an affected event-stream is avoid; the alias to a clean range proceeds", async () => {
    const bad = (await check([{ ecosystem: "npm", package: "aliaser", to: "1.0.0" }])).results[0];
    expect(bad.verdict).toBe("avoid");
    expect(advisoriesOf(bad).value.held_dependencies_affected.map((d: { package: string; installs: string }) => `${d.package}@${d.installs}`)).toEqual(["event-stream@3.3.6"]);
    const good = (await check([{ ecosystem: "npm", package: "aliaser", to: "2.0.0" }])).results[0];
    expect(good.verdict).toBe("proceed");
  });
});

describe("a safe pick is never a release the same answer judges avoid (round 10, W13)", () => {
  for (const to of [">=0.80.0", "*"]) {
    it(`react-native "${to}": safe.newest is 0.88.1, never the deprecated 1000.0.0`, async () => {
      const r = (await check([{ ecosystem: "npm", package: "react-native", to }])).results[0];
      expect(r.range_check.newest_safe_in_range).toBe("0.88.1");
      expect(r.range_check.safe_versions).not.toContain("1000.0.0");
      if (r.safe) expect(r.safe.newest).toBe("0.88.1");
      expect(JSON.stringify(r.safe ?? {})).not.toMatch(/1000\.0\.0/);
    });
  }
});
