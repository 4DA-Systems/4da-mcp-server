// SPDX-License-Identifier: Apache-2.0
/**
 * What a crate requires comes with it. A release with no advisory of its own answered proceed
 * while it required a dependency whose requirement admits no release clear of that dependency's
 * advisories (url =2.2.2 requires idna ^0.2.0, and no 0.2.x clears RUSTSEC-2024-0421). npm's
 * check already counted what a release holds; crates.io's did not read the requirement at all.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { releaseRequirements, requirementSources, resolveRequirement } from "../live/release-requirements.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { advisory, batchAsked, emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-19T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

type Dep = Record<string, unknown>;
const dep = (name: string, req: string, extra: Dep = {}): Dep => ({ name, req, features: [], optional: false, default_features: true, target: null, kind: "normal", ...extra });
const line = (name: string, vers: string, deps: Dep[], extra: Record<string, unknown> = {}) => ({ name, vers, deps, cksum: "0", features: {}, yanked: false, ...extra });
/** A crate with these versions (oldest first), each with its index line's dependencies. */
function crate(name: string, versions: Record<string, { deps?: Dep[]; extra?: Record<string, unknown> }>) {
  const list = Object.keys(versions);
  return {
    versions: list.map((num, i) => ({ num, created_at: daysAgo(900 - i * 40) })).reverse(),
    sparse: list.map((v) => line(name, v, versions[v].deps ?? [], versions[v].extra)),
  };
}

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  const shared = [dep("percent", "^2.1.0"), dep("bencher", "^0.1", { kind: "dev" }), dep("opt-serde", "^1.0", { optional: true })];
  net.crates["web-url"] = crate("web-url", {
    "2.2.1": { deps: [dep("idna-like", "^0.2.0"), ...shared] },
    "2.2.2": { deps: [dep("idna-like", "^0.2.0"), ...shared] },
    "2.5.0": { deps: [dep("idna-like", "^1.0.0"), ...shared] },
  });
  net.crates["idna-like"] = crate("idna-like", { "0.2.0": {}, "0.2.3": {}, "0.5.0": {}, "1.0.0": {}, "1.0.3": {} });
  net.crates.percent = crate("percent", { "2.1.0": {}, "2.3.1": {} });
  net.crates.bencher = crate("bencher", { "0.1.5": {} });
  net.crates["opt-serde"] = crate("opt-serde", { "1.0.0": {}, "1.0.9": {} });
  net.osv = [
    advisory("RUSTSEC-2024-0421", "crates.io", "idna-like", "1.0.0", { severity: "MODERATE" }),
    // Never fixed: any release that judged these would be flagged.
    advisory("RUSTSEC-0000-0001", "crates.io", "bencher", null, { severity: "HIGH" }),
    advisory("RUSTSEC-0000-0002", "crates.io", "opt-serde", null, { severity: "HIGH" }),
  ];
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

const check = async (items: unknown[]) => executeDependencyCheck(noDb, { items }, new LiveIntelligence(new Database(":memory:")), { now: NOW });
type Result = Awaited<ReturnType<typeof check>>["results"][number];
const advisories = (r: Result) => r.signals.find((s) => s.id === "advisories") as { value: Record<string, unknown>; effect: string; evidence: string };

describe("resolveRequirement", () => {
  const facts = { versions: ["0.2.0", "0.2.3", "0.5.0", "1.0.0", "1.0.3", "2.0.0-rc.1"], withdrawn: [], latest: "1.0.3" };
  it("crates.io: the newest release a requirement admits, or the pin", () => {
    expect(resolveRequirement("crates.io", "^0.2.0", facts)).toEqual({ version: "0.2.3", exact: false });
    expect(resolveRequirement("crates.io", "1", facts)).toEqual({ version: "1.0.3", exact: false });
    expect(resolveRequirement("crates.io", ">=0.2, <1", facts)).toEqual({ version: "0.5.0", exact: false });
    expect(resolveRequirement("crates.io", "=0.2.0", null)).toEqual({ version: "0.2.0", exact: true });
    // Nothing admitted, or no release list: it cannot be said.
    expect(resolveRequirement("crates.io", "^3", facts)).toBeNull();
    expect(resolveRequirement("crates.io", "^0.2.0", null)).toBeNull();
  });
});

describe("dependency_check: what a crates.io release requires", () => {
  it("a release that requires a dependency whose newest admitted release is affected is not proceed, and names it", async () => {
    const r = (await check([{ ecosystem: "crates.io", package: "web-url", to: "=2.2.2" }])).results[0];
    expect(r.verdict).toBe("review");
    expect(advisories(r).value).toMatchObject({
      affecting_to: [],
      held_dependencies_affected: [{ package: "idna-like", spec: "^0.2.0", installs: "0.2.3", advisories: ["RUSTSEC-2024-0421"], severity: "medium" }],
      requirements_examined: 2,
    });
    expect(r.reason).toContain('No advisory of web-url itself affects 2.2.2, but 2.2.2 requires idna-like "^0.2.0", whose newest admitted release 0.2.3 is affected (RUSTSEC-2024-0421): installing 2.2.2 installs it.');
    expect(r.reason).not.toMatch(/concern found/);
    // The safe releases on its line leave it out and name the one that requires a clean idna-like.
    expect(r.range_check).toMatchObject({ basis: "same_line", smallest_safe_in_range: "2.5.0", newest_safe_in_range: "2.5.0" });
    expect(r.reason).toMatch(/Safe on 2\.2\.2's line \(2\.x\): smallest 2\.5\.0, newest 2\.5\.0\./);
    // Dev-dependencies and optional dependencies the default feature does not enable are not what it brings.
    expect(batchAsked(net).filter((q) => /bencher|opt-serde/.test(q))).toEqual([]);
    expect(batchAsked(net)).toContain("crates.io:idna-like@0.2.3");
    expect(batchAsked(net)).toContain("crates.io:percent@2.3.1");
  });

  it("a bare version (Cargo's caret requirement) is judged the same way", async () => {
    const r = (await check([{ ecosystem: "crates.io", package: "web-url", to: "2.2.2" }])).results[0];
    expect(r.verdict).not.toBe("proceed");
    expect(JSON.stringify(r)).toContain("idna-like");
  });

  it("a release whose requirements admit clean releases is proceed, and says what was examined", async () => {
    const r = (await check([{ ecosystem: "crates.io", package: "web-url", to: "=2.5.0" }])).results[0];
    expect(r.verdict).toBe("proceed");
    expect(advisories(r).value).toMatchObject({ requirements_examined: 2 });
    expect(r.reason).toBe("No advisory, age, trust or new-dependency concern found. None of the 2 packages it requires is held at a release with a known advisory.");
  });

  it("a constraint never names a release that requires an affected dependency as safe", async () => {
    const r = (await check([{ ecosystem: "crates.io", package: "web-url", to: "^2.2" }])).results[0];
    expect(r).toMatchObject({ to: "2.5.0", verdict: "proceed" });
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "2.5.0", newest_safe_in_range: "2.5.0", safe_versions: ["2.5.0"], held_excluded: 2 });
    expect(r.reason).toMatch(/2 releases clear of web-url's own advisories left out/);
  });

  it("when every release in the constraint requires it, none is named safe and the reason says why", async () => {
    const r = (await check([{ ecosystem: "crates.io", package: "web-url", to: ">=2.2.0, <2.3.0" }])).results[0];
    expect(r.verdict).toBe("review");
    // The release outside the range is named only because what it requires was examined too.
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: null, held_excluded: 2, newest_safe_outside_range: "2.5.0" });
    expect(r.reason).toMatch(/No release in >=2\.2\.0, <2\.3\.0 is named safe: the 2 releases clear of web-url's own advisories require a dependency whose newest admitted release \(or exact pin\) has a known advisory\. Newest safe release outside it: 2\.5\.0\./);
  });

  it("a release outside the range whose own requirements are affected is not offered as the alternative", async () => {
    net.crates["web-url"] = crate("web-url", {
      "2.2.2": { deps: [dep("idna-like", "^0.2.0")] },
      "2.5.0": { deps: [dep("idna-like", "^0.5.0")] },
    });
    const r = (await check([{ ecosystem: "crates.io", package: "web-url", to: "~2.2" }])).results[0];
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: null });
    expect(r.range_check!.newest_safe_outside_range ?? null).toBeNull();
    expect(r.reason).not.toMatch(/Newest safe release outside it/);
  });

  it("an optional dependency the default feature enables, a build dependency and an exact pin are judged", async () => {
    net.crates["web-url"] = crate("web-url", {
      "3.0.0": {
        deps: [dep("percent", "^2.1.0"), dep("serde", "^1.0", { optional: true, package: "opt-serde" }), dep("bencher", "^0.1", { kind: "build" }), dep("idna-like", "=0.5.0")],
        extra: { features: { default: ["std"], std: ["serde/derive"] } },
      },
    });
    const r = (await check([{ ecosystem: "crates.io", package: "web-url", to: "=3.0.0" }])).results[0];
    expect(r.verdict).toBe("avoid");
    const held = advisories(r).value.held_dependencies_affected as Array<{ package: string; installs: string; spec: string }>;
    expect(held.map((d) => [d.package, d.spec, d.installs]).sort()).toEqual([
      ["bencher", "^0.1", "0.1.5"],
      ["idna-like", "=0.5.0", "0.5.0"],
      ["opt-serde", "^1.0", "1.0.9"],
    ]);
    expect(r.reason).toContain("exact-pins idna-like 0.5.0 (RUSTSEC-2024-0421)");
  });

  it("a required crate whose release list cannot be read: unknown, never a clean sentence", async () => {
    delete net.crates["idna-like"];
    const r = (await check([{ ecosystem: "crates.io", package: "web-url", to: "=2.5.0" }])).results[0];
    expect(r.verdict).toBe("unknown");
    expect(advisories(r).value).toMatchObject({ requirements_unchecked: 'the releases idna-like "^1.0.0" admit could not be read from crates.io' });
    expect(r.reason).toContain("Whether what 2.5.0 requires has known advisories was not examined");
    expect(r.reason).not.toMatch(/concern found/);
  });

  it("OSV.dev down for the requirements too: unknown", async () => {
    net.batchStatus = 400;
    const r = (await check([{ ecosystem: "crates.io", package: "web-url", to: "=2.5.0" }])).results[0];
    expect(r.verdict).toBe("unknown");
  });
});

describe("releaseRequirements for a crate", () => {
  it("names the held requirement with the release an install gets", async () => {
    const live = new LiveIntelligence(new Database(":memory:"));
    const sources = requirementSources(live.getReleaseSources(), live.getFixPathSources()!);
    const answer = await releaseRequirements(sources, (deps) => live.queryAdvisories(deps), { ecosystem: "crates.io", name: "web-url", version: "2.2.2" }, { deadline: Date.now() + 10_000 });
    expect(answer).toEqual({
      status: "checked",
      examined: 2,
      affected: [{ name: "idna-like", spec: "^0.2.0", exact: false, version: "0.2.3", ids: ["RUSTSEC-2024-0421"], severity: "medium" }],
    });
  });
});
