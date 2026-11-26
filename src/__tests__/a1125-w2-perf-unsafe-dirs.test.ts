// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, Track F, M1 (what was left after the lockfile reads): dependency_health spent
 * 5-9 s with no pause on 20 lockfiles of 185,000 entries in liveUnsafeDirs, which judged every
 * sourceDir of every dependency again although they name a handful of directories. Each directory
 * is now judged once; what the function returns is unchanged.
 */
import { describe, expect, it } from "vitest";
import { liveUnsafeDirs } from "../live/shell-safe.js";

const ROOT = "/work/proj";

function intelWith(deps: Array<{ sourceDirs?: string[] }>, extra: Partial<Parameters<typeof liveUnsafeDirs>[0] & object> = {}) {
  return {
    getProjectRoot: () => ROOT,
    getResolvedDeps: () => deps,
    getAuditDeps: () => deps,
    getVulnerabilities: () => null,
    getInstallDrift: () => [],
    getLockfileProblems: () => [],
    getDiscovery: () => null,
    ...extra,
  };
}

describe("liveUnsafeDirs judges each directory once (audit 2026-11-25, F-M1)", () => {
  it("returns the same directories, duplicates or not, absolute or relative", () => {
    const dirs = [ROOT, `${ROOT}/packages/ok`, `${ROOT}/packages/a;b`, `${ROOT}\\packages\\$x\\inner`, `${ROOT}/packages/a;b/`, "rel;dir/sub", `${ROOT.toUpperCase()}/Q;R`];
    const once = liveUnsafeDirs(intelWith(dirs.map((d) => ({ sourceDirs: [d] }))));
    const repeated = liveUnsafeDirs(intelWith([...dirs, ...dirs, ...dirs].map((d) => ({ sourceDirs: [d, d] }))));
    expect([...repeated].sort()).toEqual([...once].sort());
    expect([...once].sort()).toEqual(["Q;R", "packages/$x", "packages/$x/inner", "packages/a;b", "rel;dir", "rel;dir/sub"].sort());
  });

  it("a directory seen as relative and as absolute is judged in both forms", () => {
    const out = liveUnsafeDirs(intelWith([{ sourceDirs: [`${ROOT}/x;y`] }], { getInstallDrift: () => [{ dir: `${ROOT}/x;y` }], getLockfileProblems: () => [{ file: `${ROOT}/p;q/package-lock.json` }] }));
    expect([...out].sort()).toEqual(["p;q", "x;y"]);
  });

  it("a million dependencies that share three directories take well under a second, not seconds", () => {
    const shared = [`${ROOT}/packages/a;b`, `${ROOT}/packages/ok`, `${ROOT}/tools/$t`];
    const deps = Array.from({ length: 500_000 }, (_, i) => ({ sourceDirs: [shared[i % 3], shared[(i + 1) % 3]] }));
    const t0 = performance.now();
    const out = liveUnsafeDirs(intelWith(deps));
    const ms = performance.now() - t0;
    expect([...out].sort()).toEqual(["packages/a;b", "tools/$t"]);
    // Judged once per directory: about 50 ms here (2026-11-27); judging each of the 1,000,000 again took 1.6-2.0 s.
    expect(ms).toBeLessThan(1_000);
  });
});
