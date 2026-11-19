// SPDX-License-Identifier: Apache-2.0
/**
 * "No release that clears it is known" was said for a Go minimum whose clearing release was never
 * looked up (past the per-call lookup cap, or past the deadline), with `fixed_in: null`; run alone,
 * the same release named v0.41.0. Not looked up is now said as such, apart from "none exists".
 */

import { describe, expect, it } from "vitest";
import { clearsText } from "../live/held-dependencies.js";
import { releaseRequirements, type RequirementSources } from "../live/release-requirements.js";
import { requiresNote } from "../live/required-targets.js";
import type { FixTargetResult } from "../live/fix-paths.js";
import type { VulnerabilityScanResult } from "../live/types.js";

const MODULES = Array.from({ length: 10 }, (_, i) => `example.com/mod${i}`);

function sources(opts: { noFix?: string } = {}): RequirementSources {
  return {
    reads: () => true,
    requirements: async () => ({ status: "ok", data: { requirements: MODULES.map((name) => ({ name, spec: "v0.1.0" })), unreadable: 0 } }),
    releaseFacts: async () => null,
    // Each module: one advisory fixed in v0.2.0 (none for `noFix`, whose every release is affected).
    packageAdvisories: async (_eco, name) => [{ id: `GO-${name}`, versions: [], spans: [{ introduced: "0", fixed: name === opts.noFix ? null : "0.2.0", lastAffected: null }] }] as never,
    publishedVersions: async () => ["v0.1.0", "v0.2.0"],
  };
}

const query = async (deps: Array<{ name: string; version: string }>) =>
  ({
    vulnerabilities: deps.filter((d) => d.version === "v0.1.0").map((d) => ({ ecosystem: "Go", package: d.name, currentVersion: d.version, vulnId: `GO-${d.name}`, aliases: [], severity: "high", summary: "x" })),
    totalScanned: deps.length,
    offline: false,
  }) as unknown as VulnerabilityScanResult;

describe("Go clearing releases: looked up, none, or not looked up", () => {
  it("modules past the per-call lookup cap are not looked up, and say so", async () => {
    const check = await releaseRequirements(sources(), query as never, { ecosystem: "Go", name: "example.com/app", version: "v1.0.0" }, { deadline: Date.now() + 10_000 });
    expect(check?.status).toBe("checked");
    const affected = check!.status === "checked" ? check!.affected : [];
    expect(affected).toHaveLength(10);
    const looked = affected.filter((d) => d.fixedIn === "v0.2.0");
    const skipped = affected.filter((d) => d.fixedIn === null);
    expect(looked).toHaveLength(8);
    expect(skipped).toHaveLength(2);
    for (const d of skipped) {
      expect(d.fixUnknown).toMatch(/at most 8 modules/);
      expect(clearsText(d)).toMatch(/the release that clears it was not looked up/);
      expect(clearsText(d)).not.toMatch(/no release that clears it is known|no later release/);
    }
    const note = requiresNote({ target: "v1.0.0", requiresMinimums: { affected, examined: 10 } } as unknown as FixTargetResult, "Go")!;
    expect(note).not.toMatch(/is known/);
  });

  it("a deadline already past: not looked up, never 'none exists'", async () => {
    const check = await releaseRequirements(sources(), query as never, { ecosystem: "Go", name: "example.com/app", version: "v1.0.0" }, { deadline: Date.now() - 1 });
    // Nothing could be read before the deadline: the release is unchecked, not "no fix".
    expect(check?.status).toBe("unchecked");
  });

  it("a module whose every release is affected: established, 'no later release clears it'", async () => {
    const check = await releaseRequirements(sources({ noFix: MODULES[0] }), query as never, { ecosystem: "Go", name: "example.com/app", version: "v1.0.0" }, { deadline: Date.now() + 10_000 });
    const d = (check as { affected: Array<{ name: string; fixedIn?: string | null; fixUnknown?: string; ids: string[] }> }).affected.find((x) => x.name === MODULES[0])!;
    expect(d.fixedIn).toBeNull();
    expect(d.fixUnknown).toBeUndefined();
    expect(clearsText(d as never)).toBe("no later release clears it");
  });
});
