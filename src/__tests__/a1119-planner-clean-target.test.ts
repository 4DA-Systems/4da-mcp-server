// SPDX-License-Identifier: Apache-2.0
/**
 * cleanFixTarget with no per-advisory fix (advisories that give only a last affected version):
 * the registry's first release past the bound is a fix candidate only when NO advisory affects it.
 * An advisory that no release fixes affects that release too, so nothing is named.
 *
 * OSV record shapes are the real ones (api.osv.dev SEMVER ranges); the sources are in-memory
 * stand-ins, so nothing is sent.
 */

import { describe, it, expect } from "vitest";
import { cleanFixTarget, type FixPathSources, type PackageReleaseFacts } from "../live/fix-paths.js";
import { advisoryRanges, type AdvisoryRanges } from "../live/osv-ranges.js";
import type { OsvVulnerability } from "../live/types.js";

type Ev = { introduced?: string; fixed?: string; last_affected?: string };
const record = (id: string, events: Ev[]): OsvVulnerability => ({
  id,
  affected: [{ package: { name: "braces", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events }] }],
});
const ranges = (v: OsvVulnerability): AdvisoryRanges => advisoryRanges(v, "braces", "npm")!;

/** Only a last affected version: every release up to 3.0.2. */
const LAST_AFFECTED_ONLY = ranges(record("GHSA-vfj7-8cjw-p6xm", [{ introduced: "0" }, { last_affected: "3.0.2" }]));
/** No fixed and no last affected version: every release, 3.0.3 included. */
const NEVER_FIXED = ranges(record("GHSA-grv7-fg5c-xmjg", [{ introduced: "0" }]));

const facts: PackageReleaseFacts = { versions: ["3.0.0", "3.0.1", "3.0.2", "3.0.3"], withdrawn: [], withdrawnWhy: {}, latest: "3.0.3", deprecatedLatest: null };

function sources(advisories: AdvisoryRanges[]): FixPathSources {
  return {
    packageAdvisories: async () => advisories,
    releaseFacts: async () => facts,
    versionExists: async () => true,
  } as unknown as FixPathSources;
}

describe("cleanFixTarget, when no advisory names a fixed version", () => {
  it("names the first published release past the last affected one when no advisory affects it", async () => {
    const clean = await cleanFixTarget(sources([LAST_AFFECTED_ONLY]), "npm", "braces", [], "3.0.2");
    expect(clean).not.toBeNull();
    expect(clean!.target).toBe("3.0.3");
    expect(clean!.noAdvisoryFix).toBe(true);
    expect(clean!.stillAffectedBy).toEqual([]);
  });

  it("names no release when an advisory that no release fixes still affects that candidate", async () => {
    const clean = await cleanFixTarget(sources([LAST_AFFECTED_ONLY, NEVER_FIXED]), "npm", "braces", [], "3.0.2");
    // 3.0.3 is past GHSA-vfj7's bound, but GHSA-grv7 affects it and every newer release: not a fix.
    expect(clean).toBeNull();
  });

  it("names no release when the only release past the bound is the installed one", async () => {
    const clean = await cleanFixTarget(sources([LAST_AFFECTED_ONLY]), "npm", "braces", [], "3.0.3");
    expect(clean).toBeNull();
  });
});
