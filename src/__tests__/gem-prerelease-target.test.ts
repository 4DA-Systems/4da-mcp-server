// SPDX-License-Identifier: Apache-2.0
/**
 * Prerelease detection for RubyGems and Packagist fix candidates. Gem
 * prereleases are letter segments (`4.2.0.beta3`, `6.1.0.rc2`), which the
 * semver reading in osv-ranges' isPrereleaseVersion did not recognise, so a
 * beta fix event could be offered as a stable fix target (found while fixing
 * readiness audit H2, 2026-10-16).
 */

import { describe, expect, it } from "vitest";
import { isPrereleaseVersion, smallestCleanVersion, type AdvisoryRanges } from "../live/osv-ranges.js";

describe("a Gem prerelease fix event is never a stable target", () => {
  // rails-style bounds (corpus: actionpack GHSA-29gr-w57f-rpfw fixed=4.2.0.beta3).
  // `4.2.0.beta3` read as a release, so it was the smallest "clean" candidate.
  it("installed 4.1.5: the target is the next clean release, not 4.2.0.beta3", () => {
    const advisories: AdvisoryRanges[] = [
      { id: "A", spans: [{ introduced: "0", fixed: "4.1.9", lastAffected: null }], versions: [] },
      { id: "E", spans: [{ introduced: "4.1.9", fixed: "4.2.0.beta3", lastAffected: null }], versions: [] },
      { id: "F", spans: [{ introduced: "5.0.0", fixed: "5.0.1", lastAffected: null }], versions: [] },
    ];
    const t = smallestCleanVersion({ ecosystem: "RubyGems", fixes: ["4.1.9"], advisories, published: null });
    expect(t?.target).toBe("5.0.1");
  });

  it("isPrereleaseVersion knows `.beta` and `.rc` segments", () => {
    expect(isPrereleaseVersion("4.2.0.beta3", "RubyGems")).toBe(true);
    expect(isPrereleaseVersion("6.1.0.rc2", "RubyGems")).toBe(true);
    expect(isPrereleaseVersion("6.1.2.1", "RubyGems")).toBe(false);
    expect(isPrereleaseVersion("2.2.0-BETA2", "Packagist")).toBe(true);
    expect(isPrereleaseVersion("5.4.0-patch1", "Packagist")).toBe(false);
  });
});
