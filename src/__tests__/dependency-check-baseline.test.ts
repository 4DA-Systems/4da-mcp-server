// SPDX-License-Identifier: Apache-2.0
/**
 * The publish-trust baseline is never a release published after `to` (audit 2026-11-11 W1 M2-6):
 * react 19.2.0 (2025-10-01, trusted publisher) read "Publish trust dropped" against 19.1.10, a
 * backport published a year later on the 19.1 line.
 */
import { describe, expect, it } from "vitest";
import { publishTrustSignal, selectBaseline, trustBaseline } from "../tools/dependency-check-signals.js";
import type { PackageReleaseIndex, ReleaseRecord, TrustLevel } from "../live/release-metadata.js";

const rel = (version: string, publishedAt: string | null, trust: TrustLevel): ReleaseRecord => ({
  version,
  publishedAt,
  trust,
  trustEvidence: trust === 2 ? "trusted publisher (github)" : trust === 1 ? "provenance" : "token publish",
  installScripts: [],
  deprecated: null,
  withdrawn: null,
  dependencies: [],
});

// The shape of react's registry record: 19.1.10 is a maintenance release published after 19.2.0.
const index: PackageReleaseIndex = {
  ecosystem: "npm",
  name: "react",
  createdAt: "2011-10-26T17:46:21.942Z",
  releases: Object.fromEntries(
    [
      rel("19.1.0", "2025-03-28T00:00:00Z", 1),
      rel("19.1.1", "2025-07-28T00:00:00Z", 1),
      rel("19.2.0", "2025-10-01T00:00:00Z", 1),
      rel("19.1.10", "2026-10-01T00:00:00Z", 2),
      rel("19.2.1", "2026-10-02T00:00:00Z", 2),
    ].map((r) => [r.version, r]),
  ),
};

describe("the publish-trust baseline is an earlier release, never a later one", () => {
  it("react@19.2.0 is compared with 19.1.1, not the later 19.1.10", () => {
    const base = selectBaseline(index, { ecosystem: "npm", package: "react", to: "19.2.0" });
    expect(base.record?.version).toBe("19.1.1");
    const signal = publishTrustSignal({ ecosystem: "npm", package: "react", to: "19.2.0" }, index.releases["19.2.0"], base);
    expect(signal.effect).toBe("proceed");
    expect(signal.evidence).not.toContain("dropped");
  });

  it("an installed backport published after `to` is not the trust baseline", () => {
    const item = { ecosystem: "npm" as const, package: "react", to: "19.2.0", from: "19.1.10" };
    const base = trustBaseline(index, item);
    expect(base.record?.version).toBe("19.1.1");
    expect(base.note).toContain("installed 19.1.10 was published after 19.2.0");
    expect(publishTrustSignal(item, index.releases["19.2.0"], base).effect).toBe("proceed");
  });

  it("a real drop against an earlier release still reads as review", () => {
    const dropped: PackageReleaseIndex = {
      ...index,
      releases: { ...index.releases, "19.2.2": rel("19.2.2", "2026-10-03T00:00:00Z", 0) },
    };
    const item = { ecosystem: "npm" as const, package: "react", to: "19.2.2" };
    const base = trustBaseline(dropped, item);
    expect(base.record?.version).toBe("19.2.1");
    expect(publishTrustSignal(item, dropped.releases["19.2.2"], base).effect).toBe("review");
  });

  it("undated releases (Go lists) are compared by version alone", () => {
    const undated: PackageReleaseIndex = {
      ecosystem: "Go",
      name: "example.com/m",
      createdAt: null,
      releases: { "v1.1.0": rel("v1.1.0", null, 0), "v1.2.0": rel("v1.2.0", null, 0) },
    };
    expect(selectBaseline(undated, { ecosystem: "Go", package: "example.com/m", to: "v1.2.0" }).record?.version).toBe("v1.1.0");
  });
});
