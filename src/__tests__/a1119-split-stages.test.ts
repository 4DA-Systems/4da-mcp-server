// SPDX-License-Identifier: Apache-2.0
/**
 * Stages of a dependency_check pass, each on its own (dependency-check.ts checkPass): screening
 * puts every answer back in the order asked; a batch answer that is stale, failed or contradicted
 * names nothing safe from a package's advisory list; a list that leaves out what the batch query
 * names is blanked, and the item loses what was computed from it.
 */
import { describe, expect, it } from "vitest";

import type { LiveIntelligence } from "../live/index.js";
import type { AdvisoryRanges } from "../live/osv-ranges.js";
import type { VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { dropIncompleteLists, markBatchUnread, type BatchAnswer } from "../tools/dependency-check-batch.js";
import { instanceKey, lookupKey, type ItemResult, type Requested, type Resolved } from "../tools/dependency-check-items.js";
import type { Lookups } from "../tools/dependency-check-lookups.js";
import { screenItems } from "../tools/dependency-check-screen.js";
import type { RangeCheck } from "../tools/dependency-check-versions.js";

const exact = (pkg: string, version: string): Requested => ({ ecosystem: "npm", package: pkg, raw: version, target: { kind: "exact", version } });

const scanOf = (over: Partial<VulnerabilityScanResult> = {}): VulnerabilityScanResult => ({
  scannedAt: "2026-11-19T00:00:00.000Z",
  projectPath: "",
  ecosystemsScanned: [],
  totalScanned: 0,
  totalVulnerable: 0,
  platformInactiveVulnerable: 0,
  bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  vulnerabilities: [],
  cleanCount: 0,
  scanDurationMs: 0,
  cached: false,
  offline: false,
  ...over,
});

const batchOf = (scan: VulnerabilityScanResult, byInstance = new Map<string, VulnerabilityEntry[]>()): BatchAnswer => ({
  known: new Map(),
  probes: new Map(),
  osvDeps: [],
  scan,
  byInstance,
});

/** An item whose constraint was range-checked against the package's advisory list. */
const ranged = (to = "4.17.21"): Resolved => ({ ecosystem: "npm", package: "lodash", to, requested: "4.x", rangeCheck: { range: "4.x", basis: "requested" } as RangeCheck });

describe("screenItems", () => {
  it("answers a private item in its place, never looks it up, and puts every answer back in the order asked", async () => {
    const asked: string[] = [];
    const live = {
      lookupPrivateReason: (_ecosystem: string, name: string) => {
        asked.push(name);
        return name === "@acme/internal" ? "scope @acme maps to a private registry" : null;
      },
      isEnabled: () => false,
      getRegistryNotice: () => null,
    } as unknown as LiveIntelligence;
    const s = await screenItems([exact("left-pad", "1.3.0"), exact("@acme/internal", "2.0.0"), exact("lodash", "4.17.21")], live);

    expect(asked).toEqual(["left-pad", "@acme/internal", "lodash"]);
    expect(s.requested.map((r) => r.package)).toEqual(["left-pad", "lodash"]);
    expect(s.privateMeta).toEqual({ private: 1 });
    const checked: ItemResult[] = s.requested.map((r) => ({ ecosystem: r.ecosystem, package: r.package, from: null, to: r.raw, verdict: "proceed", reason: "", signals: [] }));
    const results = s.inOrder(checked);
    expect(results.map((r) => [r.package, r.verdict, r.not_checked ?? null])).toEqual([
      ["left-pad", "proceed", null],
      ["@acme/internal", "unknown", "private"],
      ["lodash", "proceed", null],
    ]);
    expect(results[1].reason).toMatch(/^NOT CHECKED \(private\): @acme\/internal is a private package/);
    expect(s.inOrderOf(["a", "b"])).toEqual(["a", null, "b"]);
  });
});

describe("markBatchUnread", () => {
  it("a current batch answer that nothing contradicts is read, and the range check stands", () => {
    const item = ranged();
    const read = markBatchUnread([item], batchOf(scanOf()), () => null);
    expect(read(item)).toBe(true);
    expect(item.rangeCheck).toBeDefined();
    expect(item.batchUnread).toBeUndefined();
  });

  it("an answer only from an expired cache is not read: no release is named safe from the list", () => {
    const item = ranged();
    const read = markBatchUnread([item], batchOf(scanOf({ staleAnswers: 1, staleReason: "OSV.dev timed out" })), () => null);
    expect(read(item)).toBe(false);
    expect(item.rangeCheck).toBeUndefined();
    expect(item.batchUnread).toBe("only an expired cached answer (OSV.dev timed out)");
  });

  it("a failed query and a contradicted answer are not read either, and say why", () => {
    const failed = ranged();
    expect(markBatchUnread([failed], batchOf(scanOf({ offline: true, uncheckedReason: "HTTP 500" })), () => null)(failed)).toBe(false);
    expect(failed.batchUnread).toBe("HTTP 500");
    expect(failed.rangeCheck).toBeUndefined();

    const contradicted = ranged();
    const why = "OSV.dev's batch answer for lodash leaves out advisories its own advisory list names for the same release (4.17.20: GHSA-x)";
    expect(markBatchUnread([contradicted], batchOf(scanOf()), () => why)(contradicted)).toBe(false);
    expect(contradicted.batchUnread).toBe("batch answer for lodash leaves out advisories its own advisory list names for the same release (4.17.20: GHSA-x), so it was not used");
  });
});

describe("dropIncompleteLists", () => {
  const entry = (vulnId: string) => ({ vulnId, package: "lodash", currentVersion: "4.17.20", ecosystem: "npm", aliases: [] }) as unknown as VulnerabilityEntry;

  it("a list that leaves out an advisory the batch query names for `to` is blanked for the package, and the item loses its range check", () => {
    const item = ranged("4.17.20");
    const lookups: Lookups = { indexes: new Map(), advisoryLists: new Map([[lookupKey(item), [] as AdvisoryRanges[]]]) };
    const byInstance = new Map([[instanceKey("npm", "lodash", "4.17.20"), [entry("GHSA-35jh-r3h4-6jhm")]]]);
    dropIncompleteLists(lookups, [item], batchOf(scanOf(), byInstance));
    expect(lookups.advisoryLists.get(lookupKey(item))).toBeNull();
    expect(item.listGap).toEqual({ ids: ["GHSA-35jh-r3h4-6jhm"], versions: ["4.17.20"], misread: [] });
    expect(item.rangeCheck).toBeUndefined();
  });

  it("a batch answer that names nothing leaves the list and the range check alone", () => {
    const item = ranged("4.17.21");
    const list: AdvisoryRanges[] = [];
    const lookups: Lookups = { indexes: new Map(), advisoryLists: new Map([[lookupKey(item), list]]) };
    dropIncompleteLists(lookups, [item], batchOf(scanOf()));
    expect(lookups.advisoryLists.get(lookupKey(item))).toBe(list);
    expect(item.listGap).toBeUndefined();
    expect(item.rangeCheck).toBeDefined();
  });
});
