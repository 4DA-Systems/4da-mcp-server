// SPDX-License-Identifier: Apache-2.0
/**
 * A release with an unmaintained-package notice on record answered proceed with "No advisory, age,
 * trust, script or new-dependency concern found." and the notice only as an id in
 * `maintenance_notices` (chrono 0.4.45, RUSTSEC-2026-0543). The verdict stays proceed (a declared
 * notice names no exploitable vulnerability); the sentence now names the notice.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck, runDependencyCheck } from "../tools/dependency-check.js";
import type { OsvVulnerability } from "../live/types.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-19T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

/** A RustSec-style unmaintained notice: the class declared on the affected entry, no grade, no fixed release. */
const notice = (id: string, name: string): OsvVulnerability =>
  ({
    id,
    aliases: [],
    summary: `${name} is unmaintained`,
    affected: [{ package: { name, ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }], database_specific: { informational: "unmaintained" } }],
  }) as unknown as OsvVulnerability;

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  const line = (vers: string) => ({ name: "time-like", vers, deps: [], cksum: "0", features: {}, yanked: false });
  net.crates["time-like"] = { versions: [{ num: "0.4.45", created_at: daysAgo(200) }, { num: "0.4.44", created_at: daysAgo(400) }], sparse: [line("0.4.44"), line("0.4.45")] };
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

const check = async (items: unknown[]) => executeDependencyCheck(noDb, { items }, new LiveIntelligence(new Database(":memory:")), { now: NOW });

describe("the proceed sentence when an unmaintained notice is on record", () => {
  it("names the notice instead of saying no advisory", async () => {
    net.osv = [notice("RUSTSEC-2026-0543", "time-like")];
    const r = (await check([{ ecosystem: "crates.io", package: "time-like", from: "0.4.44", to: "=0.4.45" }])).results[0];
    expect(r.verdict).toBe("proceed");
    expect(r.reason).toBe(
      "No vulnerability advisory, and no age, trust or new-dependency concern found; one unmaintained-package notice: RUSTSEC-2026-0543 (no exploitable vulnerability; listed in maintenance_notices).",
    );
    expect(r.reason).not.toMatch(/^No advisory/);
    const concise = (await runDependencyCheck(noDb, { items: [{ ecosystem: "crates.io", package: "time-like", to: "=0.4.45" }] }, new LiveIntelligence(new Database(":memory:")))) as { results: Array<Record<string, unknown>> };
    expect(concise.results[0]).toMatchObject({ verdict: "proceed", maintenance_notices: ["RUSTSEC-2026-0543"] });
    expect(concise.results[0].reason).toContain("one unmaintained-package notice: RUSTSEC-2026-0543");
  });

  it("counts several notices", async () => {
    net.osv = [notice("RUSTSEC-2026-0543", "time-like"), notice("RUSTSEC-2026-0544", "time-like")];
    const r = (await check([{ ecosystem: "crates.io", package: "time-like", to: "=0.4.45" }])).results[0];
    expect(r.reason).toContain("; 2 unmaintained-package notices: RUSTSEC-2026-0543, RUSTSEC-2026-0544 (no exploitable vulnerability; listed in maintenance_notices).");
  });

  it("without a notice the sentence is as before", async () => {
    const r = (await check([{ ecosystem: "crates.io", package: "time-like", from: "0.4.44", to: "=0.4.45" }])).results[0];
    expect(r.verdict).toBe("proceed");
    // crates.io has no install scripts to check, so none is claimed.
    expect(r.reason).toBe("No advisory, age, trust or new-dependency concern found.");
  });
});
