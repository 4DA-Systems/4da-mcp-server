// SPDX-License-Identifier: Apache-2.0
/**
 * "Unmaintained" wording must not downgrade a real advisory (audit 2026-11-11, M11).
 *
 * `olm-sys latest` said proceed while OSV carries GHSA-p2q9-36vw-c468, graded HIGH: that record and
 * its alias RUSTSEC-2024-0368 both say "unmaintained", and the notice predicate read the summary.
 * `tanton_engine` (RUSTSEC-2025-0031, memory-corruption) and golang.org/x/crypto (GO-2026-5932,
 * which closes its range with a fix) read proceed the same way.
 *
 * The records below are the real ones (api.osv.dev, 2026-11-11), cut down to the fields the
 * predicate reads. Two readings are pinned:
 * - the shared predicate (isMaintenanceRecord, every tool and the 4DA app): structured facts beat
 *   wording; a bare summary decides only for a record that states nothing;
 * - dependency_check's verdict: a notice is passed over only when the record DECLARES the class
 *   and names no fixed release.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { isDeclaredNotice, isMaintenanceNotice, isMaintenanceRecord, maintenanceBasis } from "../live/maintenance.js";
import { advisoryAffects, advisoryRanges } from "../live/osv-ranges.js";
import type { OsvVulnerability } from "../live/types.js";
import { executeDependencyCheck, refs } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";

const crate = (name: string, events: Array<Record<string, string>>, database_specific?: Record<string, unknown>) => ({
  package: { name, ecosystem: "crates.io" },
  ranges: [{ type: "SEMVER", events }],
  ...(database_specific ? { database_specific } : {}),
});

/** RustSec's vulnerability class: `informational: null`, an exploit category. */
const RUSTSEC_2024_0368 = {
  id: "RUSTSEC-2024-0368",
  summary: "olm-sys: wrapped library unmaintained, potentially vulnerable",
  aliases: ["GHSA-p2q9-36vw-c468"],
  database_specific: { license: "CC0-1.0" },
  affected: [crate("olm-sys", [{ introduced: "0.0.0-0" }], { categories: ["crypto-failure"], cvss: null, informational: null })],
} as unknown as OsvVulnerability;
const GHSA_P2Q9 = {
  id: "GHSA-p2q9-36vw-c468",
  summary: "olm-sys: wrapped library unmaintained, potentially vulnerable",
  aliases: ["RUSTSEC-2024-0368"],
  database_specific: { cwe_ids: ["CWE-1395"], severity: "HIGH", github_reviewed: true },
  affected: [crate("olm-sys", [{ introduced: "0" }, { last_affected: "1.3.2" }])],
} as unknown as OsvVulnerability;
const RUSTSEC_2025_0031 = {
  id: "RUSTSEC-2025-0031",
  summary: "Unsound public API in unmaintained crate",
  aliases: ["GHSA-m2xr-2vj4-wh94"],
  database_specific: { license: "CC0-1.0" },
  affected: [crate("tanton_engine", [{ introduced: "0.0.0-0" }], { categories: ["memory-corruption"], cvss: null, informational: null })],
} as unknown as OsvVulnerability;
const GHSA_M2XR = {
  id: "GHSA-m2xr-2vj4-wh94",
  summary: "tanton_engine has unsound public API",
  aliases: ["RUSTSEC-2025-0031"],
  database_specific: { cwe_ids: ["CWE-119"], severity: "MODERATE" },
  affected: [crate("tanton_engine", [{ introduced: "0" }, { last_affected: "1.0.0" }])],
} as unknown as OsvVulnerability;
/** The Go vulnerability database grades nothing and declares no class; this record has a fix. */
const GO_2026_5932 = {
  id: "GO-2026-5932",
  summary: "The golang.org/x/crypto/openpgp package is unmaintained, unsafe by design, and has known security issues",
  database_specific: { url: "https://pkg.go.dev/vuln/GO-2026-5932", review_status: "REVIEWED" },
  affected: [
    { package: { name: "golang.org/x/crypto", ecosystem: "Go" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.58.1-0.20261009181718-2f1f834330b2" }] }] },
    { package: { name: "golang.org/x/crypto/openpgp", ecosystem: "Go" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] },
  ],
} as unknown as OsvVulnerability;
/** A notice RustSec declares, with no fix: `instant` is unmaintained. */
const RUSTSEC_2024_0384 = {
  id: "RUSTSEC-2024-0384",
  summary: "`instant` is unmaintained",
  database_specific: { license: "CC0-1.0" },
  affected: [crate("instant", [{ introduced: "0.0.0-0" }], { categories: [], cvss: null, informational: "unmaintained" })],
} as unknown as OsvVulnerability;
/** A notice RustSec declares, WITH a fix: "Versions of *ring* prior to 0.17 are unmaintained." */
const RUSTSEC_2025_0010 = {
  id: "RUSTSEC-2025-0010",
  summary: "Versions of *ring* prior to 0.17 are unmaintained.",
  database_specific: { license: "CC0-1.0" },
  affected: [crate("ring", [{ introduced: "0.0.0-0" }, { fixed: "0.17.0" }], { categories: [], cvss: null, informational: "unmaintained" })],
} as unknown as OsvVulnerability;

describe("the shared predicate: structured facts beat the summary's wording", () => {
  it("a record with a severity label is a vulnerability whatever it says (GHSA-p2q9-36vw-c468, HIGH)", () => {
    expect(maintenanceBasis(GHSA_P2Q9, "olm-sys", "crates.io")).toBeNull();
    expect(isMaintenanceRecord(GHSA_P2Q9, "olm-sys", "crates.io")).toBe(false);
  });

  it("a CVSS vector, or RustSec's per-package cvss, is a grade too", () => {
    const worded = { id: "X-1", summary: "foo is unmaintained", affected: [crate("foo", [{ introduced: "0" }])] } as unknown as OsvVulnerability;
    expect(isMaintenanceRecord(worded, "foo", "crates.io")).toBe(true);
    expect(isMaintenanceRecord({ ...worded, severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] }, "foo", "crates.io")).toBe(false);
    const own = { ...worded, affected: [crate("foo", [{ introduced: "0" }], { informational: "unmaintained", cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" })] } as unknown as OsvVulnerability;
    expect(isMaintenanceRecord(own, "foo", "crates.io")).toBe(false);
  });

  it("RustSec's vulnerability class (informational null, an exploit category) is never a notice: olm-sys, tanton_engine", () => {
    expect(maintenanceBasis(RUSTSEC_2024_0368, "olm-sys", "crates.io")).toBeNull();
    expect(maintenanceBasis(RUSTSEC_2025_0031, "tanton_engine", "crates.io")).toBeNull();
    // The category alone decides, even beside a declared class.
    const both = { ...RUSTSEC_2024_0384, affected: [crate("instant", [{ introduced: "0.0.0-0" }], { categories: ["denial-of-service"], informational: "unmaintained" })] } as unknown as OsvVulnerability;
    expect(isMaintenanceRecord(both, "instant", "crates.io")).toBe(false);
    // `informational: null` is RustSec saying "not informational", whatever the summary says.
    const stated = { id: "RUSTSEC-0000-0001", summary: "bar is unmaintained", affected: [crate("bar", [{ introduced: "0.0.0-0" }], { categories: [], cvss: null, informational: null })] } as unknown as OsvVulnerability;
    expect(isMaintenanceRecord(stated, "bar", "crates.io")).toBe(false);
  });

  it("with no class stated, a `fixed` event means there is something to move to: GO-2026-5932 is a vulnerability", () => {
    expect(maintenanceBasis(GO_2026_5932, "golang.org/x/crypto", "Go")).toBeNull();
    // The same record's other package has no fix and states nothing: there the wording still decides.
    expect(maintenanceBasis(GO_2026_5932, "golang.org/x/crypto/openpgp", "Go")).toBe("wording");
  });

  it("a malicious-package record is never a notice", () => {
    const mal = { id: "MAL-2026-1", summary: "Malicious code in foo (npm): the package is no longer maintained", affected: [{ package: { name: "foo", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }] } as unknown as OsvVulnerability;
    expect(isMaintenanceRecord(mal, "foo", "npm")).toBe(false);
    expect(isMaintenanceNotice({ summary: "foo is unmaintained", malware: true })).toBe(false);
  });

  it("a declared class is a notice, and stays one in the shared predicate with a fix (the vectors ft-073, sv-023)", () => {
    expect(maintenanceBasis(RUSTSEC_2024_0384, "instant", "crates.io")).toBe("declared");
    expect(maintenanceBasis(RUSTSEC_2025_0010, "ring", "crates.io")).toBe("declared");
    expect(isMaintenanceRecord(RUSTSEC_2025_0010, "ring", "crates.io")).toBe(true);
  });

  it("a record that states nothing at all is still read by its wording (the vectors sv-011, sv-018, ft-071, ft-092)", () => {
    expect(maintenanceBasis({ id: "RUSTSEC-2099-0001", summary: "foo is unmaintained", aliases: ["GHSA-bbbb-0000-0001"] } as unknown as OsvVulnerability, "foo", "crates.io")).toBe("wording");
    expect(maintenanceBasis({ id: "SYNT-0000-0004", summary: "pkg is unmaintained", affected: [{ package: { name: "pkg", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.1.0" }] }] }] } as unknown as OsvVulnerability, "pkg", "npm")).toBe("wording");
  });
});

describe("dependency_check's reading: only a declared notice with no fixed release is passed over", () => {
  it("isDeclaredNotice: instant yes; ring (a fix) no; a worded record no; a graded or categorised one no", () => {
    expect(isDeclaredNotice(RUSTSEC_2024_0384, "instant", "crates.io")).toBe(true);
    expect(isDeclaredNotice(RUSTSEC_2025_0010, "ring", "crates.io")).toBe(false);
    expect(isDeclaredNotice(GO_2026_5932, "golang.org/x/crypto/openpgp", "Go")).toBe(false);
    expect(isDeclaredNotice(GHSA_P2Q9, "olm-sys", "crates.io")).toBe(false);
    expect(isDeclaredNotice(RUSTSEC_2024_0368, "olm-sys", "crates.io")).toBe(false);
  });

  it("the advisory list carries it: declaredNotice only where the record declares it", () => {
    expect(advisoryRanges(RUSTSEC_2024_0384, "instant", "crates.io")).toMatchObject({ maintenance: true, declaredNotice: true });
    const ring = advisoryRanges(RUSTSEC_2025_0010, "ring", "crates.io")!;
    expect(ring.maintenance).toBe(true);
    expect(ring.declaredNotice).toBeUndefined();
    expect(advisoryRanges(GHSA_P2Q9, "olm-sys", "crates.io")).toMatchObject({ maintenance: false });
  });

  const entry = (id: string, over: Record<string, unknown> = {}) =>
    ({ package: "p", currentVersion: "1.0.0", ecosystem: "crates.io", vulnId: id, aliases: [], severity: "unknown", cvssScore: null, summary: "p is unmaintained", fixedVersion: null, maintenance: true, ...over }) as never;

  it("refs: a notice is one only when its id is among the declared; otherwise it counts and says why", () => {
    expect(refs([entry("RUSTSEC-1")], new Set(["RUSTSEC-1"]))).toMatchObject([{ id: "RUSTSEC-1", maintenance: true }]);
    expect(refs([entry("GO-1")], new Set())).toMatchObject([{ id: "GO-1", maintenance: false, countedNotice: true }]);
    // No list of the package's advisories (the lookup failed): nothing is declared, so it counts.
    expect(refs([entry("RUSTSEC-1")])).toMatchObject([{ maintenance: false, countedNotice: true }]);
    // A declared notice that names a fixed release counts.
    expect(refs([entry("RUSTSEC-1", { fixedVersion: "0.17.0" })], new Set(["RUSTSEC-1"]))).toMatchObject([{ maintenance: false, countedNotice: true }]);
    // An alias group with a graded member is that member's.
    const group = [entry("RUSTSEC-1", { aliases: ["GHSA-1"] }), entry("GHSA-1", { aliases: ["RUSTSEC-1"], severity: "high", maintenance: false })];
    expect(refs(group, new Set(["RUSTSEC-1"]))).toMatchObject([{ id: "GHSA-1", severity: "high", maintenance: false }]);
  });
});

// ---------------------------------------------------------------------------------------------
// The whole tool, over stubbed registries and OSV: the three names the audit found
// ---------------------------------------------------------------------------------------------

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-11T00:00:00Z");
let OSV: OsvVulnerability[];
/** crates.io: name -> versions (oldest first), all published long ago. */
let CRATES: Record<string, string[]>;
/** Go: module -> versions. */
let GO: Record<string, string[]>;
let OSV_PACKAGE_LIST_DOWN: boolean;

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const recordsFor = (name: string, ecosystem: string) => OSV.filter((v) => v.affected?.some((a) => a.package?.name === name && a.package.ecosystem === ecosystem));
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return json({
        results: queries.map((q) => ({
          vulns: recordsFor(q.package.name, q.package.ecosystem)
            .filter((v) => advisoryAffects(advisoryRanges(v, q.package.name, q.package.ecosystem)!, q.version, q.package.ecosystem))
            .map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" })),
        })),
      });
    }
    if (url.includes("/v1/vulns/")) {
      const found = OSV.find((v) => v.id === decodeURIComponent(url.split("/v1/vulns/")[1]));
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      if (OSV_PACKAGE_LIST_DOWN) return new Response("unavailable", { status: 503 });
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string } };
      return json({ vulns: recordsFor(q.package.name, q.package.ecosystem) });
    }
    const crates = /^https:\/\/crates\.io\/api\/v1\/crates\/([^/?]+)\/versions/.exec(url);
    if (crates) {
      const versions = CRATES[decodeURIComponent(crates[1])];
      if (!versions) return json({ errors: [{ detail: "Not Found" }] }, 404);
      return json({ versions: versions.map((num, i) => ({ num, created_at: new Date(Date.UTC(2021, 0, 1 + i)).toISOString(), yanked: false })), meta: { next_page: null } });
    }
    if (url.startsWith("https://index.crates.io/")) {
      const name = url.split("/").pop()!;
      const versions = CRATES[name];
      return versions ? new Response(versions.map((vers) => JSON.stringify({ name, vers, deps: [], yanked: false })).join("\n")) : new Response("", { status: 404 });
    }
    const go = /^https:\/\/proxy\.golang\.org\/(.+)\/@(v\/list|latest|v\/(.+)\.(info|mod))$/.exec(url);
    if (go) {
      const versions = GO[go[1]];
      if (!versions) return new Response("not found", { status: 404 });
      if (go[2] === "v/list") return new Response(`${versions.join("\n")}\n`);
      if (go[4] === "info") return versions.includes(go[3]) ? json({ Version: go[3], Time: "2026-09-01T00:00:00Z" }) : new Response("not found", { status: 404 });
      return new Response(go[4] === "mod" ? `module ${go[1]}\n` : "not found", { status: go[4] === "mod" ? 200 : 404 });
    }
    return json({}, 404);
  });
}

let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  OSV = [RUSTSEC_2024_0368, GHSA_P2Q9, RUSTSEC_2025_0031, GHSA_M2XR, GO_2026_5932, RUSTSEC_2024_0384, RUSTSEC_2025_0010];
  CRATES = { "olm-sys": ["1.3.0", "1.3.1", "1.3.2"], tanton_engine: ["0.9.0", "1.0.0"], instant: ["0.1.12", "0.1.13"], ring: ["0.16.20", "0.17.0", "0.17.14"] };
  GO = { "golang.org/x/crypto": ["v0.56.0", "v0.57.0", "v0.58.0"] };
  OSV_PACKAGE_LIST_DOWN = false;
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

type Result = Record<string, any>;
const check = async (items: unknown[]) =>
  (await executeDependencyCheck(noDb, { items } as never, new LiveIntelligence(new Database(":memory:")), { now: NOW })) as unknown as { results: Result[] };
const advisories = (r: Result) => (r.signals as Array<{ id: string; value: any; effect: string; evidence: string }>).find((s) => s.id === "advisories")!;

describe("dependency_check: the names that read proceed", () => {
  it("olm-sys latest is avoid: GHSA-p2q9-36vw-c468 is HIGH (it said proceed, \"no exploitable vulnerability\")", async () => {
    const [r] = (await check([{ ecosystem: "crates.io", package: "olm-sys", to: "latest" }])).results;
    expect(r).toMatchObject({ to: "1.3.2", verdict: "avoid" });
    expect(advisories(r).value.affecting_to).toHaveLength(1);
    expect(advisories(r).value.maintenance_notices).toBeUndefined();
    expect(r.maintenance_notices).toBeUndefined();
    expect(r.reason).toMatch(/1\.3\.2 is affected by (GHSA-p2q9-36vw-c468|RUSTSEC-2024-0368) \(high/);
    expect(r.reason).not.toContain("no exploitable vulnerability");
    // Every release is affected, and the answer says so instead of naming one.
    expect(r.range_check).toMatchObject({ basis: "same_line", smallest_safe_in_range: null });
  });

  it("tanton_engine latest is review: memory-corruption, graded MODERATE by its alias", async () => {
    const [r] = (await check([{ ecosystem: "crates.io", package: "tanton_engine", to: "latest" }])).results;
    expect(r).toMatchObject({ to: "1.0.0", verdict: "review" });
    expect(advisories(r).value.affecting_to).toHaveLength(1);
    expect(r.reason).toMatch(/1\.0\.0 is affected by (GHSA-m2xr-2vj4-wh94|RUSTSEC-2025-0031) \(medium/);
  });

  it("golang.org/x/crypto v0.58.0 is review: GO-2026-5932 has a fix, and no release in v0 is past it", async () => {
    const out = await check([
      { ecosystem: "Go", package: "golang.org/x/crypto", to: "v0.58.0" },
      { ecosystem: "Go", package: "golang.org/x/crypto", to: "v0" },
    ]);
    for (const r of out.results) {
      expect(r.verdict).toBe("review");
      expect(advisories(r).value.affecting_to).toEqual(["GO-2026-5932"]);
      expect(r.reason).toContain("GO-2026-5932 (unknown)");
    }
    // The range answer agrees with the verdict: no v0 release is called safe.
    expect(out.results[1].range_check).toMatchObject({ smallest_safe_in_range: null, vulnerable_in_range: 3, affecting_all: ["GO-2026-5932"] });
  });

  it("a notice RustSec declares, with no fix, is still passed over and listed: instant", async () => {
    const [r] = (await check([{ ecosystem: "crates.io", package: "instant", to: "latest" }])).results;
    expect(r).toMatchObject({ to: "0.1.13", verdict: "proceed" });
    expect(r.maintenance_notices).toEqual(["RUSTSEC-2024-0384"]);
    expect(advisories(r).evidence).toContain("no exploitable vulnerability, listed in maintenance_notices");
  });

  it("a declared notice with a fixed release counts, and the fixed release is named: ring 0.16.20", async () => {
    const [r] = (await check([{ ecosystem: "crates.io", package: "ring", to: "0.16.20" }])).results;
    expect(r.verdict).toBe("review");
    expect(advisories(r).value.affecting_to).toEqual(["RUSTSEC-2025-0010"]);
    expect(r.reason).toContain("worded as an unmaintained-package notice, but not declared as one or it names a fixed release, so it counts");
    expect(r.range_check).toMatchObject({ basis: "same_line", range: "0.16.x", smallest_safe_in_range: null, newest_safe_outside_range: "0.17.14" });
    // The fixed line itself is clean.
    const [fixed] = (await check([{ ecosystem: "crates.io", package: "ring", to: "0.17.14" }])).results;
    expect(fixed.verdict).toBe("proceed");
  });

  it("without the package's advisory list nothing is declared: the notice counts (review), never proceed", async () => {
    OSV_PACKAGE_LIST_DOWN = true;
    const [r] = (await check([{ ecosystem: "crates.io", package: "instant", from: "0.1.12", to: "0.1.13" }])).results;
    expect(r.verdict).not.toBe("proceed");
    expect(advisories(r).value.affecting_to).toEqual(["RUSTSEC-2024-0384"]);
  });
});
