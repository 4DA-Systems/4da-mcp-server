// SPDX-License-Identifier: Apache-2.0
/**
 * A range bound the ecosystem's grammar cannot read decides nothing.
 *
 * OSV.dev's PyPI records carry bounds such as `last_affected: "2.9.0-NA"` (PYSEC-2024-264,
 * apache-airflow) and `"2.6.0-cu124"` (PYSEC-2025-189, torch). Read as equal to every version, such
 * a bound made every release of the package affected: dependency_check said `avoid` for the newest
 * apache-airflow and torch, and vulnerability_scan found no release that clears every advisory.
 *
 * The rule held here: an unreadable bound is never compared. Where its affected entry enumerates
 * versions, membership in that list decides. Where it does not, the advisory is undecidable from the
 * record: OSV.dev's own answer for the exact version decides, and without that answer the result is
 * unknown, never "affected" and never "safe".
 *
 * Records: api.osv.dev, read 2026-11-18, cut down to the `affected` entries and aliases. The
 * registries and OSV.dev are stubbed at `fetch`; the batch answers are OSV.dev's own per-version
 * answers, written out here, not worked out by this server's range reader.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { confirmTargets } from "../live/batch-confirm.js";
import type { FixPathSources, FixTargetResult } from "../live/fix-paths.js";
import type { AdvisoryQuery } from "../live/held-dependencies.js";
import {
  advisoriesAffecting,
  advisoryAffects,
  advisoryKnownToAffect,
  advisoryRanges,
  advisoryReading,
  cleanReleases,
  readableAdvisory,
  smallestCleanVersion,
  type AdvisoryRanges,
} from "../live/osv-ranges.js";
import type { PackageReleaseIndex, ReleaseRecord } from "../live/release-metadata.js";
import type { OsvVulnerability } from "../live/types.js";
import { checkRange } from "../tools/dependency-check-versions.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

type Ev = Record<string, string>;
const pysec = (id: string, name: string, events: Ev[], extra: { versions?: string[]; aliases?: string[]; severity?: string } = {}): OsvVulnerability =>
  ({
    id,
    aliases: extra.aliases ?? [],
    summary: `${name} advisory ${id}`,
    database_specific: { severity: extra.severity ?? "HIGH" },
    affected: [{ package: { name, ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events }], ...(extra.versions ? { versions: extra.versions } : {}) }],
  }) as unknown as OsvVulnerability;

/** apache-airflow, as OSV.dev serves it: three PYSEC records with a bound PEP 440 cannot read, their GHSA twins, and one fixable advisory. */
const AIRFLOW: OsvVulnerability[] = [
  pysec(
    "PYSEC-2024-264",
    "apache-airflow",
    [{ introduced: "0" }, { last_affected: "2.9.0-NA" }, { last_affected: "2.9.0-beta1" }, { last_affected: "2.9.0-beta2" }, { last_affected: "2.9.0-rc1" }, { last_affected: "2.9.0-rc2" }, { last_affected: "2.9.0-rc3" }],
    { versions: ["2.9.0b1", "2.9.0b2", "2.9.0rc1", "2.9.0rc2", "2.9.0rc3"], aliases: ["CVE-2024-32077", "GHSA-52gm-qmg3-r4qp"] },
  ),
  pysec("PYSEC-2024-266", "apache-airflow", [{ introduced: "0" }, { last_affected: "2.10.0-NA" }], { aliases: ["CVE-2024-45498", "GHSA-c392-whpc-vfpr"] }),
  pysec("PYSEC-2025-85", "apache-airflow", [{ introduced: "0" }, { last_affected: "3.0.3-NA" }], { aliases: ["CVE-2025-54831", "GHSA-q475-2pgm-7hvp"] }),
  pysec("GHSA-52gm-qmg3-r4qp", "apache-airflow", [{ introduced: "2.9.0" }, { fixed: "2.9.1" }], { versions: ["2.9.0"], aliases: ["CVE-2024-32077", "PYSEC-2024-264"] }),
  pysec("GHSA-c392-whpc-vfpr", "apache-airflow", [{ introduced: "2.10.0" }, { fixed: "2.10.1" }], { versions: ["2.10.0"], aliases: ["CVE-2024-45498", "PYSEC-2024-266"] }),
  pysec("GHSA-q475-2pgm-7hvp", "apache-airflow", [{ introduced: "3.0.3" }, { fixed: "3.0.4" }], { versions: ["3.0.3"], aliases: ["CVE-2025-54831", "PYSEC-2025-85"] }),
  pysec("GHSA-2943-9672-r45w", "apache-airflow", [{ introduced: "0" }, { fixed: "3.3.2" }], { severity: "CRITICAL" }),
];
const AIRFLOW_RELEASES = ["2.8.0", "2.9.0", "2.9.1", "2.10.0", "2.10.1", "3.0.3", "3.0.4", "3.3.2", "3.4.0"];

/** torch: PYSEC records that end at `2.6.0-cu124` / `2.6.0-NA`, none of which lists versions; one has no twin at all. */
const TORCH: OsvVulnerability[] = [
  pysec("PYSEC-2025-189", "torch", [{ introduced: "0" }, { last_affected: "2.6.0-cu124" }], { aliases: ["CVE-2025-2148", "GHSA-c678-jfcj-6jmf"] }),
  pysec("PYSEC-2025-196", "torch", [{ introduced: "0" }, { last_affected: "2.6.0-NA" }], { aliases: ["CVE-2025-3136"] }),
  pysec("GHSA-c678-jfcj-6jmf", "torch", [{ introduced: "0" }, { last_affected: "2.6.0" }], { aliases: ["CVE-2025-2148", "PYSEC-2025-189"] }),
  pysec("GHSA-rrmf-rvhw-rf47", "torch", [{ introduced: "0" }, { fixed: "2.13.0" }], { severity: "CRITICAL" }),
];
const TORCH_RELEASES = ["2.5.0", "2.6.0", "2.7.0", "2.13.0", "2.15.0"];

const ranges = (records: OsvVulnerability[], name: string): AdvisoryRanges[] => records.map((r) => advisoryRanges(r, name, "PyPI")!);
const byId = (list: AdvisoryRanges[], id: string) => list.find((a) => a.id === id)!;

describe("an unreadable bound is never compared", () => {
  const airflow = ranges(AIRFLOW, "apache-airflow");

  it("PYSEC-2024-264 lists its versions: membership in that list decides, and only that", () => {
    const a = byId(airflow, "PYSEC-2024-264");
    expect(readableAdvisory(a, "PyPI")).toBe(true);
    for (const v of ["2.9.0b1", "2.9.0rc3", "2.9.0-rc.2"]) expect(advisoryAffects(a, v, "PyPI"), v).toBe(true);
    for (const v of ["1.10.0", "2.8.0", "2.9.0", "3.3.2", "3.4.0", "99.0"]) expect(advisoryReading(a, v, "PyPI"), v).toBe("clear");
  });

  it("PYSEC-2024-266 lists none: no version is known affected, and none is called clear", () => {
    const a = byId(airflow, "PYSEC-2024-266");
    expect(readableAdvisory(a, "PyPI")).toBe(false);
    for (const v of ["1.10.0", "2.10.0", "3.4.0", "99.0"]) {
      expect(advisoryReading(a, v, "PyPI"), v).toBe("undecided");
      expect(advisoryKnownToAffect(a, v, "PyPI"), v).toBe(false);
      // The fail-closed side: a release is never called clear of an advisory that cannot be read.
      expect(advisoryAffects(a, v, "PyPI"), v).toBe(true);
    }
  });

  it("the latest apache-airflow is not known affected by any of the three; their readable twins still decide", () => {
    const known = airflow.filter((a) => advisoryKnownToAffect(a, "3.4.0", "PyPI")).map((a) => a.id);
    expect(known).toEqual([]);
    expect(airflow.filter((a) => advisoryKnownToAffect(a, "2.10.0", "PyPI")).map((a) => a.id)).toEqual(["GHSA-c392-whpc-vfpr", "GHSA-2943-9672-r45w"]);
  });

  it.each([
    ["fixed", [{ introduced: "0" }, { fixed: "2.0.0-NA" }]],
    ["last_affected", [{ introduced: "0" }, { last_affected: "2.0.0-NA" }]],
    ["introduced", [{ introduced: "1.0.0-NA" }, { fixed: "2.0.0" }]],
  ] as Array<[string, Ev[]]>)("an unreadable `%s` bound: no release is named safe because of it", (_kind, events) => {
    const a = advisoryRanges(pysec("PYSEC-0000-1", "demo", events), "demo", "PyPI")!;
    expect(readableAdvisory(a, "PyPI")).toBe(false);
    for (const v of ["0.5.0", "1.5.0", "2.0.0", "3.0.0"]) {
      expect(advisoryReading(a, v, "PyPI"), v).toBe("undecided");
      expect(advisoriesAffecting([a], v, "PyPI"), v).toEqual(["PYSEC-0000-1"]);
    }
    const view = cleanReleases([a], "PyPI", ["0.5.0", "1.5.0", "2.0.0", "3.0.0"]);
    expect(view.unreadable).toEqual(["PYSEC-0000-1"]);
    expect(view.newest).toBeNull();
    expect(view.clean("3.0.0")).toBe(false);
    // dependency_check's range check names no safe release either.
    const rec = (version: string): ReleaseRecord => ({ version, publishedAt: "2025-01-01T00:00:00Z", trust: "unknown", trustEvidence: "", installScripts: null, deprecated: null, withdrawn: null, dependencies: null }) as unknown as ReleaseRecord;
    const index: PackageReleaseIndex = { ecosystem: "PyPI", name: "demo", createdAt: null, releases: Object.fromEntries(["0.5.0", "1.5.0", "2.0.0", "3.0.0"].map((v) => [v, rec(v)])) };
    const rc = checkRange({ ecosystem: "PyPI", index, range: ">=0.1", basis: "requested", advisories: [a] });
    expect(rc.smallest_safe_in_range).toBeNull();
    expect(rc.safe_versions).toEqual([]);
  });

  it("a range with an unreadable bound is not read in part: its readable events decide nothing either", () => {
    // PYSEC-2024-264 without its list: `[0, 2.9.0rc3]` must not be taken from the range the "-NA" bound spoils.
    const record = pysec("PYSEC-2024-264", "apache-airflow", AIRFLOW[0].affected![0].ranges![0].events as Ev[]);
    const a = advisoryRanges(record, "apache-airflow", "PyPI")!;
    expect(advisoryReading(a, "2.8.0", "PyPI")).toBe("undecided");
    expect(advisoryKnownToAffect(a, "2.8.0", "PyPI")).toBe(false);
  });

  it("a readable range beside an unreadable one still decides what it covers", () => {
    const record = {
      id: "PYSEC-0000-2",
      affected: [{ package: { name: "demo", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0" }, { fixed: "1.5" }] }, { type: "ECOSYSTEM", events: [{ introduced: "2.0" }, { last_affected: "2.4-NA" }] }] }],
    } as unknown as OsvVulnerability;
    const a = advisoryRanges(record, "demo", "PyPI")!;
    expect(advisoryReading(a, "1.2", "PyPI")).toBe("affected");
    expect(advisoryReading(a, "3.0", "PyPI")).toBe("undecided");
  });
});

describe("smallestCleanVersion: an undecidable advisory names no target on its own", () => {
  const airflow = ranges(AIRFLOW, "apache-airflow");

  it("no target is named; the release the readable advisories leave clean waits for OSV.dev's own answer", () => {
    const clean = smallestCleanVersion({ ecosystem: "PyPI", fixes: ["3.3.2"], advisories: airflow, published: AIRFLOW_RELEASES, installed: "2.8.0" })!;
    expect(clean.target).toBeNull();
    // PYSEC-2024-264 lists its versions, so it is decided; the two without a list are not.
    expect(clean.unreadable).toEqual(["PYSEC-2024-266", "PYSEC-2025-85"]);
    expect(clean.ifConfirmed).toMatchObject({ target: "3.3.2", stillAffectedBy: [] });
    expect(clean.ifConfirmed?.unreadable).toBeUndefined();
  });

  it("nothing waits when the readable advisories leave no release clean", () => {
    const open = advisoryRanges(pysec("GHSA-open-open-open", "apache-airflow", [{ introduced: "3.0.0" }]), "apache-airflow", "PyPI")!;
    const clean = smallestCleanVersion({ ecosystem: "PyPI", fixes: ["3.3.2"], advisories: [...airflow, open], published: AIRFLOW_RELEASES, installed: "2.8.0" })!;
    expect(clean.target).toBeNull();
    expect(clean.ifConfirmed).toBeUndefined();
    expect(clean.unreadable).toEqual(["PYSEC-2024-266", "PYSEC-2025-85"]);
    // What is said to still affect it is only what is known to: never an advisory that cannot be read.
    expect(clean.stillAffectedBy).toEqual(["GHSA-open-open-open"]);
  });
});

describe("confirmTargets: OSV.dev's answer for the exact release settles an undecidable advisory", () => {
  const airflow = ranges(AIRFLOW, "apache-airflow");
  const sources = { packageAdvisories: async () => airflow } as unknown as FixPathSources;
  const pending = () => smallestCleanVersion({ ecosystem: "PyPI", fixes: ["3.3.2"], advisories: airflow, published: AIRFLOW_RELEASES, installed: "2.8.0" }) as FixTargetResult;
  const answering = (ids: string[]): AdvisoryQuery =>
    (async (deps: Array<{ name: string; version: string | null; ecosystem: string }>) => ({
      vulnerabilities: deps.flatMap((d) => ids.map((vulnId) => ({ vulnId, package: d.name, ecosystem: d.ecosystem, currentVersion: d.version }))),
      offline: false,
    })) as unknown as AdvisoryQuery;
  const confirm = async (query: AdvisoryQuery) => (await confirmTargets(sources, query, [{ key: "k", ecosystem: "PyPI", name: "apache-airflow", clean: pending() }], Date.now() + 5_000)).get("k");

  it("OSV.dev names nothing against 3.3.2: it is the target, checked", async () => {
    const out = await confirm(answering([]));
    expect(out).toMatchObject({ target: "3.3.2", stillAffectedBy: [] });
    expect(out?.advisoriesUnread).toBeUndefined();
    expect(out?.unreadable).toBeUndefined();
    expect(out?.ifConfirmed).toBeUndefined();
  });

  it("OSV.dev names the undecidable advisory against it: the release is affected, and is not named as checked", async () => {
    const out = await confirm(answering(["PYSEC-2024-266"]));
    expect(out?.advisoriesUnread).toBe(true);
    expect(out?.unconfirmed).toContain("PYSEC-2024-266");
  });

  it("the batch query fails: the release is a candidate that was NOT confirmed, never a checked target", async () => {
    const out = await confirm((async () => { throw new Error("HTTP 500"); }) as unknown as AdvisoryQuery);
    expect(out?.advisoriesUnread).toBe(true);
    expect(out?.unconfirmed).toMatch(/cannot be read/);
    expect(out?.unconfirmed).toMatch(/gave no current answer/);
  });
});

// ---------------------------------------------------------------------------
// Tool level
// ---------------------------------------------------------------------------

let PYPI: Record<string, string[]>;
let OSV: Record<string, OsvVulnerability[]>;
/**
 * OSV.dev's own answer per version, written out as api.osv.dev gives it: the GHSA records by their
 * ranges, and none of the PYSEC records with an unreadable bound for any release (they enumerate no
 * version of these release lists). Plain numeric comparison, not this server's range reader.
 */
const num = (v: string) => v.split(".").map(Number);
const below = (v: string, bound: string) => {
  const [a, b] = [num(v), num(bound)];
  for (let i = 0; i < Math.max(a.length, b.length); i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) < (b[i] ?? 0);
  return false;
};
const OSV_SAYS: Record<string, Record<string, (v: string) => boolean>> = {
  "apache-airflow": {
    "GHSA-2943-9672-r45w": (v) => below(v, "3.3.2"),
    "GHSA-52gm-qmg3-r4qp": (v) => v === "2.9.0",
    "GHSA-c392-whpc-vfpr": (v) => v === "2.10.0",
    "GHSA-q475-2pgm-7hvp": (v) => v === "3.0.3",
  },
  torch: {
    "GHSA-c678-jfcj-6jmf": (v) => !below("2.6.0", v),
    "GHSA-rrmf-rvhw-rf47": (v) => below(v, "2.13.0"),
  },
};
/** Ids OSV.dev names beyond those, per "name@version" (a test's own what-if). */
let BATCH: Record<string, string[]>;
let BATCH_DOWN: boolean;
let dir: string;
let priorOffline: string | undefined;

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const norm = (n: string) => n.toLowerCase().replace(/[-_.]+/g, "-");
    if (url.endsWith("/v1/querybatch")) {
      if (BATCH_DOWN) return new Response("internal error", { status: 500 });
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      const idsAt = (name: string, version: string) => [...Object.entries(OSV_SAYS[name] ?? {}).filter(([, affects]) => affects(version)).map(([id]) => id), ...(BATCH[`${name}@${version}`] ?? [])];
      return json({ results: queries.map((q) => ({ vulns: idsAt(norm(q.package.name), q.version).map((id) => ({ id, modified: "2026-11-01T00:00:00Z" })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(OSV).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: OSV[norm(q.package.name)] ?? [] });
    }
    // One release's own document (its requires_dist): served for a release the project lists.
    const release = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/([^/]+)\/json$/.exec(url);
    if (release) {
      const version = decodeURIComponent(release[2]);
      return PYPI[norm(decodeURIComponent(release[1]))]?.includes(version) ? json({ info: { version, requires_dist: null } }) : json({ message: "Not Found" }, 404);
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      const name = norm(decodeURIComponent(pypi[1]));
      const versions = PYPI[name];
      if (!versions) return json({ message: "Not Found" }, 404);
      const releases = Object.fromEntries(versions.map((v) => [v, [{ upload_time_iso_8601: "2025-06-01T00:00:00Z", yanked: false, requires_python: null }]]));
      return json({ info: { name, version: versions[versions.length - 1], license: "", classifiers: [], summary: "", yanked: false, yanked_reason: null }, releases });
    }
    return json({}, 404);
  });
}

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  PYPI = { "apache-airflow": AIRFLOW_RELEASES, torch: TORCH_RELEASES };
  OSV = { "apache-airflow": AIRFLOW, torch: TORCH };
  BATCH = {};
  BATCH_DOWN = false;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-unread-"));
  stub();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

const UNREADABLE_IDS = /PYSEC-2024-264|PYSEC-2024-266|PYSEC-2025-85|PYSEC-2025-189|PYSEC-2025-196/;

describe("dependency_check: the newest release is judged by OSV.dev's own answer for it", () => {
  const check = async (items: unknown[]) => (await executeDependencyCheck(noDb, { items, response_format: "detailed" } as never, new LiveIntelligence(new Database(":memory:")))).results as Array<Record<string, any>>;

  it("apache-airflow and torch `latest` are not condemned by the records with an unreadable bound", async () => {
    const [airflow, torch] = await check([
      { ecosystem: "PyPI", package: "apache-airflow", to: "latest" },
      { ecosystem: "PyPI", package: "torch", to: "latest" },
    ]);
    expect(airflow).toMatchObject({ to: "3.4.0", verdict: "proceed" });
    expect(torch).toMatchObject({ to: "2.15.0", verdict: "proceed" });
    for (const r of [airflow, torch]) {
      expect(JSON.stringify(r.signals.find((s: { id: string }) => s.id === "advisories"))).not.toMatch(UNREADABLE_IDS);
      expect(r.reason).not.toMatch(/is affected by/);
    }
  });

  it("an exact version OSV.dev does name an advisory against is still avoided, by that advisory alone", async () => {
    const [r] = await check([{ ecosystem: "PyPI", package: "apache-airflow", to: "2.8.0" }]);
    expect(r.verdict).toBe("avoid");
    const advisories = r.signals.find((s: { id: string }) => s.id === "advisories");
    expect(advisories.value.affecting_to).toEqual(["GHSA-2943-9672-r45w"]);
  });

  it("without OSV.dev's answer for the version the verdict is unknown: neither affected nor safe", async () => {
    BATCH_DOWN = true;
    const [r] = await check([{ ecosystem: "PyPI", package: "apache-airflow", to: "latest" }]);
    expect(r.verdict).toBe("unknown");
    expect(r.reason).not.toMatch(/is affected by/);
  });

  it("a constraint: the release it installs is judged; no other release is named safe on an unreadable range", async () => {
    const [r] = await check([{ ecosystem: "PyPI", package: "apache-airflow", to: ">=3.0" }]);
    expect(r).toMatchObject({ to: "3.4.0", verdict: "proceed" });
    expect(r.range_check.smallest_safe_in_range).toBeNull();
    expect(r.range_check.safe_versions).toEqual([]);
    expect(r.reason).toMatch(/cannot rule out any release/);
  });
});

describe("vulnerability_scan: a fix target is named once OSV.dev's answer for it is clean", () => {
  async function project() {
    fs.writeFileSync(path.join(dir, "requirements.txt"), "apache-airflow==2.8.0\ntorch==2.5.0\n");
    const li = new LiveIntelligence(new Database(":memory:"));
    const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
    const { entries, discovery } = scanProjectTree(dir);
    li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    return li;
  }
  const scan = async () => (await executeVulnerabilityScan(null, { project_path: dir, response_format: "concise" }, await project())) as Record<string, any>;
  const plan = async () => ((await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, await project())) as Record<string, any>).recommendations as Array<Record<string, any>>;
  const row = (s: Record<string, any>, name: string) => (s.vulnerable_packages as Array<Record<string, any>>).find((p) => p.package === name)!;
  const line = (s: Record<string, any>, name: string) => (s.recommendations as string[]).find((r) => r.includes(name))!;

  it("apache-airflow 2.8.0 -> 3.3.2 and torch 2.5.0 -> 2.13.0, each clean in the record data and in OSV.dev's answer", async () => {
    const s = await scan();
    expect(row(s, "apache-airflow")).toMatchObject({ fixed_version: "3.3.2", fix_checked: "all_advisories" });
    expect(row(s, "torch")).toMatchObject({ fixed_version: "2.13.0", fix_checked: "all_advisories" });
    expect(line(s, "apache-airflow")).toMatch(/Upgrade apache-airflow 2\.8\.0 → 3\.3\.2/);
    expect(line(s, "torch")).toMatch(/Upgrade torch 2\.5\.0 → 2\.13\.0/);
    expect(JSON.stringify(s.recommendations)).not.toMatch(/still affected by/);
  });

  it("OSV.dev names an undecidable advisory against the candidate: no release is named as the fix", async () => {
    BATCH["torch@2.13.0"] = ["PYSEC-2025-196"];
    const s = await scan();
    expect(row(s, "torch").fixed_version).toBeNull();
    expect(row(s, "torch").fix_checked).not.toBe("all_advisories");
    expect(line(s, "torch")).toMatch(/NOT CHECKED/);
    // apache-airflow, in the same scan, is unaffected by that.
    expect(row(s, "apache-airflow")).toMatchObject({ fixed_version: "3.3.2", fix_checked: "all_advisories" });
    const torch = (await plan()).find((p) => p.package === "torch")!;
    expect(torch.targetVersion).toBeNull();
    expect(torch.reasons.join(" | ")).toMatch(/NOT CHECKED/);
  });

  it("upgrade_planner names the same targets as the scan", async () => {
    const steps = await plan();
    expect(steps.find((s) => s.package === "apache-airflow")).toMatchObject({ targetVersion: "3.3.2", fixPathChecked: "all_advisories" });
    expect(steps.find((s) => s.package === "torch")).toMatchObject({ targetVersion: "2.13.0", fixPathChecked: "all_advisories" });
  });
});
