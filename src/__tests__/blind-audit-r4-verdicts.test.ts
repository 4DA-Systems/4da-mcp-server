// SPDX-License-Identifier: Apache-2.0
/**
 * Verdict defects from the blind pre-publish audit, round 4 (main 776849d, 2026-11-14).
 *
 * 1. An empty OSV advisory list made `safe` name a vulnerable release. A proxy answered `{}` for
 *    POST /v1/query while querybatch answered normally: `{npm, lodash, 4.17.20}` was correctly
 *    avoid, and the answer went on "Safe on 4.17.20's line: smallest 4.0.0", which eight advisories
 *    affect. The list is now checked against the ids the batch query named.
 * 2. `safe.newest` named releases the tool itself holds as `wait`: `{npm, ws, "7.x"}` named 7.5.14
 *    at 1.4 days old and `{PyPI, boto3, "~=1.44.0"}` named 1.44.3 at 0.5 days.
 * 3. Malware records without a MAL- id or CWE-506 were not read as malware: "add the ctx package"
 *    (PyPI; GHSA-4g82-3jcr-q52w "Malware in ctx", cwe_ids ["CWE-912"]) came back avoid with
 *    `malicious: false` and review_needed, not human_only.
 * 4. A 219-release downgrade (serde 1.0.219 to 1.0.0) came back safe_to_delegate with no mention.
 *
 * The OSV records in fixtures/osv/malware-wording-2026-11-14.json are the real ones (api.osv.dev);
 * registries and OSV are stubbed with their real response shapes.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import { cleanFixTarget, missingFromList } from "../live/fix-paths.js";
import { isMalware, isMalwareRecord, saysMalware } from "../live/malware.js";
import { advisoryAffects, advisoryRanges } from "../live/osv-ranges.js";
import type { OsvVulnerability, ResolvedDependency, VulnerabilityScanResult } from "../live/types.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { upgradeTypeSignal } from "../tools/dependency-check-signals.js";
import { executeWhatShouldIKnow, type BriefingLiveIntel } from "../tools/what-should-i-know.js";

const NOW = new Date();
const DAY = 86_400_000;
const daysAgo = (n: number) => new Date(NOW.getTime() - n * DAY).toISOString();

const FIXTURE = JSON.parse(
  fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "osv", "malware-wording-2026-11-14.json"), "utf8"),
) as { records: OsvVulnerability[] };
const real = (id: string) => FIXTURE.records.find((r) => r.id === id)!;

/** npm: name -> version -> publish time. PyPI: the same. */
let NPM: Record<string, Record<string, string>>;
let PYPI: Record<string, Record<string, string>>;
let OSV: OsvVulnerability[];
/** The proxy of defect 1: POST /v1/query answers `{}` while querybatch answers normally. */
let QUERY_EMPTY: boolean;

function stub() {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const same = (a: string, b: string, eco: string) => (eco === "PyPI" ? a.toLowerCase() === b.toLowerCase() : a === b);
    const recordsFor = (name: string, eco: string) => OSV.filter((v) => v.affected?.some((a) => a.package?.ecosystem === eco && same(a.package.name, name, eco)));
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
      if (QUERY_EMPTY) return json({});
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string } };
      return json({ vulns: recordsFor(q.package.name, q.package.ecosystem) });
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      const name = Object.keys(PYPI).find((n) => n.toLowerCase() === decodeURIComponent(pypi[1]).toLowerCase());
      if (!name) return json({ message: "Not Found" }, 404);
      return json({ info: { name }, releases: Object.fromEntries(Object.entries(PYPI[name]).map(([v, at]) => [v, [{ upload_time_iso_8601: at, yanked: false }]])) });
    }
    if (url.startsWith("https://api.npmjs.org/downloads/")) return json({ error: "not found" }, 404);
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = NPM[name];
      if (!doc) return json({ error: "Not found" }, 404);
      const versions = Object.keys(doc);
      const latest = versions[versions.length - 1];
      return json({
        name,
        "dist-tags": { latest },
        versions: Object.fromEntries(versions.map((v) => [v, { name, version: v, dependencies: {} }])),
        time: { created: "2015-01-01T00:00:00.000Z", ...doc },
      });
    }
    return json({}, 404);
  });
}

let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  clearNpmDownloadsMemo();
  NPM = {};
  PYPI = {};
  OSV = [];
  QUERY_EMPTY = false;
  stub();
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

type Result = Record<string, any>;
const check = async (items: unknown[]) =>
  (await executeDependencyCheck(null, { items } as never, new LiveIntelligence(new Database(":memory:")), { now: NOW })) as unknown as { results: Result[] };
const npmRecord = (id: string, name: string, events: Array<Record<string, string>>, severity = "HIGH"): OsvVulnerability =>
  ({ id, aliases: [], summary: `${name} advisory`, database_specific: { severity }, affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events }] }] }) as unknown as OsvVulnerability;

// ---------------------------------------------------------------------------------------------
// 1. An advisory list that leaves out what the batch query named names no safe release
// ---------------------------------------------------------------------------------------------

describe("defect 1: an incomplete OSV advisory list never names a safe release", () => {
  beforeEach(() => {
    // lodash on the 4.x line, cut down: three advisories that affect 4.0.0, fixed at 4.17.12, 4.17.19 and 4.17.21.
    NPM.lodash = { "4.0.0": daysAgo(3000), "4.17.11": daysAgo(2400), "4.17.15": daysAgo(2200), "4.17.20": daysAgo(2000), "4.17.21": daysAgo(1900) };
    OSV.push(
      npmRecord("GHSA-jf85-cpcp-j695", "lodash", [{ introduced: "0" }, { fixed: "4.17.12" }], "CRITICAL"),
      npmRecord("GHSA-p6mc-m468-83gw", "lodash", [{ introduced: "0" }, { fixed: "4.17.19" }]),
      npmRecord("GHSA-35jh-r3h4-6jhm", "lodash", [{ introduced: "0" }, { fixed: "4.17.21" }]),
    );
  });

  it("with OSV answering normally, lodash 4.17.20 is avoid and its line's safe release is 4.17.21 (control)", async () => {
    const [r] = (await check([{ ecosystem: "npm", package: "lodash", to: "4.17.20" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.range_check).toMatchObject({ basis: "same_line", smallest_safe_in_range: "4.17.21" });
    expect(r.reason).not.toContain("NOT CHECKED");
  });

  it("with /v1/query answering {}, lodash 4.17.20 is avoid and no release is named safe (it named 4.0.0)", async () => {
    QUERY_EMPTY = true;
    const [r] = (await check([{ ecosystem: "npm", package: "lodash", to: "4.17.20" }])).results;
    expect(r.verdict).toBe("avoid");
    expect(r.range_check).toBeUndefined();
    expect(r.reason).not.toMatch(/Safe on|smallest 4\.0\.0/);
    expect(r.reason).toContain("NOT CHECKED: OSV.dev's advisory list for lodash (/v1/query) left out GHSA-35jh-r3h4-6jhm");
    expect(r.reason).toContain("which its batch query names for 4.17.20");
  });

  it("with /v1/query answering {}, a constraint names no safe release either: its picks are checked against the batch query", async () => {
    QUERY_EMPTY = true;
    const [r] = (await check([{ ecosystem: "npm", package: "lodash", to: "^4.0.0" }])).results;
    expect(r.range_check).toBeUndefined();
    expect(r.reason).not.toMatch(/Safe in \^4\.0\.0/);
    // The pick itself was confirmed by the batch check: a proceed says so, never "NOT CHECKED" (audit 2026-11-14).
    expect(r.verdict).toBe("proceed");
    expect(r.reason).not.toContain("NOT CHECKED");
    expect(r.reason).toContain("OSV.dev's batch check lists no advisory for lodash 4.17.21. Its full advisory list for lodash (/v1/query) was incomplete");
    expect(r.reason).toContain("4.0.0");
  });

  it("missingFromList reads ids and aliases; an empty list misses every id the batch named", () => {
    const list = [advisoryRanges({ ...npmRecord("GHSA-a", "x", [{ introduced: "0" }]), aliases: ["CVE-2026-1"] }, "x", "npm")!];
    expect(missingFromList(list, ["GHSA-a", "cve-2026-1"])).toEqual([]);
    expect(missingFromList(list, ["GHSA-b"])).toEqual(["GHSA-b"]);
    expect(missingFromList([], ["GHSA-a", "GHSA-a"])).toEqual(["GHSA-a"]);
  });

  it("fix targets (vulnerability_scan, briefings, upgrade_planner): an incomplete list is read as unread, never as checked against every advisory", async () => {
    QUERY_EMPTY = true;
    const sources = new LiveIntelligence(new Database(":memory:")).getFixPathSources();
    const clean = await cleanFixTarget(sources, "npm", "lodash", ["4.17.21"], "4.17.20", ["GHSA-35jh-r3h4-6jhm"]);
    // Without the ids, the empty list would count as a complete one (OSV's normal answer for a clean package).
    const blind = await cleanFixTarget(sources, "npm", "lodash", ["4.17.21"], "4.17.20");
    expect(blind?.advisoriesUnread).toBeUndefined();
    expect(clean === null || clean.advisoriesUnread === true).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
// 2. The safe picks obey the release-age hold
// ---------------------------------------------------------------------------------------------

describe("defect 2: safe.smallest and safe.newest never name a release the hold keeps as wait", () => {
  beforeEach(() => {
    // ws 7.x, cut down: 7.4.6 is affected (GHSA-6fc8-4gx4-v693, fixed 7.4.6 -> use 7.5.10 as the fix here).
    NPM.ws = { "7.4.6": daysAgo(1500), "7.5.10": daysAgo(400), "7.5.13": daysAgo(60), "7.5.14": daysAgo(1.4) };
    OSV.push(npmRecord("GHSA-3h5v-q93c-6h6q", "ws", [{ introduced: "7.0.0" }, { fixed: "7.5.10" }]));
    PYPI.boto3 = { "1.43.9": daysAgo(20), "1.44.0": daysAgo(10), "1.44.1": daysAgo(2.5), "1.44.2": daysAgo(1.5), "1.44.3": daysAgo(0.5) };
  });

  it('{npm, ws, "7.x"}: newest is the newest settled safe release, and 7.5.14 (1.4 days) is listed as too new (it was newest)', async () => {
    const [r] = (await check([{ ecosystem: "npm", package: "ws", to: "7.x" }])).results;
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "7.5.10", newest_safe_in_range: "7.5.13", too_new: ["7.5.14"] });
    expect(r.to).toBe("7.5.13");
    expect(r.reason).toContain("7.5.14 is safe but published under 3 days ago, inside the release hold");
    const [alone] = (await check([{ ecosystem: "npm", package: "ws", to: "7.5.14" }])).results;
    expect(alone.verdict).toBe("wait");
  });

  it('{PyPI, boto3, "~=1.44.0"}: newest is 1.44.0, not 1.44.3 (0.5 days)', async () => {
    const [r] = (await check([{ ecosystem: "PyPI", package: "boto3", to: "~=1.44.0" }])).results;
    expect(r.range_check).toMatchObject({ smallest_safe_in_range: "1.44.0", newest_safe_in_range: "1.44.0", too_new: ["1.44.1", "1.44.2", "1.44.3"] });
    for (const v of ["1.44.1", "1.44.2", "1.44.3"]) {
      const [alone] = (await check([{ ecosystem: "PyPI", package: "boto3", to: v }])).results;
      expect(alone.verdict).toBe("wait");
    }
  });

  it("the concise answer lists the held-back releases beside the picks", async () => {
    const answer = (await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "ws", to: "7.x" }] } as never, new LiveIntelligence(new Database(":memory:")), { now: NOW })) as unknown as { results: Result[] };
    const { conciseItem } = await import("../tools/dependency-check-concise.js");
    expect(conciseItem(answer.results[0] as never).safe).toMatchObject({ newest: "7.5.13", too_new: ["7.5.14"] });
  });

  it("when only a young release is safe it stays named, and the note says it is inside the hold", async () => {
    NPM.ws["7.5.13"] = daysAgo(2);
    NPM.ws["7.5.10"] = daysAgo(2.2);
    const [r] = (await check([{ ecosystem: "npm", package: "ws", to: "7.x" }])).results;
    expect(r.range_check.newest_safe_in_range).toBe("7.5.14");
    expect(r.range_check.too_new).toEqual(["7.5.10", "7.5.13", "7.5.14"]);
    expect(r.reason).toContain("named because no settled safe release can take their place");
  });

  it("a security fix is not held back: above an affected `from` the smallest fix keeps its place", async () => {
    OSV.push(npmRecord("GHSA-young-fix", "ws", [{ introduced: "7.0.0" }, { fixed: "7.5.14" }]));
    const [r] = (await check([{ ecosystem: "npm", package: "ws", from: "7.4.6", to: "7.x" }])).results;
    expect(r.range_check).toMatchObject({ smallest_safe_upgrade: "7.5.14" });
    expect(r.range_check.too_new).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------------------------
// 3. Malware records without a MAL- id
// ---------------------------------------------------------------------------------------------

describe("defect 3: GHSA and PYSEC malware records count as malware", () => {
  it.each(["GHSA-4g82-3jcr-q52w", "GHSA-67r3-h899-9w95", "PYSEC-2022-199"])("the real %s (ctx, no MAL- id, no CWE-506) is malware", (id) => {
    expect(isMalwareRecord(real(id))).toBe(true);
  });

  it.each([
    ["GHSA-76p7-773f-r4q5", "XSS whose details say 'inject malicious code'"],
    ["GHSA-67hx-6x53-jw92", "Babel: 'compiling specifically crafted malicious code'"],
    ["GHSA-fvqr-27wr-82fm", "lodash prototype pollution"],
    ["GHSA-75jv-vfxf-3865", "Assemblyline, a malware analysis framework, path traversal"],
    ["GHSA-5rqg-jm4f-cqx7", "colors: an infinite loop (DoS)"],
  ])("the real %s is not malware (%s)", (id) => {
    expect(isMalwareRecord(real(id))).toBe(false);
  });

  it.each([
    "Malware in ctx",
    "Embedded malware in rc",
    "color-string@2.1.1 contains malware after npm account takeover",
    "eslint-config-prettier, synckit have embedded malicious code",
    "Malicious code in node-ipc (npm)",
    "xz ships a backdoor",
  ])("title %j is malware", (summary) => {
    expect(isMalware("GHSA-x", [], [], summary)).toBe(true);
  });

  it.each([
    "Malware scanner in clamav-wrapper allows command injection",
    "Path traversal in the malware analysis sandbox",
    "yara rules parser contains malware detection bypass",
    "Prototype pollution lets a malicious payload overwrite Object",
    "Malicious image with /dev symlink can trigger host filesystem violations",
    "BuildKit's Malicious frontend can cause file escape outside of storage root",
    "Requests vulnerable to .netrc credentials leak via malicious URLs",
  ])("title %j is not malware", (summary) => {
    expect(saysMalware(summary)).toBe(false);
  });

  it("the OpenSSF feed's database_specific flag counts", () => {
    expect(isMalwareRecord({ id: "GHSA-z", summary: "x", database_specific: { "malicious-packages-origins": [{ source: "ghsa-malware" }] } })).toBe(true);
    expect(isMalwareRecord({ id: "GHSA-z", summary: "x", affected: [{ database_specific: { "malicious-packages-origins": [{}] } }] })).toBe(true);
    expect(isMalwareRecord({ id: "GHSA-z", summary: "x", database_specific: { source: "y" } })).toBe(false);
  });

  describe("end to end", () => {
    beforeEach(() => {
      // PyPI removed ctx after the takeover: pypi.org/pypi/ctx/json answers 404 (read 2026-11-14), as the stub does.
      OSV.push(real("GHSA-4g82-3jcr-q52w"), real("GHSA-67r3-h899-9w95"), real("PYSEC-2022-199"));
    });

    it("dependency_check on ctx (a new dependency) is avoid and names the malware records", async () => {
      const [r] = (await check([{ ecosystem: "PyPI", package: "ctx", to: "latest" }])).results;
      expect(r.verdict).toBe("avoid");
      const value = r.signals.find((s: Result) => s.id === "advisories").value;
      expect(value.malicious_package?.ids).toEqual(expect.arrayContaining(["GHSA-4g82-3jcr-q52w"]));
    });

    it('"add the ctx package" is human_only, with ctx read as malware (it was review_needed, malicious: false)', async () => {
      const b = await executeWhatShouldIKnow(briefingDb(), { task: "add the ctx package" }, briefingIntel([dep("requests", "2.32.3", "PyPI")]));
      expect(b.new_packages?.map((p) => [p.name, p.verdict, p.malicious])).toEqual([["ctx", "avoid", true]]);
      expect(b.delegation_assessment.level).toBe("human_only");
    });
  });
});

// ---------------------------------------------------------------------------------------------
// 4. A large downgrade is said, and is not safe to delegate
// ---------------------------------------------------------------------------------------------

describe("defect 4: a large downgrade is review", () => {
  it("upgradeTypeSignal: many releases back, or across a breaking range, is review; a step back is info", () => {
    expect(upgradeTypeSignal({ ecosystem: "crates.io", package: "serde", from: "1.0.219", to: "1.0.0" }, 217)).toMatchObject({ effect: "review", value: "downgrade" });
    expect(upgradeTypeSignal({ ecosystem: "crates.io", package: "serde", from: "1.0.219", to: "1.0.0" }, 217).evidence).toContain("217 releases back");
    expect(upgradeTypeSignal({ ecosystem: "npm", package: "x", from: "3.1.0", to: "2.9.0" }, 4)).toMatchObject({ effect: "review" });
    expect(upgradeTypeSignal({ ecosystem: "npm", package: "x", from: "0.4.1", to: "0.3.9" }, 2)).toMatchObject({ effect: "review" });
    expect(upgradeTypeSignal({ ecosystem: "npm", package: "x", from: "1.2.3", to: "1.2.0" }, 3)).toMatchObject({ effect: "info" });
    expect(upgradeTypeSignal({ ecosystem: "npm", package: "x", from: "1.2.3", to: "1.2.0" })).toMatchObject({ effect: "info" });
  });

  it("a downgrade 40 releases back says so, is review in dependency_check, and keeps the briefing from safe_to_delegate", async () => {
    NPM.padkit = Object.fromEntries(Array.from({ length: 41 }, (_, i) => [`1.0.${i}`, daysAgo(900 - i * 10)]));
    const [r] = (await check([{ ecosystem: "npm", package: "padkit", from: "1.0.40", to: "1.0.0" }])).results;
    expect(r.verdict).toBe("review");
    expect(r.reason).toContain("1.0.40 -> 1.0.0: downgrade 40 releases back");
    const b = await executeWhatShouldIKnow(briefingDb(), { task: "downgrade padkit to 1.0.0" }, briefingIntel([dep("padkit", "1.0.40")]));
    expect(b.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(b.delegation_assessment.reason).toContain("padkit 1.0.0");
  });

  it("a step back of a few releases stays proceed", async () => {
    NPM.padkit = Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`1.0.${i}`, daysAgo(900 - i * 10)]));
    const [r] = (await check([{ ecosystem: "npm", package: "padkit", from: "1.0.4", to: "1.0.2" }])).results;
    expect(r.verdict).toBe("proceed");
  });
});

// ---------------------------------------------------------------------------------------------
// Briefing scaffolding
// ---------------------------------------------------------------------------------------------

function dep(name: string, version: string, ecosystem: ResolvedDependency["ecosystem"] = "npm"): ResolvedDependency {
  return { name, version, ecosystem, isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: ["d:/proj"] };
}

function briefingDb(): FourDADatabase {
  const instance = Object.create(FourDADatabase.prototype) as FourDADatabase;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (instance as any).db = new Database(":memory:");
  return instance;
}

function briefingIntel(deps: ResolvedDependency[]): BriefingLiveIntel {
  const live = new LiveIntelligence(new Database(":memory:"));
  const scan: VulnerabilityScanResult = {
    scannedAt: NOW.toISOString(),
    projectPath: "d:/proj",
    ecosystemsScanned: [deps[0].ecosystem],
    totalScanned: deps.length,
    totalVulnerable: 0,
    platformInactiveVulnerable: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    vulnerabilities: [],
    cleanCount: deps.length,
    scanDurationMs: 1,
    cached: false,
    offline: false,
  };
  return {
    isEnabled: () => true,
    getProjectRoot: () => "d:/proj",
    ensureVulnerabilities: async () => scan,
    getVulnerabilities: () => scan,
    getResolvedDeps: () => deps,
    getAuditDeps: () => [],
    getReleaseSources: () => live.getReleaseSources(),
    getFixPathSources: () => live.getFixPathSources(),
    queryAdvisories: (d) => live.queryAdvisories(d),
  };
}
