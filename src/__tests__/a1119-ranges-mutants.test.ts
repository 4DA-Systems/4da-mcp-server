// SPDX-License-Identifier: Apache-2.0
/**
 * Four rules that no test in the required suite held, each pinned here by the smallest case that
 * breaks when the rule is removed:
 *
 * - PEP 440: `X.rcN.devM` (a development release of a pre-release) sorts BELOW `X.rcN`, and
 *   likewise for post-releases. Sorted above, `2.0.0rc1.dev3` falls outside `[0, 2.0.0rc1)`.
 * - PyPI package names compare PEP 503-normalised: an advisory for `typing-extensions` is one for
 *   `typing_extensions` and `Typing.Extensions`, in every tool.
 * - A malware advisory is never "unfixed, so passed over": a package whose every release a malware
 *   record covers has no fix target; the advice is to remove or replace it.
 * - An advisory id with a control character inside is not an id. It is rejected, never repaired
 *   into one by dropping the character.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { cleanFixTarget, type FixPathSources, type PackageReleaseFacts } from "../live/fix-paths.js";
import { advisoryAffects, advisoryRanges, collectAffectedSpans, smallestCleanVersion, type AdvisoryRanges } from "../live/osv-ranges.js";
import type { OsvVulnerability } from "../live/types.js";
import { compareVersions, maxVersion, namesPackage, samePackageName } from "../live/version-compare.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { INVALID_ADVISORY_ID, isOsvAdvisoryId, osvAdvisoryId, thirdPartyId } from "../untrusted-text.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

describe("PEP 440: a development release sorts below the release it leads up to", () => {
  const lt = (a: string, b: string) => {
    expect(compareVersions(a, b, "PyPI"), `${a} < ${b}`).toBe(-1);
    expect(compareVersions(b, a, "PyPI"), `${b} > ${a}`).toBe(1);
  };

  it("of a pre-release, a post-release and a final release alike", () => {
    lt("2.0.0rc1.dev3", "2.0.0rc1");
    lt("2.0.0a1.dev1", "2.0.0a1");
    lt("1.0.post1.dev2", "1.0.post1");
    lt("1.0.dev5", "1.0");
  });

  it("and the whole chain keeps PEP 440's order", () => {
    const chain = ["1.0.dev1", "1.0a1.dev1", "1.0a1", "1.0a1.post1.dev2", "1.0a1.post1", "1.0b1", "1.0rc1.dev3", "1.0rc1", "1.0", "1.0.post1.dev1", "1.0.post1"];
    for (let i = 1; i < chain.length; i++) lt(chain[i - 1], chain[i]);
    expect(maxVersion([...chain].reverse(), "PyPI")).toBe("1.0.post1");
    expect([...chain].reverse().sort((a, b) => compareVersions(a, b, "PyPI"))).toEqual(chain);
  });

  it("so 2.0.0rc1.dev3 is inside an advisory that ends at 2.0.0rc1", () => {
    const record = { id: "PYSEC-0000-9", affected: [{ package: { name: "demo", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0.0rc1" }] }] }] } as unknown as OsvVulnerability;
    const a = advisoryRanges(record, "demo", "PyPI")!;
    expect(advisoryAffects(a, "2.0.0rc1.dev3", "PyPI")).toBe(true);
    expect(advisoryAffects(a, "2.0.0rc1", "PyPI")).toBe(false);
  });
});

/** An advisory as OSV.dev names the package: PEP 503-normalised. */
const TYPING: OsvVulnerability = {
  id: "PYSEC-0000-77",
  aliases: [],
  summary: "typing-extensions advisory",
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name: "typing-extensions", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.1.0" }] }] }],
} as unknown as OsvVulnerability;
const SPELLINGS = ["typing-extensions", "typing_extensions", "Typing.Extensions", "TYPING__EXTENSIONS", "typing-._extensions"];

describe("PyPI names compare PEP 503-normalised", () => {
  it.each(SPELLINGS)("an advisory for typing-extensions is one for %s", (name) => {
    expect(samePackageName("typing-extensions", name, "PyPI")).toBe(true);
    expect(samePackageName(name, "typing-extensions", "PyPI")).toBe(true);
    expect(namesPackage(name, "typing-extensions", "PyPI")).toBe(true);
    expect(collectAffectedSpans(TYPING.affected, name, "PyPI")).toEqual([{ introduced: "0", fixed: "4.1.0", lastAffected: null }]);
    const a = advisoryRanges(TYPING, name, "PyPI")!;
    expect(advisoryAffects(a, "4.0.0", "PyPI")).toBe(true);
    expect(advisoryAffects(a, "4.1.0", "PyPI")).toBe(false);
  });

  it("a different name stays different, and the folding is PyPI's alone", () => {
    expect(samePackageName("typing-extensions", "typingextensions", "PyPI")).toBe(false);
    expect(samePackageName("typing-extensions", "typing_extensions", "npm")).toBe(false);
    expect(samePackageName("typing-extensions", "typing.extensions", "crates.io")).toBe(false);
    expect(collectAffectedSpans(TYPING.affected, "typingextensions", "PyPI")).toEqual([]);
  });

  describe("in the tools, whatever spelling the caller or the requirements file uses", () => {
    const RELEASES = ["4.0.0", "4.0.1", "4.1.0", "4.2.0"];
    const fold = (n: string) => n.toLowerCase().replace(/[-_.]+/g, "-");
    let dir: string;
    let priorOffline: string | undefined;

    beforeEach(() => {
      priorOffline = process.env.FOURDA_OFFLINE;
      delete process.env.FOURDA_OFFLINE;
      dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-names-"));
      // OSV.dev and PyPI both answer for any spelling of the name, and name the package canonically.
      vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
        const url = String(input);
        const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
        const ours = (n: string) => fold(n) === "typing-extensions";
        if (url.endsWith("/v1/querybatch")) {
          const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
          return json({ results: queries.map((q) => (ours(q.package.name) && ["4.0.0", "4.0.1"].includes(q.version) ? { vulns: [{ id: TYPING.id, modified: "2026-11-01T00:00:00Z" }] } : {})) });
        }
        if (url.includes("/v1/vulns/")) return json(TYPING);
        if (url === "https://api.osv.dev/v1/query") {
          const q = JSON.parse(String(init?.body)) as { package: { name: string } };
          return json({ vulns: ours(q.package.name) ? [TYPING] : [] });
        }
        // One release's own document (its requires_dist): served for a release the project lists.
        const release = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/([^/]+)\/json$/.exec(url);
        if (release) {
          const version = decodeURIComponent(release[2]);
          return ours(decodeURIComponent(release[1])) && RELEASES.includes(version) ? json({ info: { version, requires_dist: null } }) : json({ message: "Not Found" }, 404);
        }
        const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
        if (pypi && ours(decodeURIComponent(pypi[1]))) {
          const releases = Object.fromEntries(RELEASES.map((v) => [v, [{ upload_time_iso_8601: "2025-06-01T00:00:00Z", yanked: false, requires_python: null }]]));
          return json({ info: { name: "typing_extensions", version: "4.2.0", license: "", classifiers: [], summary: "", yanked: false, yanked_reason: null }, releases });
        }
        return json({}, 404);
      });
    });

    afterEach(() => {
      vi.unstubAllGlobals();
      if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
      else process.env.FOURDA_OFFLINE = priorOffline;
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const check = async (item: Record<string, string>) =>
      ((await executeDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", ...item }], response_format: "detailed" } as never, new LiveIntelligence(new Database(":memory:")))).results as Array<Record<string, any>>)[0];

    it.each(["typing_extensions", "Typing.Extensions"])("dependency_check %s 4.0.0: avoided, and the safe release is read from the advisory's ranges", async (name) => {
      const r = await check({ package: name, to: "4.0.0" });
      expect(r.verdict).toBe("avoid");
      expect(r.signals.find((s: { id: string }) => s.id === "advisories").value.affecting_to).toEqual(["PYSEC-0000-77"]);
      expect(r.range_check).toMatchObject({ smallest_safe_in_range: null, newest_safe_outside_range: "4.2.0" });
    });

    it.each(["typing_extensions", "Typing.Extensions"])("dependency_check %s >=4.0: the smallest safe release is 4.1.0, never the affected 4.0.0", async (name) => {
      const r = await check({ package: name, to: ">=4.0" });
      expect(r).toMatchObject({ to: "4.2.0", verdict: "proceed" });
      expect(r.range_check).toMatchObject({ smallest_safe_in_range: "4.1.0", vulnerable_in_range: 2 });
    });

    it.each(["typing_extensions", "Typing.Extensions"])("vulnerability_scan of %s==4.0.0 names the fix its advisory gives", async (name) => {
      fs.writeFileSync(path.join(dir, "requirements.txt"), `${name}==4.0.0\n`);
      const li = new LiveIntelligence(new Database(":memory:"));
      const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
      const { entries, discovery } = scanProjectTree(dir);
      li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
      const scan = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "concise" }, li)) as Record<string, any>;
      expect(scan.vulnerable_packages).toHaveLength(1);
      expect(scan.vulnerable_packages[0]).toMatchObject({ current_version: "4.0.0", ids: ["PYSEC-0000-77"], fixed_version: "4.1.0", fix_checked: "all_advisories" });
    });
  });
});

describe("a malware advisory is never an unfixed one to pass over", () => {
  const span = (introduced: string, fixed: string | null) => ({ introduced, fixed, lastAffected: null });
  const MALWARE: AdvisoryRanges = { id: "MAL-2026-0001", versions: [], spans: [span("0", null)], malware: true };
  const FIXABLE: AdvisoryRanges = { id: "GHSA-fixd-fixd-fixd", versions: [], spans: [span("0", "1.2.0")] };
  const UNFIXED: AdvisoryRanges = { id: "GHSA-open-open-open", versions: [], spans: [span("0", null)] };
  const published = ["1.0.0", "1.1.0", "1.2.0"];

  it("every release is covered by a malware record: no target, and the malware is what stands in the way", () => {
    const clean = smallestCleanVersion({ ecosystem: "npm", fixes: ["1.2.0"], advisories: [MALWARE, FIXABLE], published, installed: "1.0.0" })!;
    expect(clean.target).toBeNull();
    expect(clean.maliciousLanding).toEqual(["MAL-2026-0001"]);
    expect(clean.unfixable).toEqual([]);
  });

  it("the same record without the malware mark is an unfixed advisory: the fix is named, and says what remains", () => {
    const clean = smallestCleanVersion({ ecosystem: "npm", fixes: ["1.2.0"], advisories: [UNFIXED, FIXABLE], published, installed: "1.0.0" })!;
    expect(clean).toMatchObject({ target: "1.2.0", stillAffectedBy: ["GHSA-open-open-open"], unfixable: ["GHSA-open-open-open"] });
  });

  it("cleanFixTarget says remove or replace, and names no release", async () => {
    const facts: PackageReleaseFacts = { versions: published, withdrawn: [], withdrawnWhy: {}, latest: "1.2.0", deprecatedLatest: null };
    const sources = { packageAdvisories: async () => [MALWARE, FIXABLE], releaseFacts: async () => facts } as unknown as FixPathSources;
    const clean = (await cleanFixTarget(sources, "npm", "evil-pkg", ["1.2.0"], "1.0.0"))!;
    expect(clean.target).toBeNull();
    expect(clean.malware).toEqual(["MAL-2026-0001"]);
    expect(clean.landingNote).toBe("evil-pkg is flagged malicious (MAL-2026-0001): remove or replace evil-pkg");
  });
});

describe("an advisory id with a control character inside is rejected, not repaired", () => {
  // Each is a valid id once the character is dropped, which is exactly what must not happen.
  const INSIDE = ["\u001b", "\u0000", "\u0007", "\u0008", "\u007f", "\u0085", "\u009b", "\t", "\n", "\r\n", " ", " ", " "];

  it.each(INSIDE.map((c) => [JSON.stringify(c), c]))("osvAdvisoryId: %s inside GHSA-yyyy-zzzz", (_shown, c) => {
    const id = osvAdvisoryId(`GHSA-yyyy${c}-zzzz`);
    expect(id).toBe(INVALID_ADVISORY_ID);
    expect(isOsvAdvisoryId(id)).toBe(false);
  });

  it.each(INSIDE.map((c) => [JSON.stringify(c), c]))("thirdPartyId: %s inside an alias", (_shown, c) => {
    expect(thirdPartyId(`CVE-2026${c}-12345`)).toBeNull();
  });

  it("the same ids without the character, and with whitespace only around them, are kept", () => {
    expect(osvAdvisoryId("GHSA-yyyy-zzzz")).toBe("GHSA-yyyy-zzzz");
    expect(osvAdvisoryId("  GHSA-yyyy-zzzz\r\n")).toBe("GHSA-yyyy-zzzz");
    expect(thirdPartyId(" CVE-2026-12345 ")).toBe("CVE-2026-12345");
  });
});
