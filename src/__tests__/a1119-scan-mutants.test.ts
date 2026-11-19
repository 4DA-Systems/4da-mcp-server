// SPDX-License-Identifier: Apache-2.0
/**
 * Behaviour that had no test holding it: an OSV.dev answer that is not an answer is never read
 * as clean, a batch's answers are attributed to that batch's dependencies only, the CVSS bands
 * include their lower edge, and a release the registry withdrew is never offered as safe.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { deriveSeverity, OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import { vetOfferedRelease } from "../live/offered-release.js";
import type { ResolvedDependency } from "../live/types.js";

const dep = (name: string, version = "1.0.0"): ResolvedDependency => ({
  name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [],
});

type Query = { package: { name: string }; page_token?: string };

/** OSV stub: `answer` builds the querybatch body from the queries; records answer HIGH. */
function stubOsv(answer: (queries: Query[], call: number) => unknown) {
  const stats = { batches: 0 };
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Query[] };
      return new Response(JSON.stringify(answer(queries, stats.batches++)), { status: 200 });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
      return new Response(JSON.stringify({ id, summary: `advisory ${id}`, database_specific: { severity: "HIGH" } }), { status: 200 });
    }
    throw new TypeError(`fetch failed (${url})`);
  });
  return stats;
}

function scanner(): OsvScanner {
  const cache = new LiveCache(new Database(":memory:"));
  const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("a querybatch result whose `vulns` is not a list is not an answer", () => {
  it.each([
    ["null", null],
    ["a string", "none"],
    ["an object", { id: "GHSA-aaaa-bbbb-cccc" }],
    ["a number", 0],
    ["false", false],
  ])("`vulns: %s`: both dependencies are unchecked, none clean", async (_label, vulns) => {
    stubOsv((queries) => ({ results: queries.map(() => ({ vulns })) }));
    const result = await scanner().scan([dep("lodash", "4.17.15"), dep("minimist", "1.2.0")], "/proj");
    expect(result.unchecked).toBe(2);
    expect(result.cleanCount).toBe(0);
    expect(result.offline).toBe(true);
    expect(result.uncheckedReason).toMatch(/malformed result/);
    expect(result.vulnerabilities).toEqual([]);
  });

  it("one malformed result among good ones voids the whole batch (which result is the bad one is not trusted)", async () => {
    stubOsv((queries) => ({ results: queries.map((_, i) => (i === 1 ? { vulns: null } : {})) }));
    const result = await scanner().scan([dep("a"), dep("b"), dep("c")], "/proj");
    expect(result.unchecked).toBe(3);
    expect(result.cleanCount).toBe(0);
  });

  it("the malformed answer is not cached: the next scan asks again and gets the real one", async () => {
    let good = false;
    stubOsv((queries) => ({ results: queries.map(() => (good ? {} : { vulns: null })) }));
    const s = scanner();
    const deps = [dep("lodash", "4.17.15"), dep("minimist", "1.2.0")];
    expect((await s.scan(deps, "/proj")).unchecked).toBe(2);
    good = true;
    const again = await s.scan(deps, "/proj");
    expect(again.unchecked).toBe(0);
    expect(again.cleanCount).toBe(2);
  });
});

describe("a querybatch answer with a different number of results than queries", () => {
  it("fewer results: every dependency of the batch is unchecked, after one retry", async () => {
    const stats = stubOsv((queries) => ({ results: queries.slice(0, 1).map(() => ({})) }));
    const result = await scanner().scan([dep("lodash", "4.17.15"), dep("minimist", "1.2.0")], "/proj");
    expect(result.unchecked).toBe(2);
    expect(result.cleanCount).toBe(0);
    expect(result.uncheckedReason).toMatch(/1 results for 2 queries/);
    // Not an answer, so it is asked for a second time before the batch is given up.
    expect(stats.batches).toBe(2);
  });

  it("more results: every dependency of the batch is unchecked", async () => {
    stubOsv((queries) => ({ results: [...queries.map(() => ({})), {}] }));
    const result = await scanner().scan([dep("lodash", "4.17.15"), dep("minimist", "1.2.0")], "/proj");
    expect(result.unchecked).toBe(2);
    expect(result.cleanCount).toBe(0);
  });

  it("a short answer for one batch never moves the next batch's findings onto other dependencies", async () => {
    // 1,001 dependencies are two requests. The first is answered one result short; the second
    // names an advisory for its only dependency.
    stubOsv((queries) =>
      queries.length === 1
        ? { results: [{ vulns: [{ id: "GHSA-last-0000-0001" }] }] }
        : { results: queries.slice(1).map(() => ({})) },
    );
    const deps = Array.from({ length: 1_001 }, (_, i) => dep(`pkg-${i}`));
    const result = await scanner().scan(deps, "/proj");
    expect(result.vulnerabilities.map((v) => `${v.package}:${v.vulnId}`)).toEqual(["pkg-1000:GHSA-last-0000-0001"]);
    expect(result.unchecked).toBe(1_000);
    expect(result.uncheckedDependencies).not.toContain("npm\0pkg-1000\u00001.0.0");
    expect(result.cleanCount).toBe(0);
  });

  it("a later page that answers fewer queries than were still open leaves those dependencies unchecked", async () => {
    // Page 1: both dependencies have more to come. Page 2 answers one of the two.
    stubOsv((queries) =>
      queries.some((q) => q.page_token)
        ? { results: [{ vulns: [{ id: "GHSA-page-0000-0002" }] }] }
        : { results: queries.map((_, i) => ({ vulns: [{ id: `GHSA-page-0000-000${i}` }], next_page_token: `t${i}` })) },
    );
    const result = await scanner().scan([dep("a"), dep("b")], "/proj");
    expect(result.unchecked).toBe(2);
    expect(result.cleanCount).toBe(0);
    expect(result.vulnerabilities).toEqual([]);
  });
});

describe("CVSS bands include their lower edge", () => {
  const grade = (score: string) => deriveSeverity({ severity: [{ type: "CVSS_V3", score }] }).severity;

  it.each([
    ["10.0", "critical"],
    ["9.0", "critical"],
    ["8.9", "high"],
    ["7.0", "high"],
    ["6.9", "medium"],
    ["4.0", "medium"],
    ["3.9", "low"],
    ["0.1", "low"],
    ["0.0", "unknown"],
  ])("an unlabelled advisory at CVSS %s is %s", (score, expected) => {
    expect(grade(score)).toBe(expected);
  });

  it("a vector that scores exactly 9.0 is critical", () => {
    // AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H is 9.0 in CVSS 3.1.
    const graded = deriveSeverity({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" }] });
    expect(graded.cvssScore).toBe(9.0);
    expect(graded.severity).toBe("critical");
  });
});

describe("a release the registry withdrew is never offered as safe", () => {
  const sources = (withdrawn: string[], versions: string[]) =>
    ({
      // The one advisory is fixed in 4.17.21: it affects neither 4.18.0 nor 4.18.1.
      packageAdvisories: async () => [{ id: "GHSA-jf85-cpcp-j695", spans: [{ introduced: "0", fixed: "4.17.21", lastAffected: null }], versions: [] }],
      releaseFacts: async () => ({
        versions,
        withdrawn,
        withdrawnWhy: Object.fromEntries(withdrawn.map((v) => [v, `${v} is deprecated on npm`])),
        latest: versions[versions.length - 1] ?? null,
        deprecatedLatest: null,
      }),
    }) as unknown as Parameters<typeof vetOfferedRelease>[0];

  it("withdrawn and unaffected: the offer moves to the newest release that is neither", async () => {
    const vet = await vetOfferedRelease(sources(["4.18.0"], ["4.17.20", "4.17.21", "4.18.1"]), "npm", "lodash", "4.17.20", "4.18.0");
    expect(vet.affectedBy).toEqual([]);
    expect(vet.withdrawn).toBe("4.18.0 is deprecated on npm");
    expect(vet.safe).toBe("4.18.1");
    expect(vet.safe).not.toBe(vet.offered);
    expect(vet.note).toMatch(/4\.18\.0 is deprecated on npm, so it is not offered: 4\.18\.1/);
  });

  it("withdrawn with nothing else above the installed release: no release is offered", async () => {
    const vet = await vetOfferedRelease(sources(["4.18.0"], ["4.17.21"]), "npm", "lodash", "4.17.21", "4.18.0");
    expect(vet.withdrawn).not.toBeNull();
    expect(vet.safe).toBeNull();
    expect(vet.note).toMatch(/stay on 4\.17\.21/);
  });

  it("the same release, not withdrawn, stands as offered", async () => {
    const vet = await vetOfferedRelease(sources([], ["4.17.20", "4.17.21", "4.18.0", "4.18.1"]), "npm", "lodash", "4.17.20", "4.18.0");
    expect(vet.withdrawn).toBeNull();
    expect(vet.safe).toBe("4.18.0");
    expect(vet.note).toBeNull();
  });
});
