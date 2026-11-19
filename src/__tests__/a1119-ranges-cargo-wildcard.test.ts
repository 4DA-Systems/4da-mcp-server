// SPDX-License-Identifier: Apache-2.0
/**
 * A Cargo wildcard requirement is read as Cargo reads it: `1.0.*` is `>=1.0.0, <1.1.0`, `1.*` is
 * `>=1.0.0, <2.0.0`, `*` is any version (the Cargo book, "Wildcard requirements"; the `semver`
 * crate agrees, and takes `x` / `X` for `*`).
 *
 * `1.0.*` was read as the caret requirement `^1.0`, so `{crates.io, smallvec, "1.0.*"}` answered
 * "Safe in 1.0.*: smallest 1.6.1 ... Pin exactly 1.16.5", releases Cargo would never resolve that
 * requirement to.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { cargoReqAdmits } from "../live/range-satisfies.js";
import type { OsvVulnerability } from "../live/types.js";
import { rangeAdmits } from "../tools/dependency-check-versions.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";

const admitted = (req: string, versions: string[]) => versions.filter((v) => cargoReqAdmits(req, v) === true);
const ALL = ["0.9.9", "1.0.0", "1.0.7", "1.1.0", "1.6.1", "1.16.5", "2.0.0"];

describe("Cargo wildcard requirements", () => {
  it.each(["1.0.*", "1.0.x", "1.0.X", "=1.0.*", " 1.0.* "])('"%s" admits only the 1.0 line', (req) => {
    expect(admitted(req, ALL)).toEqual(["1.0.0", "1.0.7"]);
  });

  it.each(["1.*", "1.x", "1.X"])('"%s" admits the 1 major', (req) => {
    expect(admitted(req, ALL)).toEqual(["1.0.0", "1.0.7", "1.1.0", "1.6.1", "1.16.5"]);
  });

  it('"*" admits every release', () => {
    expect(admitted("*", ALL)).toEqual(ALL);
  });

  it("below 1.0 the wildcard and the caret reading coincide, as before", () => {
    const zero = ["0.5.9", "0.6.0", "0.6.14", "0.7.0", "1.0.0"];
    expect(admitted("0.6.*", zero)).toEqual(["0.6.0", "0.6.14"]);
    expect(admitted("0.6", zero)).toEqual(["0.6.0", "0.6.14"]);
    expect(admitted("0.*", zero)).toEqual(["0.5.9", "0.6.0", "0.6.14", "0.7.0"]);
  });

  it("a bare version is still the caret requirement Cargo.toml means by it", () => {
    expect(admitted("1.0", ALL)).toEqual(["1.0.0", "1.0.7", "1.1.0", "1.6.1", "1.16.5"]);
    expect(admitted("1.0.7", ALL)).toEqual(["1.0.7", "1.1.0", "1.6.1", "1.16.5"]);
    expect(admitted("1", ALL)).toEqual(["1.0.0", "1.0.7", "1.1.0", "1.6.1", "1.16.5"]);
  });

  it("a wildcard beside another comparator narrows it", () => {
    expect(admitted(">=1.0.5, 1.0.*", ALL)).toEqual(["1.0.7"]);
    expect(admitted("1.*, <1.6.1", ALL)).toEqual(["1.0.0", "1.0.7", "1.1.0"]);
  });

  it("a prerelease of the next line is outside the wildcard", () => {
    expect(cargoReqAdmits("1.0.*", "1.1.0-rc.1")).toBe(false);
  });

  it("dependency_check's reading of a crates.io constraint follows", () => {
    expect(rangeAdmits("crates.io", "1.0.*", "1.0.0")).toBe(true);
    expect(rangeAdmits("crates.io", "1.0.*", "1.6.1")).toBe(false);
    expect(rangeAdmits("crates.io", "1.0.x", "1.16.5")).toBe(false);
  });
});

describe('dependency_check {crates.io, smallvec, "1.0.*"}', () => {
  const noDb = null as unknown as FourDADatabase;
  // crates.io, cut down: RUSTSEC-2021-0003 affects 1.0.0 up to 1.6.1.
  const VERSIONS = ["0.6.14", "1.0.0", "1.6.0", "1.6.1", "1.16.5"];
  const RUSTSEC = {
    id: "RUSTSEC-2021-0003",
    summary: "Buffer overflow in SmallVec::insert_many",
    database_specific: { severity: "CRITICAL" },
    affected: [{ package: { name: "smallvec", ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.6.1" }] }] }],
  } as unknown as OsvVulnerability;
  let priorOffline: string | undefined;

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      const affected = (v: string) => ["1.0.0", "1.6.0"].includes(v);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
        return json({ results: queries.map((q) => (q.package.name === "smallvec" && affected(q.version) ? { vulns: [{ id: RUSTSEC.id, modified: "2026-11-01T00:00:00Z" }] } : {})) });
      }
      if (url.includes("/v1/vulns/")) return json(RUSTSEC);
      if (url === "https://api.osv.dev/v1/query") return json({ vulns: [RUSTSEC] });
      const crate = /^https:\/\/crates\.io\/api\/v1\/crates\/([^/?]+)(\/versions)?/.exec(url);
      if (crate) {
        if (decodeURIComponent(crate[1]) !== "smallvec") return json({ errors: [{ detail: "Not Found" }] }, 404);
        const list = VERSIONS.map((num) => ({ num, created_at: "2025-01-01T00:00:00Z", yanked: false }));
        return crate[2] ? json({ versions: list, meta: { next_page: null } }) : json({ crate: { name: "smallvec", created_at: "2015-01-01T00:00:00Z", num_versions: list.length }, versions: list });
      }
      if (url.startsWith("https://index.crates.io/")) {
        return url.endsWith("/smallvec") ? new Response(VERSIONS.map((vers) => JSON.stringify({ name: "smallvec", vers, deps: [], yanked: false })).join("\n")) : new Response("", { status: 404 });
      }
      return json({}, 404);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
  });

  it("judges the one release Cargo admits, and names nothing outside the 1.0 line as safe in it", async () => {
    const [r] = (await executeDependencyCheck(noDb, { items: [{ ecosystem: "crates.io", package: "smallvec", to: "1.0.*" }], response_format: "detailed" } as never, new LiveIntelligence(new Database(":memory:")))).results as Array<Record<string, any>>;
    expect(r).toMatchObject({ to: "1.0.0", verdict: "avoid" });
    expect(r.range_check).toMatchObject({ range: "1.0.*", releases_in_range: 1, smallest_safe_in_range: null, newest_safe_in_range: null, newest_safe_outside_range: "1.16.5" });
    expect(r.reason).not.toMatch(/Safe in 1\.0\.\*/);
    expect(r.reason).toMatch(/No release in 1\.0\.\* is free of known advisories/);
  });
});
