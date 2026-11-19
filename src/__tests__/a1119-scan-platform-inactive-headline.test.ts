// SPDX-License-Identifier: Apache-2.0
/**
 * Advisories on dependencies not built on this host stay out of the counts and the vulnerable
 * list, and the concise summary line says they exist: a crate under `cfg(unix)` scanned on Windows
 * (nix 0.20.0, GHSA-76w9-p8mg-j927) applies to the Linux build of the same service, so an answer
 * whose first line reads clean would be misread.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { OsvHttpSource, OsvScanner } from "../live/osv-scanner.js";
import { DEFAULT_RATE_LIMITS, RateLimiter } from "../live/rate-limiter.js";
import type { ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { conciseScanResult } from "../tools/vulnerability-scan-concise.js";
import { formatScanResult } from "../tools/vulnerability-scan-format.js";
import { pageScanResult } from "../tools/vulnerability-scan-page.js";

const CTX = { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true };

const crate = (name: string, version: string, extra: Partial<ResolvedDependency> = {}): ResolvedDependency => ({
  name, version, ecosystem: "crates.io", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: ["/svc"], ...extra,
});

const RECORDS: Record<string, Record<string, unknown>> = {
  "GHSA-76w9-p8mg-j927": {
    id: "GHSA-76w9-p8mg-j927",
    summary: "Out-of-bounds write in nix::unistd::getgrouplist",
    aliases: ["RUSTSEC-2021-0119"],
    database_specific: { severity: "CRITICAL" },
    affected: [{ package: { name: "nix", ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.20.2" }] }] }],
  },
  "RUSTSEC-2024-0413": {
    id: "RUSTSEC-2024-0413",
    summary: "gtk-rs GTK3 bindings - no longer maintained",
    affected: [{ package: { name: "atk", ecosystem: "crates.io" }, database_specific: { informational: "unmaintained" } }],
  },
  "GHSA-host-only-0001": { id: "GHSA-host-only-0001", summary: "A bug in hostdep", database_specific: { severity: "MODERATE" } },
};

function stubOsv(idsFor: (name: string) => string[]) {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      return new Response(JSON.stringify({ results: queries.map((q) => ({ vulns: idsFor(q.package.name).map((id) => ({ id })) })) }), { status: 200 });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
      return RECORDS[id] ? new Response(JSON.stringify(RECORDS[id]), { status: 200 }) : new Response("{}", { status: 404 });
    }
    throw new TypeError(`fetch failed (${url})`);
  });
}

function scanner(): OsvScanner {
  const cache = new LiveCache(new Database(":memory:"));
  const limiter = new RateLimiter(DEFAULT_RATE_LIMITS);
  return new OsvScanner(cache, limiter, new OsvHttpSource(cache, limiter));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("concise summary: advisories on dependencies not built on this host", () => {
  it("nix 0.20.0 under cfg(unix): out of the counts, and the summary line says it applies to another target", async () => {
    stubOsv((name) => (name === "nix" ? ["GHSA-76w9-p8mg-j927"] : []));
    const result = await scanner().scan([crate("nix", "0.20.0", { target: "cfg(unix)", platformActive: false }), crate("serde", "1.0.200")], "/svc");
    const full = formatScanResult(result, undefined, CTX);
    const out = conciseScanResult(full) as Record<string, any>;

    // The separation and the totals are kept.
    expect(out.total_vulnerable_packages).toBe(0);
    expect(out.vulnerable_packages).toEqual([]);
    expect(out.by_severity).toEqual({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
    expect(out.not_listed.platform_inactive).toEqual({ count: 1, packages: ["nix@0.20.0"] });

    // The first line says it, in plain words, with the host it was scanned on.
    expect(Object.keys(out)[0]).toBe("summary");
    expect(out.summary).toBe(
      `+1 advisory (the worst rated critical) on 1 dependency not built on this host (${full.host_platform}): nix@0.20.0. ` +
        "It is not counted in total_vulnerable_packages or by_severity; it applies when you build for another target or with other cargo features (see not_listed.platform_inactive).",
    );
  });

  it("advisories and maintenance notices are told apart, the worst graded advisory is named, unread ones are counted", async () => {
    const vuln = (over: Partial<VulnerabilityEntry>): VulnerabilityEntry => ({
      package: "pkg", currentVersion: "1.0.0", ecosystem: "crates.io", isDev: false, isDirect: false, devScopeKnown: true,
      vulnId: "GHSA-x", aliases: [], severity: "medium", cvssScore: null, summary: "A bug", fixedVersion: null,
      published: "2026-01-01T00:00:00Z", references: [], target: "not built for x86_64-pc-windows-msvc", platformActive: false, sourceDirs: ["/svc"], ...over,
    });
    const result: VulnerabilityScanResult = {
      scannedAt: "2026-11-19T00:00:00Z", projectPath: "/svc", ecosystemsScanned: ["crates.io"], totalScanned: 40, totalVulnerable: 5,
      platformInactiveVulnerable: 4, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, cleanCount: 35, scanDurationMs: 1, cached: false, offline: false,
      vulnerabilities: [
        vuln({ package: "nix", currentVersion: "0.20.0", vulnId: "GHSA-a", severity: "high" }),
        vuln({ package: "nix", currentVersion: "0.20.0", vulnId: "GHSA-b", severity: "low" }),
        vuln({ package: "glib", currentVersion: "0.18.5", vulnId: "GHSA-c", severity: "unknown", detailUnavailable: true }),
        vuln({ package: "atk", currentVersion: "0.18.0", vulnId: "RUSTSEC-2024-0413", severity: "unknown", maintenance: true, summary: "gtk-rs GTK3 bindings - no longer maintained" }),
        vuln({ package: "gdk", currentVersion: "0.18.0", vulnId: "RUSTSEC-2024-0412", severity: "unknown", maintenance: true, summary: "gtk-rs GTK3 bindings - no longer maintained" }),
        // Built on this host: a finding like any other.
        vuln({ package: "hostdep", currentVersion: "2.0.0", vulnId: "GHSA-host", severity: "medium", platformActive: true, target: null }),
      ],
    };
    const full = formatScanResult(result, undefined, CTX);
    expect(full.platform_inactive_counts).toEqual({ advisories: 3, maintenance_notices: 2, not_read: 1, worst_advisory_severity: "high" });
    const out = conciseScanResult(full) as Record<string, any>;
    expect(out.total_vulnerable_packages).toBe(1);
    expect(out.not_listed.platform_inactive.count).toBe(5);
    expect(out.summary).toBe(
      `+3 advisories (the worst rated high, 1 not read) and 2 maintenance notices on 4 dependencies not built on this host (${full.host_platform}): nix@0.20.0, glib@0.18.5, atk@0.18.0 and 1 more. ` +
        "They are not counted in total_vulnerable_packages or by_severity; they apply when you build for another target or with other cargo features (see not_listed.platform_inactive).",
    );
  });

  it("follows an incomplete scan's NOT CHECKED headline, never replaces it", async () => {
    stubOsv((name) => (name === "nix" ? ["GHSA-76w9-p8mg-j927"] : []));
    const result = await scanner().scan([crate("nix", "0.20.0", { target: "cfg(unix)", platformActive: false })], "/svc");
    const full = formatScanResult({ ...result, totalScanned: 2, unchecked: 1, uncheckedReason: "OSV.dev timed out", offline: true }, undefined, CTX);
    const out = conciseScanResult(full) as Record<string, any>;
    expect(out.summary).toMatch(/^NOT CHECKED/);
    expect(out.summary).toMatch(/\+1 advisory \(the worst rated critical\) on 1 dependency not built on this host/);
  });

  it("a scan with no such advisory says nothing about it", async () => {
    stubOsv((name) => (name === "hostdep" ? ["GHSA-host-only-0001"] : []));
    const result = await scanner().scan([crate("hostdep", "1.0.0")], "/svc");
    const full = formatScanResult(result, undefined, CTX);
    expect(full.platform_inactive_counts).toBeUndefined();
    const out = conciseScanResult(full) as Record<string, any>;
    expect(out.summary).toBeUndefined();
    expect(out.not_listed.platform_inactive.count).toBe(0);
  });

  it("the detailed answer carries the same whole-result counts on every page", async () => {
    stubOsv((name) => (name === "nix" ? ["GHSA-76w9-p8mg-j927"] : name === "atk" ? ["RUSTSEC-2024-0413"] : []));
    const result = await scanner().scan(
      [crate("nix", "0.20.0", { target: "cfg(unix)", platformActive: false }), crate("atk", "0.18.0", { platformActive: false, isDirect: false })],
      "/svc",
    );
    const full = formatScanResult(result, undefined, CTX);
    expect(full.platform_inactive_counts).toEqual({ advisories: 1, maintenance_notices: 1, worst_advisory_severity: "critical" });
    const page = pageScanResult(full, 1, 1) as Record<string, any>;
    expect(page.platform_inactive_counts).toEqual(full.platform_inactive_counts);
  });
});
