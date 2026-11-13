// SPDX-License-Identifier: Apache-2.0
/**
 * The blind pre-publish audit of main 96c16d2 (2026-11-12) and its black-box re-run (2026-11-13):
 * B1 Go module paths the go command would not accept; S7 a go.mod `replace` the plan ignored; an
 * npm alias in `to`; a deprecated "bad release" named as dependency_check's safe release; a
 * malicious name listing one of its two records; "newest safe" for a release unfixed advisories
 * still affect. dependency_check's ecosystem cases are in dependency-check-ecosystems.test.ts and
 * the name check in dependency-check-nearmiss.test.ts; the CPU budget in pypi-range-perf.test.ts.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { checkGoModulePath, goPathShapeProblem } from "../live/go-path.js";
import { cleanFixTarget, goReplaceFix, type FixPathSources } from "../live/fix-paths.js";
import { advisoryRanges } from "../live/osv-ranges.js";
import { excludedReleases } from "../live/withdrawn-releases.js";
import type { PackageReleaseIndex, ReleaseRecord } from "../live/release-metadata.js";
import type { OsvVulnerability } from "../live/types.js";
import { maliciousName } from "../tools/dependency-check-malicious.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { analyzeUpgradeImpact } from "../tools/upgrade-impact.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

describe("B1: a Go module path the go command would not accept", () => {
  it("shape: `..`, `//`, a trailing `/`, `@`, whitespace; the canonical path guessed", () => {
    expect(goPathShapeProblem("github.com/gin-gonic/gin")).toBeNull();
    expect(goPathShapeProblem("github.com/gin-gonic/gin/")).toMatchObject({ canonical: "github.com/gin-gonic/gin" });
    expect(goPathShapeProblem("github.com//gin-gonic/gin")).toMatchObject({ canonical: "github.com/gin-gonic/gin" });
    expect(goPathShapeProblem("github.com/x/y/../../gin-gonic/gin")).toMatchObject({ canonical: "github.com/gin-gonic/gin" });
    expect(goPathShapeProblem("github.com/gin-gonic/gin@v1.6.0")).toMatchObject({ canonical: "github.com/gin-gonic/gin" });
    expect(goPathShapeProblem("github.com/gin-gonic/ gin")).not.toBeNull();
  });

  it("case: the module's own go.mod decides (Labstack/Echo declares labstack/echo)", async () => {
    const seen: string[] = [];
    const fetchFn = (async (url: string) => {
      seen.push(url);
      if (url.endsWith("/@v/v4.1.0.mod")) return new Response("module github.com/labstack/echo/v4\n\ngo 1.12\n");
      return new Response("not found", { status: 404 });
    }) as never;
    const v = await checkGoModulePath("github.com/Labstack/Echo/v4", "v4.1.0", fetchFn);
    expect(v).toMatchObject({ ok: false, canonical: "github.com/labstack/echo/v4" });
    // The proxy's case encoding, as `go` itself asks.
    expect(seen[0]).toBe("https://proxy.golang.org/github.com/!labstack/!echo/v4/@v/v4.1.0.mod");
    // A path the module declares as written passes.
    const ok = await checkGoModulePath("github.com/Azure/azure-sdk-for-go", "v68.0.0", (async () => new Response("module github.com/Azure/azure-sdk-for-go\n")) as never);
    expect(ok).toEqual({ ok: true });
  });

  it("upgrade_impact refuses a mangled path with the canonical one, before any registry lookup", async () => {
    vi.stubGlobal("fetch", async (url: string) => (String(url).endsWith(".mod") ? new Response("module github.com/gin-gonic/gin\n") : json({ Version: "v1.9.1" })));
    const out = await analyzeUpgradeImpact({ package: "github.com/GIN-gonic/gin", ecosystem: "Go", from_version: "v1.6.0" } as never, {
      net: {} as never,
      projectRoot: null,
      installed: [],
      offline: false,
    });
    expect(out).toMatchObject({ not_checked: "module_path", canonical_module_path: "github.com/gin-gonic/gin" });
    expect(String(out.error)).toMatch(/^NOT CHECKED: `github\.com\/GIN-gonic\/gin` is not a Go module path/);
  });
});

describe("S7: a go.mod `replace` decides what is built", () => {
  const GOMOD = "module example.com/s7\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\n\nreplace github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.6.3\n";

  it("the words: move the replace (or drop it, then go get); a fork or a local directory is blocked", () => {
    expect(goReplaceFix(GOMOD, "github.com/gin-gonic/gin", "1.9.1")).toEqual({
      instruction:
        "go.mod replaces github.com/gin-gonic/gin with github.com/gin-gonic/gin v1.6.3, so `go get` would leave v1.6.3 built: point the replace at the fix with `go mod edit -replace=github.com/gin-gonic/gin=github.com/gin-gonic/gin@v1.9.1`, then `go mod tidy` (or drop it with `go mod edit -dropreplace=github.com/gin-gonic/gin`, then `go get github.com/gin-gonic/gin@v1.9.1`)",
    });
    const fork = goReplaceFix(GOMOD.replace("=> github.com/gin-gonic/gin v1.6.3", "=> github.com/me/gin v1.6.3"), "github.com/me/gin", "1.9.1");
    expect(fork && "instruction" in fork && fork.instruction).toMatch(/^Blocked: go\.mod replaces github\.com\/gin-gonic\/gin with github\.com\/me\/gin v1\.6\.3/);
    const local = goReplaceFix(GOMOD.replace("=> github.com/gin-gonic/gin v1.6.3", "=> ../gin"), "github.com/gin-gonic/gin", "1.9.1");
    expect(local && "instruction" in local && local.instruction).toMatch(/^Blocked: go\.mod replaces github\.com\/gin-gonic\/gin with a local directory/);
    expect(goReplaceFix("module m\n\nrequire github.com/gin-gonic/gin v1.6.0\n", "github.com/gin-gonic/gin", "1.9.1")).toBeNull();
  });

  it("upgrade_planner gives the replace edit, never a bare `go get` that leaves v1.6.3 built", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-s7-"));
    try {
      fs.writeFileSync(path.join(dir, "go.mod"), GOMOD);
      fs.writeFileSync(path.join(dir, "go.sum"), "github.com/gin-gonic/gin v1.6.3 h1:a=\ngithub.com/gin-gonic/gin v1.6.3/go.mod h1:b=\n");
      const GIN: OsvVulnerability = { id: "GO-2021-0052", aliases: [], summary: "gin", affected: [{ package: { name: "github.com/gin-gonic/gin", ecosystem: "Go" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.9.1" }] }] }] };
      vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/v1/querybatch")) {
          const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ version: string }> };
          return json({ results: queries.map((q) => ({ vulns: q.version.replace(/^v/, "") < "1.9.1" ? [{ id: GIN.id }] : [] })) });
        }
        if (url.includes("/v1/vulns/")) return json(GIN);
        if (url === "https://api.osv.dev/v1/query") return json({ vulns: [GIN] });
        if (url.endsWith("/@v/list")) return new Response("v1.6.0\nv1.6.3\nv1.9.1\n");
        if (url.endsWith("/@latest")) return json({ Version: "v1.9.1", Time: "2023-06-01T00:00:00Z" });
        if (/\/@v\/v[^/]+\.info$/.test(url)) return json({ Version: "v1.9.1", Time: "2023-06-01T00:00:00Z" });
        return json({}, 404);
      });
      const li = new LiveIntelligence(new Database(":memory:"));
      const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
      const { entries, discovery } = scanProjectTree(dir);
      li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
      const plan = (await executeUpgradePlanner(noDb, { project_path: dir }, li)) as Record<string, any>;
      const gin = plan.recommendations.find((r: { package: string }) => r.package === "github.com/gin-gonic/gin");
      expect(gin).toMatchObject({ currentVersion: "v1.6.3", targetVersion: "v1.9.1" });
      expect(gin.upgradeCommands).toBeUndefined();
      expect(gin.upgradeInstructions[0].instruction).toMatch(/go mod edit -replace=github\.com\/gin-gonic\/gin=github\.com\/gin-gonic\/gin@v1\.9\.1/);
      expect(gin.reasons.join(" ")).toMatch(/go\.mod replaces github\.com\/gin-gonic\/gin/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("nits and the black-box re-run", () => {
  it("an npm alias in `to` is judged as the package it installs", async () => {
    process.env.FOURDA_OFFLINE = "true";
    const out = await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "my-lodash", to: "npm:lodash@4.17.20" }] }, new LiveIntelligence(new Database(":memory:")));
    expect(out.results[0]).toMatchObject({ package: "lodash", to: "4.17.20" });
    await expect(executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "x", to: "npm:" }] }, null)).rejects.toThrow(/npm alias that could not be read/);
  });

  it("a release its maintainer deprecated by itself is never dependency_check's safe release (lodash.template 4.18.0)", () => {
    const RETIRED = "This package is deprecated. Use https://socket.dev/npm/package/eta instead.";
    const rec = (version: string, deprecated: string): ReleaseRecord => ({ version, publishedAt: null, trust: 0, trustEvidence: "", installScripts: null, deprecated, withdrawn: null } as unknown as ReleaseRecord);
    const index: PackageReleaseIndex = {
      ecosystem: "npm",
      name: "lodash.template",
      createdAt: null,
      latest: "4.18.1",
      releases: {
        "4.4.0": rec("4.4.0", RETIRED),
        "4.5.0": rec("4.5.0", RETIRED),
        "4.18.0": rec("4.18.0", "Bad release. Please use lodash.template@4.5.0 instead."),
        "4.18.1": rec("4.18.1", RETIRED),
      },
    };
    const out = excludedReleases(index);
    expect([...out.keys()]).toEqual(["4.18.0"]);
  });

  it("a malicious name lists every record that covers it (GO-2025-3451 beside MAL-2025-2545)", () => {
    const record = (id: string, events: Array<Record<string, string>>): OsvVulnerability => ({ id, summary: id, affected: [{ package: { name: "github.com/boltdb-go/bolt", ecosystem: "Go" }, ranges: [{ type: "SEMVER", events }] }] });
    const advisories = [record("MAL-2025-2545", [{ introduced: "0" }]), record("GO-2025-3451", [{ introduced: "0" }]), record("GO-2020-0001", [{ introduced: "0" }, { fixed: "1.0.0" }])].map(
      (v) => advisoryRanges(v, "github.com/boltdb-go/bolt", "Go")!,
    );
    const found = maliciousName({ ecosystem: "Go", package: "github.com/boltdb-go/bolt", to: "v1.3.1", index: null, notFound: false, advisories });
    expect(found?.ids).toEqual(["GO-2025-3451", "MAL-2025-2545"]);
  });

  it("no 'newest safe release' (and no dead-line words) when advisories with no fix still affect it", async () => {
    const adv = (id: string, events: Array<Record<string, string>>): OsvVulnerability => ({ id, affected: [{ package: { name: "github.com/docker/docker", ecosystem: "Go" }, ranges: [{ type: "SEMVER", events }] }] });
    const advisories = [adv("GO-2024-0001", [{ introduced: "0" }, { fixed: "25.0.0+incompatible" }]), adv("GO-2026-0002", [{ introduced: "0" }])].map((v) => advisoryRanges(v, "github.com/docker/docker", "Go")!);
    const versions = ["20.10.0+incompatible", "25.0.0+incompatible", "28.5.2+incompatible"];
    const sources = {
      packageAdvisories: async () => advisories,
      releaseFacts: async () => ({ versions, withdrawn: [], withdrawnWhy: {}, latest: versions[2], deprecatedLatest: null }),
    } as unknown as FixPathSources;
    const clean = await cleanFixTarget(sources, "Go", "github.com/docker/docker", ["25.0.0+incompatible"], "20.10.0+incompatible");
    expect(clean?.target).toBe("25.0.0+incompatible");
    expect(clean?.newestSafe).toBeUndefined();
    expect(clean?.lineDead).toBeUndefined();
  });
});
