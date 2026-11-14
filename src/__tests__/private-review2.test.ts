// SPDX-License-Identifier: Apache-2.0
/**
 * Second review of #64. X1: every spelling of a private crate name (`acme_core`, `Acme-Core` for
 * the private `acme-core`) reached crates.io and OSV. X2: a Gemfile.lock gem from a private
 * `remote:` and a composer.lock package from a private repository were sent to OSV. Should-fix:
 * the guard reads byte and padded bodies, purls and trailing-dot hosts; a PyPI private parent gets
 * the planner's NOT CHECKED (private); an `.npmrc` default registry that is not public is said.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { fetchWithTimeout } from "../live/http-utils.js";
import { PrivateRequestRefused, registerPrivateNames, type PrivateNameSource } from "../live/private-guard.js";
import { readComposerLock, readGemfileLock, composerRepositories } from "../live/lockfile-parsers-rbphp.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradeImpact } from "../tools/upgrade-impact.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
let scratch: string;
let sent: string[];
let priorOffline: string | undefined;

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const write = (rel: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(scratch, rel)), { recursive: true });
  fs.writeFileSync(path.join(scratch, rel), content);
};
const mentions = (needle: string) => sent.filter((s) => s.toLowerCase().includes(needle));
const liveFor = (dir: string) => {
  const live = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return live;
};

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
});

afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

/** OSV answers: `vulnerable` (name@version) carries a high advisory fixed in `fixed`. */
let vulnerable: { ecosystem: string; name: string; version: string; fixed: string } | null = null;

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-r2-"));
  sent = [];
  vulnerable = null;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = typeof init?.body === "string" ? init.body : "";
      sent.push(`${url} ${body}`);
      const u = new URL(url);
      const advisory = vulnerable && {
        id: "GHSA-r2r2-r2r2-r2r2",
        modified: "2026-01-01T00:00:00Z",
        summary: "issue",
        database_specific: { severity: "HIGH" },
        affected: [{ package: { ecosystem: vulnerable.ecosystem, name: vulnerable.name }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: vulnerable.fixed }] }] }],
      };
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
        const { queries } = JSON.parse(body) as { queries: Array<{ package: { name: string } }> };
        return json({ results: queries.map((q) => ({ vulns: advisory && q.package.name === vulnerable!.name ? [{ id: advisory.id, modified: advisory.modified }] : [] })) });
      }
      if (u.hostname === "api.osv.dev" && u.pathname.startsWith("/v1/vulns/")) return json(advisory ?? {}, advisory ? 200 : 404);
      if (u.hostname === "api.osv.dev") {
        const q = JSON.parse(body || "{}") as { package?: { name?: string } };
        return json({ vulns: advisory && q.package?.name === vulnerable!.name ? [advisory] : [] });
      }
      return json({ error: "Not found" }, 404);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

function cargoProject() {
  write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nacme-core = { version = "0.1", registry = "acme" }\n');
  write(
    "Cargo.lock",
    ["version = 3", "", "[[package]]", 'name = "app"', 'version = "0.1.0"', 'dependencies = ["acme-core"]', "", "[[package]]", 'name = "acme-core"', 'version = "0.1.0"', 'source = "registry+https://dl.acme.dev/"', ""].join("\n"),
  );
  return liveFor(scratch);
}

describe("X1: every spelling of a private crate", () => {
  it("dependency_check on acme_core and Acme-Core sends nothing naming it", async () => {
    const live = cargoProject();
    const result = await executeDependencyCheck(
      noDb,
      { items: [{ ecosystem: "crates.io", package: "acme_core", to: "0.2.0" }, { ecosystem: "crates.io", package: "Acme-Core", to: "0.2.0" }] },
      live,
    );
    expect(result.results.map((r) => r.verdict)).toEqual(["unknown", "unknown"]);
    expect(mentions("acme")).toEqual([]);
  });

  it("upgrade_impact on acme_core is refused, and the guard refuses index.crates.io/ac/me/acme_core", async () => {
    const live = cargoProject();
    const impact = await executeUpgradeImpact(noDb, { package: "acme_core", ecosystem: "crates.io", to_version: "0.2.0" }, live);
    expect(String((impact as { error?: string }).error)).toContain("NOT CHECKED (private)");
    await expect(fetchWithTimeout("https://index.crates.io/ac/me/acme_core")).rejects.toBeInstanceOf(PrivateRequestRefused);
    await expect(fetchWithTimeout("https://crates.io/api/v1/crates/Acme-Core/versions")).rejects.toBeInstanceOf(PrivateRequestRefused);
    expect(mentions("acme")).toEqual([]);
  });
});

describe("X2: Ruby and PHP private sources", () => {
  it("a gem from a GEM section whose remote is not rubygems.org is never sent", async () => {
    write("Gemfile", 'source "https://rubygems.org"\ngem "rails"\nsource "https://gems.acme.dev/" do\n  gem "acme-auth"\nend\n');
    write(
      "Gemfile.lock",
      [
        "GEM",
        "  remote: https://gems.acme.dev/",
        "  specs:",
        "    acme-auth (1.2.0)",
        "",
        "GEM",
        "  remote: https://rubygems.org/",
        "  specs:",
        "    rack (2.0.1)",
        "",
        "PLATFORMS",
        "  ruby",
        "",
        "DEPENDENCIES",
        "  acme-auth!",
        "  rack",
        "",
      ].join("\n"),
    );
    const live = liveFor(scratch);
    const scan = await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(mentions("rack").length).toBeGreaterThan(0);
    expect(mentions("acme")).toEqual([]);
    expect(scan.privateExcluded?.dependencies.map((d) => d.name)).toEqual(["acme-auth"]);
    const check = await executeDependencyCheck(noDb, { items: [{ ecosystem: "RubyGems" as never, package: "acme-auth", to: "1.3.0" }] }, live).catch((e: Error) => e);
    // dependency_check does not take RubyGems: whatever it answers, nothing named acme leaves.
    expect(check).toBeDefined();
    expect(mentions("acme")).toEqual([]);
  });

  it("composer: a package from a private dist host or a declared vcs repository is never sent", async () => {
    write(
      "composer.json",
      JSON.stringify({ require: { "acme/billing": "^1.0", "acme/vcs-lib": "^2.0", "symfony/yaml": "^5.0" }, repositories: [{ type: "vcs", url: "https://github.com/acme/vcs-lib.git" }] }),
    );
    write(
      "composer.lock",
      JSON.stringify({
        packages: [
          { name: "acme/billing", version: "1.0.0", dist: { type: "zip", url: "https://satis.acme.dev/dist/acme-billing-1.0.0.zip" } },
          { name: "acme/vcs-lib", version: "2.0.0", source: { type: "git", url: "https://github.com/acme/vcs-lib.git" }, dist: { type: "zip", url: "https://api.github.com/repos/acme/vcs-lib/zipball/abc" } },
          { name: "symfony/yaml", version: "v5.0.0", dist: { type: "zip", url: "https://api.github.com/repos/symfony/yaml/zipball/def" } },
        ],
      }),
    );
    const live = liveFor(scratch);
    await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(mentions("symfony/yaml").length).toBeGreaterThan(0);
    expect(mentions("acme")).toEqual([]);
  });

  it("the readers: remotes, dist hosts and declared repositories", () => {
    const gems = readGemfileLock(["GEM", "  remote: https://rubygems.org/", "  specs:", "    rack (2.0.1)", "", "GEM", "  remote: https://user:token@gems.acme.dev/", "  specs:", "    acme-auth (1.2.0)", ""].join("\n"));
    expect(gems.privateIndex).toEqual([{ name: "acme-auth", version: "1.2.0", registry: "https://gems.acme.dev" }]);
    const repos = composerRepositories({ repositories: { packagist: { type: "composer", url: "https://repo.packagist.org" }, acme: { type: "composer", url: "https://packages.acme.dev" } } });
    const lock = readComposerLock(
      {
        packages: [
          { name: "acme/a", version: "1.0.0", dist: { type: "zip", url: "https://packages.acme.dev/dists/acme/a/1.0.0/x.zip" } },
          { name: "acme/local", version: "1.0.0", dist: { type: "path", url: "../local" } },
          { name: "monolog/monolog", version: "2.0.0", dist: { type: "zip", url: "https://api.github.com/repos/Seldaek/monolog/zipball/x" } },
        ],
      },
      repos,
    );
    expect(lock.privateIndex.map((p) => p.name)).toEqual(["acme/a", "acme/local"]);
  });
});

/**
 * Registered under a key, so held strongly. Registered weakly (as it was), the source was
 * collected before its tests ran when the GC came early: the CI failure on Node 24 (run
 * 43241199693), reproduced locally with `--expose-gc` and the gc() below. The server's live
 * layer is held the same way; any other layer by the context of the requests made for it.
 */
const guardedSource: PrivateNameSource = { privateReason: (eco, name) => (name.toLowerCase().includes("guarded-r2") ? `private (${eco})` : null) };

describe("the choke point reads every body form", () => {
  // Registered before each test (the suite forgets every source after each one, test-setup.ts),
  // and after a collection: a strongly held source survives it.
  beforeEach(() => {
    (globalThis as { gc?: () => void }).gc?.();
    registerPrivateNames(guardedSource, "test:private-review2");
  });

  it.each([
    ["bytes", new TextEncoder().encode(JSON.stringify({ package: { name: "guarded-r2", ecosystem: "npm" } }))],
    ["leading whitespace", `\n  ${JSON.stringify({ queries: [{ package: { name: "guarded-r2", ecosystem: "npm" } }] })}`],
    ["a purl", JSON.stringify({ package: { purl: "pkg:npm/%40acme/guarded-r2@1.0.0" } })],
    ["an unencoded scoped purl", JSON.stringify({ queries: [{ package: { purl: "pkg:npm/@acme/guarded-r2@1.0.0" } }] })],
  ])("refuses a body in %s", async (_, body) => {
    const spy = vi.fn(async () => new Response("{}"));
    vi.stubGlobal("fetch", spy);
    await expect(fetchWithTimeout("https://api.osv.dev/v1/query", { method: "POST", body: body as BodyInit })).rejects.toBeInstanceOf(PrivateRequestRefused);
    expect(spy).not.toHaveBeenCalled();
  });

  it("refuses a host spelled with a trailing dot", async () => {
    await expect(fetchWithTimeout("https://registry.npmjs.org./guarded-r2")).rejects.toBeInstanceOf(PrivateRequestRefused);
  });
});

describe("a PyPI private parent in upgrade_planner", () => {
  it("urllib3 under the private acme-client: NOT CHECKED (private) with privateParents", async () => {
    write("pyproject.toml", '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["acme-client"]\n');
    write(
      "uv.lock",
      [
        "version = 1",
        'requires-python = ">=3.9"',
        "",
        "[[package]]",
        'name = "acme-client"',
        'version = "1.0.0"',
        'source = { registry = "https://pypi.acme.dev/simple" }',
        'dependencies = [{ name = "urllib3" }]',
        "",
        "[[package]]",
        'name = "urllib3"',
        'version = "1.26.0"',
        'source = { registry = "https://pypi.org/simple" }',
        "",
      ].join("\n"),
    );
    vulnerable = { ecosystem: "PyPI", name: "urllib3", version: "1.26.0", fixed: "1.26.18" };
    const live = liveFor(scratch);
    const plan = (await executeUpgradePlanner(noDb, { include_dev: true }, live)) as { recommendations: Array<{ package: string; reasons: string[]; privateParents?: Array<{ parent: string }> }> };
    const step = plan.recommendations.find((r) => r.package === "urllib3");
    expect(step?.privateParents?.map((p) => p.parent)).toEqual(["acme-client"]);
    expect(step?.reasons[0]).toContain("NOT CHECKED (private): urllib3 arrives through acme-client");
    expect(mentions("acme")).toEqual([]);
  });
});

describe("an .npmrc default registry that is not public", () => {
  // Until 6.3.0 the host was read as a mirror and unscoped names were sent (review of #64, S5). R7
  // made the policy one for every ecosystem, as for a pip `--index-url`: any package may be
  // published only there, so the project's npm packages are private unless FOURDA_PUBLIC_MIRRORS
  // declares the host a mirror.
  const project = () => {
    write(".npmrc", "registry=https://artifactory.acme.dev/api/npm/npm/\n");
    write("package.json", JSON.stringify({ name: "app", dependencies: { "zqart-internal": "1.0.0" } }));
    write("package-lock.json", JSON.stringify({ name: "app", lockfileVersion: 3, packages: { "": { name: "app", dependencies: { "zqart-internal": "1.0.0" } }, "node_modules/zqart-internal": { version: "1.0.0" } } }));
  };

  it("makes the project's npm packages private, says why, and sends none of them", async () => {
    project();
    const live = liveFor(scratch);
    const check = await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "zqart-internal", to: "1.0.0" }] }, live);
    expect(String(check._meta?.registry_notice)).toContain("Your npm registry is artifactory.acme.dev");
    expect(String(check._meta?.registry_notice)).toContain("FOURDA_PUBLIC_MIRRORS=artifactory.acme.dev");
    const scan = (await executeVulnerabilityScan(noDb, {}, live)) as { registry_notice?: string };
    expect(scan.registry_notice).toContain("treated as private");
    expect(live.getPrivateDependencies().map((p) => p.name)).toEqual(["zqart-internal"]);
    expect(mentions("zqart")).toEqual([]);
  });

  it("FOURDA_PUBLIC_MIRRORS declares the host a mirror: the packages are checked again", async () => {
    project();
    process.env.FOURDA_PUBLIC_MIRRORS = "artifactory.acme.dev";
    try {
      const live = liveFor(scratch);
      expect(live.getPrivateDependencies()).toEqual([]);
      expect(live.getRegistryNotice()).toBeNull();
      await executeVulnerabilityScan(noDb, {}, live);
      expect(mentions("zqart").length).toBeGreaterThan(0);
    } finally {
      delete process.env.FOURDA_PUBLIC_MIRRORS;
    }
  });
});
