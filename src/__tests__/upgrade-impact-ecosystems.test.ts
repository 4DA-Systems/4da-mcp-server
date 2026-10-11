// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_impact for PyPI and Go, and the opt-in GitHub release-notes
 * fallback (FOURDA_GITHUB_CHANGELOG). Offline: every response is a recorded
 * one (src/__tests__/fixtures/upgrade-impact/, captured 2026-10-11 from
 * pypi.org, files.pythonhosted.org, proxy.golang.org and api.github.com),
 * served by a fake fetch that fails on any URL it does not know.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { deflateRawSync, gzipSync } from "node:zlib";
import { analyzeUpgradeImpact, type InstalledDep, type UpgradeImpactParams } from "../tools/upgrade-impact.js";
import { createUpgradeNet, type UpgradeCache } from "../live/upgrade-sources.js";
import { CHANGELOG_PARSER_VERSION, isChangelogName, parseChangelog } from "../live/changelog.js";
import { githubCacheKey, githubChangelogEnabled, rawChangelogUrl, releasesToSections, versionFromTag } from "../live/github-releases.js";
import { readZipRootTextFiles } from "../live/zip-archive.js";
import { goMajorPath, goTagPrefix } from "../live/upgrade-go.js";
import { goImportInModule, goPackageName, pythonImportNames, scanGoSource, scanPythonSource } from "../tools/upgrade-impact-imports.js";
import type { FetchFn } from "../live/package-archive.js";

const FIX = path.join(__dirname, "fixtures", "upgrade-impact");
const fixture = (name: string) => fs.readFileSync(path.join(FIX, name), "utf8");

// ---------------------------------------------------------------- archive builders

function tarEntry(name: string, body: string): Buffer {
  const data = Buffer.from(body, "utf8");
  const h = Buffer.alloc(512);
  h.write(name, 0, "utf8");
  h.write(data.length.toString(8).padStart(11, "0") + "\0", 124, "ascii");
  h.write("0", 156, "ascii");
  h.write("ustar\0", 257, "ascii");
  h.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([h, padded]);
}
const tgz = (files: Record<string, string>): Buffer =>
  gzipSync(Buffer.concat([...Object.entries(files).map(([n, b]) => tarEntry(n, b)), Buffer.alloc(1024)]));

/** A zip with one deflated entry per file (CRCs left 0: the reader does not check them). */
function zip(files: Record<string, string>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [name, body] of Object.entries(files)) {
    const raw = Buffer.from(body, "utf8");
    const data = deflateRawSync(raw);
    const nameBuf = Buffer.from(name, "utf8");
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(8, 8);
    lfh.writeUInt32LE(data.length, 18);
    lfh.writeUInt32LE(raw.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(20, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(8, 10);
    cdh.writeUInt32LE(data.length, 20);
    cdh.writeUInt32LE(raw.length, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt32LE(offset, 42);
    locals.push(lfh, nameBuf, data);
    centrals.push(cdh, nameBuf);
    offset += 30 + nameBuf.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(Object.keys(files).length, 8);
  eocd.writeUInt16LE(Object.keys(files).length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

// ---------------------------------------------------------------- fake network

interface Recorded {
  calls: string[];
  headers: Array<Record<string, string>>;
  fetch: FetchFn;
}

function recorded(routes: Record<string, () => Response>): Recorded {
  const calls: string[] = [];
  const headers: Array<Record<string, string>> = [];
  const fetch: FetchFn = async (url, init) => {
    calls.push(url);
    headers.push({ ...((init?.headers as Record<string, string>) ?? {}) });
    if (url === "https://api.osv.dev/v1/query") return Response.json({ vulns: [] });
    const route = routes[url];
    if (!route) throw new Error(`unrecorded URL ${url}`);
    return route();
  };
  return { calls, headers, fetch };
}

const flaskJson = () => JSON.parse(fixture("pypi-flask.json")) as { releases: Record<string, Array<{ url: string }>> };

function flaskRoutes(): Record<string, () => Response> {
  const doc = flaskJson();
  const sdist = doc.releases["3.0.0"].find((f) => f.url.endsWith(".tar.gz"))!.url;
  return {
    "https://pypi.org/pypi/flask/json": () => Response.json(doc),
    [sdist]: () => new Response(tgz({ "flask-3.0.0/CHANGES.rst": fixture("flask-3.0.0-CHANGES.rst"), "flask-3.0.0/PKG-INFO": "" })),
  };
}

const proxy = "https://proxy.golang.org";

function pgxRoutes(): Record<string, () => Response> {
  return {
    [`${proxy}/github.com/jackc/pgx/v5/@v/list`]: () => new Response(fixture("go-pgx-v5-list.txt")),
    [`${proxy}/github.com/jackc/pgx/v4/@v/list`]: () => new Response(fixture("go-pgx-v4-list.txt")),
    [`${proxy}/github.com/jackc/pgx/v5/@v/v5.0.0.info`]: () => new Response(fixture("go-pgx-v5.0.0.info")),
    [`${proxy}/github.com/jackc/pgx/v5/@v/v5.0.0.zip`]: () =>
      new Response(zip({ "github.com/jackc/pgx/v5@v5.0.0/CHANGELOG.md": fixture("pgx-v5.0.0-CHANGELOG.md"), "github.com/jackc/pgx/v5@v5.0.0/conn.go": "package pgx" })),
  };
}

function cobraRoutes(github: "ok" | "limited" | "absent"): Record<string, () => Response> {
  const routes: Record<string, () => Response> = {
    [`${proxy}/github.com/spf13/cobra/@v/list`]: () => new Response(fixture("go-cobra-list.txt")),
    [`${proxy}/github.com/spf13/cobra/@v/v1.10.2.zip`]: () =>
      new Response(zip({ "github.com/spf13/cobra@v1.10.2/README.md": "# cobra", "github.com/spf13/cobra@v1.10.2/command.go": "package cobra" })),
  };
  for (const v of ["v1.8.1", "v1.9.0", "v1.9.1", "v1.10.0", "v1.10.1", "v1.10.2"]) {
    routes[`${proxy}/github.com/spf13/cobra/@v/${v}.info`] = () =>
      v === "v1.10.2" ? new Response(fixture("go-cobra-v1.10.2.info")) : Response.json({ Version: v, Time: "2025-01-01T00:00:00Z" });
  }
  const api = "https://api.github.com/repos/spf13/cobra/releases?per_page=100&page=1";
  if (github === "ok") routes[api] = () => new Response(fixture("github-cobra-releases.json"));
  if (github === "limited") {
    routes[api] = () =>
      new Response(JSON.stringify({ message: "API rate limit exceeded" }), {
        status: 403,
        headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1791721054" },
      });
  }
  return routes;
}

class MemCache implements UpgradeCache {
  store = new Map<string, unknown>();
  get<T>(key: string): T | null {
    return (this.store.get(key) as T) ?? null;
  }
  set(key: string, data: unknown): void {
    this.store.set(key, JSON.parse(JSON.stringify(data)));
  }
}

let root: string;

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "upgrade-impact-eco-"));
  fs.mkdirSync(path.join(root, "app"), { recursive: true });
  fs.writeFileSync(
    path.join(root, "app", "web.py"),
    ["from flask import Flask, abort", "import flask.json as fj", "import yaml", "app = Flask(__name__)", "fj.dumps({})", "yaml.safe_load('')"].join("\n"),
  );
  fs.writeFileSync(path.join(root, "app", "unrelated.py"), "import flaskext\nfrom flask_cors import CORS\n");
  fs.writeFileSync(
    path.join(root, "main.go"),
    [
      "package main",
      "",
      "import (",
      '\t"context"',
      '\t"github.com/jackc/pgx/v4"',
      '\tpgxpool "github.com/jackc/pgx/v4/pgxpool"',
      '\t"github.com/spf13/cobra"',
      ")",
      "",
      "func main() { c, _ := pgx.Connect(context.Background(), \"\"); _ = c; _, _ = pgxpool.Connect(nil, \"\"); _ = cobra.Command{} }",
    ].join("\n"),
  );
  fs.writeFileSync(path.join(root, "other.go"), 'package main\nimport "github.com/jackc/pgx/v5"\nvar _ = pgx.Identifier{}\n');
  const sp = path.join(root, ".venv", "lib", "python3.12", "site-packages");
  fs.mkdirSync(path.join(sp, "PyYAML-6.0.1.dist-info"), { recursive: true });
  fs.writeFileSync(path.join(sp, "PyYAML-6.0.1.dist-info", "top_level.txt"), "_yaml\nyaml\n");
  fs.mkdirSync(path.join(sp, "python_dateutil-2.9.0.dist-info"), { recursive: true });
  fs.writeFileSync(
    path.join(sp, "python_dateutil-2.9.0.dist-info", "RECORD"),
    "dateutil/__init__.py,sha256=x,1\ndateutil/parser/_parser.py,sha256=x,1\npython_dateutil-2.9.0.dist-info/RECORD,,\n",
  );
});

afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
});

function run(params: UpgradeImpactParams, f: Recorded, opts: { installed?: InstalledDep[]; github?: boolean; cache?: UpgradeCache } = {}) {
  return analyzeUpgradeImpact(params, {
    net: createUpgradeNet(opts.cache ?? null, f.fetch),
    projectRoot: root,
    installed: opts.installed ?? [],
    offline: false,
    githubChangelog: opts.github ?? false,
  });
}

// ---------------------------------------------------------------- PyPI

describe("upgrade_impact on PyPI", () => {
  it("reads versions from the JSON API and the changelog from the sdist (flask 2.3.2 -> 3.0.0)", async () => {
    const f = recorded(flaskRoutes());
    const r = (await run({ package: "Flask", ecosystem: "PyPI", from_version: "2.3.2", to_version: "3.0.0" }, f)) as Record<string, any>;
    expect(r.error).toBeUndefined();
    expect(r.package).toBe("Flask");
    expect(r.ecosystem).toBe("PyPI");
    expect(r.versions_between.map((v: { version: string }) => v.version)).toEqual(["2.3.3", "3.0.0"]);
    expect(r.versions_between[1].published).toBe("2023-09-30T14:36:10.961495Z");
    expect(r.upgrade_type).toBe("major");
    expect(r.changelog).toMatchObject({ found: true, file: "flask-3.0.0/CHANGES.rst", covers_range: true });
    expect(r.changelog.sections.map((s: { version: string; date: string }) => [s.version, s.date])).toEqual([
      ["3.0.0", "2023-09-30"],
      ["2.3.3", "2023-08-21"],
    ]);
    expect(r.github_fallback).toBeUndefined();
    expect(r._meta.sources).toEqual(["api.osv.dev", "files.pythonhosted.org", "pypi.org"]);
    expect(r.release_notes_url).toBe("https://github.com/pallets/flask/releases");
  });

  it("matches import sites on the module name and says the name was assumed", async () => {
    const r = (await run({ package: "flask", ecosystem: "pypi", from_version: "2.3.2" }, recorded(flaskRoutes()))) as Record<string, any>;
    expect(r.to_version).toBe("3.0.0");
    expect(r.your_code.files).toEqual([{ path: "app/web.py", matches: 2 }]);
    expect(r.your_code.symbols_used).toEqual(expect.arrayContaining(["Flask", "abort", "dumps"]));
    expect(r.your_code.import_names).toEqual(["flask"]);
    expect(r.your_code.import_name_source).toBe("assumed");
    expect(r.your_code.import_name_note).toMatch(/assumption/);
  });

  it("infers PyPI from a lockfile entry spelled differently (PEP 503) and reads a line request", async () => {
    const installed: InstalledDep[] = [{ name: "flask", version: "2.3.2", ecosystem: "PyPI", isDirect: true }];
    const r = (await run({ package: "Flask", to_version: "3" }, recorded(flaskRoutes()), { installed })) as Record<string, any>;
    expect(r.ecosystem).toBe("PyPI");
    expect(r.from_version).toBe("2.3.2");
    expect(r.to_version).toBe("3.0.0");
  });

  it("maps distributions to import names from venv metadata, then the known table, then an assumption", () => {
    expect(pythonImportNames(root, "PyYAML")).toEqual({
      names: ["_yaml", "yaml"],
      source: "installed-metadata",
      evidence: ".venv/lib/python3.12/site-packages/PyYAML-6.0.1.dist-info/top_level.txt",
    });
    expect(pythonImportNames(root, "python-dateutil")).toMatchObject({ names: ["dateutil"], source: "installed-metadata" });
    expect(pythonImportNames(root, "beautifulsoup4")).toEqual({ names: ["bs4"], source: "known-mapping" });
    expect(pythonImportNames(null, "Pillow")).toEqual({ names: ["PIL"], source: "known-mapping" });
    expect(pythonImportNames(root, "zope.interface")).toEqual({ names: ["zope_interface"], source: "assumed" });
  });

  it("scans `import x`, `import x.y as z`, `from x import (a, b)` and attribute uses", () => {
    const symbols = new Set<string>();
    const src = ["import yaml, os", "from yaml.loader import (", "    SafeLoader,", "    FullLoader as FL,", ")", "import yamllint", "yaml.dump(x)"].join("\n");
    expect(scanPythonSource(src, ["yaml"], symbols)).toBe(2);
    expect([...symbols].sort()).toEqual(["FullLoader", "SafeLoader", "dump"]);
  });

  it("says when a release has no sdist to read a changelog from", async () => {
    const doc = flaskJson();
    doc.releases["3.0.0"] = doc.releases["3.0.0"].filter((f) => !f.url.endsWith(".tar.gz"));
    const f = recorded({ "https://pypi.org/pypi/flask/json": () => Response.json(doc) });
    const r = (await run({ package: "flask", ecosystem: "PyPI", from_version: "2.3.2" }, f)) as Record<string, any>;
    expect(r.changelog.found).toBe(false);
    expect(r.changelog.reason).toMatch(/no source distribution on PyPI/);
    expect(r.breaking_changes_count).toBeNull();
    expect(r.github_fallback.how_to_enable).toMatch(/FOURDA_GITHUB_CHANGELOG=true .*github\.com\/pallets\/flask/);
  });
});

// ---------------------------------------------------------------- Go

describe("upgrade_impact on Go", () => {
  const installed: InstalledDep[] = [{ name: "github.com/jackc/pgx/v4", version: "v4.17.2", ecosystem: "Go", isDirect: true }];

  it("reads a major upgrade as a module path change, with the changelog from the target module's zip", async () => {
    const f = recorded(pgxRoutes());
    const r = (await run({ package: "github.com/jackc/pgx/v4", to_version: "v5.0.0" }, f, { installed })) as Record<string, any>;
    expect(r.error).toBeUndefined();
    expect(r.package).toBe("github.com/jackc/pgx/v5");
    expect(r.from_version).toBe("v4.17.2");
    expect(r.to_version).toBe("v5.0.0");
    expect(r.module_path_change).toMatchObject({ from: "github.com/jackc/pgx/v4", to: "github.com/jackc/pgx/v5" });
    // The rest of the v4 line, then v5 up to the target (prereleases left out).
    expect(r.versions_between.map((v: { version: string }) => v.version)).toEqual(["v4.18.0", "v4.18.1", "v4.18.2", "v4.18.3", "v5.0.0"]);
    expect(r.versions_between[4].published).toBe("2022-09-17T15:36:36Z");
    expect(r.upgrade_type).toBe("major");
    expect(r.changelog).toMatchObject({ found: true, file: "github.com/jackc/pgx/v5@v5.0.0/CHANGELOG.md" });
    expect(r.breaking_changes_count).toBeGreaterThan(0);
    // Imports of the OLD module are the ones that change; pgx/v5 in other.go is not counted.
    expect(r.your_code.files).toEqual([{ path: "main.go", matches: 2 }]);
    expect(r.your_code.symbols_used).toEqual(expect.arrayContaining(["Connect"]));
    expect(r.summary).toMatch(/module path changes to github\.com\/jackc\/pgx\/v5 \(1 file imports github\.com\/jackc\/pgx\/v4\)/);
    expect(r._meta.sources).toEqual(["api.osv.dev", "proxy.golang.org"]);
  });

  it("accepts the new module path and finds the installed old major by its base path", async () => {
    const r = (await run({ package: "github.com/jackc/pgx/v5", to_version: "5.0.0" }, recorded(pgxRoutes()), { installed })) as Record<string, any>;
    expect(r.ecosystem).toBe("Go");
    expect(r.module_path_change?.from).toBe("github.com/jackc/pgx/v4");
    expect(r.from_version).toBe("v4.17.2");
  });

  it("scans Go import blocks with aliases, and never counts another major of the module", () => {
    const symbols = new Set<string>();
    const src = fs.readFileSync(path.join(root, "main.go"), "utf8");
    expect(scanGoSource(src, "github.com/jackc/pgx/v4", symbols)).toBe(2);
    expect([...symbols].sort()).toEqual(["Connect"]);
    expect(goImportInModule("github.com/spf13/cobra/v2", "github.com/spf13/cobra")).toBe(false);
    expect(goImportInModule("github.com/spf13/cobra/doc", "github.com/spf13/cobra")).toBe(true);
    expect(goPackageName("github.com/go-chi/chi/v5")).toBe("chi");
    expect(goPackageName("gopkg.in/yaml.v3")).toBe("yaml");
    expect(goMajorPath("github.com/jackc/pgx/v4", 5)).toBe("github.com/jackc/pgx/v5");
    expect(goMajorPath("gopkg.in/yaml.v2", 3)).toBe("gopkg.in/yaml.v3");
    expect(goMajorPath("github.com/spf13/cobra", 2)).toBe("github.com/spf13/cobra/v2");
  });

  it("derives the release tag prefix from the proxy's recorded ref, else from the path", () => {
    expect(goTagPrefix("github.com/aws/aws-sdk-go-v2/service/s3", "v1.50.0", { Ref: "refs/tags/service/s3/v1.50.0" })).toBe("service/s3");
    expect(goTagPrefix("github.com/jackc/pgx/v5", "v5.0.0", { Ref: "refs/tags/v5.0.0" })).toBe("");
    expect(goTagPrefix("github.com/aws/aws-sdk-go-v2/service/s3", "v1.50.0", null)).toBe("service/s3");
    expect(goTagPrefix("github.com/foo/bar/v2", "v2.1.0", null)).toBe("");
  });
});

// ---------------------------------------------------------------- GitHub fallback (opt-in)

describe("GitHub release-notes fallback", () => {
  const cobra: UpgradeImpactParams = { package: "github.com/spf13/cobra", ecosystem: "Go", from_version: "v1.8.0", to_version: "v1.10.2" };

  it("is off by default: says the changelog is unavailable and how to enable the fallback, and never contacts GitHub", async () => {
    const f = recorded(cobraRoutes("absent"));
    const r = (await run(cobra, f)) as Record<string, any>;
    expect(r.changelog).toMatchObject({ found: false });
    expect(r.changelog.reason).toMatch(/ships no changelog file/);
    expect(r.breaking_changes_count).toBeNull();
    expect(r.github_fallback).toEqual({
      enabled: false,
      how_to_enable: expect.stringMatching(/^Set FOURDA_GITHUB_CHANGELOG=true .* on github\.com\/spf13\/cobra/),
    });
    expect(r.summary).toMatch(/breaking changes are unknown .*FOURDA_GITHUB_CHANGELOG=true/);
    expect(f.calls.some((u) => u.includes("github.com/repos"))).toBe(false);
    expect(r._meta.sources).toEqual(["api.osv.dev", "proxy.golang.org"]);
  });

  it("when enabled, reads the repository's releases (named by the proxy's VCS origin) as the changelog", async () => {
    process.env.GITHUB_TOKEN = "test-token";
    const f = recorded(cobraRoutes("ok"));
    const r = (await run(cobra, f, { github: true })) as Record<string, any>;
    expect(r.changelog).toMatchObject({ found: true, source: "github-releases", url: "https://github.com/spf13/cobra/releases", covers_range: true });
    expect(r.changelog.sections.map((s: { version: string }) => s.version)).toEqual(["1.10.2", "1.10.1", "1.10.0", "1.9.1", "1.9.0", "1.8.1"]);
    expect(r.github_fallback).toMatchObject({ enabled: true, used: true, source: "github-releases" });
    const entries = r.changelog.sections.flatMap((s: { entries: Array<{ text: string }> }) => s.entries.map((e) => e.text));
    expect(entries.some((t: string) => /made their first contribution|Full Changelog/i.test(t))).toBe(false);
    expect(r.summary).toMatch(/\(from GitHub release notes\)/);
    expect(r._meta.sources).toEqual(["api.github.com", "api.osv.dev", "proxy.golang.org"]);
    expect(r._meta.privacy).toMatch(/FOURDA_GITHUB_CHANGELOG is on/);
    const apiCall = f.calls.findIndex((u) => u.startsWith("https://api.github.com/"));
    expect(f.headers[apiCall].Authorization).toBe("Bearer test-token");
  });

  it("reports a rate limit with its reset time, and does not cache it", async () => {
    const cache = new MemCache();
    const f = recorded(cobraRoutes("limited"));
    const r = (await run(cobra, f, { github: true, cache })) as Record<string, any>;
    expect(r.changelog.found).toBe(false);
    expect(r.github_fallback.used).toBe(false);
    expect(r.github_fallback.reason).toMatch(/rate limit reached \(resets at 2026-10-11T.*\); set GITHUB_TOKEN/);
    await run(cobra, f, { github: true, cache });
    expect(f.calls.filter((u) => u.startsWith("https://api.github.com/")).length).toBe(2);
  });

  it("caches release notes under a key that carries the parser version", async () => {
    const cache = new MemCache();
    const f = recorded(cobraRoutes("ok"));
    await run(cobra, f, { github: true, cache });
    await run(cobra, f, { github: true, cache });
    expect(f.calls.filter((u) => u.startsWith("https://api.github.com/")).length).toBe(1);
    const keys = [...cache.store.keys()].filter((k) => k.startsWith("upgrade-impact:github:"));
    expect(keys.length).toBe(1);
    expect(keys[0]).toContain(`:p${CHANGELOG_PARSER_VERSION}:`);
    expect(
      githubCacheKey("releases", "o/r", { pkg: "x", ecosystem: "npm", repository: null, from: "1.0.0", to: "2.0.0", order: () => 0 }),
    ).toContain(`:p${CHANGELOG_PARSER_VERSION}:`);
  });

  it("is enabled only by an explicit truthy FOURDA_GITHUB_CHANGELOG", () => {
    expect(githubChangelogEnabled({})).toBe(false);
    expect(githubChangelogEnabled({ FOURDA_GITHUB_CHANGELOG: "0" })).toBe(false);
    expect(githubChangelogEnabled({ FOURDA_GITHUB_CHANGELOG: "false" })).toBe(false);
    for (const v of ["1", "true", "TRUE", "yes", "on"]) expect(githubChangelogEnabled({ FOURDA_GITHUB_CHANGELOG: v })).toBe(true);
  });

  it("reads versions from release tags, skipping other packages' tags in a monorepo", () => {
    expect(versionFromTag("v1.2.3", "x", null)).toBe("1.2.3");
    expect(versionFromTag("release-2.0", "x", null)).toBe("2.0");
    expect(versionFromTag("3.0.0rc1", "x", null)).toBe("3.0.0rc1");
    expect(versionFromTag("@vitejs/plugin-react@4.3.0", "@vitejs/plugin-react", null)).toBe("4.3.0");
    expect(versionFromTag("vite@6.0.0", "@vitejs/plugin-react", null)).toBeNull();
    expect(versionFromTag("tokio-1.40.0", "tokio", null)).toBe("1.40.0");
    expect(versionFromTag("tokio-macros-2.4.0", "tokio", null)).toBeNull();
    expect(versionFromTag("service/s3/v1.50.0", "github.com/aws/aws-sdk-go-v2/service/s3", "service/s3")).toBe("1.50.0");
    expect(versionFromTag("service/sqs/v1.30.0", "github.com/aws/aws-sdk-go-v2/service/s3", "service/s3")).toBeNull();
    expect(versionFromTag("nightly", "x", null)).toBeNull();
  });

  it("turns release bodies into sections, keeping the author's headings as `under`", () => {
    const releases = JSON.parse(fixture("github-cobra-releases.json"));
    const sections = releasesToSections(releases, "github.com/spf13/cobra", "");
    const v1100 = sections.find((s) => s.version === "1.10.0")!;
    expect(v1100.date).toMatch(/^2025-/);
    expect(v1100.entries.length).toBeGreaterThan(3);
    expect(v1100.entries.every((e) => !/first contribution/.test(e.text))).toBe(true);
  });

  it("reads a raw changelog file only from a GitHub link that names one", () => {
    expect(rawChangelogUrl("https://github.com/pallets/flask/blob/main/CHANGES.rst")).toBe(
      "https://raw.githubusercontent.com/pallets/flask/main/CHANGES.rst",
    );
    expect(rawChangelogUrl("https://flask.palletsprojects.com/page/changes/")).toBeNull();
    expect(rawChangelogUrl("https://github.com/pallets/flask/blob/main/README.md")).toBeNull();
    expect(rawChangelogUrl("https://github.com/pallets/flask/releases")).toBeNull();
  });
});

// ---------------------------------------------------------------- parser and archive

describe("changelog formats and archives", () => {
  it("parses reStructuredText release titles, their Released lines and RST sub-headings", () => {
    const sections = parseChangelog(fixture("flask-3.0.0-CHANGES.rst"));
    expect(sections.slice(0, 3).map((s) => [s.version, s.date])).toEqual([
      ["3.0.0", "2023-09-30"],
      ["2.3.3", "2023-08-21"],
      ["2.3.2", "2023-05-01"],
    ]);
    expect(sections[0].entries.some((e) => /^Released/.test(e.text))).toBe(false);
    const rst = parseChangelog(["2.0.0", "=====", "", "Breaking changes", "~~~~~~~~~~~~~~~~", "", "- Dropped Python 3.8", "- New `x` argument", ""].join("\n"));
    expect(rst[0].entries.map((e) => [e.kind, e.under])).toEqual([
      ["breaking", "Breaking changes"],
      ["breaking", "Breaking changes"],
    ]);
  });

  it("reads root-level files of a zip under a module prefix, deflated or not, and nothing deeper", () => {
    const buf = zip({
      "example.com/m@v1.0.0/CHANGELOG.md": "## 1.0.0\n- x\n",
      "example.com/m@v1.0.0/sub/CHANGELOG.md": "nested",
      "example.com/m@v1.0.0/main.go": "package m",
    });
    const files = readZipRootTextFiles(buf, isChangelogName, "example.com/m@v1.0.0/");
    expect([...files.keys()]).toEqual(["example.com/m@v1.0.0/CHANGELOG.md"]);
    expect(files.get("example.com/m@v1.0.0/CHANGELOG.md")).toContain("## 1.0.0");
    expect(() => readZipRootTextFiles(Buffer.from("not a zip at all, definitely"), isChangelogName)).toThrow(/not a zip/);
  });
});
