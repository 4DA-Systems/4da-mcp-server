// SPDX-License-Identifier: Apache-2.0
/**
 * Private package names never leave the machine (audit 2026-11-11 W1 M2-2). Until 6.3.0 every
 * dependency name went to OSV.dev and the registries, private ones included; FOURDA_OFFLINE was
 * the only off switch, and it stops everything. These tests import only the tools and the live
 * layer, so they run (and fail) against a server without the exclusion.
 *
 * Each test captures every outbound request body and URL, and asserts the private name is in none.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { vulnerabilityCoverage } from "../live/scan-coverage.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradeImpact } from "../tools/upgrade-impact.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
let scratch: string;
let sent: string[];
let priorOffline: string | undefined;
const saved: Record<string, string | undefined> = {};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const write = (rel: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(scratch, rel)), { recursive: true });
  fs.writeFileSync(path.join(scratch, rel), content);
};
const leaked = (name: string) => sent.filter((s) => s.includes(name));

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
});

afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-"));
  sent = [];
  for (const k of ["GOPRIVATE", "FOURDA_PRIVATE_PACKAGES"]) saved[k] = process.env[k];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      sent.push(`${url} ${typeof init?.body === "string" ? init.body : ""}`);
      const u = new URL(url);
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
        const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
        return json({ results: queries.map(() => ({ vulns: [] })) });
      }
      if (u.hostname === "api.osv.dev") return json({ vulns: [] });
      return json({ error: "Not found" }, 404);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

/** A project with a lockfile naming a private scoped package, a public one, and an .npmrc. */
function npmProject(npmrc: string | null) {
  write("package.json", JSON.stringify({ name: "app", dependencies: { "@acme/secret-billing": "1.2.3", lodash: "4.17.21" } }));
  write(
    "package-lock.json",
    JSON.stringify({
      name: "app",
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: { "@acme/secret-billing": "1.2.3", lodash: "4.17.21" } },
        "node_modules/@acme/secret-billing": { version: "1.2.3" },
        "node_modules/lodash": { version: "4.17.21" },
      },
    }),
  );
  if (npmrc !== null) write(".npmrc", npmrc);
  const live = new LiveIntelligence(new Database(":memory:"));
  live.initFromProject(scratch, ["@acme/secret-billing", "lodash"], [], "javascript");
  return live;
}

describe("a scope the project's .npmrc maps to a private registry", () => {
  it("vulnerability scan: the private name is never sent, and is reported as not checked (private), never clean", async () => {
    const live = npmProject("@acme:registry=https://npm.acme.internal/\n");
    const scan = await live.scanVulnerabilities(scratch);
    expect(sent.length).toBeGreaterThan(0); // lodash was checked
    expect(leaked("secret-billing")).toEqual([]);
    const coverage = vulnerabilityCoverage(scan, { enabled: true });
    expect(coverage).not.toBeNull();
    expect(coverage!.note).toContain("NOT CHECKED (private)");
    expect(coverage!.note).toContain("@acme/secret-billing");
  });

  it("dependency_check: the private item is unknown (not checked, private) and nothing about it is sent", async () => {
    const live = npmProject("@acme:registry=https://npm.acme.internal/\n");
    const result = await executeDependencyCheck(
      noDb,
      { items: [{ ecosystem: "npm", package: "@acme/secret-billing", to: "1.2.4" }, { ecosystem: "npm", package: "lodash", to: "4.17.21" }] },
      live,
    );
    expect(result.results[0].package).toBe("@acme/secret-billing");
    expect(result.results[0].verdict).toBe("unknown");
    expect(result.results[0].reason).toContain("NOT CHECKED (private)");
    expect(result.results[1].package).toBe("lodash");
    expect(leaked("secret-billing")).toEqual([]);
  });

  it("vulnerability_scan's coverage lists each private package with why, concise and detailed", async () => {
    const live = npmProject("@acme:registry=https://npm.acme.internal/\n");
    for (const response_format of ["concise", "detailed"] as const) {
      const out = (await executeVulnerabilityScan(noDb, { response_format }, live)) as {
        summary?: string;
        total_vulnerable_packages: number | null;
        coverage?: { private_dependencies?: number; private_dependency_list?: Array<{ name: string; why: string }> };
      };
      expect(out.summary).toContain("NOT CHECKED (private)");
      expect(out.total_vulnerable_packages).toBeNull();
      expect(out.coverage?.private_dependencies).toBe(1);
      expect(out.coverage?.private_dependency_list?.[0]).toMatchObject({ name: "@acme/secret-billing" });
      expect(out.coverage?.private_dependency_list?.[0].why).toContain(".npmrc");
    }
    expect(leaked("secret-billing")).toEqual([]);
  });

  it("a public scope is still checked", async () => {
    const live = npmProject("@acme:registry=https://registry.npmjs.org/\n");
    await live.scanVulnerabilities(scratch);
    expect(leaked("secret-billing").length).toBeGreaterThan(0);
  });
});

describe("GOPRIVATE and FOURDA_PRIVATE_PACKAGES", () => {
  it("a module matching GOPRIVATE is never sent by dependency_check", async () => {
    process.env.GOPRIVATE = "github.com/acme-corp/*";
    const live = new LiveIntelligence(new Database(":memory:"));
    const result = await executeDependencyCheck(noDb, { items: [{ ecosystem: "Go", package: "github.com/acme-corp/ledger", to: "v1.4.0" }] }, live);
    expect(result.results[0].verdict).toBe("unknown");
    expect(result.results[0].reason).toContain("GOPRIVATE");
    expect(sent).toEqual([]);
  });

  it("a name on FOURDA_PRIVATE_PACKAGES is never sent, by dependency_check or upgrade_impact", async () => {
    process.env.FOURDA_PRIVATE_PACKAGES = "npm:acme-*, PyPI:internal-tools";
    const live = new LiveIntelligence(new Database(":memory:"));
    const result = await executeDependencyCheck(
      noDb,
      { items: [{ ecosystem: "npm", package: "acme-widgets", to: "2.0.0" }, { ecosystem: "PyPI", package: "internal-tools", to: "1.0.0" }] },
      live,
    );
    expect(result.results.map((r) => r.verdict)).toEqual(["unknown", "unknown"]);
    const impact = await executeUpgradeImpact(noDb, { package: "acme-widgets", ecosystem: "npm", to_version: "2.0.0" }, live);
    expect(String((impact as { error?: string }).error)).toContain("NOT CHECKED (private)");
    expect(sent).toEqual([]);
  });
});

describe("lockfiles that install from a private registry", () => {
  it("a Cargo.lock crate from another registry or from git is never sent", async () => {
    write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1"\nacme-ledger = { version = "0.3", registry = "acme" }\n');
    write(
      "Cargo.lock",
      [
        "version = 3",
        "",
        "[[package]]",
        'name = "app"',
        'version = "0.1.0"',
        'dependencies = ["acme-ledger", "acme-git-tool", "serde"]',
        "",
        "[[package]]",
        'name = "acme-ledger"',
        'version = "0.3.1"',
        'source = "sparse+https://cargo.acme.internal/index/"',
        "",
        "[[package]]",
        'name = "acme-git-tool"',
        'version = "0.1.0"',
        'source = "git+ssh://git@github.com/acme/git-tool?branch=main#0123456789abcdef"',
        "",
        "[[package]]",
        'name = "serde"',
        'version = "1.0.200"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        "",
      ].join("\n"),
    );
    const live = new LiveIntelligence(new Database(":memory:"));
    live.initFromProject(scratch, ["serde", "acme-ledger"], [], "rust");
    const scan = await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(leaked("serde").length).toBeGreaterThan(0);
    expect(leaked("acme-ledger")).toEqual([]);
    expect(leaked("acme-git-tool")).toEqual([]);
    expect(vulnerabilityCoverage(scan, { enabled: true })?.note).toContain("NOT CHECKED (private)");
  });

  it("a uv.lock package from a private index is never sent", async () => {
    write("pyproject.toml", '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["requests", "acme-auth"]\n');
    write(
      "uv.lock",
      [
        "version = 1",
        "",
        "[[package]]",
        'name = "acme-auth"',
        'version = "2.1.0"',
        'source = { registry = "https://pypi.acme.internal/simple" }',
        "",
        "[[package]]",
        'name = "requests"',
        'version = "2.32.3"',
        'source = { registry = "https://pypi.org/simple" }',
        "",
      ].join("\n"),
    );
    const live = new LiveIntelligence(new Database(":memory:"));
    live.initFromProject(scratch, ["requests", "acme-auth"], [], "python");
    await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(leaked("requests").length).toBeGreaterThan(0);
    expect(leaked("acme-auth")).toEqual([]);
    // dependency_check knows it from the lockfile too.
    const result = await executeDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", package: "acme_auth", to: "2.2.0" }] }, live);
    expect(result.results[0].reason).toContain("NOT CHECKED (private)");
    expect(leaked("acme")).toEqual([]);
  });
});
