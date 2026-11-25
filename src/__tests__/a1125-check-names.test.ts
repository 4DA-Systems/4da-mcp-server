// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish audit 2026-11-25, E3: dependency_check screened package names for npm only. For PyPI,
 * crates.io and Go an item whose "package" was a local path, a git URL, a requirement line with
 * `--index-url`, a tarball URL or a Cargo inline table was sent whole to pypi.org / crates.io /
 * proxy.golang.org and OSV.dev (home directory and private host included). Each ecosystem's own name
 * grammar now decides before anything is sent; a refused item answers NOT CHECKED, not_checked "input".
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { checkGoModulePath, goModulePathGrammarProblem } from "../live/go-path.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;
let sent: string[];
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  sent = [];
  // Every request is recorded (URL and body) and answered "not found": nothing here needs an answer.
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    sent.push(`${String(input)} ${typeof init?.body === "string" ? init.body : ""}`);
    return new Response(JSON.stringify({}), { status: 404, headers: { "content-type": "application/json" } });
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const check = async (items: unknown[]) =>
  (await executeDependencyCheck(noDb, { items } as never, new LiveIntelligence(new Database(":memory:")))) as { summary: string; results: Array<Record<string, any>> };

const LEAKS: Array<[string, string, string]> = [
  ["PyPI", "git+https://git.zqxcorp.internal/zqx-gitpip.git", "1.0"],
  ["PyPI", "C:/Users/zqxdev/src/zqx-pypath", "1.0"],
  ["PyPI", "./libs/zqx-editable3", "1.0"],
  ["PyPI", "-e ./libs/zqx-editable4", "1.0"],
  ["PyPI", "zqx-x2 @ file:///C:/Users/zqxdev/zqx-x2", "1.0"],
  ["PyPI", "zqx-x3==1.0 --index-url https://pypi.zqxcorp.internal/simple", "1.0"],
  ["PyPI", "https://pkgs.zqxcorp.internal/zqx-arch-1.0.tar.gz", "1.0"],
  ["PyPI", "/home/zqxdev/src/zqx-posix", "1.0"],
  ["PyPI", "zqx-extras[socks]", "1.0"],
  ["crates.io", "zqx-c2 --registry zqxreg", "1.0.0"],
  ["crates.io", "../zqx-cpath", "1.0.0"],
  ["crates.io", "git+https://git.zqxcorp.internal/zqx-cgit", "1.0.0"],
  ["crates.io", 'zqx-c3 = { git = "https://git.zqxcorp.internal/zqx-c3" }', "1.0.0"],
  ["crates.io", "C:\\Users\\zqxdev\\zqx-cwin", "1.0.0"],
  ["Go", "C:/Users/zqxdev/src/zqx-gomod", "v1.0.0"],
  ["Go", "../zqx-gofork", "v1.0.0"],
  ["Go", "zqxmod/internal/zqx", "v1.0.0"],
  ["Go", "git+https://git.zqxcorp.internal/zqx-gogit", "v1.0.0"],
  ["Go", "zqx.example.com/x:y", "v1.0.0"],
  ["Go", "git.zqxcorp.internal/zqx/lib", "v1.0.0"],
  ["Go", "10.20.30.40/zqx/lib", "v1.0.0"],
  ["Go", "zqx-build.local/lib", "v1.0.0"],
  ["npm", "zqx-tool --registry zqxreg", "1.0.0"],
  ["npm", "C:\\Users\\zqxdev\\zqx-npmwin", "1.0.0"],
];

describe("E3: a package that is not a registry name is refused before anything is sent", () => {
  it.each(LEAKS)("%s %s: NOT CHECKED, and nothing about it leaves the machine", async (ecosystem, pkg, to) => {
    const { results, summary } = await check([{ ecosystem, package: pkg, to }]);
    expect(results).toHaveLength(1);
    expect(results[0].verdict).toBe("unknown");
    expect(["input", "module_path", "private"]).toContain(results[0].not_checked);
    expect(results[0].reason).toMatch(/^NOT CHECKED/);
    expect(results[0].reason).toMatch(/Nothing (?:about it )?was sent/);
    expect(summary).toMatch(/^NOT CHECKED/);
    expect(sent.filter((s) => /zqx/i.test(s))).toEqual([]);
  });

  it("the leaks the audit found are refused as input, with the ecosystem's own name rule named", async () => {
    const { results } = await check([
      { ecosystem: "PyPI", package: "C:/Users/zqxdev/src/zqx-pypath", to: "1.0" },
      { ecosystem: "crates.io", package: "../zqx-cpath", to: "1.0.0" },
      { ecosystem: "Go", package: "C:/Users/zqxdev/src/zqx-gomod", to: "v1.0.0" },
    ]);
    expect(results.map((r) => r.not_checked)).toEqual(["input", "input", "input"]);
    expect(results[0].reason).toMatch(/is not a valid PyPI project name/);
    expect(results[1].reason).toMatch(/is not a valid crates\.io crate name/);
    expect(results[2].reason).toMatch(/is not a valid Go module path/);
    expect(results[0].reason).toMatch(/Nothing was sent to PyPI or OSV\.dev/);
    expect(results[2].reason).toMatch(/Nothing was sent to the Go proxy or OSV\.dev/);
    expect(sent.filter((s) => /zqx/i.test(s))).toEqual([]);
  });

  it("one refused item does not refuse the others: real names are still looked up", async () => {
    const { results } = await check([
      { ecosystem: "PyPI", package: "./libs/zqx-editable3", to: "1.0" },
      { ecosystem: "PyPI", package: "Jinja2", to: "3.1.2" },
      { ecosystem: "crates.io", package: "serde_json", to: "1.0.0" },
      { ecosystem: "Go", package: "golang.org/x/net", to: "v0.17.0" },
      { ecosystem: "npm", package: "@babel/core", to: "7.0.0" },
    ]);
    expect(results[0].not_checked).toBe("input");
    for (const r of results.slice(1)) expect(r.not_checked).not.toBe("input");
    expect(sent.some((s) => s.includes("pypi.org/pypi/jinja2/json"))).toBe(true);
    expect(sent.some((s) => s.includes("crates.io") && s.includes("serde_json"))).toBe(true);
    expect(sent.some((s) => s.includes("golang.org/x/net"))).toBe(true);
    expect(sent.some((s) => s.includes("registry.npmjs.org/") && s.includes("babel"))).toBe(true);
    expect(sent.filter((s) => /zqx/i.test(s))).toEqual([]);
  });

  it("names every registry really has pass each grammar", async () => {
    const ok: Array<[string, string]> = [
      ["PyPI", "zope.interface"],
      ["PyPI", "ruamel.yaml"],
      ["PyPI", "Django"],
      ["PyPI", "backports_abc"],
      ["PyPI", "a"],
      ["crates.io", "serde-json"],
      ["crates.io", "Inflector"],
      ["crates.io", "r2d2"],
      ["Go", "gopkg.in/yaml.v2"],
      ["Go", "github.com/Azure/azure-sdk-for-go"],
      ["Go", "go.uber.org/zap"],
      ["Go", "k8s.io/client-go"],
      ["Go", "github.com/golang-jwt/jwt/v4"],
      ["npm", "JSONStream"],
      ["npm", "lodash.merge"],
    ];
    const { results } = await check(ok.map(([ecosystem, pkg]) => ({ ecosystem, package: pkg, to: ecosystem === "Go" ? "v1.0.0" : "1.0.0" })));
    results.forEach((r, i) => expect([ok[i], r.not_checked]).not.toEqual([ok[i], "input"]));
  });
});

describe("E3: go-path.ts refuses a path that is no module path before it reads the proxy", () => {
  it("goModulePathGrammarProblem names what is wrong", () => {
    expect(goModulePathGrammarProblem("C:/Users/zqxdev/src/zqx-gomod")).toMatch(/:/);
    expect(goModulePathGrammarProblem("zqxmod/internal")).toMatch(/domain/);
    expect(goModulePathGrammarProblem("-x.example.com/y")).not.toBeNull();
    expect(goModulePathGrammarProblem("golang.org/x/net")).toBeNull();
    expect(goModulePathGrammarProblem("gopkg.in/yaml.v2")).toBeNull();
    expect(goModulePathGrammarProblem("github.com/Labstack/Echo/v4")).toBeNull();
  });

  it("checkGoModulePath sends nothing for such a path", async () => {
    const fetchFn = vi.fn(async () => new Response("module x\n"));
    const v = await checkGoModulePath("C:/Users/zqxdev/src/zqx-gomod", "v1.0.0", fetchFn as never);
    expect(v.ok).toBe(false);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("bounded: a long hostile path is answered at once", () => {
    const t = Date.now();
    expect(goModulePathGrammarProblem(`${"a.".repeat(50_000)}/${"-".repeat(50_000)}:`)).not.toBeNull();
    expect(Date.now() - t).toBeLessThan(200);
  });
});
