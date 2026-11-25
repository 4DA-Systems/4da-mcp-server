// SPDX-License-Identifier: Apache-2.0
/**
 * Review of the 2026-11-25 fix round, lockfile lane (items 1-5):
 * 1. A Gemfile that assigns from a block (`x = if ... end`, `x = case`, `x = begin`), defines an
 *    endless method (`def x = 1`) or holds a heredoc is followed. A lockfile read whole and only not
 *    compared with its manifest is a note, never a lead: totals stay numbers and the plan keeps its
 *    vulnerability data (CocoaPods read NOT CHECKED with null totals).
 * 2. gems.locked beside a byte-identical Gemfile.lock is no CONFLICT.
 * 3. A DEPENDENCIES entry with no spec is PARTIAL, unless the Gemfile restricts it to platforms.
 * 4. Manifest sections that were never compared are compared where the lock records them, and said
 *    as not compared where it does not.
 * 5. An entry another package needs and the file lacks is worded as that, not as a cut.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { gemfileDeclared } from "../live/lockfile-parsers-rbphp.js";
import type { OsvEcosystem } from "../live/types.js";
import { dispatchTool } from "../tool-dispatch.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";

let scratch: string;
let dir: string;
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

beforeEach(() => {
  scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1125-r2-")));
  dir = path.join(scratch, "project");
  const home = path.join(scratch, "home");
  fs.mkdirSync(dir, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  setEnv("FOURDA_OFFLINE", undefined);
  setEnv("FOURDA_MCP_HOME", home);
  setEnv("HOME", home);
  setEnv("USERPROFILE", home);
  setEnv("APPDATA", path.join(home, "AppData", "Roaming"));
  setEnv("LOCALAPPDATA", path.join(home, "AppData", "Local"));
  setEnv("XDG_CONFIG_HOME", undefined);
  setEnv("XDG_CONFIG_DIRS", path.join(home, "xdg-none"));
  setEnv("ProgramData", path.join(home, "ProgramData"));
  setEnv("NPM_CONFIG_USERCONFIG", path.join(home, ".npmrc"));
  setEnv("NPM_CONFIG_GLOBALCONFIG", path.join(home, "global-npmrc"));
  setEnv("FOURDA_PUBLIC_MIRRORS", undefined);
  setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const u = new URL(String(input));
      const body = typeof init?.body === "string" ? init.body : "";
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
        const { queries } = JSON.parse(body) as { queries: unknown[] };
        return json({ results: queries.map(() => ({ vulns: [] })) });
      }
      if (u.hostname === "api.osv.dev") return json({ vulns: [] });
      return json({ error: "Not found" }, 404);
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  clearLiveIntelligence();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

const write = (files: Record<string, string>) => {
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
};
const problems = (ecosystem: OsvEcosystem) => resolveVersionSource(dir, ecosystem).problems ?? [];

async function call(tool: string, args: Record<string, unknown>): Promise<Record<string, any>> {
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(dir);
  live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
  const db = new FourDADatabase(path.join(scratch, `standalone-${Math.random().toString(36).slice(2)}.db`));
  try {
    const result = (await dispatchTool(tool, db, args)) as { content: Array<{ text: string }> };
    return JSON.parse(result.content[0].text) as Record<string, any>;
  } finally {
    db.close();
  }
}

const LOCK = (specs: string, deps: string, extra = "") => `${extra}GEM
  remote: https://rubygems.org/
  specs:
${specs}
PLATFORMS
  ruby

DEPENDENCIES
${deps}
BUNDLED WITH
   2.4.22
`;
const RAKE_LOCK = LOCK("    rake (13.2.1)\n", "  rake\n");

// ---------------------------------------------------------------------------------------------
// 1. Gemfile shapes, and NOT CROSS-CHECKED is a note
// ---------------------------------------------------------------------------------------------

describe("1b: the Gemfile shapes real projects use are followed", () => {
  const followed = (text: string) => {
    const got = gemfileDeclared(text);
    if ("error" in got) throw new Error(got.error);
    return got.names;
  };
  it.each([
    ["x = if ... else ... end", 'x = if ENV["A"]\n  "1"\nelse\n  "2"\nend\ngem "rack"\n', ["rack"]],
    ["x = case ... end", 'x = case ENV["A"]\nwhen "a" then 1\nend\ngem "rack"\n', ["rack"]],
    ["x = begin ... rescue ... end", 'x = begin\n  File.read("v")\nrescue\n  nil\nend\ngem "rack"\n', ["rack"]],
    ["opts = if path (CocoaPods)", "def cp_gem(name, path: false)\n  return gem name if X\n  opts = if path\n    {}\n  else\n    {}\n  end\n  gem name, opts\nend\ngem 'rack'\n", ["rack"]],
    ["endless def", 'def foo = 1\ndef bar(a) = a\ngem "rack"\n', ["rack"]],
    ["heredoc holding keywords", 'x = <<~EOS\n  if this\n  end\nEOS\ngem "rack"\n', ["rack"]],
    ["while modifier", 'i = 0\ni += 1 while i < 3\ngem "rack"\n', ["rack"]],
    ["one-line if then end", 'if true then gem "a" end\ngem "rack"\n', ["rack"]],
    ["end.to_s", 'ENV.fetch("X") do\n  "y"\nend.to_s\ngem "rack"\n', ["rack"]],
    ["one-line group (item 4)", 'group :test do; gem "rack"; end\ngem "rake"\n', ["rack", "rake"]],
    ["while ... do", 'while false do\n  gem "a"\nend\ngem "rack"\n', ["rack"]],
    ["percent literal holding a keyword", "x = %q{ if }\ny = %w[do end]\ngem 'rack'\n", ["rack"]],
    ["class << self", "class << self\n  def x\n  end\nend\ngem 'rack'\n", ["rack"]],
  ])("%s", (_label, text, names) => {
    expect(followed(text)).toEqual(names);
  });

  it("CocoaPods' Gemfile (assigns from an if) is followed, and its lockfile has no problem", () => {
    write({
      Gemfile: "def cp_gem(name, repo_name, branch = 'master', path: false)\n  return gem name if SKIP\n  opts = if path\n           { :path => \"../#{repo_name}\" }\n         else\n           { :git => url, :branch => branch }\n         end\n  gem name, opts\nend\n\nsource 'https://rubygems.org'\n\ngroup :development do\n  cp_gem 'claide', 'CLAide'\n  gem 'rake'\nend\n",
      "Gemfile.lock": RAKE_LOCK,
    });
    expect(problems("RubyGems")).toEqual([]);
  });
});

describe("2: gems.locked beside a Gemfile.lock", () => {
  it("byte-identical (or only line endings apart): no CONFLICT", () => {
    write({ "gems.rb": "source 'https://rubygems.org'\ngem 'rake'\n", "gems.locked": RAKE_LOCK, "Gemfile.lock": RAKE_LOCK.replace(/\n/g, "\r\n") });
    expect(problems("RubyGems")).toEqual([]);
    expect(resolveVersionSource(dir, "RubyGems").extraSources).toEqual([path.join(dir, "Gemfile.lock")]);
  });
  it("different: CONFLICT, as before", () => {
    write({ "gems.rb": "source 'https://rubygems.org'\ngem 'rake'\n", "gems.locked": RAKE_LOCK, "Gemfile.lock": LOCK("    rake (12.0.0)\n", "  rake\n") });
    expect(problems("RubyGems").map((p) => [path.basename(p.file), p.conflict])).toEqual([["Gemfile.lock", true]]);
  });
});

describe("3: a DEPENDENCIES entry with no spec", () => {
  it("is PARTIAL (F/gem-dropspec: rack listed, its spec gone)", () => {
    write({ Gemfile: 'source "https://rubygems.org"\ngem "rack", "2.0.1"\ngem "rake"\n', "Gemfile.lock": LOCK("    rake (13.2.1)\n", "  rack (= 2.0.1)\n  rake\n") });
    const got = problems("RubyGems");
    expect(got).toHaveLength(1);
    expect(got[0].partial).toBe(true);
    expect(got[0].error).toMatch(/\(rack\)/);
  });
  it("is no damage for a platform-only gem, a conditional one, or bundler", () => {
    write({
      Gemfile: 'source "https://rubygems.org"\ngem "tzinfo-data", platforms: %i[ windows jruby ]\ngem "wdm", ">= 0.1.0" if Gem.win_platform?\nplatforms :jruby do\n  gem "jdbc"\nend\ngem "rake"\n',
      "Gemfile.lock": LOCK("    rake (13.2.1)\n", "  bundler\n  jdbc\n  rake\n  tzinfo-data\n  wdm (>= 0.1.0)\n"),
    });
    expect(problems("RubyGems")).toEqual([]);
  });
  it("is not judged with no Gemfile to say which gems are platform-only", () => {
    write({ "Gemfile.lock": LOCK("    rake (13.2.1)\n", "  rake\n  tzinfo-data\n") });
    expect(problems("RubyGems")).toEqual([]);
  });
});

describe("4: manifest sections that were never compared", () => {
  const PDM = (groups: string, names: string[]) =>
    `[metadata]\ngroups = ${groups}\nlock_version = "4.4.1"\n\n${names.map((n) => `[[package]]\nname = "${n}"\nversion = "1.0.0"\nsummary = ""\nfiles = []\n`).join("\n")}`;
  const POETRY = (names: string[]) => `${names.map((n) => `[[package]]\nname = "${n}"\nversion = "1.0.0"\ndescription = ""\noptional = false\npython-versions = "*"\nfiles = []\n`).join("\n")}\n[metadata]\nlock-version = "2.1"\npython-versions = "^3.9"\ncontent-hash = "0"\n`;
  const notes = (eco: OsvEcosystem) => problems(eco).filter((p) => p.notCrossChecked);
  const partials = (eco: OsvEcosystem) => problems(eco).filter((p) => p.partial);

  it("PDM [tool.pdm.dev-dependencies]: a group the lock holds is compared (pd05)", () => {
    write({ "pyproject.toml": '[project]\nname = "x"\ndependencies = ["anyio"]\n[tool.pdm.dev-dependencies]\ndev = ["pytest", "flask", "-e file:///${PROJECT_ROOT}/sub"]\n', "pdm.lock": PDM('["default", "dev"]', ["anyio", "pytest"]) });
    expect(partials("PyPI")[0]?.error).toMatch(/pyproject\.toml declares flask, but/);
  });
  it("PDM: a group the lock does not record is said as not compared, a note (pd02, pd04)", () => {
    write({ "pyproject.toml": '[project]\nname = "x"\ndependencies = ["anyio"]\n[project.optional-dependencies]\nweb2 = ["flask"]\n[tool.pdm.dev-dependencies]\nweb3 = ["django"]\n', "pdm.lock": PDM('["default"]', ["anyio"]) });
    expect(partials("PyPI")).toEqual([]);
    expect(notes("PyPI")[0]?.error).toMatch(/does not record the groups web2, web3/);
  });
  it("Poetry 2: [project.optional-dependencies] and [dependency-groups] are compared (p2-02, p2-03)", () => {
    write({ "pyproject.toml": '[project]\nname = "x"\ndependencies = ["anyio"]\n[project.optional-dependencies]\nweb = ["flask"]\n[dependency-groups]\ndocs = ["mkdocs"]\n', "poetry.lock": POETRY(["anyio"]) });
    expect(partials("PyPI")[0]?.error).toMatch(/declares flask and mkdocs, but/);
  });
  it("a gem moved from path: to the registry in the Gemfile only (rb22), and a multi-line path: gem is no move", () => {
    write({
      Gemfile: "source 'https://rubygems.org'\ngem 'rake'\ngem 'kaminari'\ngem 'draw_all',\n  path: 'gems/draw_all',\n  require: false\n",
      "Gemfile.lock": `PATH\n  remote: vendor/kaminari\n  specs:\n    kaminari (1.2.2)\n\nPATH\n  remote: gems/draw_all\n  specs:\n    draw_all (0.1.0)\n\n${LOCK("    rake (13.2.1)\n", "  draw_all!\n  kaminari!\n  rake\n")}`,
    });
    const got = partials("RubyGems");
    expect(got).toHaveLength(1);
    expect(got[0].error).toMatch(/Gemfile installs kaminari from the registry, but this lockfile holds it from a local path/);
    expect(got[0].error).not.toMatch(/draw_all/);
  });
  it("composer: an empty packages-dev beside a require-dev it lacks is said as not compared (php05)", () => {
    write({
      "composer.json": JSON.stringify({ require: { "a/a": "1" }, "require-dev": { "mockery/mockery": "^1" } }),
      "composer.lock": JSON.stringify({ packages: [{ name: "a/a", version: "1.0.0", dist: { type: "zip", url: "https://api.github.com/x" } }], "packages-dev": [] }),
    });
    expect(partials("Packagist")).toEqual([]);
    expect(notes("Packagist")[0]?.error).toMatch(/require-dev \(mockery\/mockery\) was not compared/);
  });
  it("Pipfile: a custom category the lock holds is compared; one it lacks is said (pf07)", () => {
    const lock = (extra: Record<string, unknown>) => JSON.stringify({ _meta: { sources: [] }, default: { six: { version: "==1.16.0" } }, develop: {}, ...extra });
    write({ Pipfile: '[packages]\nsix = "*"\n\n[docs]\nmkdocs = "*"\n', "Pipfile.lock": lock({}) });
    expect(partials("PyPI")).toEqual([]);
    expect(notes("PyPI")[0]?.error).toMatch(/no section for the category docs/);
    write({ "Pipfile.lock": lock({ docs: { sphinx: { version: "==7.0.0" } } }) });
    expect(partials("PyPI")[0]?.error).toMatch(/Pipfile declares mkdocs, but/);
  });
});

describe("1a: a lockfile only not compared with its manifest is a note, never a lead", () => {
  it("the totals stay numbers, the summary leads with nothing, the plan keeps its data", async () => {
    write({ "composer.json": "{ not json", "composer.lock": JSON.stringify({ packages: [{ name: "a/a", version: "1.0.0", dist: { type: "zip", url: "https://api.github.com/repos/a/a/zipball/x" } }], "packages-dev": [] }) });
    const scan = await call("vulnerability_scan", { force_refresh: true });
    expect(scan.total_vulnerable_packages).toBe(0);
    expect(scan.found_in_checked_dependencies).toBeUndefined();
    expect(scan.summary ?? "").not.toMatch(/NOT CHECKED/);
    expect(scan.coverage.not_cross_checked_lockfiles.map((p: { path: string }) => p.path)).toEqual(["composer.lock"]);
    const plan = await call("upgrade_planner", {});
    expect(plan.vulnerabilityDataAvailable).toBe(true);
  });
});
