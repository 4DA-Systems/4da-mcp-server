// SPDX-License-Identifier: Apache-2.0
/**
 * Pins and manifests that were skipped without a word:
 * - `tornado==6.0.4,!=6.0.5`: an `==` clause is an exact pin whatever other clauses accompany it;
 * - a pyproject.toml whose requirements are exact `==` pins, with no lockfile: checked the way
 *   requirements pins are, as exact pins in package.json and Cargo.toml already are;
 * - `replace` directives in a go.work that uses the module: honoured as go.mod's are;
 * - gems.locked (Bundler's lockfile beside gems.rb): read as the Gemfile.lock it is.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { parseRequirements, resolvePython, unpinnedRequirements } from "../live/lockfile-parsers-pygo.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { goIndirectRaise } from "../live/pygo-parents.js";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups, unsupportedEcosystem } from "../project-tree.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

let dir: string;
let priorOffline: string | undefined;
/** Every (name, version) a stubbed OSV batch was asked about. */
let asked: string[];
const write = (rel: string, content: string) => {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
  return file;
};

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1119-skipped-"));
  asked = [];
  // OSV: requests carries one HIGH advisory, whatever the version.
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      for (const q of queries) asked.push(`${q.package.name}@${q.version}`);
      return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name.toLowerCase() === "requests" ? { vulns: [{ id: "GHSA-requests" }] } : {})) }), { status: 200 });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      return new Response(JSON.stringify({ id, summary: id, database_specific: { severity: "HIGH" } }), { status: 200 });
    }
    throw new TypeError(`fetch failed (${url})`);
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

// force_refresh: `asked` must show every dependency of this scan, not only those no earlier test's answer is cached for.
const scan = async (extra: Record<string, unknown> = {}) =>
  (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed", force_refresh: true, ...extra }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
const pinsOf = (ecosystem: "PyPI" | "Go" | "RubyGems", at = dir) => resolveVersionSource(at, ecosystem).instances.map((i) => `${i.name}@${i.version}`).sort();

describe("an `==` clause is an exact pin whatever other clauses accompany it", () => {
  const REQUIREMENTS = [
    "numpy==1.19.*",
    "tornado==6.0.4,!=6.0.5",
    "idna>=2.5,==2.8",
    "requests==2.19.1",
    'urllib3 (==1.26.5, <2) ; python_version >= "3.6"',
    "six===1.16.0,>=1.0 --hash=sha256:abc",
    "flask>=2,<3",
    "click!=8.0.0",
    "",
  ].join("\n");

  it("the pin is read, with or without spaces, parentheses, markers and options", () => {
    const pins = Object.fromEntries(parseRequirements(REQUIREMENTS).map((p) => [p.name, p.version]));
    expect(pins).toEqual({ numpy: "1.19.*", tornado: "6.0.4", idna: "2.8", requests: "2.19.1", urllib3: "1.26.5", six: "1.16.0" });
    expect(parseRequirements("tornado == 6.0.4 , != 6.0.5\n")).toEqual([{ name: "tornado", version: "6.0.4" }]);
  });

  it("what has no exact clause is still listed as unpinned, and nothing is in neither list", () => {
    expect(unpinnedRequirements(REQUIREMENTS).names.sort()).toEqual(["click", "flask"]);
  });

  it("the scan checks tornado 6.0.4 and idna 2.8", async () => {
    write("requirements.txt", "tornado==6.0.4,!=6.0.5\nidna>=2.5,==2.8\nrequests==2.19.1\n");
    const result = await scan();
    expect(result.total_dependencies_scanned).toBe(3);
    expect(asked.sort()).toEqual(["idna@2.8", "requests@2.19.1", "tornado@6.0.4"]);
  });
});

describe("a pyproject.toml of exact pins with no lockfile", () => {
  const PYPROJECT = `[project]
name = "fx"
version = "0.1.0"
dependencies = [
  "requests==2.19.1",
  "PyYAML==5.1",
  "flask>=2",
  "click",
]

[project.optional-dependencies]
docs = ["sphinx==7.2.6"]

[dependency-groups]
test = ["pytest==5.4.2", {include-group = "lint"}]
lint = ["ruff>=0.4"]
`;

  it("the reader returns the exact pins and lists the rest as unpinned", () => {
    write("pyproject.toml", PYPROJECT);
    const read = resolvePython(dir);
    expect(read.source).toBe(path.join(dir, "pyproject.toml"));
    expect(read.kind).toBe("declared_ranges");
    expect(read.instances).toEqual([
      { name: "requests", version: "2.19.1" },
      { name: "pyyaml", version: "5.1" },
      { name: "sphinx", version: "7.2.6" },
      { name: "pytest", version: "5.4.2", dev: true },
    ]);
    expect(read.unpinned).toEqual([{ file: path.join(dir, "pyproject.toml"), names: ["flask", "click", "ruff"] }]);
  });

  it("the scan checks them, as direct dependencies, and says what it could not", async () => {
    write("pyproject.toml", PYPROJECT);
    const result = await scan();
    expect(result.ecosystems_scanned).toEqual(["PyPI"]);
    expect(result.total_dependencies_scanned).toBe(4);
    expect(asked.sort()).toEqual(["pytest@5.4.2", "pyyaml@5.1", "requests@2.19.1", "sphinx@7.2.6"]);
    expect(result.vulnerabilities.find((v: { package: string }) => v.package === "requests")).toMatchObject({ current_version: "2.19.1", is_direct: true, is_dev: false });
    // Only the pins were checked: the tree they install is resolved nowhere, and ranged names have no version.
    expect(result.coverage.complete).toBe(false);
    expect(result.coverage.note).toMatch(/NO LOCKFILE: pyproject\.toml has no lockfile, so only the 4 exact pins declared there were checked/);
    expect(result.coverage.unpinned_requirements).toEqual([{ file: "pyproject.toml", count: 3, names: ["flask", "click", "ruff"] }]);
    expect(JSON.stringify(result)).not.toMatch(/4 requirements in pyproject\.toml name no exact version/);
  });

  it("with include_dev: false the dependency-group pin is left out", async () => {
    write("pyproject.toml", PYPROJECT);
    await scan({ include_dev: false });
    expect(asked.sort()).toEqual(["pyyaml@5.1", "requests@2.19.1", "sphinx@7.2.6"]);
  });

  it("beside a requirements file the pins of both are read", () => {
    write("pyproject.toml", PYPROJECT);
    write("requirements.txt", "gunicorn==19.9.0\n");
    const read = resolvePython(dir);
    expect(read.kind).toBe("manifest");
    expect(pinsOf("PyPI")).toEqual(["gunicorn@19.9.0", "pytest@5.4.2", "pyyaml@5.1", "requests@2.19.1", "sphinx@7.2.6"]);
  });

  it("beside a lockfile the lockfile is what is installed: the manifest's pins are not a second source", () => {
    write("pyproject.toml", PYPROJECT);
    write("uv.lock", 'version = 1\nrequires-python = ">=3.8"\n\n[[package]]\nname = "click"\nversion = "8.1.7"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "flask"\nversion = "2.3.0"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "pyyaml"\nversion = "5.1"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "requests"\nversion = "2.19.1"\nsource = { registry = "https://pypi.org/simple" }\n');
    const read = resolvePython(dir);
    expect(read.kind).toBe("lockfile");
    expect(read.source).toBe(path.join(dir, "uv.lock"));
    expect(read.extraSources ?? []).toEqual([]);
  });

  it("a pyproject.toml with no exact pin is left to the unpinned-requirements path, as before", () => {
    write("pyproject.toml", '[project]\nname = "fx"\ndependencies = ["flask>=2"]\n');
    const read = resolvePython(dir);
    expect(read.source).toBeNull();
    expect(read.instances).toEqual([]);
  });

  it("a pin behind an index that is not public is never sent", async () => {
    write("pyproject.toml", '[project]\nname = "fx"\ndependencies = ["acme-internal==1.0.0", "requests==2.19.1"]\n\n[tool.uv]\nindex-url = "https://pkgs.acme.dev/simple"\n');
    const result = await scan();
    expect(asked).toEqual([]);
    expect(JSON.stringify(result)).toMatch(/NOT CHECKED/);
  });
});

describe("go.work `replace` directives are honoured as go.mod's are", () => {
  const GO_MOD = "module github.com/golang/example\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n";

  it("a replace in the workspace file above a module it uses decides what is built", () => {
    write("go.work", "go 1.21\n\nuse ./svc\n\nreplace golang.org/x/text => golang.org/x/text v0.3.8\n");
    write("svc/go.mod", GO_MOD);
    expect(pinsOf("Go", path.join(dir, "svc"))).toEqual(["golang.org/x/text@v0.3.8"]);
  });

  it("block form, a versioned left side, and a go.work beside the go.mod", () => {
    write("go.work", "go 1.21\n\nuse (\n\t.\n\t./tools\n)\n\nreplace (\n\tgolang.org/x/text v0.3.0 => golang.org/x/text v0.3.8\n\tgolang.org/x/net v0.1.0 => golang.org/x/net v0.7.0\n)\n");
    write("go.mod", GO_MOD);
    expect(pinsOf("Go")).toEqual(["golang.org/x/text@v0.3.8"]);
  });

  it("go.work wins over a go.mod replace of the same module", () => {
    write("go.work", "go 1.21\n\nuse ./svc\n\nreplace golang.org/x/text => golang.org/x/text v0.3.8\n");
    write("svc/go.mod", `${GO_MOD}\nreplace golang.org/x/text => golang.org/x/text v0.3.5\n`);
    expect(pinsOf("Go", path.join(dir, "svc"))).toEqual(["golang.org/x/text@v0.3.8"]);
  });

  it("a replace by a directory makes the module local code: not a release, never sent", () => {
    write("go.work", "go 1.21\n\nuse ./svc\n\nreplace golang.org/x/text => ../forks/text\n");
    write("svc/go.mod", GO_MOD);
    const read = resolveVersionSource(path.join(dir, "svc"), "Go");
    expect(read.instances).toEqual([]);
    expect(read.privateIndex).toEqual(expect.arrayContaining([expect.objectContaining({ name: "golang.org/x/text", local: true })]));
  });

  it("a go.work that does not use the module leaves it alone", () => {
    write("go.work", "go 1.21\n\nuse ./other\n\nreplace golang.org/x/text => golang.org/x/text v0.3.8\n");
    write("svc/go.mod", GO_MOD);
    expect(pinsOf("Go", path.join(dir, "svc"))).toEqual(["golang.org/x/text@v0.3.0"]);
  });

  it("no `go get` is named for an indirect module the workspace replaces: it would not change the build", () => {
    write("go.work", "go 1.21\n\nuse ./svc\n\nreplace golang.org/x/text => golang.org/x/text v0.3.8\n");
    const goMod = write("svc/go.mod", "module github.com/golang/example\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0 // indirect\n");
    expect(goIndirectRaise(goMod, "golang.org/x/text", "v0.3.8", "v0.41.0")).toBeNull();
    // The same module with no workspace replace keeps its command.
    fs.rmSync(path.join(dir, "go.work"));
    const plain = write("plain/go.mod", "module github.com/golang/example\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0 // indirect\n");
    expect(goIndirectRaise(plain, "golang.org/x/text", "v0.3.0", "v0.41.0")).toBe("go get golang.org/x/text@v0.41.0");
  });
});

describe("gems.locked is read as the Gemfile.lock it is", () => {
  const GEMS_LOCKED = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.0.7)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n";

  it("the reader returns its gems", () => {
    write("gems.rb", 'source "https://rubygems.org"\ngem "rack"\n');
    write("gems.locked", GEMS_LOCKED);
    const read = resolveVersionSource(dir, "RubyGems");
    expect(read.source).toBe(path.join(dir, "gems.locked"));
    expect(pinsOf("RubyGems")).toEqual(["rack@2.0.7"]);
  });

  it("a directory that holds only gems.locked is found and scanned", async () => {
    write("services/api/gems.locked", GEMS_LOCKED);
    const { entries } = scanProjectTree(dir);
    const groups = treeResolutionGroups(entries);
    expect(groups.map((g) => `${path.relative(dir, g.dir).replace(/\\/g, "/")}:${g.language}`)).toContain("services/api:ruby");
    const result = await scan();
    expect(result.ecosystems_scanned).toEqual(["RubyGems"]);
    expect(asked).toEqual(["rack@2.0.7"]);
  });

  it("Gemfile.lock is the one read when both are present and there is no gems.rb", () => {
    write("Gemfile.lock", GEMS_LOCKED.replace("2.0.7", "2.2.8"));
    write("gems.locked", GEMS_LOCKED);
    expect(pinsOf("RubyGems")).toEqual(["rack@2.2.8"]);
    expect(resolveVersionSource(dir, "RubyGems").problems ?? []).toEqual([]);
  });

  it("with a gems.rb Bundler uses gems.locked, and a Gemfile.lock left beside it is said to be passed over", () => {
    write("gems.rb", 'source "https://rubygems.org"\ngem "rack"\n');
    write("Gemfile.lock", GEMS_LOCKED.replace("2.0.7", "2.2.8"));
    write("gems.locked", GEMS_LOCKED);
    expect(pinsOf("RubyGems")).toEqual(["rack@2.0.7"]);
    expect(resolveVersionSource(dir, "RubyGems").problems).toEqual([expect.objectContaining({ file: path.join(dir, "Gemfile.lock"), conflict: true })]);
  });

  it("a damaged gems.locked is named like a damaged Gemfile.lock", () => {
    write("gems.locked", GEMS_LOCKED.slice(0, GEMS_LOCKED.indexOf("PLATFORMS")));
    const problems = resolveVersionSource(dir, "RubyGems").problems ?? [];
    expect(problems).toEqual([expect.objectContaining({ file: path.join(dir, "gems.locked"), partial: true })]);
  });

  it("gems.rb with no lockfile is NOT COVERED, as a Gemfile with no Gemfile.lock is, never \"nothing found\"", async () => {
    expect(unsupportedEcosystem("gems.rb", ["gems.rb"])).toBe("RubyGems (gems.rb with no gems.locked)");
    expect(unsupportedEcosystem("gems.rb", ["gems.rb", "gems.locked"])).toBeNull();
    write("gems.rb", 'source "https://rubygems.org"\ngem "rack"\n');
    const result = await scan();
    expect(result.total_vulnerable_packages).not.toBe(0);
    expect(JSON.stringify(result)).toMatch(/NOT COVERED[^"]*gems\.rb/);
    expect(JSON.stringify(result)).not.toMatch(/none of an unsupported one either/);
  });
});
