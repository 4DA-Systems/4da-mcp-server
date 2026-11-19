// SPDX-License-Identifier: Apache-2.0
/**
 * A Poetry project with no poetry.lock: what its `[tool.poetry.dependencies]`,
 * `[tool.poetry.dev-dependencies]` and `[tool.poetry.group.<name>.dependencies]` tables declare.
 * In Poetry a bare version (`requests = "2.31.0"`) is an exact pin, as `==2.31.0` is: that version
 * is installed, so it is scanned as that version, as a PEP 621 `requests==2.31.0` is. Every other
 * constraint (`^`, `~`, `>=,<`, `*`, `2.31.*`, several constraints) names no installed version and
 * is listed as unpinned, never scanned or sent as a version. `python` is not a package. A git or
 * url entry is not a registry release (not_checkable), a path entry is the project's own code, and
 * an entry from a private source is private: none of them is sent.
 */

import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { removeProject, stubOsv, tempProject } from "./helpers/a1119-readers.js";

const PYPROJECT = `[tool.poetry]
name = "demo"
version = "0.1.0"

[[tool.poetry.source]]
name = "acme"
url = "https://pkgs.acme.dev/simple/"
priority = "explicit"

[tool.poetry.dependencies]
python = "^3.9"
requests = "2.31.0"
urllib3 = { version = "1.26.5", extras = ["socks"] }
PyYAML = "==6.0.1"
idna = "=3.4"
flask = "^2.0"
django = "~4.2"
jinja2 = ">=2,<3"
click = "*"
werkzeug = "2.3.*"
numpy = [
  { version = "1.24.4", python = "<3.12" },
  { version = "1.26.4", python = ">=3.12" },
]
mylib = { path = "../mylib", develop = true }
gitpkg = { git = "https://github.com/example/gitpkg.git", tag = "v1.0.0" }
urlpkg = { url = "https://files.example.org/urlpkg-1.0.0-py3-none-any.whl" }
omega-risk = { version = "1.4.0", source = "acme" }

[tool.poetry.group.dev.dependencies]
pytest = "7.4.0"
black = "^23.1"

[tool.poetry.dev-dependencies]
coverage = { version = "7.2.7" }
`;

const read = (dir: string) => resolveVersionSource(dir, "PyPI");

describe("Poetry dependency tables with no poetry.lock", () => {
  let dirs: string[];
  let priorOffline: string | undefined;
  const project = (files: Record<string, string>) => {
    const dir = tempProject(files);
    dirs.push(dir);
    return dir;
  };
  beforeEach(() => {
    dirs = [];
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    dirs.forEach(removeProject);
  });

  it("an exact version is a pin, scanned as that version; a group's pin is a development one", () => {
    const source = read(project({ "pyproject.toml": PYPROJECT }));
    const pins = Object.fromEntries(source.instances.map((i) => [i.name, `${i.version}${i.dev ? " dev" : ""}`]));
    expect(pins).toEqual({ requests: "2.31.0", urllib3: "1.26.5", pyyaml: "6.0.1", idna: "3.4", "omega-risk": "1.4.0", pytest: "7.4.0 dev", coverage: "7.2.7 dev" });
    expect(source.kind).toBe("declared_ranges");
  });

  it("every other constraint is listed as unpinned; python, git, url and path entries are not", () => {
    const source = read(project({ "pyproject.toml": PYPROJECT }));
    const unpinned = (source.unpinned ?? []).flatMap((u) => u.names).sort();
    expect(unpinned).toEqual(["black", "click", "django", "flask", "jinja2", "numpy", "werkzeug"]);
    expect((source.uncheckable ?? []).map((u) => `${u.name} ${u.kind}`).sort()).toEqual(["gitpkg git", "urlpkg url"]);
    for (const name of ["python", "mylib", "gitpkg", "urlpkg"]) expect(source.versions.has(name)).toBe(false);
  });

  it("a project with only ranges lists them all, and checks nothing", () => {
    const source = read(project({ "pyproject.toml": `[tool.poetry.dependencies]\npython = "^3.9"\nflask = "^2.0"\nclick = "*"\n` }));
    expect(source.instances).toEqual([]);
  });

  it("vulnerability_scan sends the pins, never a range's floor, the python constraint, a git, url or path entry, or a private source's name", async () => {
    const { asked } = stubOsv([]);
    const dir = project({ "pyproject.toml": PYPROJECT });
    const live = new LiveIntelligence(new Database(":memory:"));
    const { entries, discovery } = scanProjectTree(dir);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    const answer = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed", include_dev: true }, live)) as Record<string, any>;
    expect(asked.sort()).toEqual(["coverage@7.2.7", "idna@3.4", "pytest@7.4.0", "pyyaml@6.0.1", "requests@2.31.0", "urllib3@1.26.5"]);
    const sent = JSON.stringify(asked);
    for (const name of ["omega-risk", "flask", "click", "numpy", "python", "mylib", "gitpkg", "urlpkg", "black"]) expect(sent).not.toContain(name);
    expect(answer.coverage.unpinned_requirements[0].names.sort()).toEqual(["black", "click", "django", "flask", "jinja2", "numpy", "werkzeug"]);
    expect(answer.coverage.not_checkable.map((u: { package: string }) => u.package).sort()).toEqual(["gitpkg", "urlpkg"]);
    // The private source's pin and the local path are reported as private, never as checked.
    expect(JSON.stringify(answer.coverage.private_dependency_list)).toMatch(/omega-risk/);
  });

  it("a primary private Poetry source: no pin is sent at all", async () => {
    const { asked } = stubOsv([]);
    const dir = project({
      "pyproject.toml": `[[tool.poetry.source]]\nname = "corp"\nurl = "https://pkgs.corp.dev/simple/"\n\n[tool.poetry.dependencies]\npython = "^3.9"\nrequests = "2.31.0"\n`,
    });
    const live = new LiveIntelligence(new Database(":memory:"));
    const { entries, discovery } = scanProjectTree(dir);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, live);
    expect(asked).toEqual([]);
  });
});
