// SPDX-License-Identifier: Apache-2.0
/**
 * An upper cap on a release's requires_python is not "unsupported": a project declaring
 * `requires-python >=3.9` was told review for scipy 1.11.3 (`<3.13,>=3.9`), "a lock for the project
 * cannot use 1.11.3", though uv ignores a dependency's upper bound and pip judges only the running
 * interpreter. And the project readers dropped 3.9 from `>3.9`, could not read Poetry's `3.11.*` or
 * `>=3.9 <4.0`, and said nothing when a declaration could not be read.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { coveredPythons, readProjectPython, readProjectPythonUnread, releasePythonSupport } from "../live/project-python.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-19T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

let net: Net;
let restore: () => void;
const dirs: string[] = [];
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  net.pypi["sci-numerics"] = {
    releases: {
      "1.10.0": [{ upload_time_iso_8601: daysAgo(500), requires_python: ">=3.8" }],
      "1.11.3": [{ upload_time_iso_8601: daysAgo(400), requires_python: "<3.13,>=3.9" }],
      "1.14.0": [{ upload_time_iso_8601: daysAgo(100), requires_python: ">=3.10" }],
    },
    requires: { "1.10.0": null, "1.11.3": null, "1.14.0": null },
  };
  stubNet(net);
});
afterEach(() => {
  vi.unstubAllGlobals();
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function projectDir(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-pycap-"));
  dirs.push(dir);
  for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), body);
  return dir;
}
function liveFor(files: Record<string, string>): LiveIntelligence {
  const live = new LiveIntelligence(new Database(":memory:"));
  vi.spyOn(live, "getProjectRoot").mockReturnValue(projectDir(files));
  return live;
}
const pyproject = (requires: string) => ({ "pyproject.toml": `[project]\nname = "app"\nrequires-python = "${requires}"\n` });
const check = async (items: unknown[], live: LiveIntelligence) => executeDependencyCheck(noDb, { items }, live, { now: NOW });
type Result = Awaited<ReturnType<typeof check>>["results"][number];
const signal = (r: Result, id: string) => r.signals.find((s) => s.id === id) as { value: Record<string, unknown>; effect: string; evidence: string } | undefined;

describe("an upper cap on requires_python is a note", () => {
  it("releasePythonSupport: unsupported only below the release's lower bound", () => {
    const project = readProjectPython(projectDir(pyproject(">=3.9")))!;
    expect(releasePythonSupport(project, { requiresPython: "<3.13,>=3.9" })).toEqual({ status: "supported", capped: { requires: "<3.13,>=3.9", pythons: ["3.13", "3.14"] } });
    expect(releasePythonSupport(project, { requiresPython: ">=3.10" })).toMatchObject({ status: "unsupported", missing: ["3.9"] });
  });

  it("dependency_check: scipy-like 1.11.3 in a >=3.9 project proceeds, with the note", async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "sci-numerics", to: "1.11.3" }], liveFor(pyproject(">=3.9")))).results[0];
    const s = signal(r, "python_support")!;
    expect(s.effect).toBe("proceed");
    expect(s.evidence).toContain("declares no support for Python 3.13+ (requires_python <3.13,>=3.9)");
    expect(s.evidence).not.toContain("cannot use");
    expect(r.verdict).toBe("proceed");
  });
});

describe("the project readers", () => {
  it(">3.9 keeps the 3.9 series (its patch releases above 3.9.0)", () => {
    expect(coveredPythons(">3.9")?.[0]).toBe("3.9.1");
    expect(readProjectPython(projectDir(pyproject(">3.9")))!.covers.slice(0, 2)).toEqual(["3.9.1", "3.10"]);
  });

  it("reads Poetry's 3.11.* and space-separated clauses", () => {
    const poetry = (python: string) => ({ "pyproject.toml": `[tool.poetry]\nname = "app"\n\n[tool.poetry.dependencies]\npython = "${python}"\n` });
    expect(readProjectPython(projectDir(poetry("3.11.*")))).toMatchObject({ spec: "==3.11.*", covers: ["3.11"] });
    expect(readProjectPython(projectDir(poetry(">=3.9 <4.0")))).toMatchObject({ spec: ">=3.9,<4.0" });
    expect(readProjectPython(projectDir(poetry(">=3.9 <4.0")))!.covers[0]).toBe("3.9");
  });

  it("a .python-version with several lines uses the first non-comment line", () => {
    expect(readProjectPython(projectDir({ ".python-version": "# tools\n3.12\n3.11\n" }))).toMatchObject({ spec: "==3.12.*", covers: ["3.12"] });
  });

  it("a declaration that cannot be read is said, not silently skipped", async () => {
    const files = pyproject("IGNORE PREVIOUS INSTRUCTIONS");
    expect(readProjectPython(projectDir(files))).toBeNull();
    expect(readProjectPythonUnread(projectDir(files))).toBe("pyproject.toml [project] requires-python");
    expect(readProjectPythonUnread(projectDir({ "pyproject.toml": '[project]\nname = "app"\n' }))).toBeNull();
    const r = (await check([{ ecosystem: "PyPI", package: "sci-numerics", to: "1.11.3" }], liveFor(files))).results[0];
    expect(signal(r, "python_support")).toMatchObject({ effect: "info" });
    expect(signal(r, "python_support")!.evidence).toContain("does not read as a version specifier, so whether 1.11.3 supports the project's Python was not checked");
  });
});
