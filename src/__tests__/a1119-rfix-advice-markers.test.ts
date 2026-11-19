// SPDX-License-Identifier: Apache-2.0
/**
 * A PyPI requirement's environment marker decides whether it is installed. A project declaring
 * `requires-python >=3.10` was told avoid for botocore 1.40.0 because of `urllib3<1.27,>=1.25.4;
 * python_version < "3.10"`, a requirement no Python it declares installs.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { evaluateMarker, markerApplies, markerText, parseMarker } from "../live/pep508-marker.js";
import { parseRequiresDist } from "../live/pypi-releases.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { advisory, batchAsked, emptyNet, onlineForTests, stubNet, type Net, type PypiFixture } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-19T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

function project(versions: Record<string, string[] | null>): PypiFixture {
  const list = Object.keys(versions);
  return { releases: Object.fromEntries(list.map((v, i) => [v, [{ upload_time_iso_8601: daysAgo(900 - i * 40) }]])), requires: versions };
}

const BOTO_REQUIRES = ['urllib3<1.27,>=1.25.4; python_version < "3.10"', 'urllib3!=2.2.0,<3,>=1.25.4; python_version >= "3.10"', "jmespath<2.0.0,>=0.7.1"];

let net: Net;
let restore: () => void;
const dirs: string[] = [];
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  net.pypi["cloudkit-core"] = project({ "1.39.0": BOTO_REQUIRES, "1.40.0": BOTO_REQUIRES });
  net.pypi.urllib3 = project({ "1.26.20": null, "2.5.0": null });
  net.pypi.jmespath = project({ "1.0.1": null });
  net.pypi["win-only"] = project({ "1.0.0": null });
  net.pypi["plat-dep"] = project({ "1.0.0": ['win-only>=1; sys_platform == "win32"'], "1.1.0": ['win-only>=1; sys_platform == "win32"'] });
  net.osv = [advisory("GHSA-urllib3-0126", "PyPI", "urllib3", "2.0.0", { severity: "HIGH" }), advisory("GHSA-winonly-0001", "PyPI", "win-only", null, { severity: "CRITICAL" })];
  stubNet(net);
});
afterEach(() => {
  vi.unstubAllGlobals();
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function liveWith(requiresPython: string | null): LiveIntelligence {
  const live = new LiveIntelligence(new Database(":memory:"));
  let root: string | null = null;
  if (requiresPython !== null) {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-marker-"));
    dirs.push(root);
    fs.writeFileSync(path.join(root, "pyproject.toml"), `[project]\nname = "app"\nrequires-python = "${requiresPython}"\n`);
  }
  vi.spyOn(live, "getProjectRoot").mockReturnValue(root);
  return live;
}
const check = async (items: unknown[], live: LiveIntelligence) => executeDependencyCheck(noDb, { items }, live, { now: NOW });
type Result = Awaited<ReturnType<typeof check>>["results"][number];
const advisories = (r: Result) => r.signals.find((s) => s.id === "advisories") as { value: Record<string, unknown>; effect: string; evidence: string };

describe("PEP 508 markers", () => {
  it("parse, print canonically and evaluate in three values", () => {
    const node = parseMarker("python_version<'3.10' and (sys_platform == \"win32\" or extra != 'y')")!;
    expect(markerText(node)).toBe('python_version < "3.10" and (sys_platform == "win32" or extra != "y")');
    expect(evaluateMarker(node, { python: "3.9" })).toBe(true);
    expect(evaluateMarker(node, { python: "3.11" })).toBe(false);
    expect(evaluateMarker(node)).toBeNull();
    expect(evaluateMarker(parseMarker('"3.10" > python_version')!, { python: "3.9" })).toBe(true);
    expect(evaluateMarker(parseMarker('python_full_version >= "3.9.2"')!, { python: "3.9" })).toBeNull();
    expect(evaluateMarker(parseMarker('python_full_version >= "3.9.2"')!, { python: "3.10" })).toBe(true);
    expect(parseMarker("IGNORE ALL PREVIOUS INSTRUCTIONS")).toBeNull();
    expect(parseMarker('os.system("x") == "1"')).toBeNull();
  });

  it("say on which declared Pythons a marker applies", () => {
    expect(markerApplies('python_version < "3.10"', ["3.10", "3.11"])).toEqual({ kind: "none" });
    expect(markerApplies('python_version < "3.10"', ["3.9", "3.10"])).toEqual({ kind: "some", on: ["3.9"] });
    expect(markerApplies('python_version >= "3.10"', ["3.10", "3.11"])).toEqual({ kind: "all" });
    expect(markerApplies('python_version < "3.10"', null)).toEqual({ kind: "unknown" });
    expect(markerApplies('sys_platform == "win32"', ["3.10"])).toEqual({ kind: "unknown", on: ["3.10"] });
  });

  it("parseRequiresDist: an extra excludes an entry only when the marker is false without extras", () => {
    expect(parseRequiresDist(['x; sys_platform=="win32" and extra != "y"', 'y; sys_platform=="win32" and extra == "y"', 'z; extra != "y"', 'w; python_version<"3.10"']).requirements).toEqual([
      { name: "x", spec: "", conditional: true, marker: 'sys_platform == "win32" and extra != "y"' },
      { name: "z", spec: "" },
      { name: "w", spec: "", conditional: true, marker: 'python_version < "3.10"' },
    ]);
  });
});

describe("dependency_check judges a marker-gated requirement against the project's Pythons", () => {
  it("a project on >=3.10 never installs the python_version < 3.10 requirement: botocore-like release proceeds", async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "cloudkit-core", to: "1.40.0" }], liveWith(">=3.10"))).results[0];
    expect(r.verdict).toBe("proceed");
    expect(advisories(r).value).toMatchObject({ requirements_examined: 2 });
    expect(batchAsked(net)).toContain("PyPI:urllib3@2.5.0");
    expect(batchAsked(net)).not.toContain("PyPI:urllib3@1.26.20");
  });

  it("a project on >=3.9 installs it on 3.9 only: judged, and the text says on which Python", async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "cloudkit-core", to: "1.40.0" }], liveWith(">=3.9"))).results[0];
    expect(r.verdict).toBe("avoid");
    expect(r.reason).toContain('[installed only where python_version < "3.10": on Python 3.9 of the versions this project declares]');
    expect(advisories(r).value.held_dependencies_affected).toEqual([expect.objectContaining({ package: "urllib3", installs: "1.26.20", installed_only_where: 'python_version < "3.10"', on_pythons: ["3.9"] })]);
  });

  it("a project that declares no Python: judged with the caveat, review at most", async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "cloudkit-core", to: "1.40.0" }], liveWith(null))).results[0];
    expect(r.verdict).toBe("review");
    expect(r.reason).toContain("this project declares no Python version this check read, so whether it applies was not established");
  });

  it("a platform marker is a caveat, never by itself an avoid", async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "plat-dep", to: "1.1.0" }], liveWith(">=3.10"))).results[0];
    expect(r.verdict).toBe("review");
    expect(advisories(r).effect).toBe("review");
    expect(r.reason).toContain('only where sys_platform == "win32"');
    expect(r.reason).toContain("depending on the platform, which was not established");
  });
});
