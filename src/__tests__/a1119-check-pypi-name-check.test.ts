// SPDX-License-Identifier: Apache-2.0
/**
 * npm's lookalike-name check had no PyPI side: `expres` got review with "did you mean express",
 * while `numpi` got proceed with no name signal at all. PyPI names are compared as PyPI compares
 * them, against the bundled popular list, and an established project is not flagged for its name.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck, runDependencyCheck } from "../tools/dependency-check.js";
import { pypiNearMissOf } from "../tools/dependency-check-nearmiss-pypi.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, onlineForTests, stubNet, type Net, type PypiFixture } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-19T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

/** A project whose releases were first uploaded `oldest` days ago, `count` of them, 20 days apart. */
function project(count: number, oldest: number): PypiFixture {
  const versions = Array.from({ length: count }, (_, i) => `1.${i}.0`);
  return { releases: Object.fromEntries(versions.map((v, i) => [v, [{ upload_time_iso_8601: daysAgo(oldest - i * 20) }]])), requires: Object.fromEntries(versions.map((v) => [v, null])) };
}

let net: Net;
let restore: () => void;
let dir: string | null = null;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  net.pypi.numpi = project(1, 100);
  net.pypi.numpy = project(12, 4000);
  net.pypi.jinja = project(12, 4000);
  net.pypi["python3-dateutil"] = project(2, 300);
  net.pypi["Python_Dateutil"] = project(12, 4000);
  stubNet(net);
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  dir = null;
});

const live = () => new LiveIntelligence(new Database(":memory:"));
const check = async (items: unknown[], l = live()) => executeDependencyCheck(noDb, { items }, l, { now: NOW });
type Result = Awaited<ReturnType<typeof check>>["results"][number];
const nameCheck = (r: Result) => r.signals.find((s) => s.id === "name_check") as { value: Record<string, unknown>; effect: string; evidence: string } | undefined;
const latest = (pkg: string) => Object.keys(net.pypi[pkg].releases).pop()!;

describe("pypiNearMissOf", () => {
  it("compares PEP 503 names against the popular list and never flags a popular name", () => {
    expect(pypiNearMissOf("numpi")).toEqual({ of: "numpy", closeness: "one_edit" });
    expect(pypiNearMissOf("python3_dateutil")).toEqual({ of: "python-dateutil", closeness: "one_edit" });
    expect(pypiNearMissOf("Python_Dateutil")).toBeNull();
    expect(pypiNearMissOf("numpy")).toBeNull();
    expect(pypiNearMissOf("nump")).toBeNull();
  });
});

describe("dependency_check: a PyPI name one slip from a popular project", () => {
  it("a near-miss with a short history is review, with did you mean", async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "numpi", to: latest("numpi") }])).results[0];
    expect(r.verdict).toBe("review");
    expect(nameCheck(r)).toMatchObject({ effect: "review", value: { near_miss_of: "numpy", closeness: "one_edit", releases: 1, age_days: 100, weekly_downloads: null } });
    expect(r.reason).toContain("name_check: numpi is one character away from numpy, one of the most-used PyPI projects");
    expect(r.reason).toContain("Did you mean numpy?");
    // Judged from what was already read: the project document and OSV.dev, nothing else.
    expect(net.requests.filter((q) => !/^(GET https:\/\/pypi\.org\/pypi\/|POST https:\/\/api\.osv\.dev\/)/.test(q))).toEqual([]);
    const concise = (await runDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", package: "numpi", to: latest("numpi") }] }, live())) as { results: Array<Record<string, unknown>> };
    expect(concise.results[0]).toMatchObject({ verdict: "review" });
    expect(String(concise.results[0].reason)).toContain("Did you mean numpy?");
  });

  it("a near-miss first published days ago with one release is avoid", async () => {
    net.pypi.numpi = project(1, 10);
    const r = (await check([{ ecosystem: "PyPI", package: "numpi", to: latest("numpi") }])).results[0];
    expect(r.verdict).toBe("avoid");
    expect(nameCheck(r)!.evidence).toContain("Do not install it. Did you mean numpy?");
  });

  it("an established project is not flagged for its name, and a popular one is not checked at all", async () => {
    const [jinja, numpy, dateutil] = (
      await check([
        { ecosystem: "PyPI", package: "jinja", to: latest("jinja") },
        { ecosystem: "PyPI", package: "numpy", to: latest("numpy") },
        { ecosystem: "PyPI", package: "Python_Dateutil", to: latest("Python_Dateutil") },
      ])
    ).results;
    expect(nameCheck(jinja)).toMatchObject({ effect: "info", value: { near_miss_of: "jinja2", releases: 12 } });
    expect(jinja.verdict).toBe("proceed");
    // A name on the popular list is its own package, whatever it neighbours (pyaml, one edit from pyyaml).
    expect(pypiNearMissOf("pyaml")).toBeNull();
    expect(nameCheck(numpy)).toBeUndefined();
    expect(nameCheck(dateutil)).toBeUndefined();
  });

  it("a name the project's lockfiles already hold is not a new dependency", async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-pyname-"));
    fs.writeFileSync(path.join(dir, "requirements.txt"), `NumPi==${latest("numpi")}\n`);
    const l = live();
    const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
    const { entries, discovery } = scanProjectTree(dir);
    l.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    expect(l.getResolvedDeps().some((d) => d.ecosystem === "PyPI" && d.name.toLowerCase() === "numpi")).toBe(true);
    const r = (await check([{ ecosystem: "PyPI", package: "numpi", to: latest("numpi") }], l)).results[0];
    expect(nameCheck(r)).toBeUndefined();
  });

  it("a name PyPI does not serve is unknown, with did you mean", async () => {
    const r = (await check([{ ecosystem: "PyPI", package: "pandsa", to: "2.0.0" }])).results[0];
    expect(r.verdict).toBe("unknown");
    expect(r.reason).toContain("(did you mean pandas?)");
  });
});
