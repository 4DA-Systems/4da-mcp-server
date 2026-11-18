// SPDX-License-Identifier: Apache-2.0
/**
 * A package pinned in any requirements file of the project is declared by the user: it is a
 * direct dependency, and the fix is to change that pin in that file. `Pygments==2.7.3` in
 * requirements-dev.txt was called transitive ("never bump it directly", "not declared in your
 * manifest", waiting on upstream) although bumping the pin clears every advisory.
 *
 * End to end through vulnerability_scan and upgrade_planner, with OSV and PyPI stubbed.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import type { OsvVulnerability } from "../live/types.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import type { FourDADatabase } from "../db.js";

const noDb = null as unknown as FourDADatabase;

const advisory = (id: string, name: string, fixed: string): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name, ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed }] }] }],
});

const ADVISORIES: Record<string, OsvVulnerability[]> = {
  pygments: [advisory("PYSEC-2021-140", "pygments", "2.7.4"), advisory("PYSEC-2023-117", "pygments", "2.15.0")],
  pytest: [advisory("PYSEC-2022-42969", "pytest", "7.2.0")],
  mkdocs: [advisory("PYSEC-2021-878", "mkdocs", "1.2.3")],
  idna: [advisory("PYSEC-2024-60", "idna", "3.15")],
};
const RELEASES: Record<string, string[]> = {
  pygments: ["2.7.3", "2.7.4", "2.15.0", "2.20.0"],
  pytest: ["5.4.2", "7.2.0"],
  mkdocs: ["1.1.2", "1.2.3"],
  idna: ["2.7", "3.15"],
  requests: ["2.19.1"],
  jinja2: ["2.10"],
};

const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
const affects = (v: OsvVulnerability, version: string) => cmp(version, v.affected![0].ranges[0].events.find((e) => e.fixed)!.fixed!) < 0;

let dir: string;
let priorOffline: string | undefined;

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1119-declared-"));
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (ADVISORIES[q.package.name.toLowerCase()] ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(ADVISORIES).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: ADVISORIES[q.package.name.toLowerCase()] ?? [] });
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      const name = decodeURIComponent(pypi[1]).toLowerCase();
      const versions = RELEASES[name];
      if (!versions) return json({}, 404);
      const releases = Object.fromEntries(versions.map((v) => [v, [{ upload_time_iso_8601: "2024-01-01T00:00:00Z", yanked: false }]]));
      return json({ info: { name, version: versions[versions.length - 1], license: "", classifiers: [], summary: "", yanked: false, yanked_reason: null }, releases });
    }
    return json({}, 404);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

const write = (rel: string, body: string) => {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
};

type Step = { package: string; scope: string; action: string; targetVersion?: string; reasons: string[]; upgradeInstructions?: Array<{ dir: string; instruction: string }> };

async function plan() {
  const live = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  const result = (await executeUpgradePlanner(noDb, { project_path: dir, max_recommendations: 50 }, live)) as { recommendations: Step[] };
  return (name: string) => result.recommendations.find((s) => s.package === name) as Step;
}
const scan = async () =>
  (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed" }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
const instructions = (step: Step) => (step.upgradeInstructions ?? []).map((i) => i.instruction).join(" | ");

describe("a pin in requirements-dev.txt beside a requirements.txt", () => {
  beforeEach(() => {
    write("requirements.txt", "Jinja2==2.10\nrequests==2.19.1\n");
    write("requirements-dev.txt", "Pygments==2.7.3\n");
  });

  it("the scan lists it as a direct dev dependency and recommends the upgrade, never 'transitive'", async () => {
    const result = await scan();
    const rows = result.vulnerabilities.filter((v: { package: string }) => v.package === "pygments");
    expect(rows).toHaveLength(2);
    for (const row of rows) expect(row).toMatchObject({ current_version: "2.7.3", is_direct: true, is_dev: true });
    expect(result.fix_targets["pygments@2.7.3"]).toMatchObject({ action: "upgrade_direct", target: "2.15.0" });
    const line = result.recommendations.find((r: string) => /pygments/i.test(r));
    expect(line).toMatch(/^Upgrade pygments 2\.7\.3 → 2\.15\.0/);
    expect(JSON.stringify(result.recommendations)).not.toMatch(/is transitive|never bump it directly/);
  });

  it("the planner says to change the pin in requirements-dev.txt, not that it waits on upstream", async () => {
    const pygments = (await plan())("pygments");
    expect(pygments).toMatchObject({ scope: "direct", action: "upgrade_direct", targetVersion: "2.15.0" });
    expect(instructions(pygments)).toBe("change `Pygments==2.7.3` to `Pygments==2.15.0` in requirements-dev.txt");
    expect(pygments.reasons.join(" ")).not.toMatch(/not declared in your manifest|waiting/i);
  });
});

describe("the same holds for every requirements file the project has", () => {
  it("requirements-test.txt, requirements/docs.txt and an included file: each pin is direct and edited where it is written", async () => {
    write("requirements.txt", "-r pinned/web.txt\nrequests==2.19.1\n");
    write("pinned/web.txt", "idna==2.7\n");
    write("requirements-test.txt", "pytest==5.4.2\n");
    write("requirements/docs.txt", "mkdocs==1.1.2\nPygments==2.7.3\n");
    const step = await plan();
    expect(step("pytest")).toMatchObject({ scope: "direct", action: "upgrade_direct" });
    expect(instructions(step("pytest"))).toMatch(/^change `pytest==5\.4\.2` to `pytest==7\.2\.0` in requirements-test\.txt/);
    expect(step("mkdocs")).toMatchObject({ scope: "direct", action: "upgrade_direct" });
    expect(instructions(step("mkdocs"))).toMatch(/^change `mkdocs==1\.1\.2` to `mkdocs==1\.2\.3` in requirements\/docs\.txt/);
    expect(instructions(step("pygments"))).toMatch(/^change `Pygments==2\.7\.3` to `Pygments==2\.15\.0` in requirements\/docs\.txt/);
    expect(step("idna")).toMatchObject({ scope: "direct", action: "upgrade_direct" });
    expect(instructions(step("idna"))).toMatch(/^change `idna==2\.7` to `idna==3\.15` in pinned\/web\.txt/);

    const result = await scan();
    for (const name of ["pytest", "mkdocs", "pygments", "idna"]) {
      expect(result.vulnerabilities.find((v: { package: string }) => v.package === name)).toMatchObject({ is_direct: true });
    }
    // Dev by the file's name; idna comes in through requirements.txt, so it is production.
    expect(result.vulnerabilities.find((v: { package: string }) => v.package === "pytest").is_dev).toBe(true);
    expect(result.vulnerabilities.find((v: { package: string }) => v.package === "idna").is_dev).toBe(false);
  });

  it("a compiled file's `# via <package>` pin is still someone else's requirement: transitive", async () => {
    write("requirements.in", "requests==2.19.1\n");
    write("requirements-dev.txt", "# This file was autogenerated by uv via the following command:\n#    uv pip compile requirements.in -o requirements-dev.txt\nidna==2.7\n    # via requests\nrequests==2.19.1\n    # via -r requirements.in\n");
    const idna = (await plan())("idna");
    expect(idna.scope).toBe("transitive");
    expect(instructions(idna)).not.toMatch(/^change `idna==2\.7`/);
  });
});
