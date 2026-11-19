// SPDX-License-Identifier: Apache-2.0
/**
 * A requirements pin is dev-only when every file that brings it in is a dev file by name: the
 * file it is written in, and every file that includes that one with `-r`. A production file a
 * dev file includes (`requirements-dev.txt` -> `-r prod.txt`) installs in production too, so
 * its pins are scanned as production, also with `include_dev: false`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { resolvePython } from "../live/lockfile-parsers-pygo.js";
import { LiveIntelligence } from "../live/index.js";
import { scanCurrentProject } from "../project-scanner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

let dir: string;
let priorOffline: string | undefined;
const write = (rel: string, content: string) => {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
};
/** name -> the scope the reader recorded for that pin: "dev", or "unknown" (never discounted, never left out). */
const scopes = () => Object.fromEntries(resolvePython(dir).instances.map((i) => [i.name, i.dev === true ? "dev" : i.dev === false ? "runtime" : "unknown"]));

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1119-devscope-"));
  // OSV: django and pytest each carry one HIGH advisory, whatever the version.
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      return new Response(JSON.stringify({ results: queries.map((q) => (["django", "pytest"].includes(q.package.name.toLowerCase()) ? { vulns: [{ id: `GHSA-${q.package.name.toLowerCase()}` }] } : {})) }), { status: 200 });
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

const scan = async (extra: Record<string, unknown> = {}) =>
  (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed", ...extra }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;

describe("a dev-named requirements file that includes a production file", () => {
  beforeEach(() => {
    write("prod.txt", "Django==3.2.0\ngunicorn==19.9.0\n");
    write("requirements-dev.txt", "-r prod.txt\npytest==5.4.2\n");
  });

  it("the reader marks only the dev file's own pins as dev", () => {
    expect(scopes()).toEqual({ django: "unknown", gunicorn: "unknown", pytest: "dev" });
  });

  it("the project's declared dependencies put the production pins under dependencies, the dev file's own under devDependencies", () => {
    const python = scanCurrentProject(dir).depsByEcosystem.python;
    expect([...python.deps].sort()).toEqual(["django", "gunicorn"]);
    expect(python.devDeps).toEqual(["pytest"]);
  });

  it("Django is scanned as production: not dev, and its grade is the advisory's own", async () => {
    const result = await scan();
    const django = result.vulnerabilities.find((v: { package: string }) => v.package === "django");
    expect(django).toMatchObject({ current_version: "3.2.0", is_dev: false, severity: "high", advisory_severity: "high" });
    const pytest = result.vulnerabilities.find((v: { package: string }) => v.package === "pytest");
    expect(pytest).toMatchObject({ is_dev: true, dev_scope_known: true, severity: "medium", advisory_severity: "high" });
  });

  it("include_dev: false still scans the production pins, and leaves out only the dev file's own", async () => {
    const result = await scan({ include_dev: false });
    expect(result.total_dependencies_scanned).toBe(2);
    expect(result.vulnerabilities.map((v: { package: string }) => v.package)).toEqual(["django"]);
    expect(result.total_vulnerable_packages).toBe(1);
  });
});

describe("the rule, over other include shapes", () => {
  it("a chain of dev-named files stays dev", () => {
    write("requirements-dev.txt", "-r requirements-test.txt\nblack==24.1.0\n");
    write("requirements-test.txt", "pytest==5.4.2\n");
    expect(scopes()).toEqual({ black: "dev", pytest: "dev" });
  });

  it("a dev-named file that a production file includes installs in production", () => {
    write("requirements.txt", "-r requirements-dev.txt\nrequests==2.19.1\n");
    write("requirements-dev.txt", "pytest==5.4.2\n");
    expect(scopes()).toEqual({ pytest: "unknown", requests: "unknown" });
    expect(scanCurrentProject(dir).depsByEcosystem.python).toEqual({ deps: expect.arrayContaining(["pytest", "requests"]), devDeps: [] });
  });

  it("a production file reached only through two dev files is still production", () => {
    write("requirements-dev.txt", "-r requirements-test.txt\n");
    write("requirements-test.txt", "-r pinned/base.txt\npytest==5.4.2\n");
    write("pinned/base.txt", "Django==3.2.0\n");
    expect(scopes()).toEqual({ django: "unknown", pytest: "dev" });
  });

  it("a package both a production and a dev file pin is production", () => {
    write("requirements.txt", "six==1.16.0\n");
    write("requirements-dev.txt", "six==1.16.0\npytest==5.4.2\n");
    expect(scopes()).toEqual({ six: "unknown", pytest: "dev" });
  });

  it("requirements/dev.txt including requirements/base.txt: base pins are production", () => {
    write("requirements/base.txt", "Django==3.2.0\n");
    write("requirements/dev.txt", "-r base.txt\npytest==5.4.2\n");
    expect(scopes()).toEqual({ django: "unknown", pytest: "dev" });
  });

  it("an include loop ends, and decides nothing by itself", () => {
    write("requirements-dev.txt", "-r requirements-test.txt\nblack==24.1.0\n");
    write("requirements-test.txt", "-r requirements-dev.txt\npytest==5.4.2\n");
    expect(scopes()).toEqual({ black: "dev", pytest: "dev" });
  });
});
