// SPDX-License-Identifier: Apache-2.0
/**
 * A scan that could not know what is installed never reads as a clean one. The server tells
 * agents that an answer STARTING with NOT CHECKED is incomplete, so that is where it is said,
 * and the totals are null.
 *
 * Before this, on a package.json of 126 dependencies and no lockfile, vulnerability_scan had no
 * summary at all and answered `total_dependencies_scanned: 4, total_vulnerable_packages: 0`,
 * every severity 0; only `coverage.note` said that 122 ranges were not checked. An empty folder
 * (or a wrong path that exists) answered `coverage.complete: true` with zero totals.
 * dependency_health and the briefing already withheld on the same folders.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LiveIntelligence } from "../live/index.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

/** Packages the OSV stub reports one HIGH advisory for. */
const VULNERABLE = new Set(["lodash", "smallvec"]);

let dir: string;
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-bc-scan-"));
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      return new Response(JSON.stringify({ results: queries.map((q) => (VULNERABLE.has(q.package.name.toLowerCase()) ? { vulns: [{ id: `GHSA-${q.package.name.toLowerCase()}` }] } : {})) }), { status: 200 });
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

const write = (rel: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), content);
};
const npmLock = (deps: Record<string, string>) =>
  JSON.stringify({
    name: "x",
    lockfileVersion: 3,
    packages: {
      "": { name: "x", dependencies: deps },
      ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` }])),
    },
  });
const scan = async (extra: Record<string, unknown> = {}) =>
  (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true, ...extra }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;

/** Every total a reader could take for "clean". */
const totals = (r: Record<string, any>) => [r.total_vulnerable_packages, r.by_severity, r.by_advisory_severity];

describe("a manifest with no lockfile", () => {
  it("ranges and a few exact pins: the answer starts NOT CHECKED, the totals are null, the pins' count is a lower bound", async () => {
    write("package.json", JSON.stringify({ dependencies: { express: "^4.18.0", react: "^18.2.0", "left-pad": "1.3.0", ms: "2.1.3" }, devDependencies: { vitest: "^1.0.0" } }));
    for (const format of ["concise", "detailed"]) {
      const r = await scan({ response_format: format });
      expect(r.summary, format).toMatch(
        /^NOT CHECKED: no lockfile was read for this project, so what is installed is not known: the 3 declared ranges in package\.json were not checked; only the 2 exact pins were, and nothing they bring in\. This is not a clean result\. Generate a lockfile \(npm install --package-lock-only\) and scan again\./,
      );
      expect(totals(r), format).toEqual([null, null, null]);
      expect(r.total_dependencies_scanned, format).toBe(2);
      expect(r.found_in_checked_dependencies, format).toMatchObject({ vulnerable_packages: 0, by_severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } });
      expect(r.found_in_checked_dependencies.note, format).toMatch(/^Only the 2 exact pins declared in the manifest were checked, and nothing they bring in; these counts are a lower bound\./);
      expect(r.coverage, format).toMatchObject({ complete: false });
    }
  });

  it("a vulnerable exact pin is still found and listed, under the same lead", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20", express: "^4.18.0" } }));
    const r = await scan();
    expect(r.summary).toMatch(/^NOT CHECKED: no lockfile was read/);
    expect(totals(r)).toEqual([null, null, null]);
    expect(r.found_in_checked_dependencies.vulnerable_packages).toBe(1);
    expect(r.vulnerable_packages.map((p: { package: string }) => p.package)).toEqual(["lodash"]);
  });

  it("ranges only: nothing was checked, and it says so first", async () => {
    write("package.json", JSON.stringify({ dependencies: { express: "^4.18.0", react: "^18.2.0" } }));
    const r = await scan();
    expect(r.summary).toMatch(/^NOT CHECKED: no lockfile was read for this project, so what is installed is not known: the 2 declared ranges in package\.json were not checked\. This is not a clean result\./);
    expect(totals(r)).toEqual([null, null, null]);
    expect(r.found_in_checked_dependencies).toBeUndefined();
  });

  it("exact pins only: what they bring in was resolved nowhere", async () => {
    write("Cargo.toml", '[package]\nname = "fx"\nversion = "0.1.0"\n\n[dependencies]\nsmallvec = "=1.6.0"\nregex = "=1.5.4"\n');
    const r = await scan();
    expect(r.summary).toMatch(/^NOT CHECKED: no lockfile was read for this project, so what is installed is not known: only the 2 exact pins declared in Cargo\.toml were checked, and nothing they bring in\. This is not a clean result\. Generate a lockfile \(cargo generate-lockfile\) and scan again\./);
    expect(totals(r)).toEqual([null, null, null]);
    expect(r.found_in_checked_dependencies.vulnerable_packages).toBe(1);
  });
});

describe("what stays as it was", () => {
  it("a lockfile read for the project: totals are numbers and nothing leads the answer", async () => {
    write("package.json", JSON.stringify({ dependencies: { "left-pad": "1.3.0" } }));
    write("package-lock.json", npmLock({ "left-pad": "1.3.0" }));
    const r = await scan();
    expect(r.summary).toBeUndefined();
    expect(r.total_vulnerable_packages).toBe(0);
    expect(r.coverage).toMatchObject({ complete: true, lockfiles_read: 1 });
  });

  it("a lockfile read, and another manifest beside it without one: counted, with the manifest named in coverage", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
    write("package-lock.json", npmLock({ lodash: "4.17.20" }));
    write("tools/package.json", JSON.stringify({ dependencies: { express: "^4.18.0" } }));
    const r = await scan();
    expect(r.total_vulnerable_packages).toBe(1);
    expect(String(r.summary ?? "")).not.toMatch(/no lockfile was read for this project/);
    expect(r.coverage).toMatchObject({ complete: false });
    expect(r.coverage.note).toMatch(/1 manifest has no lockfile beside it and is no workspace member of one above \(tools\/package\.json\), so the dependencies it declares were not resolved and NOT checked/);
  });

  it("a requirements file's exact pins are the versions: counted", async () => {
    write("requirements.txt", "requests==2.31.0 \\\n    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f\nidna==3.4 \\\n    --hash=sha256:90b77e79eaa3eba6de819a0c442c0b4ceefc341a7a2ab77d7562bf49f425c5c2\n");
    const r = await scan();
    expect(r.total_vulnerable_packages).toBe(0);
    expect(String(r.summary ?? "")).not.toMatch(/^NOT CHECKED/);
  });
});

describe("a folder with nothing this server reads", () => {
  it("an empty folder: NOT CHECKED, null totals, and coverage does not call it complete", async () => {
    for (const format of ["concise", "detailed"]) {
      const r = await scan({ response_format: format });
      expect(r.summary, format).toBe(
        "NOT CHECKED: no lockfile or manifest this server reads was found under the project root, so nothing was scanned. If the project is in another folder, pass that folder as project_path.",
      );
      expect(totals(r), format).toEqual([null, null, null]);
      expect(r.total_dependencies_scanned, format).toBe(0);
      expect(r.coverage, format).toMatchObject({ complete: false });
      expect(r.coverage.note, format).toMatch(/^no lockfile or manifest this server reads was found/);
    }
  });

  it("source files and no manifest: the same", async () => {
    write("src/main.py", "print('hello')\n");
    write("README.md", "# notes\n");
    const r = await scan();
    expect(r.summary).toMatch(/^NOT CHECKED: no lockfile or manifest this server reads was found/);
    expect(totals(r)).toEqual([null, null, null]);
  });

  it("only an ecosystem this server does not read: the lead names it", async () => {
    write("pom.xml", "<project><modelVersion>4.0.0</modelVersion></project>\n");
    const r = await scan();
    expect(r.summary).toMatch(/^NOT CHECKED: nothing was scanned\. NOT COVERED: 1 manifest\/lockfile of ecosystems or formats this server does not read \(Maven\): pom\.xml/);
    expect(totals(r)).toEqual([null, null, null]);
  });

  it("a project that declares no dependency at all is a real zero", async () => {
    write("package.json", JSON.stringify({ name: "x" }));
    write("package-lock.json", JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x" } } }));
    const r = await scan();
    expect(String(r.summary ?? "")).not.toMatch(/^NOT CHECKED/);
    expect(r.total_vulnerable_packages).toBe(0);
    expect(r.coverage).toMatchObject({ complete: true });
  });
});

describe("a lockfile that exists and could not be read, beside one that could", () => {
  it("an unparseable package-lock.json beside pinned requirements: NOT CHECKED leads, the totals are a lower bound", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "^4.17.20" } }));
    write("package-lock.json", '{ "name": "x", "lockfileVersion": 3, "packages": { "": {');
    write("requirements.txt", "requests==2.31.0\nidna==3.4\n");
    const r = await scan();
    expect(r.summary).toMatch(/^NOT CHECKED/);
    expect(r.summary).toMatch(/package-lock\.json/);
    expect(totals(r)).toEqual([null, null, null]);
    expect(r.found_in_checked_dependencies.note).toMatch(/not read \(see coverage\); these counts cover only what was read and are a lower bound/);
    expect(r.coverage).toMatchObject({ complete: false });
  });
});
