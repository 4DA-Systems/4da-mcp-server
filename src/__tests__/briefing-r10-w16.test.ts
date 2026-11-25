// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know, pre-publish round 10 (W16): a final reviewer's findings.
 *
 * 2. A pip-style specifier on an npm-only name hid malware: `add event-stream==3.3.6` in an npm-only
 *    project was read as PyPI only (PyPI has no event-stream: unknown, review_needed). A comparator
 *    the task did not tie to PyPI is a guess: npm is judged too with the same constraint, and the
 *    worst answer stands. `pip install` / `poetry add` stay fixed to PyPI.
 * 3. In a mixed npm + PyPI project, "add rsa 4.7" / "add numpy 2.1" / "add pandas 2.2.3" came back
 *    review_needed: npm's "No published, non-withdrawn release of rsa matches 4.7" (unknown) or an
 *    npm namesake's near-miss "review" outranked PyPI's proceed.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import type { ResolvedDependency } from "../live/types.js";
import { detectAllNewPackages } from "../tools/briefing-new-packages.js";
import { readTaskVersions } from "../tools/briefing-requested-versions.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import type { FourDADatabase } from "../db.js";
import { advisory, dep, installFetchStub, memoryDb, readyScan, stubIntel, type Stub } from "./helpers/briefing-stub.js";

const NPM = [dep("lodash", "4.17.20"), dep("react", "18.2.0")];
const MIXED = [...NPM, dep("requests", "2.32.3", "PyPI")];

/** PyPI in memory: `/pypi/<name>/json` with every release. */
const PYPI: Record<string, string[]> = {
  rsa: ["4.7", "4.9"],
  numpy: ["2.1.0", "2.1.3", "2.2.0"],
  pandas: ["2.2.2", "2.2.3"],
  requests: ["2.31.0", "2.32.3"],
};

let stub: Stub;
let db: FourDADatabase;
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  clearNpmDownloadsMemo();
  db = memoryDb();
  stub = {
    asked: [],
    npm: {
      "event-stream": { latest: "4.0.1", versions: ["3.3.5", "3.3.6", "4.0.1"] },
      rc: { latest: "1.2.8", versions: ["1.2.8", "1.2.9"] },
      // npm namesakes of PyPI projects, with no release the task names.
      rsa: { latest: "0.0.3", versions: ["0.0.3"] },
      pandas: { latest: "0.0.3", versions: ["0.0.3"] },
      numpy: { latest: "0.0.1", versions: ["0.0.1"] },
    },
    osv: [
      advisory("MAL-2018-event-stream", "event-stream", "CRITICAL", { versions: ["3.3.6"] }, "npm", true),
      advisory("MAL-2021-rc", "rc", "CRITICAL", { versions: ["1.2.9"] }, "npm", true),
    ],
  };
  installFetchStub(stub);
  const npmAndOsv = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    // One release's own document (its requires_dist), for a release the project lists.
    const pypiRelease = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/([^/]+)\/json$/.exec(url);
    if (pypiRelease) {
      const version = decodeURIComponent(pypiRelease[2]);
      return PYPI[decodeURIComponent(pypiRelease[1]).toLowerCase()]?.includes(version) ? json({ info: { version, requires_dist: null } }) : json({ message: "Not Found" }, 404);
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi) {
      stub.asked.push(url);
      const name = decodeURIComponent(pypi[1]).toLowerCase();
      const versions = PYPI[name];
      if (!versions) return json({ message: "Not Found" }, 404);
      return json({
        info: { name, version: versions[versions.length - 1] },
        releases: Object.fromEntries(versions.map((v, i) => [v, [{ upload_time_iso_8601: new Date(Date.UTC(2019, 0, 1 + i)).toISOString(), yanked: false }]])),
      });
    }
    return npmAndOsv(input, init);
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const brief = (task: string, deps: ResolvedDependency[] = NPM) => executeWhatShouldIKnow(db, { task }, stubIntel(deps, {}, readyScan()));

describe("2. a pip-style comparator on an npm-only name is a guess: npm is judged too (round 10, W16)", () => {
  it.each([
    ["add event-stream==3.3.6", "3.3.6"],
    ["add event-stream>=3.3.6", ">=3.3.6"],
  ])("readers: %s carries npm as an alternative with the constraint translated", (task, to) => {
    const pkg = detectAllNewPackages(task, NPM).find((p) => p.name === "event-stream");
    expect(pkg).toMatchObject({ ecosystem: "PyPI", alternatives: ["npm"] });
    expect(pkg?.fallbackOnly).toBeUndefined();
    expect(readTaskVersions(task, NPM).requested).toMatchObject([{ name: "event-stream", ecosystem: "PyPI", to, alternatives: ["npm"] }]);
  });

  it("add event-stream==3.3.6 in an npm-only project: npm's malicious 3.3.6 is human_only", async () => {
    const r = await brief("add event-stream==3.3.6");
    expect(r.requested_versions).toMatchObject([{ name: "event-stream", ecosystem: "npm", to: "3.3.6", malicious: true }]);
    expect(r.new_packages).toMatchObject([{ name: "event-stream", ecosystem: "npm", malicious: true }]);
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it("add rc==1.2.9 in an npm-only project is human_only", async () => {
    const r = await brief("add rc==1.2.9");
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it.each(["pip install event-stream==3.3.6", "poetry add event-stream==3.3.6"])("an explicit command stays fixed to PyPI: %s", (task) => {
    expect(readTaskVersions(task, NPM).requested.every((r) => r.ecosystem === "PyPI" && !r.alternatives)).toBe(true);
    expect(detectAllNewPackages(task, NPM).every((p) => p.ecosystem === "PyPI" && !p.alternatives)).toBe(true);
  });

  it("in a project that uses PyPI, npm is a fallback only: PyPI's answer stands when it has the release", async () => {
    const pkg = detectAllNewPackages("add requests==2.31.0", MIXED.filter((d) => d.name !== "requests").concat(dep("flask", "3.1.0", "PyPI")));
    expect(pkg[0]).toMatchObject({ ecosystem: "PyPI", alternatives: ["npm"], fallbackOnly: true });
  });
});

describe("3. an ecosystem with no such release, or a namesake's near-miss, is not the answer (round 10, W16)", () => {
  it.each(["add rsa 4.7", "add pandas 2.2.3", "add numpy 2.1"])("mixed npm + PyPI project: %s is not review_needed over npm's namesake", async (task) => {
    const r = await brief(task, MIXED);
    for (const v of r.requested_versions ?? []) expect(v).toMatchObject({ ecosystem: "PyPI", verdict: "proceed" });
    for (const p of r.new_packages ?? []) expect(p.verdict).toBe("proceed");
    expect(r.delegation_assessment.level).not.toBe("review_needed");
  });

  it("an npm namesake that has the release but is only a near-miss of a popular npm name (pandas ~ canvas) does not outrank PyPI's proceed", async () => {
    stub.npm.pandas = { latest: "2.2.3", versions: ["2.2.3"] };
    const r = await brief("add pandas 2.2.3", MIXED);
    expect(r.requested_versions).toMatchObject([{ name: "pandas", ecosystem: "PyPI", verdict: "proceed" }]);
    for (const p of r.new_packages ?? []) expect(p).toMatchObject({ ecosystem: "PyPI", verdict: "proceed" });
    // Decided on PyPI (a popular name there): npm's namesake is not listed (third blind check, item 4).
    expect(r.unverified_words).toBeUndefined();
  });

  it("malware from an ecosystem that has the name and release still wins in a mixed project", async () => {
    const r = await brief("add event-stream 3.3.6", MIXED);
    expect(r.delegation_assessment.level).toBe("human_only");
  });
});

describe("a tie between the comparator's guess and the project's own ecosystem reports the project's (round 10, final check)", () => {
  it("add event-stream<=3.3.6 in an npm-only project: npm is reported, never PyPI's namesake release", async () => {
    PYPI["event-stream"] = ["1.6.3"];
    try {
      const r = await brief("add event-stream<=3.3.6");
      const rows = (r.requested_versions ?? []).filter((x) => x.name === "event-stream");
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) {
        expect(row.ecosystem).toBe("npm");
        expect(row.resolved ?? "").not.toBe("1.6.3");
      }
      for (const p of (r.new_packages ?? []).filter((x) => x.name === "event-stream")) expect(p.ecosystem).toBe("npm");
    } finally {
      delete PYPI["event-stream"];
    }
  });
});
