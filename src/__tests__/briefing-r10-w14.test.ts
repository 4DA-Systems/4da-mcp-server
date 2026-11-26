// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know, pre-publish round 10 (W14): an independent reviewer's findings on how the
 * briefing reads a task and what it lets a coding agent delegate.
 *
 * 1. The ecosystem was guessed from the project, not from the command or the specifier: in an
 *    npm-only project `poetry add pyyaml@5.3` judged npm's `pyyaml` in requested_versions while
 *    new_packages judged PyPI's; "add requests~=2.31" offered npm's deprecated `request` as the
 *    fix; "add flask<2.2.5" listed npm's flask "proceed" beside PyPI's "avoid".
 * 2. A compromised release with no MAL- id (PYSEC-2024-154, a crypto-miner in ultralytics 8.3.41)
 *    was review_needed, where a MAL- id gets human_only.
 * 3. `smallvec = "=1.6.0"`: the reason said Cargo reads it as ^1.6.0 and installs 1.16.5.
 * 4. "add a retry with backoff to the client" checked npm `retry`; "add a progress bar" `progress`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import { isMalware } from "../live/malware.js";
import type { ResolvedDependency } from "../live/types.js";
import { detectAllNewPackages } from "../tools/briefing-new-packages.js";
import { readTaskVersions } from "../tools/briefing-requested-versions.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { advisory, dep, installFetchStub, memoryDb, readyScan, stubIntel, type Stub } from "./helpers/briefing-stub.js";
import { waitingWords } from "./helpers/a1127-task-packages.js";

const NPM = [dep("lodash", "4.17.20"), dep("react", "18.2.0")];
const RUST = [dep("tokio", "1.40.0", "crates.io")];

const added = (task: string, deps: ResolvedDependency[] = NPM) => detectAllNewPackages(task, deps).map((p) => `${p.ecosystem}:${p.name}${p.version ? `@${p.version}` : ""}`);
const requested = (task: string, deps: ResolvedDependency[] = NPM) => readTaskVersions(task, deps).requested.map((r) => `${r.ecosystem}:${r.name}@${r.to}`);

/** PyPI in memory: `/pypi/<name>/json` with every release. */
const PYPI: Record<string, string[]> = {
  pyyaml: ["5.3", "5.4", "6.0.2"],
  requests: ["2.31.0", "2.32.3"],
  flask: ["2.2.4", "2.2.5", "3.1.0"],
  django: ["2.2.0", "4.2.16"],
  ultralytics: ["8.3.40", "8.3.41", "8.3.48"],
};
const CRATES: Record<string, string[]> = { smallvec: ["1.6.0", "1.6.1", "1.16.5"], serde_yaml: ["0.8.26", "0.9.34"] };

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
      pyyaml: { latest: "0.0.1", versions: ["0.0.1"] },
      flask: { latest: "0.2.10", versions: ["0.2.10"] },
      request: { latest: "2.88.2", versions: ["2.88.2"] },
      retry: { latest: "0.13.1", versions: ["0.13.1"] },
      progress: { latest: "2.0.3", versions: ["2.0.3"] },
    },
    osv: [
      advisory("GHSA-8q59-q68h-6hv4", "pyyaml", "CRITICAL", { versions: ["5.3"] }, "PyPI"),
      advisory("GHSA-m2qf-hxjv-5gpq", "flask", "HIGH", { versions: ["2.2.4"] }, "PyPI"),
      advisory("GHSA-request-ssrf", "request", "MEDIUM", {}, "npm"),
      advisory("GHSA-django-sqli", "django", "CRITICAL", { versions: ["2.2.0"] }, "PyPI"),
      // The real record's own words (api.osv.dev/v1/vulns/PYSEC-2024-154): no MAL- id, no CWE-506.
      advisory("PYSEC-2024-154", "ultralytics", "HIGH", { versions: ["8.3.41"] }, "PyPI", false, "A number of releases of ultralytics contained malicious crypto miner software."),
      advisory("GHSA-43w2-9j62-hq99", "smallvec", "CRITICAL", { versions: ["1.6.0"] }, "crates.io"),
    ],
  };
  installFetchStub(stub);
  const npmAndOsv = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
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
    const crate = /^https:\/\/crates\.io\/api\/v1\/crates\/([^/?]+)$/.exec(url);
    if (crate) {
      stub.asked.push(url);
      const versions = CRATES[decodeURIComponent(crate[1])];
      if (!versions) return json({ errors: [{ detail: "Not Found" }] }, 404);
      return json({
        crate: { num_versions: versions.length, created_at: "2018-01-01T00:00:00Z" },
        versions: versions.map((num, i) => ({ num, created_at: new Date(Date.UTC(2019, 0, 1 + i)).toISOString(), yanked: false })),
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

describe("1. the command and the specifier fix the ecosystem, for every reader", () => {
  it.each([
    ["poetry add pyyaml@5.3", "PyPI:pyyaml@5.3"],
    ["uv add pyyaml==5.3", "PyPI:pyyaml@5.3"],
    ["uv pip install pyyaml==5.3", "PyPI:pyyaml@5.3"],
    ["pdm add pyyaml==5.3", "PyPI:pyyaml@5.3"],
    ["pipenv install pyyaml==5.3", "PyPI:pyyaml@5.3"],
    ["pip install django==2.2.0", "PyPI:django@2.2.0"],
    ["cargo add smallvec@1.6.0", "crates.io:smallvec@1.6.0"],
    ["go get github.com/gin-gonic/gin@v1.6.0", "Go:github.com/gin-gonic/gin@v1.6.0"],
  ])("an npm project: %s is read in its manager's ecosystem by both readers", (task, want) => {
    expect(requested(task)).toEqual([want]);
    expect(added(task)).toEqual([want]);
  });

  it.each([
    ["gem install rails -v 5.0.0", "rails"],
    ["composer require monolog/monolog", "monolog/monolog"],
    ["conda install numpy", "numpy"],
  ])("an npm project: %s is never checked as an npm package", (task, name) => {
    expect(added(task).filter((a) => a.startsWith("npm:"))).toEqual([]);
    expect(requested(task).filter((a) => a.startsWith("npm:"))).toEqual([]);
    void name;
  });

  it("the clause after a foreign command is still read", () => {
    expect(added("gem install rails and add lodahs")).toEqual(["npm:lodahs"]);
  });

  it("poetry add pyyaml@5.3 in an npm project: PyPI's critical 5.3 is human_only (it was review_needed on npm's pyyaml)", async () => {
    const r = await brief("poetry add pyyaml@5.3");
    expect(r.requested_versions).toMatchObject([{ name: "pyyaml", ecosystem: "PyPI", to: "5.3", verdict: "avoid" }]);
    expect(r.new_packages?.every((p) => p.ecosystem === "PyPI")).toBe(true);
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it.each(["requests~=2.31", "requests===2.31.0", "requests==2.31.*", "requests>=2.31", "requests<2.32"])("add %s reads as PyPI and never offers npm's request", (spec) => {
    expect(added(`add ${spec}`).every((a) => a.startsWith("PyPI:"))).toBe(true);
    expect(requested(`add ${spec}`).every((a) => a.startsWith("PyPI:"))).toBe(true);
  });

  it("add requests~=2.31: no did_you_mean of npm's deprecated request", async () => {
    const r = await brief("add requests~=2.31");
    for (const p of r.new_packages ?? []) {
      expect(p.ecosystem).toBe("PyPI");
      expect(p.did_you_mean).not.toBe("request");
    }
    expect(JSON.stringify(r)).not.toMatch(/did you mean request\b/);
  });

  it("add flask<2.2.5: one finding for flask, the worst, never a proceed row beside PyPI's avoid", async () => {
    const r = await brief("add flask<2.2.5");
    const flask = (r.new_packages ?? []).filter((p) => p.name === "flask");
    expect(flask).toHaveLength(1);
    expect(flask[0]).toMatchObject({ ecosystem: "PyPI", verdict: "avoid" });
    expect(r.summary).not.toMatch(/flask[^;]*\(proceed/);
  });

  it("gem install rails -v 5.0.0 in an npm project: named NOT CHECKED, never safe_to_delegate", async () => {
    const r = await brief("gem install rails -v 5.0.0");
    expect(r.new_packages ?? []).toEqual([]);
    expect(r.requested_versions ?? []).toEqual([]);
    expect(r.summary).toContain("rails (RubyGems: not read by this server)");
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  it("a guessed name both ecosystems publish at that version: the worst answer stands in requested_versions too", async () => {
    stub.npm.flask = { latest: "2.2.4", versions: ["2.2.4"] };
    const mixed = [...NPM, dep("requests", "2.32.3", "PyPI")];
    const r = await brief("add flask 2.2.4", mixed);
    expect(r.requested_versions).toMatchObject([{ name: "flask", ecosystem: "PyPI", verdict: "avoid" }]);
    expect(r.new_packages).toMatchObject([{ name: "flask", ecosystem: "PyPI", verdict: "avoid" }]);
    expect(r.summary).not.toMatch(/flask[^;]*\(proceed/);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  it("the requests reader and the new-package reader agree when a name is checked in two ecosystems", async () => {
    const r = await brief("add flask<2.2.5");
    // Both readers answered, once each: an empty list would agree with anything.
    expect(r.requested_versions).toMatchObject([{ name: "flask", ecosystem: "PyPI", to: "<2.2.5", verdict: "avoid" }]);
    expect(r.new_packages).toMatchObject([{ name: "flask", ecosystem: "PyPI", version: "<2.2.5", verdict: "avoid" }]);
  });
});

describe("2. a malicious release without a MAL- id is human_only", () => {
  it("the shared classifier reads crypto-miner wording", () => {
    expect(isMalware("PYSEC-2024-154", [], [], "A number of releases of ultralytics contained malicious crypto miner software.")).toBe(true);
    expect(isMalware("X-1", [], [], "foo 1.2.3 contains a cryptominer")).toBe(true);
    expect(isMalware("X-2", [], [], "Compromised release ships a hidden coin miner")).toBe(true);
    expect(isMalware("X-3", [], [], "bar contained cryptocurrency mining software")).toBe(true);
    expect(isMalware("X-4", [], [], "Malicious crypto-miner in baz")).toBe(true);
    // Not malware: a vulnerability in a mining tool, an RCE someone may use to run a miner, a detector.
    expect(isMalware("N-1", [], [], "Path traversal in coin-miner-dashboard")).toBe(false);
    expect(isMalware("N-2", [], [], "Remote code execution in foo, exploited in the wild to run crypto miners")).toBe(false);
    expect(isMalware("N-3", [], [], "Denial of service in the cryptominer pool parser")).toBe(false);
    expect(isMalware("N-4", [], [], "Crypto miner detection bypass in scanner-x")).toBe(false);
    expect(isMalware("N-5", [], [], "xmrig-wrapper contains a buffer overflow")).toBe(false);
  });

  it("pip install ultralytics==8.3.41 (PYSEC-2024-154) is human_only", async () => {
    const r = await brief("pip install ultralytics==8.3.41");
    expect(r.requested_versions).toMatchObject([{ name: "ultralytics", ecosystem: "PyPI", to: "8.3.41", malicious: true }]);
    expect(r.delegation_assessment.level).toBe("human_only");
  });
});

describe("3. Cargo's `=` pin is kept when the briefing asks dependency_check", () => {
  it('add serde_yaml = "0.8" and smallvec = "=1.6.0": the exact pin is read as exactly 1.6.0', async () => {
    const task = 'add serde_yaml = "0.8" and smallvec = "=1.6.0"';
    expect(requested(task, RUST)).toContain("crates.io:smallvec@=1.6.0");
    // Final design of the 2026-11-25 fixes: neither crate is on a bundled list, so the briefing hands both back,
    // each at the pin the task writes (Cargo's `=` kept), and dependency_check judges them there.
    const r = await brief(task, RUST);
    // Round 7, C7: no version in the entry; the agent asks dependency_check at the pin the task writes.
    expect(waitingWords(r)).toContainEqual({ word: "smallvec", read_as: "crates.io" });
    expect(r.delegation_assessment.level).toBe("confirmation_needed");
    const check = (await executeDependencyCheck(null, { items: [{ ecosystem: "crates.io", package: "smallvec", to: "=1.6.0" }] }, stubIntel(RUST, {}, readyScan()) as never)) as { results: Array<{ package: string; verdict: string; to: string; reason: string }> };
    const smallvec = check.results.find((v) => v.package === "smallvec");
    expect(smallvec).toMatchObject({ verdict: "avoid", to: "1.6.0" });
    expect(smallvec?.reason).not.toMatch(/1\.16\.5|\^1\.6\.0/);
  });
});

describe("4. a word after an article, followed by more prose, is no package", () => {
  it.each(["add a retry with backoff to the client", "add a progress bar", "add the debug output to the logger", "add some retry logic"])("names nothing: %s", (task) => {
    expect(added(task)).toEqual([]);
  });

  it.each([
    ["add a logger, lodahs", "npm:lodahs"],
    ["add the `retry` package", "npm:retry"],
    ["add a retry 0.13.1 dependency", "npm:retry@0.13.1"],
  ])("still reads %s", (task, want) => {
    expect(added(task)).toContain(want);
  });
});
