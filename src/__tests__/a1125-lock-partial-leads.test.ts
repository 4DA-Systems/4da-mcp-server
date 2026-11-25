// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, track A, F2: a lockfile read only in part (PARTIAL: older than its manifest,
 * truncated, entries skipped), refused (a requirements include outside the project) or in conflict
 * with the one read never led the scan's answer. The summary had no line for it, the totals were
 * numbers ("0 vulnerable" beside coverage.complete false), while upgrade_planner said the same
 * project's vulnerability data was not available.
 *
 * Now such a file leads the summary as an unreadable one does: the first words are NOT CHECKED,
 * the totals are null, and what was found among what was read is under
 * found_in_checked_dependencies. upgrade_planner and dependency_health agree. An intact project is
 * unchanged: complete, numeric totals, no found_in_checked_dependencies.
 *
 * Every request is recorded by a stubbed fetch: nothing leaves the process.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";

let scratch: string;
let project: string;
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

beforeEach(() => {
  scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1125-partial-")));
  project = path.join(scratch, "project");
  const home = path.join(scratch, "home");
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  setEnv("FOURDA_OFFLINE", undefined);
  setEnv("FOURDA_MCP_HOME", home);
  setEnv("HOME", home);
  setEnv("USERPROFILE", home);
  setEnv("APPDATA", path.join(home, "AppData", "Roaming"));
  setEnv("LOCALAPPDATA", path.join(home, "AppData", "Local"));
  setEnv("XDG_CONFIG_HOME", undefined);
  setEnv("XDG_CONFIG_DIRS", path.join(home, "xdg-none"));
  setEnv("ProgramData", path.join(home, "ProgramData"));
  setEnv("VIRTUAL_ENV", undefined);
  setEnv("PIP_CONFIG_FILE", undefined);
  setEnv("PIP_INDEX_URL", undefined);
  setEnv("PIP_EXTRA_INDEX_URL", undefined);
  setEnv("UV_CONFIG_FILE", undefined);
  setEnv("NPM_CONFIG_USERCONFIG", path.join(home, ".npmrc"));
  setEnv("NPM_CONFIG_GLOBALCONFIG", path.join(home, "global-npmrc"));
  setEnv("FOURDA_PUBLIC_MIRRORS", undefined);
  setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const u = new URL(String(input));
      const body = typeof init?.body === "string" ? init.body : "";
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
        const { queries } = JSON.parse(body) as { queries: unknown[] };
        return json({ results: queries.map(() => ({ vulns: [] })) });
      }
      if (u.hostname === "api.osv.dev") return json({ vulns: [] });
      return json({ error: "Not found" }, 404);
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  clearLiveIntelligence();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

function liveFor(files: Record<string, string>): void {
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(project, file)), { recursive: true });
    fs.writeFileSync(path.join(project, file), content);
  }
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(project);
  live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
}

async function call(tool: string, args: Record<string, unknown>): Promise<Record<string, any>> {
  const db = new FourDADatabase(path.join(scratch, `standalone-${Math.random().toString(36).slice(2)}.db`));
  try {
    const result = (await dispatchTool(tool, db, args)) as { content: Array<{ text: string }> };
    return JSON.parse(result.content[0].text) as Record<string, any>;
  } finally {
    db.close();
  }
}

const GEMFILE_LOCK = `GEM
  remote: https://rubygems.org/
  specs:
    rake (13.2.1)

PLATFORMS
  ruby

DEPENDENCIES
  rake (= 13.2.1)

BUNDLED WITH
   2.4.22
`;
const STALE_GEM = { Gemfile: "source 'https://rubygems.org'\n\ngem 'rake', '13.2.1'\ngem 'carrierwave', '1.3.1'\n", "Gemfile.lock": GEMFILE_LOCK };
const INTACT_GEM = { Gemfile: "source 'https://rubygems.org'\n\ngem 'rake', '13.2.1'\n", "Gemfile.lock": GEMFILE_LOCK };

describe("F2: a lockfile read in part leads the scan answer, as the planner says", () => {
  for (const format of ["concise", "detailed"] as const) {
    it(`C1 (Gemfile.lock older than the Gemfile), ${format}: NOT CHECKED first, totals null, counts under found_in_checked_dependencies`, async () => {
      liveFor(STALE_GEM);
      const scan = await call("vulnerability_scan", { force_refresh: true, response_format: format });
      expect(scan.summary).toMatch(/^NOT CHECKED: PARTIAL: 1 lockfile/);
      expect(scan.summary).toContain("Gemfile declares carrierwave, but this lockfile has no entry for it");
      expect(scan.coverage.complete).toBe(false);
      expect(scan.coverage.partial_lockfiles.map((p: { path: string }) => p.path)).toEqual(["Gemfile.lock"]);
      expect(scan.total_vulnerable_packages).toBeNull();
      expect(scan.found_in_checked_dependencies.vulnerable_packages).toBe(0);
      expect(scan.found_in_checked_dependencies.note).toMatch(/lower bound/);
    });
  }

  it("upgrade_planner and dependency_health say the same of the same project", async () => {
    liveFor(STALE_GEM);
    const plan = await call("upgrade_planner", {});
    expect(plan.vulnerabilityDataAvailable).toBe(false);
    const health = await call("dependency_health", {});
    expect(health.scoreCoverage?.complete).toBe(false);
    expect(health.summary).toContain("Gemfile.lock");
  });

  it("a requirements include refused (outside the project) leads too", async () => {
    fs.writeFileSync(path.join(scratch, "outside.txt"), "six==1.16.0\n");
    liveFor({ "requirements.txt": "-r ../outside.txt\nrequests==2.25.0\n" });
    const scan = await call("vulnerability_scan", { force_refresh: true });
    expect(scan.summary).toMatch(/^NOT CHECKED: REFUSED: 1 requirements include/);
    expect(scan.total_vulnerable_packages).toBeNull();
    expect(scan.found_in_checked_dependencies).toBeDefined();
  });

  it("control: the intact project is complete, with numeric totals and nothing leading", async () => {
    liveFor(INTACT_GEM);
    const scan = await call("vulnerability_scan", { force_refresh: true });
    expect(scan.coverage.complete).toBe(true);
    expect(scan.summary ?? "").not.toMatch(/NOT CHECKED|PARTIAL/);
    expect(scan.total_vulnerable_packages).toBe(0);
    expect(scan.found_in_checked_dependencies).toBeUndefined();
    const plan = await call("upgrade_planner", {});
    expect(plan.vulnerabilityDataAvailable).toBe(true);
  });
});
