// SPDX-License-Identifier: Apache-2.0
/**
 * Every upgrade_planner row has `commands` or a stated reason, never neither. A uv project's
 * freshness upgrades (httpx 0.27.2 -> 0.28.1, no advisory) used to come back with an empty
 * `commands` and only "1 0.x minor version behind": nothing said why there was nothing to run.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import Database from "better-sqlite3";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { LiveIntelligence } from "../live/index.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { explainCommandlessRows, NO_COMMAND_REASON_START } from "../tools/upgrade-planner-commandless.js";

const row = (over: Record<string, unknown> = {}) => ({
  package: "httpx",
  ecosystem: "PyPI",
  currentVersion: "0.27.2",
  targetVersion: "0.28.1",
  action: "upgrade_direct",
  reasons: ["1 0.x minor version behind (breaking: below 1.0 a minor bump is a major one)"],
  commands: [] as unknown[],
  ...over,
});

describe("explainCommandlessRows", () => {
  it("a freshness upgrade with no command says why and what to do by hand", () => {
    const r = row();
    explainCommandlessRows([r], () => false);
    const added = r.reasons.at(-1)!;
    expect(added.startsWith(NO_COMMAND_REASON_START)).toBe(true);
    expect(added).toMatch(/not a security fix/);
    expect(added).toMatch(/pyproject\.toml/);
    expect(added).toMatch(/0\.28\.1/);
  });

  it("a row whose fix starts with a hand edit says nothing runs before it", () => {
    const r = row({ upgradeInstructions: [{ dir: ".", instruction: "widen the requirement, then run uv lock" }] });
    explainCommandlessRows([r], () => true);
    expect(r.reasons.at(-1)).toMatch(/by hand; upgradeInstructions says what to edit/);
  });

  it("leaves rows with commands, other actions, or no target alone", () => {
    const rows = [
      row({ commands: [{ dir: ".", run: "uv lock --upgrade-package httpx==0.28.1" }] }),
      row({ action: "waiting_on_upstream" }),
      row({ targetVersion: null }),
    ];
    explainCommandlessRows(rows, () => false);
    for (const r of rows) expect(r.reasons).toHaveLength(1);
  });

  it("is idempotent", () => {
    const r = row();
    explainCommandlessRows([r], () => true);
    explainCommandlessRows([r], () => true);
    expect(r.reasons.filter((x) => x.startsWith(NO_COMMAND_REASON_START))).toHaveLength(1);
  });
});

describe("upgrade_planner: a freshness upgrade in a uv project", () => {
  let dir: string;
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1123-triage-cmd-"));
    fs.writeFileSync(path.join(dir, "pyproject.toml"), '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["httpx<1.0.0,>=0.25.1"]\n');
    fs.writeFileSync(
      path.join(dir, "uv.lock"),
      'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\ndependencies = [{ name = "httpx" }]\n\n[package.metadata]\nrequires-dist = [{ name = "httpx", specifier = "<1.0.0,>=0.25.1" }]\n\n[[package]]\nname = "httpx"\nversion = "0.27.2"\nsource = { registry = "https://pypi.org/simple" }\n',
    );
  });
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
  afterEach(() => vi.unstubAllGlobals());

  it("every row has commands or a reason that says why there are none", async () => {
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
        return new Response(JSON.stringify({ results: queries.map(() => ({})) }), { status: 200 });
      }
      if (url.includes("pypi.org/pypi/httpx/json")) {
        const rel = (t: string) => [{ upload_time_iso_8601: t, yanked: false, packagetype: "sdist", filename: "x.tar.gz" }];
        return new Response(JSON.stringify({ info: { name: "httpx", version: "0.28.1", classifiers: [], license: null }, releases: { "0.27.2": rel("2024-08-27T00:00:00Z"), "0.28.1": rel("2024-12-06T00:00:00Z") } }), { status: 200 });
      }
      if (url.includes("/v1/query")) return new Response("{}", { status: 200 });
      return new Response("{}", { status: 404 });
    });
    const intel = new LiveIntelligence(new Database(":memory:"));
    const plan = (await executeUpgradePlanner(null as never, { project_path: dir }, intel)) as { recommendations: Array<{ package: string; action: string; commands: unknown[]; reasons: string[] }> };
    const httpx = plan.recommendations.find((r) => r.package === "httpx");
    expect(httpx, JSON.stringify(plan).slice(0, 800)).toBeDefined();
    for (const r of plan.recommendations) {
      expect(Array.isArray(r.commands)).toBe(true);
      if (r.commands.length === 0 && r.action === "upgrade_direct") expect(r.reasons.some((x) => x.startsWith(NO_COMMAND_REASON_START))).toBe(true);
    }
  });
});
