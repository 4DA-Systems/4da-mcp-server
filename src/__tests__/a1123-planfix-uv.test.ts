// SPDX-License-Identifier: Apache-2.0
/**
 * uv steps that failed or did nothing in the candidate run of 2026-11-23:
 * - fastapi-backend: `uv lock --upgrade-package fastapi==0.162.6` exited 1 ("requirements are
 *   unsatisfiable"): fastapi 0.162.6 requires Python ">=3.11" and the project supports
 *   ">=3.10, <4.0". The declared requirement admits the release, so the requirement check let it
 *   through; the Python support check did not exist. Now the row says to raise requires-python
 *   first, as a hand step, and run_order leaves it out.
 * - mcp-python-sdk (a uv workspace, members examples/servers/*, each with a uv.lock left from before
 *   it joined): the members' `uv lock --upgrade-package anyio==4.14.2`, `... certifi`, `... idna`
 *   ran three times each without effect (uv in a member reads and writes the root's uv.lock), and
 *   `uv lock --upgrade-package mcp==1.30.0` in examples/servers/simple-tool exited 1 ("your
 *   workspace requires mcp"): mcp is the workspace's own package.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { withPythonSupport, type RunnableRow } from "../tools/upgrade-plan-runnable.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const runs = (result: Record<string, any>) => (result.run_order as Array<{ dir: string; run: string }>).map((s) => `${s.dir} ${s.run}`);
const pkg = (name: string, version: string, extra = "") => `[[package]]\nname = "${name}"\nversion = "${version}"\nsource = { registry = "https://pypi.org/simple" }\n${extra}`;

describe("a uv pin whose release needs a newer Python than the project supports", () => {
  function backend() {
    h.ADVISORIES = { fastapi: [adv("PYSEC-0000-0001", "fastapi", fixedIn("0.162.6"), "PyPI")] };
    h.PYPI = { fastapi: { "0.115.0": { requiresPython: ">=3.8" }, "0.162.6": { requiresPython: ">=3.11", requiresDist: [] } } };
    h.write("pyproject.toml", '[project]\nname = "app"\nversion = "0.1.0"\nrequires-python = ">=3.10,<4.0"\ndependencies = ["fastapi<1.0.0,>=0.114.2"]\n');
    h.write(
      "uv.lock",
      [
        'version = 1\nrequires-python = ">=3.10, <4.0"\n',
        '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\ndependencies = [\n    { name = "fastapi" },\n]\n\n[package.metadata]\nrequires-dist = [{ name = "fastapi", specifier = ">=0.114.2,<1.0.0" }]\n',
        pkg("fastapi", "0.115.0"),
      ].join("\n"),
    );
  }

  it("is a hand step (raise requires-python, then the command), never a command alone, and run_order leaves it out", async () => {
    backend();
    const { result, step } = await h.plan();
    const row = step("fastapi");
    expect(row).toMatchObject({ action: "upgrade_direct", targetVersion: "0.162.6" });
    expect(row.upgradeCommands).toBeUndefined();
    expect(row.commands).toEqual([]);
    expect(row.upgradeInstructions).toEqual([
      {
        dir: ".",
        instruction:
          'fastapi 0.162.6 requires Python ">=3.11", and this project supports Python ">=3.10, <4.0" (uv.lock), down to 3.10: `uv lock --upgrade-package fastapi==0.162.6` alone cannot lock it. Raise requires-python in pyproject.toml to a range fastapi 0.162.6 supports, then run `uv lock --upgrade-package fastapi==0.162.6`',
      },
    ]);
    expect(row.reasons.join(" ")).not.toMatch(/Fixable now with a lockfile refresh/);
    expect(result.run_order).toEqual([]);
  });

  it("keeps the command when the release supports the project's lowest Python", async () => {
    backend();
    h.PYPI.fastapi["0.162.6"].requiresPython = ">=3.9";
    const { result, step } = await h.plan();
    expect(step("fastapi").commands).toEqual([{ dir: ".", run: "uv lock --upgrade-package fastapi==0.162.6" }]);
    expect(runs(result)).toEqual([". uv lock --upgrade-package fastapi==0.162.6"]);
  });

  it("moves a parent lever's pin the same way (starlette's row: fastapi 0.162.6 as the lever)", async () => {
    h.write("uv.lock", 'version = 1\nrequires-python = ">=3.10, <4.0"\n');
    const lever = { name: "fastapi", to: "0.162.6", commands: [{ dir: ".", command: "uv lock --upgrade-package fastapi==0.162.6", refresh: true as const }] };
    const row: RunnableRow = { package: "starlette", ecosystem: "PyPI", currentVersion: "0.38.6", targetVersion: "1.3.1", scope: "transitive", reasons: [], parentUpgrades: [{ levers: [lever] }] };
    const facts = { versions: ["0.162.6"], withdrawn: [], latest: "0.162.6", requiresPython: { "0.162.6": ">=3.11" } };
    await withPythonSupport([row], h.dir, { releaseFacts: async () => facts as never });
    const moved = row.parentUpgrades![0].levers[0];
    expect(moved.commands).toBeUndefined();
    expect(moved.instructions?.[0].instruction).toMatch(/^fastapi 0\.162\.6 requires Python ">=3\.11", and this project supports Python ">=3\.10, <4\.0" \(uv\.lock\)/);
  });
});

describe("a uv workspace whose members keep their own uv.lock", () => {
  function workspace() {
    h.ADVISORIES = {
      anyio: [adv("PYSEC-2026-4024", "anyio", fixedIn("4.14.2"), "PyPI")],
      mcp: [adv("PYSEC-2026-1616", "mcp", fixedIn("1.30.0"), "PyPI")],
    };
    h.PYPI = {
      anyio: { "4.6.2.post1": { requiresPython: ">=3.9" }, "4.14.2": { requiresPython: ">=3.9", requiresDist: [] } },
      mcp: { "0.7.0": { requiresPython: ">=3.10" }, "1.30.0": { requiresPython: ">=3.10", requiresDist: [] } },
    };
    h.write(
      "pyproject.toml",
      '[project]\nname = "mcp"\nversion = "1.1.0"\nrequires-python = ">=3.10"\ndependencies = ["anyio>=4.6"]\n\n[tool.uv.workspace]\nmembers = ["examples/servers/*"]\n\n[tool.uv.sources]\nmcp = { workspace = true }\n',
    );
    h.write(
      "uv.lock",
      [
        'version = 1\nrequires-python = ">=3.10"\n\n[manifest]\nmembers = [\n    "mcp",\n    "mcp-simple-tool",\n]\n',
        '[[package]]\nname = "mcp"\nversion = "1.1.0"\nsource = { editable = "." }\ndependencies = [\n    { name = "anyio" },\n]\n\n[package.metadata]\nrequires-dist = [{ name = "anyio", specifier = ">=4.6" }]\n',
        '[[package]]\nname = "mcp-simple-tool"\nversion = "0.1.0"\nsource = { editable = "examples/servers/simple-tool" }\ndependencies = [\n    { name = "anyio" },\n    { name = "mcp" },\n]\n',
        pkg("anyio", "4.6.2.post1"),
      ].join("\n"),
    );
    h.write("examples/servers/simple-tool/pyproject.toml", '[project]\nname = "mcp-simple-tool"\nversion = "0.1.0"\nrequires-python = ">=3.10"\ndependencies = ["anyio>=4.6.2.post1", "mcp>=0.7.0"]\n');
    h.write(
      "examples/servers/simple-tool/uv.lock",
      [
        'version = 1\nrequires-python = ">=3.10"\n',
        '[[package]]\nname = "mcp-simple-tool"\nversion = "0.1.0"\nsource = { editable = "." }\ndependencies = [\n    { name = "anyio" },\n    { name = "mcp" },\n]\n\n[package.metadata]\nrequires-dist = [\n    { name = "anyio", specifier = ">=4.6.2.post1" },\n    { name = "mcp", specifier = ">=0.7.0" },\n]\n',
        pkg("anyio", "4.6.2.post1"),
        pkg("mcp", "0.7.0", 'dependencies = [\n    { name = "anyio" },\n]\n'),
      ].join("\n"),
    );
  }

  it("names each uv command once, at the workspace root, and says the member's lockfile is not uv's", async () => {
    workspace();
    const { result, step } = await h.plan();
    const anyio = step("anyio");
    expect(anyio.commands).toEqual([{ dir: ".", run: "uv lock --upgrade-package anyio==4.14.2" }]);
    expect(anyio.reasons.join(" ")).not.toMatch(/in examples\/servers\/simple-tool/);
    expect(anyio.reasons.join(" ")).toMatch(/examples\/servers\/simple-tool\/uv\.lock is not the lockfile uv uses: that directory is a member of the uv workspace at the project root/);
    expect(runs(result).filter((r) => r.includes("anyio"))).toEqual([". uv lock --upgrade-package anyio==4.14.2"]);
    expect(result.run_order_note).toMatch(/examples\/servers\/simple-tool\/uv\.lock is not read by uv/);
  });

  it("never plans an upgrade of the workspace's own package; its stale copy is a hand step", async () => {
    workspace();
    const { result, step } = await h.plan();
    const mcp = step("mcp");
    expect(mcp.commands).toEqual([]);
    expect(mcp.upgradeCommands).toBeUndefined();
    expect(mcp.reasons.join(" ")).toMatch(/mcp is a package this workspace defines itself/);
    expect(mcp.upgradeInstructions?.[0]).toMatchObject({ dir: "examples/servers/simple-tool" });
    expect(mcp.upgradeInstructions[0].instruction).toMatch(/^delete examples\/servers\/simple-tool\/uv\.lock/);
    expect(runs(result).some((r) => r.includes("mcp=="))).toBe(false);
  });
});
