// SPDX-License-Identifier: Apache-2.0
/**
 * A vulnerable PyPI dependency a uv project declares gets the command that moves it, or the
 * manifest edit it needs, or a sentence saying why neither is named: never nothing.
 *
 * full-stack-fastapi-template's backend declares `pyjwt>=2.8.0,<3.0.0` (2.9.0 locked; 2.15.0 is
 * the fix) and, as a dev dependency, `pytest>=7.4.3,<8.0.0` (7.4.4 locked; 9.0.3 is the fix).
 * `uv lock --upgrade-package pyjwt==2.15.0` moves pyjwt; pytest's requirement has to be widened
 * first (`uv lock --upgrade-package pytest==9.0.3` alone: "app:dev's requirements are
 * unsatisfiable").
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");

function uvBackend() {
  h.ADVISORIES = {
    pyjwt: [adv("GHSA-pxh4-856f-4h89", "pyjwt", fixedIn("2.15.0"), "PyPI", "CRITICAL")],
    pytest: [adv("PYSEC-2026-1845", "pytest", fixedIn("9.0.3"), "PyPI", "MODERATE")],
  };
  h.PYPI = {
    pyjwt: { "2.9.0": { requiresPython: ">=3.8" }, "2.15.0": { requiresPython: ">=3.9" } },
    pytest: { "7.4.4": { requiresPython: ">=3.7" }, "9.0.3": { requiresPython: ">=3.9", requiresDist: [] } },
  };
  h.write(
    "pyproject.toml",
    '[project]\nname = "app"\nversion = "0.1.0"\nrequires-python = ">=3.10,<4.0"\ndependencies = ["pyjwt<3.0.0,>=2.8.0"]\n\n[tool.uv]\ndev-dependencies = ["pytest<8.0.0,>=7.4.3"]\n',
  );
  h.write(
    "uv.lock",
    [
      'version = 1\nrequires-python = ">=3.10, <4.0"\n',
      '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\ndependencies = [\n    { name = "pyjwt" },\n]\n\n[package.dev-dependencies]\ndev = [\n    { name = "pytest" },\n]\n\n[package.metadata]\nrequires-dist = [{ name = "pyjwt", specifier = ">=2.8.0,<3.0.0" }]\n\n[package.metadata.requires-dev]\ndev = [{ name = "pytest", specifier = ">=7.4.3,<8.0.0" }]\n',
      '[[package]]\nname = "pyjwt"\nversion = "2.9.0"\nsource = { registry = "https://pypi.org/simple" }\n',
      '[[package]]\nname = "pytest"\nversion = "7.4.4"\nsource = { registry = "https://pypi.org/simple" }\n',
    ].join("\n"),
  );
}

describe("a vulnerable dependency a uv project declares", () => {
  it("whose requirement admits the fix: the uv command that moves the lock to exactly that release", async () => {
    uvBackend();
    const { step } = await h.plan({ include_dev: true });
    const row = step("pyjwt");
    expect(row).toMatchObject({ scope: "direct", action: "upgrade_direct", targetVersion: "2.15.0" });
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: "uv lock --upgrade-package pyjwt==2.15.0", refresh: true }]);
    expect(row.upgradeInstructions).toBeUndefined();
    expect(reasonsOf(row)).toMatch(/uv lock --upgrade-package pyjwt==2\.15\.0/);
  });

  it("whose requirement excludes the fix: the manifest edit, then the command", async () => {
    uvBackend();
    const { step } = await h.plan({ include_dev: true });
    const row = step("pytest");
    expect(row).toMatchObject({ scope: "direct", action: "upgrade_direct", targetVersion: "9.0.3" });
    expect(row.upgradeCommands).toBeUndefined();
    expect(row.upgradeInstructions).toHaveLength(1);
    expect(row.upgradeInstructions[0].dir).toBe(".");
    expect(row.upgradeInstructions[0].instruction).toMatch(/pyproject\.toml requires pytest ">=7\.4\.3,<8\.0\.0" \(the "dev" dependency group\), which excludes 9\.0\.3: widen that requirement to admit 9\.0\.3, then run `uv lock --upgrade-package pytest==9\.0\.3`/);
  });

  it("in a Poetry project: a stated reason, never neither a command nor a reason", async () => {
    uvBackend();
    fs.rmSync(path.join(h.dir, "uv.lock"));
    h.write(
      "poetry.lock",
      '[[package]]\nname = "pyjwt"\nversion = "2.9.0"\ndescription = ""\noptional = false\npython-versions = ">=3.8"\nfiles = []\n\n[metadata]\nlock-version = "2.0"\npython-versions = "^3.10"\ncontent-hash = "x"\n',
    );
    const { step } = await h.plan();
    const row = step("pyjwt");
    expect(row).toMatchObject({ scope: "direct", action: "upgrade_direct" });
    expect(row.upgradeCommands).toBeUndefined();
    expect(row.upgradeInstructions).toBeUndefined();
    expect(reasonsOf(row)).toMatch(/No command is named for this upgrade: Poetry's `poetry update` resolves to the newest release/);
  });
});
