// SPDX-License-Identifier: Apache-2.0
/**
 * uv keeps every other locked version it can. full-stack-fastapi-template's backend locks
 * virtualenv 20.26.5 and filelock 3.16.1; the fix is virtualenv 21.14.13, and the plan said
 * "a refresh resolves it to 21.15.12: `uv lock --upgrade-package virtualenv`". uv kept filelock
 * 3.16.1, which 21.x excludes (">=3.24.2"), and landed on 20.33.1, which GHSA-8rjx-v5ww-45pp
 * affects. `uv lock --upgrade-package virtualenv==21.14.13` reached the fix. When the release a
 * refresh would reach requires a co-dependency at a version the lock does not hold, the refresh
 * names the fix itself.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");

function backend(newFilelock = "filelock<5,>=3.24.2") {
  h.ADVISORIES = {
    virtualenv: [adv("GHSA-8rjx-v5ww-45pp", "virtualenv", [{ introduced: "0" }, { fixed: "21.14.13" }], "PyPI")],
  };
  h.PYPI = {
    virtualenv: {
      "20.26.5": { requiresPython: ">=3.7", requiresDist: ["filelock<4,>=3.12.2"] },
      "20.33.1": { requiresPython: ">=3.8", requiresDist: ["filelock<4,>=3.12.2"] },
      "21.14.13": { requiresPython: ">=3.8", requiresDist: [newFilelock] },
      "21.15.12": { requiresPython: ">=3.8", requiresDist: [newFilelock] },
    },
    "pre-commit": { "3.8.0": { requiresPython: ">=3.9", requiresDist: ["virtualenv>=20.10.0"] } },
    filelock: { "3.16.1": {}, "3.24.2": {} },
  };
  h.write("pyproject.toml", '[project]\nname = "app"\nversion = "0.1.0"\nrequires-python = ">=3.10,<4.0"\ndependencies = ["pre-commit>=3.6.2,<4.0.0"]\n');
  h.write(
    "uv.lock",
    [
      'version = 1\nrequires-python = ">=3.10, <4.0"\n',
      '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\ndependencies = [\n    { name = "pre-commit" },\n]\n\n[package.metadata]\nrequires-dist = [{ name = "pre-commit", specifier = ">=3.6.2,<4.0.0" }]\n',
      '[[package]]\nname = "filelock"\nversion = "3.16.1"\nsource = { registry = "https://pypi.org/simple" }\n',
      '[[package]]\nname = "pre-commit"\nversion = "3.8.0"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "virtualenv" },\n]\n',
      '[[package]]\nname = "virtualenv"\nversion = "20.26.5"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "filelock" },\n]\n',
    ].join("\n"),
  );
}

describe("a uv refresh whose newest admitted release needs a co-dependency the lock holds lower", () => {
  it("names the fix itself, so uv moves the co-dependency instead of stopping short", async () => {
    backend();
    const { step } = await h.plan();
    const row = step("virtualenv");
    expect(row).toMatchObject({ scope: "transitive", action: "lockfile_refresh", targetVersion: "21.14.13" });
    expect(row.refreshCommands).toEqual([{ dir: ".", command: "uv lock --upgrade-package virtualenv==21.14.13" }]);
    expect(reasonsOf(row)).toMatch(/virtualenv 21\.15\.12 requires filelock "<5,>=3\.24\.2", which excludes the locked filelock 3\.16\.1/);
  });

  it("keeps the plain refresh when the lock already holds what the newest release needs", async () => {
    backend("filelock<5,>=3.12.2");
    const { step } = await h.plan();
    expect(step("virtualenv").refreshCommands).toEqual([{ dir: ".", command: "uv lock --upgrade-package virtualenv" }]);
  });
});
