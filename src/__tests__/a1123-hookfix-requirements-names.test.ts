// SPDX-License-Identifier: Apache-2.0
/**
 * The guard reads the Python requirement files the server reads (src/project-tree.ts
 * isRequirementsFileName, mirrored in the hook, which imports nothing): `dev-requirements.txt`,
 * `dev_requirements.txt` and the like as well as `requirements-*.txt` and `requirements/*.txt`.
 * `requirements.in` (ranges for pip-compile) is not read, as the server does not read it.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { isRequirementsFileName } from "../project-tree.js";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

describe("requirement file names", () => {
  it.each(["requirements.txt", "requirements-dev.txt", "requirements_test.txt", "dev-requirements.txt", "dev_requirements.txt", "_test_minimum_requirements.txt", "Requirements.TXT", "requirements/base.txt"])("%s is read", (name) => {
    expect(isRequirementsFileName(name.split("/").pop()!) || name.startsWith("requirements/")).toBe(true);
    const file = s.file(name, "click>=8.1\n");
    expect(s.edit(file, "click>=8.1\n", "click>=8.1\npytest==8.3.2\n").items).toEqual([{ ecosystem: "PyPI", package: "pytest", to: "8.3.2" }]);
  });

  it.each(["requirements.in", "requirements.lock", "notes.txt", "requirements.txt.bak"])("%s is not read", (name) => {
    expect(isRequirementsFileName(name)).toBe(false);
    const file = s.file(name, "click>=8.1\n");
    expect(s.edit(file, "click>=8.1\n", "click>=8.1\npytest==8.3.2\n").decision).toBe("allow");
  });
});
