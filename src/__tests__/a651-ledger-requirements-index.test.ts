// SPDX-License-Identifier: Apache-2.0
/**
 * A name withheld because a requirements file of the project sets an index or find-links is recorded
 * `private`, as 6.5.0 recorded it. Final check (2026-11-25, cases req-index-url, req-extra,
 * req-findlinks, req-index-short): privateRegistryRuleCovers saw a requirements `--index-url` only
 * through the names already in the file, so `dependency_check {PyPI zqpy-new}` was withheld (right)
 * but recorded `local_source`, which the guard hook holds for ever: no new dependency could be added.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "a651-ledger-req-"));
  fs.mkdirSync(path.join(dir, ".git"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function liveWith(requirements: string): LiveIntelligence {
  fs.writeFileSync(path.join(dir, "requirements.txt"), requirements);
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

describe("a requirements index or find-links makes a new name private, and recorded so", () => {
  it.each([
    ["--index-url", "--index-url https://corp.example/simple\n"],
    ["-i", "-i https://corp.example/simple\n"],
    ["--extra-index-url", "--extra-index-url https://corp.example/simple\n"],
    ["--find-links", "--find-links https://corp.example/wheels/\n"],
  ])("%s", (_label, line) => {
    const li = liveWith(`${line}requests==2.25.0\n`);
    expect(li.lookupPrivateReason("PyPI", "acme-new")).not.toBeNull();
    expect(li.privateRegistryRuleCovers("PyPI", "acme-new")).toBe(true);
  });

  it("control: no index line, nothing withheld", () => {
    const li = liveWith("requests==2.25.0\n");
    expect(li.lookupPrivateReason("PyPI", "acme-new")).toBeNull();
    expect(li.privateRegistryRuleCovers("PyPI", "acme-new")).toBe(false);
  });
});
