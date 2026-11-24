// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_planner's `vulnerabilityDataAvailable` and vulnerability_scan's `coverage.complete` say the
 * same thing about the same lockfiles. The 6.5.1 candidate counted merge-conflicted, unreadable and
 * partly read lockfiles for the plan but left go.sum out ("the scan leaves go.sum out"), while the
 * scan's coverage lists a conflicted go.sum and says `complete: false`: review of the candidate
 * (2026-11-24, proj/u-gosum) saw `vulnerabilityDataAvailable: true` beside the scan's
 * `coverage.complete: false`. A second lockfile that disagrees with the one read and a requirements
 * include that was refused make the scan incomplete too, and the plan counted neither. Both now
 * come from one source (lockfileProblemNotes), so they cannot drift apart again.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.ADVISORIES = { tar: [adv("GHSA-r6q2-hw4h-h46w", "tar", fixedIn("7.5.21"))] };
  h.NPM = { tar: { latest: "7.5.21", versions: { "6.1.15": {}, "7.5.21": {} } } };
  h.GO = { "golang.org/x/text": ["v0.3.0", "v0.3.8"] };
  h.npmProject({ tar: "~6.1.11" }, {}, { tar: { version: "6.1.15" } });
});
afterEach(() => h.dispose());

async function agree(): Promise<{ scanComplete: boolean; planAvailable: boolean; summary: string }> {
  const scan = await h.scan();
  const { result } = await h.plan();
  return { scanComplete: scan.coverage.complete, planAvailable: result.vulnerabilityDataAvailable, summary: result.summary };
}

describe("the plan is CVE-aware exactly when the scan is complete", () => {
  it("a go.sum with merge-conflict markers (review repro u-gosum)", async () => {
    h.write("go.mod", "module example.com/p\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n");
    h.write("go.sum", "<<<<<<< HEAD\ngolang.org/x/text v0.3.0 h1:abc=\n=======\ngolang.org/x/text v0.3.8 h1:def=\n>>>>>>> b\n");
    const r = await agree();
    expect(r).toMatchObject({ scanComplete: false, planAvailable: false });
    expect(r.summary).toMatch(/^NOT CHECKED/);
  });

  it("a second npm lockfile that disagrees with the one read", async () => {
    h.write("yarn.lock", '# yarn lockfile v1\n\n\ntar@~6.1.11:\n  version "6.1.14"\n  resolved "https://registry.yarnpkg.com/tar/-/tar-6.1.14.tgz#x"\n');
    const r = await agree();
    expect(r.scanComplete).toBe(false);
    expect(r.planAvailable).toBe(false);
  });

  it("a requirements include that points outside the project is refused", async () => {
    h.write("py/requirements.txt", "-r ../../outside-requirements.txt\nrequests==2.31.0\n");
    const r = await agree();
    expect(r.scanComplete).toBe(false);
    expect(r.planAvailable).toBe(false);
  });

  it("control: the npm lockfile alone, complete and available", async () => {
    const r = await agree();
    expect(r).toMatchObject({ scanComplete: true, planAvailable: true });
  });
});
