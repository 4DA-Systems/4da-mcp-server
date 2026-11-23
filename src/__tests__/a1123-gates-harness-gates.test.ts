// SPDX-License-Identifier: Apache-2.0
/**
 * The release harnesses (scripts/ci-gates.mjs RELEASE_HARNESSES): each one exists, runs
 * against a server named on its command line, and is run by its job in
 * .github/workflows/plan-exec.yml, a workflow that is not a pull-request job and can be started
 * by hand on the commit to be released.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { RELEASE_HARNESSES, harnessWorkflowFindings, jobBlock } from "../../scripts/ci-gates.mjs";

const root = path.resolve(import.meta.dirname, "..", "..");
const workflow = fs.readFileSync(path.join(root, ".github", "workflows", "plan-exec.yml"), "utf8");

describe("release harnesses", () => {
  it("names the three harnesses, each with a script that exists and a command taking the server", () => {
    expect(new Set(RELEASE_HARNESSES.map((h) => h.script.split("/")[1]))).toEqual(new Set(["plan-exec", "env", "app-mode"]));
    for (const h of RELEASE_HARNESSES) {
      expect(fs.existsSync(path.join(root, h.script)), h.script).toBe(true);
      expect(h.command).toBe(`node ${h.script} --server dist/index.js`);
      expect(fs.readFileSync(path.join(root, h.script), "utf8"), `${h.script} documents --server`).toContain("--server");
    }
  });

  it("plan-exec.yml runs every harness in its job, weekly and by hand, never on a pull request", () => {
    expect(harnessWorkflowFindings(workflow)).toEqual([]);
    expect(workflow).toMatch(/^\s{2}schedule:/m);
    expect(workflow).not.toMatch(/^\s{2}(pull_request|push):/m);
    // Every job uploads what it found, whatever the outcome.
    for (const job of new Set(RELEASE_HARNESSES.map((h) => h.job))) expect(jobBlock(workflow, job), job).toMatch(/upload-artifact[\s\S]*if: always\(\)/);
  });

  it("finds a harness its job no longer runs, a missing job and a missing manual trigger", () => {
    const without = workflow.replace("for h in concurrency firstrun-kill firstrun-together", "for h in concurrency firstrun-together");
    expect(harnessWorkflowFindings(without)).toEqual([expect.stringMatching(/`env` job does not run bench\/env\/firstrun-kill\.mjs/)]);
    const noJob = workflow.replace(/^ {2}app-mode:$/m, "  app-mode-renamed:");
    expect(harnessWorkflowFindings(noJob)).toEqual([expect.stringMatching(/no `app-mode` job/)]);
    expect(harnessWorkflowFindings(workflow.replace(/^ {2}workflow_dispatch:/m, "  workflow_call:"))).toEqual([expect.stringMatching(/no workflow_dispatch/)]);
  });
});
