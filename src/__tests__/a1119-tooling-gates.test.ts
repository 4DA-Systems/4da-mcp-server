// SPDX-License-Identifier: Apache-2.0
/**
 * A green job must mean the strongest suites ran. vitest exits 0 when a suite skips itself, so the
 * CI conformance job and the release's verify job check the report (scripts/ci-gates.mjs), and
 * `pnpm run check` holds the workflows to that. These tests show each check failing on the input
 * it exists for, and passing on the workflows as they are.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { corpusGatedTests, jobBlock, jobNames, testsRanFindings, workflowGateFindings } from "../../scripts/ci-gates.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const workflow = (name: string) => readFileSync(path.join(root, ".github", "workflows", name), "utf8");
const ci = workflow("ci.yml");
const release = workflow("release.yml");
const gated: string[] = corpusGatedTests(root);

/** A vitest JSON report holding one file whose tests have the given statuses. */
const report = (file: string, statuses: string[]) => ({
  testResults: [{ name: `/work/repo/${file}`, status: "passed", assertionResults: statuses.map((status, i) => ({ status, fullName: `t${i}` })) }],
});

describe("corpus-gated test files", () => {
  it("are the four that read the conformance corpus", () => {
    expect(gated).toEqual([
      "src/__tests__/a1119-tooling-readme-claims.test.ts",
      "src/__tests__/conformance.test.ts",
      "src/__tests__/lockfile-parents-names.test.ts",
      "src/__tests__/rule-vectors.test.ts",
    ]);
  });
});

describe("tests-ran: a report is accepted only when each named file ran in full", () => {
  const file = "src/__tests__/conformance.test.ts";

  it("accepts a file whose tests all passed, whatever the path separators", () => {
    expect(testsRanFindings(report(file, ["passed", "passed"]), [file])).toEqual([]);
    const windows = { testResults: [{ name: `C:\\work\\repo\\${file.replaceAll("/", "\\")}`, assertionResults: [{ status: "passed" }] }] };
    expect(testsRanFindings(windows, [file])).toEqual([]);
  });

  it.each([
    ["a skipped suite", ["skipped", "skipped"], /2 of 2 tests did not pass \(2 skipped\)/],
    ["one skipped test among passed ones", ["passed", "skipped", "passed"], /1 of 3 tests did not pass \(1 skipped\)/],
    ["a pending and a todo test", ["passed", "pending", "todo"], /2 of 3 tests did not pass \(1 pending, 1 todo\)/],
    ["a failed test", ["passed", "failed"], /1 of 2 tests did not pass \(1 failed\)/],
    ["a file with no tests", [], /0 tests ran/],
  ])("refuses %s", (_label, statuses, message) => {
    const findings = testsRanFindings(report(file, statuses), [file]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatch(message);
    expect(findings[0]).toContain(file);
  });

  it("refuses a file that is not in the report, an empty file list and a report of another shape", () => {
    expect(testsRanFindings(report("src/__tests__/other.test.ts", ["passed"]), [file])).toEqual([`${file}: not in the report (the file did not run)`]);
    // A name that only ends the same way is another file.
    expect(testsRanFindings(report(`src/__tests__/not-${path.basename(file)}`, ["passed"]), [file])).toHaveLength(1);
    expect(testsRanFindings(report(file, ["passed"]), [])).toHaveLength(1);
    expect(testsRanFindings({}, [file])).toHaveLength(1);
    expect(testsRanFindings(null, [file])).toHaveLength(1);
  });
});

describe("the workflows as they are", () => {
  it("pass every workflow gate", () => {
    expect(workflowGateFindings({ ci, release, gated })).toEqual([]);
  });

  it("ci.yml: the conformance job runs every corpus-gated file and checks its report", () => {
    const job = jobBlock(ci, "conformance") as string;
    for (const file of gated) expect(job).toContain(file);
    expect(job).toContain("scripts/ci-gates.mjs tests-ran");
  });

  it("ci.yml: the nightly report needs every other job", () => {
    const jobs: string[] = jobNames(ci);
    expect(jobs).toContain("install-smoke");
    expect(jobs).toContain("bundle");
    const needs = /needs:\s*\[([^\]]*)\]/.exec(jobBlock(ci, "nightly-report") as string)![1].split(",").map((name) => name.trim());
    expect([...needs].sort()).toEqual(jobs.filter((job) => job !== "nightly-report").sort());
  });

  it("ci.yml: only the upstream schema file itself passes the current-main contract step", () => {
    // Its own job since the vendored review sets made one contract run about ten minutes long.
    const job = jobBlock(ci, "contract-upstream") as string;
    expect(job).toContain("App-schema contract (the desktop app's current main)");
    expect(jobBlock(ci, "checks") as string).toContain("App-schema contract (vendored contract/app-schema.sql)");
    const step = job.slice(job.indexOf("App-schema contract (the desktop app's current main)"));
    expect(step).toContain('[ "$code" = "200" ] ||');
    expect(step).not.toMatch(/exit 0/);
    expect(step).not.toMatch(/"404"/);
  });

  it("ci.yml: the job that fetches the cargo fixture's crates requires a cargo result", () => {
    const test = jobBlock(ci, "test") as string;
    expect(test).toContain("cargo fetch --manifest-path test-fixtures/cargo-platform/Cargo.toml");
    // Every `pnpm test` of that job, the better-sqlite3 pass included.
    expect(test.match(/run: pnpm test/g)).toHaveLength(2);
    expect(test.match(/FOURDA_REQUIRE_CARGO: "1"/g)).toHaveLength(2);
  });

  it("release.yml: verify has the corpus and the cargo crates, requires both, and checks the report", () => {
    const verify = jobBlock(release, "verify") as string;
    const order = [
      "pnpm run build",
      "cargo fetch --manifest-path test-fixtures/cargo-platform/Cargo.toml",
      "node scripts/fetch-conformance.mjs",
      "pnpm exec vitest run",
      "scripts/ci-gates.mjs tests-ran",
      "name: The tagged commit is on main",
      "name: CI passed on the tagged commit",
      "name: Pack the npm tarball",
    ].map((needle) => [needle, verify.indexOf(needle)] as const);
    for (const [needle, at] of order) expect(at, needle).toBeGreaterThan(-1);
    expect(order.map(([, at]) => at)).toEqual([...order.map(([, at]) => at)].sort((a, b) => a - b));
    expect(verify).toContain('FOURDA_REQUIRE_CONFORMANCE: "1"');
    expect(verify).toContain('FOURDA_REQUIRE_CARGO: "1"');
    // A bare `pnpm test` there would be the run whose skips nothing looks at.
    expect(verify).not.toMatch(/run: pnpm test\b/);
  });

  it("release.yml: verify asks for the CI push run of exactly the tagged commit, read-only", () => {
    const verify = jobBlock(release, "verify") as string;
    expect(verify).toContain("actions/workflows/ci.yml/runs?head_sha=$GITHUB_SHA&branch=main&event=push");
    expect(verify).toContain('[ "$conclusion" = "success" ]');
    expect(verify).toMatch(/permissions:\n\s+contents: read\n\s+actions: read/);
    expect(verify).not.toMatch(/:\s*write\b/);
  });

  it("release.yml: the jobs that install and build without pushing keep no checkout credentials", () => {
    for (const job of ["verify", "install-smoke", "bundles", "publish"]) {
      const block = jobBlock(release, job) as string;
      expect(block, job).toMatch(/uses: actions\/checkout@[0-9a-f]{40}[^\n]*\n\s+with:\n\s+persist-credentials: false/);
    }
  });

  it("every action in every workflow is pinned to a commit", () => {
    for (const name of ["ci.yml", "release.yml"]) {
      const uses = [...workflow(name).matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)].map((m) => m[1]);
      expect(uses.length, name).toBeGreaterThan(0);
      for (const use of uses) expect(use, `${name}: ${use}`).toMatch(/@[0-9a-f]{40}$/);
    }
  });
});

describe("the workflow gates fail on the workflows they exist for", () => {
  const without = (text: string, needle: string) => {
    expect(text).toContain(needle);
    return text.replaceAll(needle, "");
  };

  it("a corpus-gated file missing from the conformance job", () => {
    const findings: string[] = workflowGateFindings({ ci: without(ci, "src/__tests__/lockfile-parents-names.test.ts"), release, gated });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toContain("does not run src/__tests__/lockfile-parents-names.test.ts");
  });

  it("a file named only in a comment does not count", () => {
    const commented = ci.replace(/^(\s+)(src\/__tests__\/lockfile-parents-names\.test\.ts)/m, "$1# $2");
    expect(commented).not.toBe(ci);
    expect(workflowGateFindings({ ci: commented, release, gated })).toHaveLength(1);
  });

  it("a conformance job that no longer checks its report, or no longer requires the corpus", () => {
    expect(workflowGateFindings({ ci: without(ci, 'node scripts/ci-gates.mjs tests-ran "$RUNNER_TEMP/conformance-report.json"'), release, gated })).toHaveLength(1);
    // The pinned job's env block; the 4DA-main job keeps its own.
    const notRequired = without(ci, 'conformance-report.json"\n        env:\n          FOURDA_REQUIRE_CONFORMANCE: "1"\n');
    expect(workflowGateFindings({ ci: notRequired, release, gated })).toEqual(['.github/workflows/ci.yml: the conformance job lacks `FOURDA_REQUIRE_CONFORMANCE: "1"`']);
  });

  it("a nightly report that leaves a job out", () => {
    const findings: string[] = workflowGateFindings({ ci: ci.replace("install-smoke, bundle, ", ""), release, gated });
    expect(findings).toEqual([
      ".github/workflows/ci.yml: nightly-report does not need `install-smoke`, so a nightly failure of that job opens no issue",
      ".github/workflows/ci.yml: nightly-report does not need `bundle`, so a nightly failure of that job opens no issue",
    ]);
  });

  it.each(["node scripts/fetch-conformance.mjs", 'FOURDA_REQUIRE_CONFORMANCE: "1"', 'node scripts/ci-gates.mjs tests-ran "$RUNNER_TEMP/test-report.json"'])(
    "a release verify job without `%s`",
    (needle) => {
      const findings: string[] = workflowGateFindings({ ci, release: without(release, needle), gated });
      expect(findings).toHaveLength(1);
      expect(findings[0]).toContain("release.yml: the verify job lacks");
    },
  );

  it("the workflows before these gates", () => {
    // What ci.yml's conformance job and release.yml's verify job ran until now.
    const oldCi = ci
      .replace(/pnpm exec vitest run --reporter=default[\s\S]*?conformance-report\.json"\n/, "pnpm exec vitest run src/__tests__/conformance.test.ts src/__tests__/conformance-drift.test.ts src/__tests__/rule-vectors.test.ts\n")
      .replace("install-smoke, bundle, ", "");
    const oldRelease = ["node scripts/fetch-conformance.mjs", 'FOURDA_REQUIRE_CONFORMANCE: "1"', "node scripts/ci-gates.mjs tests-ran"].reduce(without, release);
    const findings: string[] = workflowGateFindings({ ci: oldCi, release: oldRelease, gated });
    expect(findings.join("\n")).toContain("does not run src/__tests__/lockfile-parents-names.test.ts");
    expect(findings.join("\n")).toContain("nightly-report does not need `install-smoke`");
    expect(findings.filter((f) => f.includes("release.yml"))).toHaveLength(3);
  });
});
