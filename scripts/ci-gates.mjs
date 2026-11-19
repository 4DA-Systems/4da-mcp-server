// SPDX-License-Identifier: Apache-2.0
/**
 * Gates on the gates: a green test run must mean the strongest suites ran.
 *
 * vitest exits 0 when a suite skips itself, and the conformance suites skip
 * when the corpus is not there. So a job can be green having checked nothing
 * it was added for. Two checks close that:
 *
 *   node scripts/ci-gates.mjs tests-ran <vitest-json-report> [test-file ...]
 *
 *     Reads a report written by `vitest run --reporter=json` and fails unless
 *     each named test file is in it with at least one test, every test of it
 *     passed, and none was skipped. With no file named it checks every test
 *     file that reads the conformance corpus (`corpusGatedTests`).
 *
 *   workflowGateFindings (used by scripts/check-repo.mjs)
 *
 *     Every corpus-gated test file is named in ci.yml's `conformance` job (the
 *     only CI job that has the corpus), release.yml's `verify` job fetches the
 *     corpus, requires it, and runs `tests-ran` over its report, and ci.yml's
 *     `nightly-report` job needs every other job, so no nightly failure goes
 *     unreported.
 */
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const slashes = (p) => p.replaceAll("\\", "/");

/** Test files (repo-relative, forward slashes) that read the conformance corpus and skip without it. */
export function corpusGatedTests(repoRoot = root) {
  const dir = join(repoRoot, "src", "__tests__");
  return readdirSync(dir)
    .filter((name) => name.endsWith(".test.ts") && /FOURDA_CONFORMANCE_DIR/.test(readFileSync(join(dir, name), "utf8")))
    .map((name) => `src/__tests__/${name}`)
    .sort();
}

/**
 * What is wrong with `report` (vitest's JSON reporter output) for the test files in `files`.
 * @returns One line per problem; empty when every file ran in full and passed.
 */
export function testsRanFindings(report, files) {
  const results = Array.isArray(report?.testResults) ? report.testResults : null;
  if (!results) return ["the report has no testResults: is it a `vitest run --reporter=json` report?"];
  if (files.length === 0) return ["no test file was named, so nothing was checked"];
  const findings = [];
  for (const file of files) {
    const entry = results.find((r) => typeof r?.name === "string" && slashes(r.name).endsWith(`/${slashes(file)}`));
    if (!entry) {
      findings.push(`${file}: not in the report (the file did not run)`);
      continue;
    }
    const tests = Array.isArray(entry.assertionResults) ? entry.assertionResults : [];
    const count = (status) => tests.filter((t) => t.status === status).length;
    const notPassed = tests.length - count("passed");
    if (tests.length === 0) findings.push(`${file}: 0 tests ran (${entry.message || "the suite skipped or failed to load"})`);
    else if (notPassed > 0) {
      const statuses = [...new Set(tests.map((t) => t.status))].filter((s) => s !== "passed").map((s) => `${count(s)} ${s}`);
      findings.push(`${file}: ${notPassed} of ${tests.length} tests did not pass (${statuses.join(", ")})`);
    }
  }
  return findings;
}

/** The text of one job of a workflow file: from its `  <job>:` line to the next job's. Null when absent. */
export function jobBlock(workflowText, job) {
  const lines = workflowText.split(/\r?\n/);
  const start = lines.findIndex((line) => line === `  ${job}:`);
  if (start < 0) return null;
  let end = lines.findIndex((line, i) => i > start && /^ {2}[A-Za-z0-9_-]+:\s*$/.test(line));
  if (end < 0) end = lines.length;
  // Comment lines do not run anything: a gate named only in a comment is not there.
  return lines
    .slice(start, end)
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
}

/** The job ids of a workflow file, in order. */
export function jobNames(workflowText) {
  const lines = workflowText.split(/\r?\n/);
  const jobs = lines.indexOf("jobs:");
  if (jobs < 0) return [];
  return lines.slice(jobs + 1).flatMap((line) => /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line)?.[1] ?? []);
}

/**
 * What the workflows are missing for the corpus-gated suites to count, and for
 * every nightly failure to be reported.
 * @param {{ ci: string, release: string, gated: string[] }} input workflow texts and `corpusGatedTests()`
 * @returns One line per problem.
 */
export function workflowGateFindings({ ci, release, gated }) {
  const findings = [];
  const conformance = jobBlock(ci, "conformance");
  if (conformance === null) findings.push(".github/workflows/ci.yml: no `conformance` job");
  else {
    for (const file of gated) {
      if (!conformance.includes(file)) {
        findings.push(`.github/workflows/ci.yml: the conformance job does not run ${file}, which skips without the corpus and so runs in no CI job`);
      }
    }
    for (const need of ['FOURDA_REQUIRE_CONFORMANCE: "1"', "scripts/ci-gates.mjs tests-ran"]) {
      if (!conformance.includes(need)) findings.push(`.github/workflows/ci.yml: the conformance job lacks \`${need}\``);
    }
  }
  const report = jobBlock(ci, "nightly-report");
  const needs = report === null ? null : /^\s+needs:\s*\[([^\]]*)\]/m.exec(report);
  if (!needs) findings.push(".github/workflows/ci.yml: no `nightly-report` job with a `needs: [...]` list");
  else {
    const needed = needs[1].split(",").map((name) => name.trim());
    for (const job of jobNames(ci)) {
      if (job !== "nightly-report" && !needed.includes(job)) {
        findings.push(`.github/workflows/ci.yml: nightly-report does not need \`${job}\`, so a nightly failure of that job opens no issue`);
      }
    }
  }
  const verify = jobBlock(release, "verify");
  if (verify === null) findings.push(".github/workflows/release.yml: no `verify` job");
  else {
    for (const need of ["node scripts/fetch-conformance.mjs", 'FOURDA_REQUIRE_CONFORMANCE: "1"', "scripts/ci-gates.mjs tests-ran"]) {
      if (!verify.includes(need)) findings.push(`.github/workflows/release.yml: the verify job lacks \`${need}\`, so a release can pass with the conformance suites skipped`);
    }
  }
  return findings;
}

/** True when this file is the script node was started with (drive-letter case differs between shells on Windows). */
function isMain() {
  if (!process.argv[1]) return false;
  const [a, b] = [resolve(process.argv[1]), fileURLToPath(import.meta.url)];
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

if (isMain()) {
  const [command, reportPath, ...named] = process.argv.slice(2);
  if (command !== "tests-ran" || !reportPath) {
    console.error("Usage: node scripts/ci-gates.mjs tests-ran <vitest-json-report> [test-file ...]");
    process.exit(2);
  }
  let report;
  try {
    report = JSON.parse(readFileSync(reportPath, "utf8"));
  } catch (error) {
    console.error(`ci-gates: cannot read ${reportPath}: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
  const files = named.length > 0 ? named : corpusGatedTests();
  const findings = testsRanFindings(report, files);
  if (findings.length > 0) {
    console.error(`ci-gates: ${findings.length} suite(s) did not run in full\n  ${findings.join("\n  ")}`);
    process.exit(1);
  }
  console.log(`ci-gates: OK, ran in full with every test passed: ${files.join(", ")}`);
}
