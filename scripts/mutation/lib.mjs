// SPDX-License-Identifier: Apache-2.0
/**
 * The parts of the mutation check that decide, kept apart from the runner so they can be tested:
 * where a mutant applies, what is wrong with a mutant list, and which tests a vitest JSON
 * report says failed.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** Where `m.find` sits in its file under `root`, or `{ error }` saying why it cannot be applied. */
export function locate(m, root) {
  const path = join(root, m.file);
  if (!existsSync(path)) return { error: `${m.file} does not exist` };
  const text = readFileSync(path, "utf8");
  const hits = [];
  for (let at = text.indexOf(m.find); at >= 0; at = text.indexOf(m.find, at + 1)) hits.push(at);
  if (hits.length === 0) return { error: `the text to replace is no longer in ${m.file}: ${JSON.stringify(m.find).slice(0, 120)}` };
  if (m.nth === undefined && hits.length !== 1) return { error: `the text to replace occurs ${hits.length} times in ${m.file}; give nth` };
  if (m.nth !== undefined && (!Number.isInteger(m.nth) || m.nth < 1 || m.nth > hits.length)) {
    return { error: `nth ${m.nth}, but the text occurs ${hits.length} times in ${m.file}` };
  }
  const at = hits[(m.nth ?? 1) - 1];
  return { path, text, at, line: text.slice(0, at).split("\n").length };
}

/** The source of `m`'s file with the mutant applied (`loc` from locate). */
export function applied(m, loc) {
  return loc.text.slice(0, loc.at) + m.replace + loc.text.slice(loc.at + m.find.length);
}

/** Every problem with the mutant list, one line each; empty when every mutant can be applied. */
export function validate(list, root) {
  const problems = [];
  const seen = new Set();
  for (const m of list) {
    const where = `${m.id ?? "(no id)"}:`;
    if (!m.id || seen.has(m.id)) problems.push(`${where} missing or duplicate id`);
    seen.add(m.id);
    if (typeof m.file !== "string" || !m.file) { problems.push(`${where} no file`); continue; }
    if (!m.find || typeof m.replace !== "string" || m.find === m.replace) problems.push(`${where} find must be non-empty and differ from replace`);
    if (!m.intent) problems.push(`${where} no intent (the wrong behaviour the mutant introduces)`);
    if (m.equivalent !== undefined && !String(m.equivalent).trim()) problems.push(`${where} equivalent needs its reason`);
    for (const t of m.tests ?? []) if (!existsSync(join(root, t))) problems.push(`${where} test file ${t} does not exist`);
    if (m.find) {
      const loc = locate(m, root);
      if (loc.error) problems.push(`${where} ${loc.error}`);
    }
  }
  return problems;
}

/**
 * `validate` as repository-gate findings (scripts/check-repo.mjs): the same check as
 * `run.mjs --check`, so a change that moves or rewrites a mutant's text fails the pull request
 * until the mutant is updated with it. Reads files only.
 */
export function listFindings(list, root) {
  return validate(list, root).map((p) => `scripts/mutation/mutations.mjs: mutant ${p} (update its find/replace in the same change; scripts/mutation/README.md)`);
}

/**
 * The failed tests in a vitest JSON report, as `src/__tests__/<file> :: <test>`; a file that
 * failed to load counts as one. Null when there is no report.
 */
export function failures(reportText) {
  if (reportText === null) return null;
  try {
    const report = JSON.parse(reportText);
    const failed = [];
    for (const f of report.testResults ?? []) {
      const file = String(f.name).replaceAll("\\", "/").replace(/^.*?\/(src\/__tests__\/)/, "$1");
      const tests = (f.assertionResults ?? []).filter((t) => t.status === "failed");
      if (f.status === "failed" && tests.length === 0) failed.push(`${file} :: (the file failed to run) ${String(f.message ?? "").split("\n")[0].slice(0, 160)}`);
      for (const t of tests) failed.push(`${file} :: ${t.fullName}`);
    }
    return { total: report.numTotalTests ?? null, passed: report.numPassedTests ?? null, failed };
  } catch (error) {
    return { total: null, passed: null, failed: [`(unreadable report: ${String(error).slice(0, 120)})`] };
  }
}
