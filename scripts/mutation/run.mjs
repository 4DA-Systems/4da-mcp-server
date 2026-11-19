// SPDX-License-Identifier: Apache-2.0
/**
 * Mutation check: does the test suite notice when the code it guards is wrong?
 *
 *   node scripts/mutation/run.mjs --check             every mutant still applies (nothing is changed)
 *   node scripts/mutation/run.mjs [--only ID,ID] [--out DIR] [--stage-timeout-ms N]
 *
 * Every mutant in mutations.mjs is validated before anything is changed: its `find` text must
 * occur exactly once in its file (or at its `nth` occurrence) and its `tests` must exist, or the
 * run stops with exit 2, so a mutant cannot rot into a no-op. Then, on pristine source, the build
 * and the full suite must pass (the baseline; otherwise nothing can be judged). Each mutant is
 * then applied in turn: build (a mutant that does not compile is INVALID), its `tests` first,
 * and only when those all pass the full suite. Any failing test kills it. The file is restored
 * from memory after every mutant and compared byte for byte; dist/ is rebuilt from pristine
 * source at the end.
 *
 * Writes results.jsonl, summary.md and survivors.txt to --out (default: a folder under the OS
 * temp directory). Exit 0 when every mutant was killed or is listed `equivalent`; 1 when one
 * survived or did not compile; 2 when the list or the baseline is broken; 3 when a file could
 * not be restored.
 *
 * Set FOURDA_REQUIRE_CONFORMANCE=1 (CI does) so a missing conformance corpus fails the baseline:
 * without the corpus, mutants that only the corpus suites kill read as survivors.
 */
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { applied, failures, locate, validate } from "./lib.mjs";
import { mutations } from "./mutations.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const USAGE = "usage: node scripts/mutation/run.mjs [--check] [--only ID,ID] [--out DIR] [--stage-timeout-ms N]";

function parseArgs(argv) {
  const opts = { check: false, only: null, out: null, stageTimeoutMs: 15 * 60_000 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) fail(`${a} needs a value\n${USAGE}`, 2);
      return argv[++i];
    };
    if (a === "--check") opts.check = true;
    else if (a === "--only") opts.only = value().split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--out") opts.out = resolve(value());
    else if (a === "--stage-timeout-ms") opts.stageTimeoutMs = Number(value());
    else if (a === "--help" || a === "-h") { console.log(USAGE); process.exit(0); }
    else fail(`unknown argument ${a}\n${USAGE}`, 2);
  }
  if (!Number.isFinite(opts.stageTimeoutMs) || opts.stageTimeoutMs <= 0) fail("--stage-timeout-ms must be a positive number", 2);
  return opts;
}

function fail(message, code) {
  console.error(`mutation: ${message}`);
  process.exit(code);
}

function sh(command, { env = {}, timeout } = {}) {
  const started = Date.now();
  const r = spawnSync(command, {
    cwd: root, shell: true, encoding: "utf8", timeout, killSignal: "SIGKILL",
    env: { ...process.env, ...env }, maxBuffer: 256 * 1024 * 1024,
  });
  const out = `${r.stdout ?? ""}\n${r.stderr ?? ""}`.trim();
  return { status: r.status, timedOut: r.error?.code === "ETIMEDOUT", ms: Date.now() - started, tail: out.split("\n").slice(-15).join("\n") };
}

/** One vitest run over `files` (all files when empty). Killed = it did not pass. */
function testStage(files, out, label, timeout) {
  const reportFile = join(out, `tmp-${label}.json`);
  rmSync(reportFile, { force: true });
  const r = sh(`pnpm exec vitest run --reporter=json --outputFile="${reportFile}" ${files.join(" ")}`, { timeout });
  const report = failures(existsSync(reportFile) ? readFileSync(reportFile, "utf8") : null);
  rmSync(reportFile, { force: true });
  return { passed: r.status === 0, timedOut: r.timedOut, ms: r.ms, report, tail: r.status === 0 ? "" : r.tail.slice(-1500) };
}

const opts = parseArgs(process.argv.slice(2));
const problems = validate(mutations, root);
if (opts.check) {
  for (const m of mutations) {
    const loc = locate(m, root);
    console.log(`${m.id.padEnd(5)} ${loc.error ? `ERROR ${loc.error}` : `ok    ${m.file}:${loc.line}${m.equivalent ? "  (equivalent)" : ""}`}`);
  }
  console.log(`${mutations.length} mutants, ${problems.length} problem(s)`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(problems.length ? 2 : 0);
}
if (problems.length) fail(`the mutant list is broken; nothing was changed:\n  ${problems.join("\n  ")}`, 2);

let selected = mutations;
if (opts.only) {
  const unknown = opts.only.filter((id) => !mutations.some((m) => m.id === id));
  if (unknown.length) fail(`no mutant with id ${unknown.join(", ")}`, 2);
  selected = mutations.filter((m) => opts.only.includes(m.id));
}

const dirty = sh(`git status --porcelain --untracked-files=no -- ${[...new Set(selected.map((m) => m.file))].join(" ")}`);
if (dirty.status !== 0) fail(`git status failed:\n${dirty.tail}`, 2);
if (dirty.tail.trim()) fail(`files the mutants change have uncommitted edits; commit them first:\n${dirty.tail}`, 2);

const out = opts.out ?? join(tmpdir(), `4da-mutation-${Date.now()}`);
mkdirSync(out, { recursive: true });
const resultsFile = join(out, "results.jsonl");
writeFileSync(resultsFile, "");
const head = sh("git rev-parse HEAD").tail.trim();
console.log(`mutation: ${selected.length} of ${mutations.length} mutants at ${head}; results in ${out}`);

// The baseline: a suite that already fails would kill every mutant.
const baseBuild = sh("pnpm run build", { timeout: opts.stageTimeoutMs });
if (baseBuild.status !== 0) fail(`the pristine source does not build:\n${baseBuild.tail}`, 2);
const baseline = testStage([], out, "baseline", opts.stageTimeoutMs);
if (!baseline.passed) fail(`the full suite fails on pristine source, so no mutant can be judged:\n  ${(baseline.report?.failed ?? [baseline.tail]).slice(0, 20).join("\n  ")}`, 2);
console.log(`baseline: build ok, ${baseline.report?.passed} of ${baseline.report?.total} tests pass (${Math.round(baseline.ms / 1000)} s)`);

let current = null; // { path, text } of the file now mutated
const restore = () => {
  if (!current) return true;
  writeFileSync(current.path, current.text);
  const ok = readFileSync(current.path, "utf8") === current.text;
  current = null;
  return ok;
};
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => { restore(); fail(`stopped by ${signal}; the mutated file was restored`, 130); });

const results = [];
selected.forEach((m, index) => {
  const loc = locate(m, root);
  const rec = { id: m.id, area: m.area, file: m.file, line: loc.line, intent: m.intent, ...(m.equivalent ? { equivalent: m.equivalent } : {}) };
  current = { path: loc.path, text: loc.text };
  try {
    writeFileSync(loc.path, applied(m, loc));
    const build = sh("pnpm run build", { timeout: opts.stageTimeoutMs });
    if (build.status !== 0) {
      Object.assign(rec, { verdict: "INVALID", detail: `does not compile: ${build.tail.split("\n").filter((l) => /error/i.test(l)).slice(0, 3).join(" / ")}` });
    } else {
      const stages = [];
      if (m.tests?.length) stages.push(["likely", testStage(m.tests, out, `${m.id}-likely`, opts.stageTimeoutMs)]);
      if (stages.every(([, s]) => s.passed)) stages.push(["full", testStage([], out, `${m.id}-full`, opts.stageTimeoutMs)]);
      const killer = stages.find(([, s]) => !s.passed);
      rec.stages = stages.map(([name, s]) => ({ name, passed: s.passed, timedOut: s.timedOut, ms: s.ms, failed: s.report?.failed.slice(0, 10) ?? null, tail: s.passed || s.report?.failed.length ? undefined : s.tail }));
      if (killer) {
        const [name, s] = killer;
        const n = s.report?.failed.length ?? 0;
        rec.verdict = "KILLED";
        rec.detail = s.timedOut ? `${name} tests timed out` : `by the ${name === "likely" ? "likely tests" : "full suite"}: ${n ? `${n} failed, first ${s.report.failed[0]}` : "the run failed without a test failure"}`;
      } else {
        rec.verdict = m.equivalent ? "EQUIVALENT" : "SURVIVED";
        rec.detail = m.equivalent ? `survived as expected: ${m.equivalent}` : "every test passes with this mutant";
      }
    }
  } finally {
    if (!restore()) {
      appendFileSync(resultsFile, `${JSON.stringify({ ...rec, restored: false })}\n`);
      fail(`could not restore ${m.file}; stopping. Check it with git diff.`, 3);
    }
  }
  results.push(rec);
  appendFileSync(resultsFile, `${JSON.stringify(rec)}\n`);
  console.log(`[${index + 1}/${selected.length}] ${m.id} ${m.file}:${loc.line} ${rec.verdict} ${rec.detail}`);
});

const rebuilt = sh("pnpm run build", { timeout: opts.stageTimeoutMs });
const bad = results.filter((r) => r.verdict === "SURVIVED" || r.verdict === "INVALID");
const count = (v) => results.filter((r) => r.verdict === v).length;
const esc = (s) => String(s).replaceAll("|", "\\|");
const summary = [
  `## Mutation check at ${head.slice(0, 12)}`,
  "",
  `${results.length} mutants: ${count("KILLED")} killed, ${count("SURVIVED")} survived, ${count("EQUIVALENT")} equivalent, ${count("INVALID")} invalid. Baseline: ${baseline.report?.passed} of ${baseline.report?.total} tests.`,
  "",
  ...(bad.length ? ["### Not killed", "", ...bad.map((r) => `- **${r.id}** \`${r.file}:${r.line}\` ${r.verdict}: ${r.intent}`), ""] : []),
  "| id | file:line | verdict | detail |",
  "|---|---|---|---|",
  ...results.map((r) => `| ${r.id} | ${r.file}:${r.line} | ${r.verdict} | ${esc(r.detail).slice(0, 220)} |`),
  "",
].join("\n");
writeFileSync(join(out, "summary.md"), summary);
writeFileSync(join(out, "survivors.txt"), bad.map((r) => `${r.id} ${r.file}:${r.line} ${r.verdict}: ${r.intent}`).join("\n") + (bad.length ? "\n" : ""));
console.log(`\n${summary}`);
if (rebuilt.status !== 0) fail("dist/ could not be rebuilt from pristine source after the run", 3);
if (bad.length) {
  console.error(`mutation: ${bad.length} mutant(s) not killed (outside the equivalent list): ${bad.map((r) => r.id).join(", ")}`);
  process.exit(1);
}
