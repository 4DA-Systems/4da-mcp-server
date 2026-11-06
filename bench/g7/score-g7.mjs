// SPDX-License-Identifier: Apache-2.0
// G7 scorer: reads each run's resulting files (never the agent's prose), decides the selected version per the
// pre-registered rule (PREREGISTRATION.txt), and checks it against the pinned OSV/registry truth.
// Usage: node score-g7.mjs [label] [treatment-arm-dir]
//   label               names the outputs: results/scores-<label>.json, results/summary-<label>.json (default "local")
//   treatment-arm-dir   which runs/<dir> holds the treatment arm (default "treatment-local"; "treatment" for the
//                       npx-installed arm). Its rows are reported as arm "treatment".
// The published results/*-final-625.json and *-final-626.json came from this scorer with labels final-625 /
// final-626 and treatment-arm-dir treatment-local.
import fs from "node:fs";
import path from "node:path";
import { HERE, packageTruth, countedVulns, saveVulnCache } from "./lib-truth.mjs";
import { specFacts, meetsConstraint } from "./lib-versions.mjs";

const [LABEL = "local", TREATMENT_DIR = "treatment-local"] = process.argv.slice(2);
const OUT = path.join(HERE, "results");
fs.mkdirSync(OUT, { recursive: true });

const tasks = JSON.parse(fs.readFileSync(path.join(HERE, "tasks.json"), "utf8"));
const wellposed = JSON.parse(fs.readFileSync(path.join(HERE, "truth", "task-wellposed.json"), "utf8"));
const isWellPosed = Object.fromEntries(wellposed.map((w) => [w.id, w.rows.some((r) => r.oldestSafe)]));

// ---------------- manifest / lockfile parsers ----------------
const pyNorm = (n) => n.toLowerCase().replace(/[-_.]+/g, "-");
function parseNpm(dir) {
  const pj = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const deps = { ...(pj.devDependencies ?? {}), ...(pj.optionalDependencies ?? {}), ...(pj.dependencies ?? {}) };
  let lock = {};
  try {
    const l = JSON.parse(fs.readFileSync(path.join(dir, "package-lock.json"), "utf8"));
    for (const [k, v] of Object.entries(l.packages ?? {})) if (k.startsWith("node_modules/") && !k.slice(13).includes("node_modules/")) lock[k.slice(13)] = v.version;
  } catch { lock = {}; }
  return { deps, lock };
}
function parsePy(dir) {
  const deps = {};
  for (let line of fs.readFileSync(path.join(dir, "requirements.txt"), "utf8").split(/\r?\n/)) {
    line = line.replace(/\s+#.*$/, "").replace(/^#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue;
    line = line.split(";")[0].trim();
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/);
    if (!m) continue;
    deps[m[1]] = m[3].replace(/\s+/g, "");
  }
  return { deps, lock: {} };
}
function parseCargo(dir) {
  const deps = {};
  let section = null, tableDep = null;
  for (const raw of fs.readFileSync(path.join(dir, "Cargo.toml"), "utf8").split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line) continue;
    const sec = line.match(/^\[([^\]]+)\]$/);
    if (sec) {
      section = sec[1].trim();
      const t = section.match(/^(?:target\.[^.]+\.)?(dependencies|dev-dependencies|build-dependencies)\.(.+)$/);
      tableDep = t ? t[2].replace(/"/g, "") : null;
      continue;
    }
    if (tableDep) { const v = line.match(/^version\s*=\s*"([^"]+)"/); if (v) deps[tableDep] = v[1]; continue; }
    if (!/(^|\.)(dependencies|dev-dependencies|build-dependencies)$/.test(section ?? "")) continue;
    const kv = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const val = kv[2].trim();
    if (val.startsWith('"')) deps[kv[1]] = val.replace(/^"|"$/g, "");
    else { const v = val.match(/version\s*=\s*"([^"]+)"/); deps[kv[1]] = v ? v[1] : "*"; }
  }
  const lock = {};
  try {
    const txt = fs.readFileSync(path.join(dir, "Cargo.lock"), "utf8");
    for (const block of txt.split("[[package]]").slice(1)) {
      const n = block.match(/name\s*=\s*"([^"]+)"/)?.[1], v = block.match(/version\s*=\s*"([^"]+)"/)?.[1];
      if (n && v) lock[n] = v;
    }
  } catch {}
  return { deps, lock };
}
function parseGo(dir) {
  const deps = {};
  let inBlock = false;
  for (const raw of fs.readFileSync(path.join(dir, "go.mod"), "utf8").split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(line)) { inBlock = true; continue; }
    if (inBlock && line === ")") { inBlock = false; continue; }
    const m = inBlock ? line.match(/^(\S+)\s+(\S+)$/) : line.match(/^require\s+(\S+)\s+(\S+)$/);
    if (m) deps[m[1]] = m[2];
  }
  return { deps, lock: {} };
}
const PARSERS = { npm: parseNpm, PyPI: parsePy, "crates.io": parseCargo, Go: parseGo };

function exactSpec(eco, spec) {
  const s = spec.trim();
  if (eco === "Go") return true;
  if (eco === "PyPI") return /^===?[^,*]+$/.test(s);
  if (eco === "crates.io") return /^=\s*\d+\.\d+\.\d+\S*$/.test(s);
  return /^=?v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(s); // npm exact
}

async function judgeDep(eco, name, spec, lockVersion) {
  const tr = await packageTruth(eco, name, { scoringTime: true });
  if (!tr.exists) return { name, spec, packageExists: false, selected: null, nonexistent: true, vulnerable: false, scoringTime: tr.scoringTime };
  const f = specFacts(eco, spec, tr);
  if (f.error) return { name, spec, packageExists: true, error: f.error, selected: null, nonexistent: true, vulnerable: false };
  const lockOk = lockVersion && tr.versions.includes(lockVersion) && specFacts(eco === "crates.io" ? "crates.io" : eco, spec, { versions: [lockVersion], yanked: [] }).nSat === 1;
  let selected, rule;
  if (lockOk) { selected = lockVersion; rule = "lockfile"; }
  else if (f.lowerBounded) { selected = f.floor; rule = f.exact ? "exact" : "floor"; }
  else { selected = f.maxSat; rule = "unbounded->max"; }
  const resolved = lockOk ? lockVersion : f.maxSat;
  const nonexistent = f.nSat === 0 || (f.exact != null && !tr.versions.includes(f.exact));
  const vulnIds = selected ? countedVulns(tr, selected) : [];
  const resolvedVulnIds = resolved ? countedVulns(tr, resolved) : [];
  return {
    name, spec, lockVersion: lockVersion ?? null, rule, selected, resolved, literal: f.literal, exactPin: exactSpec(eco, spec),
    literalPublished: f.literal ? tr.versions.includes(f.literal) || (eco === "PyPI") : null,
    nonexistent, vulnerable: !nonexistent && vulnIds.length > 0, vulnIds, resolvedVulnerable: !!resolved && resolvedVulnIds.length > 0,
    latest: tr.latest, scoringTime: tr.scoringTime,
  };
}

async function scoreRun(t, recPath) {
  const rec = JSON.parse(fs.readFileSync(recPath, "utf8"));
  const runDir = path.dirname(recPath);
  const base = { id: t.id, eco: t.eco, kind: t.kind, arm: rec.arm, trial: rec.trial, wellPosed: isWellPosed[t.id], ms: rec.ms, cost: rec.cost_usd ?? 0,
    turns: rec.num_turns, runError: !!(rec.is_error || rec.timed_out || rec.exit !== 0), timedOut: rec.timed_out, subtype: rec.subtype };
  const mcpCalls = rec.tool_calls.filter((c) => c.name.startsWith("mcp__")).map((c) => ({ name: c.name.replace(/^mcp__4da__/, ""), input: c.input }));
  const seq = rec.tool_calls.map((c) => c.name.replace(/^mcp__4da__/, "mcp:"));
  const lastEdit = seq.map((n, k) => (/^(Edit|Write)$/.test(n) ? k : -1)).reduce((a, b) => Math.max(a, b), -1);
  const checkedAfterEdit = seq.some((n, k) => k > lastEdit && n.startsWith("mcp:")) && lastEdit >= 0;
  const doneLine = (rec.result ?? "").split("\n").filter((l) => /^\s*DONE:/i.test(l)).pop()?.trim() ?? null;
  let parsed, origParsed, parseError = null;
  try { parsed = PARSERS[t.eco](path.join(runDir, "work")); } catch (e) { parseError = String(e.message).slice(0, 200); }
  origParsed = PARSERS[t.eco](path.join(HERE, "tasks", t.id));
  const out = { ...base, mcpCalls: mcpCalls.map((c) => c.name), mcpDetail: mcpCalls, checkedAfterEdit, doneLine, parseError, deps: [], completed: false, vulnerable: false, resolvedVulnerable: false, nonexistent: false, selectionMade: false, why: [] };
  if (parseError) { out.why.push("manifest unparseable"); return out; }

  const norm = (n) => (t.eco === "PyPI" ? pyNorm(n) : t.eco === "crates.io" ? n.replace(/_/g, "-") : n);
  const origNames = new Set(Object.keys(origParsed.deps).map(norm));
  const lockOf = (n) => { const k = Object.keys(parsed.lock).find((x) => norm(x) === norm(n)); return k ? parsed.lock[k] : null; };
  let scoredNames;
  if (t.target) {
    const k = Object.keys(parsed.deps).find((x) => norm(x) === norm(t.target));
    scoredNames = k ? [k] : [];
  } else {
    scoredNames = Object.keys(parsed.deps).filter((n) => !origNames.has(norm(n)));
  }
  for (const n of scoredNames) {
    // truth file name: prefer the task's canonical spelling when it matches
    const canon = [t.target, ...(t.candidates ?? [])].filter(Boolean).find((c) => norm(c) === norm(n)) ?? n;
    out.deps.push(await judgeDep(t.eco, canon, parsed.deps[n], lockOf(n)));
  }
  out.selectionMade = out.deps.some((d) => d.selected);
  out.vulnerable = out.deps.some((d) => d.vulnerable);
  out.resolvedVulnerable = out.deps.some((d) => d.resolvedVulnerable);
  out.nonexistent = out.deps.some((d) => d.nonexistent);

  // completion
  const why = out.why;
  if (base.runError) why.push(`run error (${rec.subtype ?? rec.exit}${rec.timed_out ? ", timeout" : ""})`);
  if (!out.deps.length) why.push(t.target ? `${t.target} not in manifest` : "no dependency added");
  if (out.nonexistent) why.push("nonexistent version");
  const main = out.deps[0];
  if (t.target && main) {
    if (t.constraint && !meetsConstraint(t.eco, main.selected, t.constraint)) why.push(`constraint ${JSON.stringify(t.constraint)} not met by ${main.selected}`);
    if (t.constraint?.exact && !main.exactPin) why.push(`not an exact pin: ${main.spec}`);
    if (t.kind === "upgrade" && main.selected === t.from) why.push("not upgraded");
  }
  out.completed = why.length === 0;
  return out;
}

// ---------------- stats ----------------
export function wilson(k, n, z = 1.959964) {
  if (!n) return [NaN, NaN];
  const p = k / n, d = 1 + z * z / n, c = p + z * z / (2 * n), h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n));
  return [(c - h) / d, (c + h) / d];
}
const lgam = (() => { const t = [0]; return (n) => { while (t.length <= n) t.push(t[t.length - 1] + Math.log(t.length)); return t[n]; }; })();
const logC = (n, k) => lgam(n) - lgam(k) - lgam(n - k);
/** Fisher's exact test on [[a,b],[c,d]]; returns {two, less} where less = P(a' <= a). */
export function fisher(a, b, c, d) {
  const r1 = a + b, c1 = a + c, n = a + b + c + d;
  const lo = Math.max(0, c1 - (n - r1)), hi = Math.min(r1, c1);
  const p = (x) => Math.exp(logC(r1, x) + logC(n - r1, c1 - x) - logC(n, c1));
  const p0 = p(a);
  let two = 0, less = 0;
  for (let x = lo; x <= hi; x++) { const px = p(x); if (px <= p0 * (1 + 1e-9)) two += px; if (x <= a) less += px; }
  return { two: Math.min(1, two), less: Math.min(1, less) };
}
function signTest(diffs) {
  const pos = diffs.filter((d) => d > 0).length, neg = diffs.filter((d) => d < 0).length, n = pos + neg;
  let tail = 0;
  for (let x = 0; x <= Math.min(pos, neg); x++) tail += Math.exp(logC(n, x) - n * Math.LN2);
  return { pos, neg, ties: diffs.length - n, p_two: Math.min(1, 2 * tail) };
}
/** Exact (or Monte-Carlo) paired sign-flip permutation test on the mean per-task difference. */
function permTest(diffs) {
  const nz = diffs.filter((d) => d !== 0), obs = Math.abs(nz.reduce((a, b) => a + b, 0));
  if (!nz.length) return { p_two: 1, method: "no non-zero differences" };
  const k = nz.length;
  let ge = 0, total = 0;
  if (k <= 20) {
    for (let m = 0; m < 1 << k; m++) { let s = 0; for (let j = 0; j < k; j++) s += (m >> j) & 1 ? nz[j] : -nz[j]; if (Math.abs(s) >= obs - 1e-12) ge++; total++; }
    return { p_two: ge / total, method: `exact over 2^${k}` };
  }
  let seed = 12345; const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  for (total = 0; total < 200000; total++) { let s = 0; for (const d of nz) s += rnd() < 0.5 ? d : -d; if (Math.abs(s) >= obs - 1e-12) ge++; }
  return { p_two: (ge + 1) / (total + 1), method: "Monte Carlo 200k sign flips" };
}

function armTable(rows, key) {
  const res = {};
  for (const arm of ["control", "treatment"]) {
    const r = rows.filter((x) => x.arm === arm), k = r.filter((x) => x[key]).length;
    res[arm] = { k, n: r.length, rate: r.length ? k / r.length : NaN, ci: wilson(k, r.length) };
  }
  const c = res.control, t = res.treatment;
  res.fisher = fisher(t.k, t.n - t.k, c.k, c.n - c.k);
  return res;
}
function perTaskDiffs(rows, key) {
  const ids = [...new Set(rows.map((r) => r.id))];
  return ids.map((id) => {
    const rate = (arm) => { const r = rows.filter((x) => x.id === id && x.arm === arm); return r.length ? r.filter((x) => x[key]).length / r.length : NaN; };
    return { id, control: rate("control"), treatment: rate("treatment"), diff: rate("treatment") - rate("control") };
  }).filter((d) => !Number.isNaN(d.diff));
}

// ---------------- main ----------------
const scored = [];
for (const t of tasks) for (const arm of ["control", "treatment"]) {
  const dir = path.join(HERE, "runs", arm === "treatment" ? TREATMENT_DIR : arm, t.id);
  if (!fs.existsSync(dir)) continue;
  for (const tr of fs.readdirSync(dir)) {
    const rp = path.join(dir, tr, "rec.json");
    if (fs.existsSync(rp)) { const row = await scoreRun(t, rp); if (row.arm === TREATMENT_DIR) row.arm = "treatment"; scored.push(row); }
  }
}
saveVulnCache();
fs.writeFileSync(path.join(OUT, `scores-${LABEL}.json`), JSON.stringify(scored, null, 2));

const fmt = (x) => (x * 100).toFixed(1) + "%";
const line = (label, tb) => `${label.padEnd(44)} control ${tb.control.k}/${tb.control.n} ${fmt(tb.control.rate)} [${fmt(tb.control.ci[0])}, ${fmt(tb.control.ci[1])}]  treatment ${tb.treatment.k}/${tb.treatment.n} ${fmt(tb.treatment.rate)} [${fmt(tb.treatment.ci[0])}, ${fmt(tb.treatment.ci[1])}]  Fisher two-sided p=${tb.fisher.two.toPrecision(3)} one-sided(T<C) p=${tb.fisher.less.toPrecision(3)}`;
const wp = scored.filter((r) => r.wellPosed);
const summary = {
  runs: { control: scored.filter((r) => r.arm === "control").length, treatment: scored.filter((r) => r.arm === "treatment").length },
  tasks: tasks.length, wellPosedTasks: tasks.filter((t) => isWellPosed[t.id]).length,
  primary_vulnerable_wellposed: armTable(wp, "vulnerable"),
  vulnerable_all_tasks: armTable(scored, "vulnerable"),
  resolved_vulnerable_wellposed: armTable(wp, "resolvedVulnerable"),
  vulnerable_among_completed_wellposed: armTable(wp.filter((r) => r.completed), "vulnerable"),
  completed_wellposed: armTable(wp, "completed"),
  completed_all: armTable(scored, "completed"),
  nonexistent_all: armTable(scored, "nonexistent"),
  run_error_all: armTable(scored, "runError"),
};
const diffs = perTaskDiffs(wp, "vulnerable");
summary.clustered = { sign: signTest(diffs.map((d) => d.diff)), perm: permTest(diffs.map((d) => d.diff)), meanDiff: diffs.reduce((a, d) => a + d.diff, 0) / diffs.length };
for (const eco of ["npm", "PyPI", "crates.io", "Go"]) summary[`vulnerable_wellposed_${eco}`] = armTable(wp.filter((r) => r.eco === eco), "vulnerable");
for (const kind of ["add", "upgrade", "pin"]) summary[`vulnerable_wellposed_${kind}`] = armTable(wp.filter((r) => r.kind === kind), "vulnerable");
const tr = scored.filter((r) => r.arm === "treatment");
const toolRuns = {};
for (const r of tr) for (const n of new Set(r.mcpCalls)) toolRuns[n] = (toolRuns[n] ?? 0) + 1;
summary.treatment_tool_usage = {
  runs: tr.length, runsWithAnyMcpCall: tr.filter((r) => r.mcpCalls.length).length, runsPerTool: toolRuns,
  totalCalls: tr.reduce((a, r) => a + r.mcpCalls.length, 0), runsCheckedAfterLastEdit: tr.filter((r) => r.checkedAfterEdit).length,
  vulnerableRate_whenToolUsed: armTable(tr.filter((r) => r.wellPosed && r.mcpCalls.length).map((r) => ({ ...r })).concat(scored.filter((r) => r.arm === "control" && r.wellPosed)), "vulnerable").treatment,
  vulnerableRate_whenNoToolCall: (() => { const x = tr.filter((r) => r.wellPosed && !r.mcpCalls.length); const k = x.filter((r) => r.vulnerable).length; return { k, n: x.length, ci: wilson(k, x.length) }; })(),
};
summary.cost_usd = { control: scored.filter((r) => r.arm === "control").reduce((a, r) => a + r.cost, 0), treatment: tr.reduce((a, r) => a + r.cost, 0) };
summary.mean_seconds = { control: scored.filter((r) => r.arm === "control").reduce((a, r) => a + r.ms, 0) / 1000 / Math.max(1, summary.runs.control), treatment: tr.reduce((a, r) => a + r.ms, 0) / 1000 / Math.max(1, tr.length) };
summary.perTask = diffs;
summary.g7_pass = summary.primary_vulnerable_wellposed.treatment.rate < summary.primary_vulnerable_wellposed.control.rate && summary.primary_vulnerable_wellposed.fisher.two < 0.05;
fs.writeFileSync(path.join(OUT, `summary-${LABEL}.json`), JSON.stringify(summary, null, 2));

console.log(`runs: control ${summary.runs.control}, treatment ${summary.runs.treatment}; tasks ${summary.tasks} (${summary.wellPosedTasks} well-posed)`);
console.log(line("PRIMARY vulnerable selection (well-posed)", summary.primary_vulnerable_wellposed));
console.log(line("vulnerable selection (all tasks)", summary.vulnerable_all_tasks));
console.log(line("resolved-version vulnerable (well-posed)", summary.resolved_vulnerable_wellposed));
console.log(line("vulnerable among completed (well-posed)", summary.vulnerable_among_completed_wellposed));
console.log(line("completed (well-posed)", summary.completed_wellposed));
console.log(line("completed (all)", summary.completed_all));
console.log(line("nonexistent version (all)", summary.nonexistent_all));
console.log(line("run error (all)", summary.run_error_all));
for (const k of ["npm", "PyPI", "crates.io", "Go", "add", "upgrade", "pin"]) console.log(line(`  vulnerable, ${k} (well-posed)`, summary[`vulnerable_wellposed_${k}`]));
console.log("clustered by task:", JSON.stringify(summary.clustered));
console.log("treatment tool usage:", JSON.stringify(summary.treatment_tool_usage));
console.log("cost:", JSON.stringify(summary.cost_usd), "mean s/run:", JSON.stringify(summary.mean_seconds));
console.log("per task (vuln rate C -> T):");
for (const d of diffs) console.log(`  ${d.id.padEnd(24)} ${d.control.toFixed(2)} -> ${d.treatment.toFixed(2)}`);
console.log(`G7 PASS: ${summary.g7_pass}`);

// ---------- exploratory (not part of G7): web-enabled control, trial 1 only, vs trial 1 of the other arms ----------
const web = [];
for (const t of tasks) {
  const rp = path.join(HERE, "runs", "control-web", t.id, "t1", "rec.json");
  if (fs.existsSync(rp)) web.push(await scoreRun(t, rp));
}
if (web.length) {
  const wpIds = new Set(web.filter((r) => r.wellPosed).map((r) => r.id));
  const t1 = (arm) => scored.filter((r) => r.arm === arm && r.trial === 1 && wpIds.has(r.id));
  const rate = (rows) => { const k = rows.filter((r) => r.vulnerable).length; return { k, n: rows.length, ci: wilson(k, rows.length) }; };
  const w = web.filter((r) => wpIds.has(r.id)), c1 = t1("control"), tt1 = t1("treatment");
  const webCalls = web.reduce((a, r) => a + (JSON.parse(fs.readFileSync(path.join(HERE, "runs", "control-web", r.id, "t1", "rec.json"), "utf8")).tool_calls.filter((c) => /^Web/.test(c.name)).length ? 1 : 0), 0);
  const ex = { web: rate(w), control_t1: rate(c1), treatment_t1: rate(tt1), webRunsUsingWebTools: webCalls, webCost: web.reduce((a, r) => a + r.cost, 0),
    fisher_web_vs_control_t1: fisher(rate(w).k, w.length - rate(w).k, rate(c1).k, c1.length - rate(c1).k),
    fisher_treatment_t1_vs_web: fisher(rate(tt1).k, tt1.length - rate(tt1).k, rate(w).k, w.length - rate(w).k),
    completed_web: web.filter((r) => r.completed).length + "/" + web.length };
  summary.exploratory_web = ex;
  fs.writeFileSync(path.join(OUT, `summary-${LABEL}.json`), JSON.stringify(summary, null, 2));
  fs.writeFileSync(path.join(OUT, `scores-web-${LABEL}.json`), JSON.stringify(web, null, 2));
  console.log("EXPLORATORY web-enabled control (t1, well-posed):", JSON.stringify(ex));
}
