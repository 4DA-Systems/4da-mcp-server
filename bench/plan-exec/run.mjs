// SPDX-License-Identifier: Apache-2.0
/**
 * Plan-execution harness: does running the plan work? For each project of a pinned public
 * corpus (corpus.json): clone it at its tag (commit checked), ask the server for the whole
 * plan (upgrade_planner, max_recommendations 1000) and a detailed scan, run the plan's steps
 * top to bottom in a copy, then rescan from a fresh server process. Reports per project the
 * steps run, failed, refused, without effect and lowering a version, the advisories before and
 * after, and the plan's own prediction against the result; then the gate (thresholds.json).
 *
 *   node bench/plan-exec/run.mjs --server <dist/index.js | installed package dir>
 *        [--corpus bench/plan-exec/corpus.json] [--only id,id] [--work <dir>] [--out <dir>]
 *        [--thresholds bench/plan-exec/thresholds.json] [--keep] [--shared-caches] [--no-gate]
 *
 * Safety: package-manager commands run with scripts disabled (lib.mjs prepareCommand), only
 * lockfile and manifest changes are run, every token is checked before a shell sees it, the
 * copies' own package-manager releases, plugins and hooks are removed first, and nothing runs
 * inside this repository (--work must be outside it). The server's data folder and the
 * package managers' caches live under --work (--shared-caches keeps the user's caches).
 *
 * Exit: 0 the gate passed, 1 it failed, 2 the harness could not start.
 */
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { hermeticEnv, openSession, resolveServer, rmTree } from "../lib/mcp-session.mjs";
import {
  addedVersions,
  advisoryDelta,
  extractSteps,
  inventory,
  lowerings,
  mergeOverride,
  planJson,
  predictionCheck,
  prepareCommand,
  presentAnywhere,
  shellLine,
  tokenize,
  totals,
  gateFindings,
  yarn1DeleteEntries,
  yarnFlavorOf,
} from "./lib.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const argv = process.argv.slice(2);
const opt = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const flag = (name) => argv.includes(`--${name}`);

function fail(message) {
  console.error(`plan-exec: ${message}`);
  process.exit(2);
}

let server;
try {
  server = resolveServer(opt("server"));
} catch (e) {
  fail(e.message);
}
const corpusPath = path.resolve(opt("corpus") ?? path.join(here, "corpus.json"));
const thresholdsPath = path.resolve(opt("thresholds") ?? path.join(here, "thresholds.json"));
const work = path.resolve(opt("work") ?? fs.mkdtempSync(path.join(os.tmpdir(), "4da-plan-exec-")));
const out = path.resolve(opt("out") ?? path.join(os.tmpdir(), `4da-plan-exec-results-${Date.now()}`));
const inside = (child, parent) => {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
};
if (inside(work, repoRoot)) fail(`--work ${work} is inside the repository; give a directory outside it`);
const corpus = JSON.parse(fs.readFileSync(corpusPath, "utf8"));
const only = opt("only")?.split(",").map((s) => s.trim()).filter(Boolean);
const projects = corpus.projects.filter((p) => !only || only.includes(p.id));
if (only && projects.length !== only.length) fail(`--only names ${only.filter((id) => !projects.some((p) => p.id === id)).join(", ")}, not in ${corpusPath}`);
fs.mkdirSync(work, { recursive: true });
fs.mkdirSync(path.join(out, "raw"), { recursive: true });

const caches = path.join(work, "caches");
const commandEnv = {
  ...process.env,
  COREPACK_ENABLE_DOWNLOAD_PROMPT: "0",
  COREPACK_ENABLE_STRICT: "0",
  GIT_TERMINAL_PROMPT: "0",
  npm_config_update_notifier: "false",
  ...(flag("shared-caches")
    ? {}
    : {
        npm_config_cache: path.join(caches, "npm"),
        npm_config_store_dir: path.join(caches, "pnpm-store"),
        YARN_CACHE_FOLDER: path.join(caches, "yarn"),
        YARN_GLOBAL_FOLDER: path.join(caches, "yarn-berry"),
        COREPACK_HOME: path.join(caches, "corepack"),
        CARGO_HOME: path.join(caches, "cargo"),
        GOMODCACHE: path.join(caches, "gomod"),
        GOPATH: path.join(caches, "gopath"),
        UV_CACHE_DIR: path.join(caches, "uv"),
        UV_PYTHON_INSTALL_DIR: path.join(caches, "uv-python"),
      }),
};
// The server never sees the package managers' settings, and never the user's app database.
const serverHome = path.join(work, "server-home");
const serverCwd = path.join(work, "server-cwd");
fs.mkdirSync(serverCwd, { recursive: true });

const tail = (s, n = 12) => String(s ?? "").trim().split("\n").filter((l) => l.trim()).slice(-n).join("\n").slice(-2000);

function git(cwd, ...args) {
  const r = spawnSync("git", ["-c", "core.autocrlf=false", "-c", "core.longpaths=true", "-c", "advice.detachedHead=false", ...args], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_LFS_SKIP_SMUDGE: "1", GIT_TERMINAL_PROMPT: "0" },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${tail(r.stderr, 3)}`);
  return r.stdout.trim();
}

const clones = new Map();
function cloneAt(entry) {
  const key = `${entry.repo}@${entry.tag}`;
  if (clones.has(key)) return clones.get(key);
  const dst = path.join(work, "src", `${path.basename(entry.repo)}-${entry.tag}`.replace(/[^A-Za-z0-9._-]/g, "_"));
  rmTree(dst);
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  git(path.dirname(dst), "clone", "--quiet", "--depth", "1", "--branch", entry.tag, "--single-branch", entry.repo, dst);
  const head = git(dst, "rev-parse", "HEAD");
  if (!head.startsWith(entry.commit)) throw new Error(`${entry.repo} tag ${entry.tag} is at ${head}, not the pinned ${entry.commit}`);
  clones.set(key, dst);
  return dst;
}

/** Remove what would run a project's own code from a package manager: checked-in releases, plugins, hooks. */
function disarm(root) {
  const removed = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isSymbolicLink()) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === "node_modules" || e.name === ".git") continue;
        if (e.name === ".yarn") {
          for (const sub of ["releases", "plugins"]) {
            if (fs.existsSync(path.join(p, sub))) {
              rmTree(path.join(p, sub));
              removed.push(path.relative(root, path.join(p, sub)));
            }
          }
        }
        walk(p);
      } else if (e.name === ".yarnrc.yml" || e.name === ".yarnrc") {
        const text = fs.readFileSync(p, "utf8");
        // yarnPath / yarn-path run a checked-in release; plugins load checked-in code.
        const kept = text.replace(/^(yarnPath|yarn-path)\s*[:\s].*$/gm, "").replace(/^plugins:\s*\n(?:[ \t-].*\n?)*/m, "");
        if (kept !== text) {
          fs.writeFileSync(p, kept);
          removed.push(`${path.relative(root, p)}: yarnPath / plugins`);
        }
      } else if (e.name === ".pnpmfile.cjs" || e.name === ".pnpmfile.mjs") {
        fs.rmSync(p);
        removed.push(path.relative(root, p));
      }
    }
  };
  walk(root);
  return removed;
}

/** A detailed scan, every page, retried while some lookups are NOT CHECKED. */
async function fullScan(session, project) {
  let last = null;
  for (let attempt = 1; attempt <= 6; attempt++) {
    const rows = [];
    let offset = 0;
    let first = null;
    for (let page = 0; page < 50; page++) {
      const r = await session.call("vulnerability_scan", { project_path: project, response_format: "detailed", limit: 1000, ...(offset ? { offset } : {}) });
      if (r.isError || !r.json) throw new Error(`vulnerability_scan failed: ${tail(r.text, 3)}`);
      first ??= r.json;
      rows.push(...(r.json.vulnerabilities ?? []));
      const next = r.json.truncated?.next_offset;
      if (typeof next !== "number" || next <= offset) break;
      offset = next;
    }
    const unchecked = first.coverage?.unchecked_dependencies ?? 0;
    const notChecked = /^\s*(NOT CHECKED|STALE)/.test(String(first.summary ?? ""));
    last = { json: first, rows, complete: unchecked === 0 && !notChecked, attempts: attempt };
    if (last.complete) return last;
  }
  return last;
}

/** The whole plan, retried while its vulnerability data is incomplete. */
async function fullPlan(session, project) {
  let r = null;
  for (let attempt = 1; attempt <= 6; attempt++) {
    r = await session.call("upgrade_planner", { project_path: project, max_recommendations: 1000 });
    if (r.isError || !r.json) throw new Error(`upgrade_planner failed: ${tail(r.text, 3)}`);
    if (r.json.vulnerabilityDataAvailable !== false) break;
  }
  return r;
}

/** Run one `&&`-joined command line in `dir` of the copy. */
function runLine(copy, dir, line, entry) {
  const parsed = tokenize(line);
  if ("refused" in parsed) return [{ dir, run: line, refused: parsed.refused }];
  const results = [];
  for (const part of parsed.parts) {
    const cwd = path.resolve(copy, dir);
    if (!inside(cwd, copy) || !fs.existsSync(cwd)) {
      results.push({ dir, run: part.join(" "), refused: `directory ${dir} is not inside the project copy` });
      break;
    }
    const lock = path.join(cwd, "yarn.lock");
    const yarnFlavor = fs.existsSync(lock) ? yarnFlavorOf(fs.readFileSync(lock, "utf8")) : "classic";
    const prepared = prepareCommand(part, { yarnFlavor });
    if ("refused" in prepared) {
      results.push({ dir, run: part.join(" "), refused: prepared.refused });
      break;
    }
    const tool = entry.tools?.[prepared.argv[0]];
    const final = tool ? [...tool, ...prepared.argv.slice(1)] : prepared.argv;
    const started = Date.now();
    const r = spawnSync(shellLine(final), { cwd, shell: true, encoding: "utf8", maxBuffer: 1 << 28, timeout: 20 * 60_000, env: { ...commandEnv, ...(entry.env ?? {}), ...prepared.env } });
    const exit = r.status ?? (r.error ? `error: ${r.error.message}` : `signal ${r.signal}`);
    results.push({ dir, run: part.join(" "), ran: final.join(" "), added: prepared.added, exit, ms: Date.now() - started, out: tail(`${r.stdout ?? ""}\n${r.stderr ?? ""}`) });
    if (exit !== 0) break;
  }
  return results;
}

function runAction(copy, action, entry) {
  if (action.type === "run") return runLine(copy, action.dir, action.run, entry);
  if (action.type === "yarn1-delete") {
    const lock = path.resolve(copy, action.dir, "yarn.lock");
    if (!inside(lock, copy) || !fs.existsSync(lock)) return [{ dir: action.dir, run: `delete yarn.lock entries of ${action.name}`, exit: "no yarn.lock there", ms: 0 }];
    const n = yarn1DeleteEntries(lock, action.name);
    return [{ dir: action.dir, run: `delete yarn.lock entries of ${action.name} (${n} removed)`, exit: 0, ms: 0 }, ...runLine(copy, action.dir, "yarn install", entry)];
  }
  if (action.type === "override") {
    const file = path.resolve(copy, action.dir, action.file);
    const label = `add ${action.snippet} to ${action.file}`;
    if (!inside(file, copy) || !fs.existsSync(file)) return [{ dir: action.dir, run: label, exit: `${action.file} does not exist in ${action.dir}`, ms: 0 }];
    try {
      fs.writeFileSync(file, JSON.stringify(mergeOverride(JSON.parse(fs.readFileSync(file, "utf8")), action.snippet), null, 2) + "\n");
    } catch (e) {
      return [{ dir: action.dir, run: label, exit: `the snippet could not be applied: ${e.message}`, ms: 0 }];
    }
    return [{ dir: action.dir, run: label, exit: 0, ms: 0 }, ...(action.then ? runLine(copy, action.dir, action.then, entry) : [])];
  }
  return [{ dir: action.dir ?? ".", run: JSON.stringify(action), refused: "unknown action" }];
}

async function runProject(entry) {
  const result = { id: entry.id, repo: entry.repo, tag: entry.tag, commit: entry.commit, dir: entry.dir, package_manager: entry.package_manager };
  const copy = path.join(work, "projects", entry.id);
  const save = (name, obj) => fs.writeFileSync(path.join(out, "raw", `${entry.id}.${name}.json`), JSON.stringify(obj, null, 1));
  try {
    const src = cloneAt(entry);
    rmTree(copy);
    fs.cpSync(path.join(src, entry.dir ?? "."), copy, { recursive: true, filter: (p) => !/[\\/]\.git([\\/]|$)/.test(p) });
    result.disarmed = disarm(copy);
    const env = hermeticEnv({ home: serverHome });
    const s1 = await openSession({ server, cwd: serverCwd, env });
    result.server_version = s1.version;
    let before;
    let plan;
    try {
      before = await fullScan(s1, copy);
      plan = planJson((await fullPlan(s1, copy)).raw);
    } finally {
      await s1.close();
    }
    save("before.scan", before.json);
    save("plan", plan);
    const extracted = extractSteps(plan);
    result.order_source = extracted.source;
    result.order_note = extracted.note;
    result.plan_rows = extracted.rows.length;
    const initial = inventory(copy);
    const earlier = new Map();
    let prev = initial;
    const steps = [];
    for (const step of extracted.steps) {
      const cmds = step.actions.flatMap((a) => runAction(copy, a, entry));
      const after = inventory(copy);
      const lowered = lowerings(prev, after, earlier, initial).filter((l) => l.set_by !== "other");
      for (const [k, vs] of addedVersions(prev, after)) for (const v of vs) (earlier.get(k) ?? earlier.set(k, new Set()).get(k)).add(v);
      const targets = step.rows.map((r) => ({ ecosystem: r.ecosystem, package: r.package, version: r.currentVersion }));
      const gone = targets.filter((t) => !presentAnywhere(after, t.ecosystem, t.package, t.version));
      const ran = cmds.some((c) => c.exit !== undefined);
      const failed = cmds.some((c) => c.exit !== undefined && c.exit !== 0);
      const refused = cmds.some((c) => c.refused);
      const outcome = cmds.length === 0 ? "nothing_to_run" : failed ? "failed" : refused ? "refused" : targets.length > 0 && gone.length === 0 ? "without_effect" : "worked";
      steps.push({ n: step.n, fixes: step.fixes, targets: targets.map((t) => `${t.package}@${t.version}`), outcome, ran, lowered, cmds });
      console.log(`  ${entry.id} step ${step.n}: ${outcome}${lowered.length ? ` LOWERED ${lowered.map((l) => `${l.key.split("|").pop()} ${l.from}->${l.to}`).join(", ")}` : ""} ${cmds.map((c) => c.refused ? `[refused: ${c.run}]` : `[${c.exit}] ${c.run}`).join(" ; ").slice(0, 300)}`);
      prev = after;
    }
    const s2 = await openSession({ server, cwd: serverCwd, env });
    let afterScan;
    try {
      afterScan = await fullScan(s2, copy);
    } finally {
      await s2.close();
    }
    save("after.scan", afterScan.json);
    result.scan_incomplete = !before.complete || !afterScan.complete;
    const delta = advisoryDelta(before.rows, afterScan.rows);
    result.advisories = { before: before.rows.length, after: afterScan.rows.length, cleared: delta.cleared.length, introduced: delta.introduced.length, introduced_list: delta.introduced };
    result.prediction = predictionCheck({ beforeRows: before.rows, afterRows: afterScan.rows, steps: extracted.steps });
    const count = (o) => steps.filter((s) => s.outcome === o).length;
    result.counts = {
      steps: steps.length,
      steps_run: steps.filter((s) => s.ran).length,
      steps_failed: count("failed"),
      steps_refused: count("refused"),
      steps_without_effect: count("without_effect"),
      steps_lowering: steps.filter((s) => s.lowered.length > 0).length,
      steps_lowering_earlier: steps.filter((s) => s.lowered.some((l) => l.set_by === "earlier_step")).length,
    };
    result.steps = steps;
  } catch (e) {
    result.error = e instanceof Error ? e.message : String(e);
  } finally {
    if (!flag("keep")) {
      const left = rmTree(copy);
      if (left) result.cleanup = `the copy was not fully removed: ${left}`;
    }
  }
  return result;
}

/** The line of a command's output that says why it failed (package managers end with a log pointer). */
const reason = (out) => {
  const lines = String(out ?? "").split("\n").map((l) => l.trim()).filter(Boolean);
  return (lines.find((l) => /ERESOLVE|error[:\s]|ERR!|ERR_|did not match|failed to|unsatisfiable|not found/i.test(l) && !/complete log of this run/i.test(l)) ?? lines.at(-1) ?? "").slice(0, 240);
};

function summaryMarkdown(results, t, findings, thresholds) {
  const lines = [];
  lines.push(`# Plan execution: ${path.basename(server)} (${results.find((r) => r.server_version)?.server_version ?? "version unknown"})`, "");
  lines.push(`Server: \`${server}\``, `Order source(s): ${Object.entries(t.order_sources).map(([s, n]) => `${s} ${n}`).join(", ") || "none"}`, "");
  lines.push("| project | pm | order | steps | run | failed | refused | no effect | lowered | advisories before -> after | copies predicted left / left / new |", "|---|---|---|---|---|---|---|---|---|---|---|");
  for (const r of results) {
    if (r.error) {
      lines.push(`| ${r.id} | ${r.package_manager} | ERROR: ${r.error.replace(/\|/g, "/").slice(0, 200)} |||||||||`);
      continue;
    }
    const c = r.counts;
    lines.push(`| ${r.id} @ ${r.tag} | ${r.package_manager} | ${r.order_source} | ${c.steps} | ${c.steps_run} | ${c.steps_failed} | ${c.steps_refused} | ${c.steps_without_effect} | ${c.steps_lowering} | ${r.advisories.before} -> ${r.advisories.after} | ${r.prediction.predicted_remaining} / ${r.prediction.remaining} / ${r.prediction.new_vulnerable_copies} |`);
  }
  lines.push(`| **total** | | | ${t.steps} | ${t.steps_run} | ${t.steps_failed} | ${t.steps_refused} | ${t.steps_without_effect} | ${t.steps_lowering} | ${t.advisories_before} -> ${t.advisories_after} (${t.net_cleared_ratio ?? "n/a"} cleared) | ${t.predicted_remaining} / ${t.remaining} / ${t.vulnerable_copies_after - (t.remaining)} |`, "");
  const bad = results.flatMap((r) => (r.steps ?? []).filter((s) => s.outcome !== "worked" && s.outcome !== "nothing_to_run" || s.lowered.length > 0).map((s) => ({ id: r.id, s })));
  if (bad.length) {
    lines.push("## Steps that did not simply work", "");
    for (const { id, s } of bad) {
      const cmd = s.cmds.find((c) => c.refused || (c.exit !== undefined && c.exit !== 0)) ?? s.cmds[0];
      lines.push(`- ${id} #${s.n} ${s.outcome}${s.lowered.length ? `, lowered ${s.lowered.map((l) => `${l.key.split("|").slice(1).join(" ")} ${l.from} -> ${l.to} (${l.set_by})`).join("; ")}` : ""}: \`${cmd?.run ?? ""}\`${cmd?.refused ? ` (refused: ${cmd.refused})` : cmd?.exit !== undefined && cmd.exit !== 0 ? ` exit ${cmd.exit}: ${reason(cmd.out)}` : ""}`);
    }
    lines.push("");
  }
  const { about: _about, ...limits } = thresholds;
  lines.push(`## Gate (${path.basename(thresholdsPath)})`, "", "```json", JSON.stringify(limits, null, 1), "```", "", findings.length ? `FAILED:\n${findings.map((f) => `- ${f}`).join("\n")}` : "PASSED", "");
  return lines.join("\n");
}

console.log(`plan-exec: server ${server}\n  corpus ${corpusPath} (${projects.length} project(s))\n  work ${work}\n  results ${out}`);
const results = [];
for (const entry of projects) {
  console.log(`- ${entry.id} (${entry.repo} @ ${entry.tag}, ${entry.package_manager})`);
  const r = await runProject(entry);
  results.push(r);
  console.log(r.error ? `  ERROR ${r.error}` : `  ${r.order_source}: ${r.counts.steps} steps, ${r.counts.steps_failed} failed, ${r.counts.steps_refused} refused, ${r.counts.steps_without_effect} without effect, ${r.counts.steps_lowering} lowering; advisories ${r.advisories.before} -> ${r.advisories.after}`);
}
const t = totals(results);
const thresholds = JSON.parse(fs.readFileSync(thresholdsPath, "utf8"));
const findings = flag("no-gate") ? [] : gateFindings(t, thresholds, results);
fs.writeFileSync(path.join(out, "plan-exec-result.json"), JSON.stringify({ server, corpus: corpusPath, totals: t, gate: flag("no-gate") ? "not applied" : findings.length ? "failed" : "passed", findings, projects: results }, null, 1));
fs.writeFileSync(path.join(out, "plan-exec-summary.md"), summaryMarkdown(results, t, findings, thresholds));
if (!flag("keep")) {
  for (const dir of [path.join(work, "src"), caches, serverHome, serverCwd, path.join(work, "projects")]) rmTree(dir);
  try {
    fs.rmdirSync(work);
  } catch {
    // The caller's own --work directory, or something left in it: kept.
  }
}
console.log(`\ntotals: ${JSON.stringify(t)}\n${findings.length ? `GATE FAILED:\n  ${findings.join("\n  ")}` : flag("no-gate") ? "gate not applied" : "GATE PASSED"}\nresults: ${path.join(out, "plan-exec-result.json")}\nsummary: ${path.join(out, "plan-exec-summary.md")}`);
process.exit(findings.length ? 1 : 0);
