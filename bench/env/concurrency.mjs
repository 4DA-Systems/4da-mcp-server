// SPDX-License-Identifier: Apache-2.0
/**
 * Several server processes on ONE data folder, started at once, each looping mixed calls for a
 * while: scans of their own and of other projects, dependency_health, get_context in the
 * project a process was started in, decisions and memories written. Fails on:
 *   - an error answer, or a "database is locked" / missing-table / unreadable-store text;
 *   - an answer about the wrong project, or one that differs from the single-process baseline
 *     (dependency count, stack);
 *   - a write whose answer said it was kept that a fresh server cannot read back, or that the
 *     store does not hold; a store that fails `PRAGMA integrity_check`.
 *
 *   node bench/env/concurrency.mjs --server <dist/index.js | package dir> [--seconds 60] [--cold] [--work <dir>] [--out <dir>] [--keep]
 *
 * The folder is created by one session first (steady state); --cold starts every process on an
 * empty folder, which also exercises the first-start race firstrun-together.mjs measures.
 *
 * Offline throughout (lib.mjs). Exit 1 on a violation.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { BROKEN, baseline, finish, offlineEnv, openSession, options, rmTree, scanFacts, stack, writeProjects } from "./lib.mjs";

const opts = options();
const seconds = Number(opts.opt("seconds", "60"));
const dirs = writeProjects(path.join(opts.work, "projects"));
const names = Object.keys(dirs);
const base = await baseline(opts.server, opts.work, dirs);
const home = path.join(opts.work, "shared-home");
const empty = path.join(opts.work, "empty");
fs.mkdirSync(empty, { recursive: true });
// Steady state: one session creates the store first, so this measures processes sharing a
// folder; the first-start race is firstrun-together.mjs's. --cold starts on an empty folder.
if (!process.argv.includes("--cold")) {
  const warm = await openSession({ server: opts.server, cwd: empty, env: offlineEnv(home) });
  await warm.call("agent_memory", { action: "store", agent_type: "env-warm", subject: "env-warm", content: "warm" });
  await warm.close();
}

// One process started in each project (its default project), and as many in an empty directory
// passing project_path.
const workers = [...names.map((n) => ({ own: n, cwd: dirs[n] })), ...names.map((_, k) => ({ own: null, cwd: empty, k }))];
const sessions = await Promise.all(workers.map((w) => openSession({ server: opts.server, cwd: w.cwd, env: offlineEnv(home) })));
const violations = [];
const stats = { calls: 0, errors: 0, broken: 0, wrongProject: 0, differs: 0, writesClaimed: 0 };
const kept = { decisions: [], memories: [] };
// Each agent holds at most 1,000 memories: a worker moves to a new agent_type every 500.
const agents = new Map();
const agentFor = (k) => {
  const n = (agents.get(k) ?? 0) + 1;
  agents.set(k, n);
  return `env-w${k}-${Math.floor(n / 500)}`;
};
const note = (w, tool, r, problem) => {
  stats.calls++;
  if (r.isError) stats.errors++;
  if (BROKEN.test(r.text)) stats.broken++;
  if (problem) violations.push(`worker ${w}: ${tool}: ${problem}`);
  else if (r.isError) violations.push(`worker ${w}: ${tool} answered an error: ${r.text.slice(0, 200)}`);
  else if (BROKEN.test(r.text)) violations.push(`worker ${w}: ${tool}: ${r.text.match(BROKEN)?.[0]}`);
};

const deadline = Date.now() + seconds * 1000;
await Promise.all(
  workers.map(async (w, k) => {
    const s = sessions[k];
    for (let i = 0; Date.now() < deadline; i++) {
      try {
        const step = i % 4;
        if (step === 0) {
          // A scan: the worker's own project (no argument) or another one by path.
          const name = w.own && i % 8 === 0 ? w.own : names[(i + k) % names.length];
          const r = await s.call("vulnerability_scan", w.own === name ? {} : { project_path: dirs[name] });
          const f = scanFacts(r);
          const b = base[name].scan;
          let problem = null;
          if (path.basename(String(f.project ?? "")) !== name) {
            stats.wrongProject++;
            problem = `scan of ${name} answered about ${f.project}`;
          } else if (f.deps !== b.deps) {
            stats.differs++;
            problem = `scan of ${name} read ${f.deps} dependencies, ${b.deps} alone`;
          }
          note(k, "vulnerability_scan", r, problem);
        } else if (step === 1 && w.own && i % 8 === 1) {
          // dependency_health answers about the project the server was started in.
          const r = await s.call("dependency_health", {});
          const p = r.json?.projectPath ?? r.json?.project_path ?? null;
          note(k, "dependency_health", r, p && path.basename(p) !== w.own ? `health in ${w.own} answered about ${p}` : null);
        } else if (step === 1 && w.own) {
          const r = await s.call("get_context", {});
          note(k, "get_context", r, stack(r) === base[w.own].stack ? null : `stack ${stack(r)} in ${w.own}, ${base[w.own].stack} alone`);
        } else if (step === 1) {
          const name = names[(i + k) % names.length];
          const r = await s.call("upgrade_planner", { project_path: dirs[name] });
          const p = r.json?.projectPath ?? r.json?.projectScope ?? null;
          note(k, "upgrade_planner", r, p && path.basename(p) !== name ? `plan of ${name} answered about ${p}` : null);
        } else {
          const subject = `env-conc-w${k}-${i}`;
          const tool = step === 2 ? "decision_memory" : "agent_memory";
          const args = step === 2 ? { action: "record", decision_type: "pattern", subject, decision: `d ${subject}`, rationale: "r" } : { action: "store", agent_type: agentFor(k), subject, content: `c ${subject}` };
          const r = await s.call(tool, args);
          if (!r.isError && /success|recorded|stored/i.test(r.text)) {
            stats.writesClaimed++;
            (step === 2 ? kept.decisions : kept.memories).push(subject);
          }
          note(k, tool, r, null);
        }
      } catch (e) {
        violations.push(`worker ${k}: ${e instanceof Error ? e.message : String(e)}`);
        break;
      }
    }
  }),
);
await Promise.all(sessions.map((s) => s.close()));
for (const [k, s] of sessions.entries()) {
  const bad = s.state.stderr.split("\n").filter((l) => BROKEN.test(l));
  for (const l of bad.slice(0, 3)) violations.push(`worker ${k} stderr: ${l.slice(0, 200)}`);
}

// Read every write back through a fresh server on the same folder, then from the store itself.
// Memories are recalled per agent: recall searches each agent's newest entries (at most 1,000).
const reader = await openSession({ server: opts.server, cwd: empty, env: offlineEnv(home) });
const listed = await reader.call("decision_memory", { action: "list", limit: 100000 });
const recalledText = [];
for (const [k, n] of agents) for (let b = 0; b <= Math.floor(n / 500); b++) recalledText.push((await reader.call("agent_memory", { action: "recall", query: `env-conc-w${k}`, filter_agent: `env-w${k}-${b}`, limit: 1000 })).text);
await reader.close();
const recalled = recalledText.join("\n");
const lostD = kept.decisions.filter((sub) => !listed.text.includes(`"${sub}"`));
const lostM = kept.memories.filter((sub) => !recalled.includes(`"${sub}"`));
if (lostD.length) violations.push(`${lostD.length} of ${kept.decisions.length} decisions answered as kept are not listed by a fresh server (first: ${lostD[0]})`);
if (lostM.length) violations.push(`${lostM.length} of ${kept.memories.length} memories answered as kept are not recalled by a fresh server (first: ${lostM[0]})`);
// And from the store itself: every write answered as kept is a row, and the files are sound.
const integrity = {};
const { DatabaseSync } = await import("node:sqlite");
const store = path.join(home, "4da-mcp");
for (const f of fs.existsSync(store) ? fs.readdirSync(store).filter((f) => f.endsWith(".db")) : []) {
  let db;
  try {
    db = new DatabaseSync(path.join(store, f), { readOnly: true });
    integrity[f] = db.prepare("PRAGMA integrity_check").get().integrity_check;
    if (f === "standalone.db") {
      const rows = (table) => new Set(db.prepare(`SELECT subject FROM ${table} WHERE subject LIKE 'env-conc-w%'`).all().map((r) => r.subject));
      const [d, m] = [rows("developer_decisions"), rows("agent_memory")];
      const missing = [...kept.decisions.filter((s) => !d.has(s)), ...kept.memories.filter((s) => !m.has(s))];
      if (missing.length) violations.push(`${missing.length} writes answered as kept are not in ${f} (first: ${missing[0]})`);
    }
  } catch (e) {
    integrity[f] = `unreadable: ${e.message}`;
  } finally {
    db?.close();
  }
  if (integrity[f] !== "ok") violations.push(`${f}: integrity_check ${integrity[f]}`);
}
if (kept.decisions.length === 0 || kept.memories.length === 0) violations.push("no write was answered as kept, so nothing was checked");

finish("concurrency", opts, { seconds, processes: workers.length, stats, writes: { decisions: kept.decisions.length, memories: kept.memories.length }, integrity, baseline: base }, violations);
if (!opts.keep) rmTree(opts.work);
