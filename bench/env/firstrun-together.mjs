// SPDX-License-Identifier: Apache-2.0
/**
 * Servers started together on a fresh data folder, as an editor restoring several windows or
 * a fleet of agents does: one started in each project and two in an empty directory, all at
 * the same instant, on one empty folder. Each must see its own project: the same tools as a
 * session on a fresh folder (before and after the others start), its own stack from
 * get_context, its own project and dependency count from a scan with no argument, and its
 * decision kept.
 *
 *   node bench/env/firstrun-together.mjs --server <entry> [--reps 5] [--extra 2] [--work <dir>] [--out <dir>] [--keep]
 *
 * Offline throughout. Exit 1 on a violation.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { BROKEN, baseline, finish, offlineEnv, openSession, options, rmTree, scanFacts, stack, writeProjects } from "./lib.mjs";

const opts = options();
const reps = Number(opts.opt("reps", "5"));
const extra = Number(opts.opt("extra", "2"));
const dirs = writeProjects(path.join(opts.work, "projects"));
const names = Object.keys(dirs);
const base = await baseline(opts.server, opts.work, dirs);
const empty = path.join(opts.work, "empty");
fs.mkdirSync(empty, { recursive: true });

const violations = [];
const rows = [];
for (let rep = 0; rep < reps; rep++) {
  const home = path.join(opts.work, "homes", `rep-${rep}`);
  const cwds = [...names.map((n) => ({ own: n, cwd: dirs[n] })), ...Array.from({ length: extra }, () => ({ own: null, cwd: empty }))];
  const sessions = await Promise.all(cwds.map((c) => openSession({ server: opts.server, cwd: c.cwd, env: offlineEnv(home) })));
  const firstLists = await Promise.all(sessions.map((s) => s.tools()));
  const answers = await Promise.all(
    sessions.map(async (s, k) => {
      const c = cwds[k];
      const subject = `env-together-${rep}-${k}`;
      const [ctx, scan, rec] = await Promise.all([
        c.own ? s.call("get_context", {}) : null,
        c.own ? s.call("vulnerability_scan", {}) : null,
        s.call("decision_memory", { action: "record", decision_type: "pattern", subject, decision: "d", rationale: "r" }),
      ]);
      return { ctx, scan, rec, subject };
    }),
  );
  const laterLists = await Promise.all(sessions.map((s) => s.tools()));
  await Promise.all(sessions.map((s) => s.close()));
  const reader = await openSession({ server: opts.server, cwd: empty, env: offlineEnv(home) });
  const listed = await reader.call("decision_memory", { action: "list", limit: 100 });
  await reader.close();
  const want = base[names[0]].tools;
  const problems = [];
  for (const [k, c] of cwds.entries()) {
    const who = c.own ? `server in ${c.own}` : `server ${k} in an empty directory`;
    for (const [when, list] of [["first", firstLists[k]], ["later", laterLists[k]]]) {
      const got = [...list].sort().join(",");
      if (got !== want) problems.push(`${who}: ${when} tools/list has ${list.length} tools, a session on a fresh folder ${base[names[0]].toolCount}`);
    }
    const a = answers[k];
    if (c.own) {
      if (stack(a.ctx) !== base[c.own].stack) problems.push(`${who}: get_context stack ${stack(a.ctx)}, alone ${base[c.own].stack}`);
      const f = scanFacts(a.scan);
      if (path.basename(String(f.project ?? "")) !== c.own) problems.push(`${who}: scan answered about ${f.project}`);
      else if (f.deps !== base[c.own].scan.deps) problems.push(`${who}: scan read ${f.deps} dependencies, alone ${base[c.own].scan.deps}`);
    }
    for (const r of [a.ctx, a.scan, a.rec].filter(Boolean)) if (BROKEN.test(r.text)) problems.push(`${who}: ${r.text.match(BROKEN)?.[0]}`);
    if (a.rec.isError || !listed.text.includes(a.subject)) problems.push(`${who}: its decision was not kept`);
    for (const l of sessions[k].state.stderr.split("\n").filter((l) => BROKEN.test(l)).slice(0, 2)) problems.push(`${who} stderr: ${l.slice(0, 200)}`);
  }
  rows.push({ rep, sessions: cwds.length, problems });
  console.log(`rep ${rep}: ${cwds.length} servers on one fresh folder -> ${problems.length ? `${problems.length} problem(s)` : "each saw its own project"}`);
  for (const p of problems) violations.push(`rep ${rep}: ${p}`);
  if (!opts.keep) rmTree(home);
}
finish("firstrun-together", opts, { reps, servers: names.length + extra, rows, baseline: base }, violations);
if (!opts.keep) rmTree(opts.work);
