// SPDX-License-Identifier: Apache-2.0
/**
 * Hard kills during the FIRST start of an empty data folder, then a fresh session on that
 * folder, which must work. An editor restarts a server by killing it (on Windows every
 * `child.kill()` is TerminateProcess), and the first start is when the store is created.
 *
 * For each delay (ms) and repetition, on a new empty data folder, in a project:
 *   - `list`: initialize + tools/list, kill <delay> ms later (the editor case: the listing
 *     schedules the background start-up work);
 *   - `call`: initialize + a vulnerability_scan, kill <delay> ms after sending it.
 * Then a normal session on the same folder must list the same tools as a session on a fresh
 * folder, scan the project as the baseline does, keep a decision, and say nothing that means
 * the store is broken.
 *
 *   node bench/env/firstrun-kill.mjs --server <entry> [--delays 0,10,...] [--reps 2] [--modes list,call] [--work <dir>] [--out <dir>] [--keep]
 *
 * Offline throughout. A kill window is timing-dependent: a clean sweep on one machine is not
 * proof for another; a broken folder anywhere is a real defect. Exit 1 on a violation.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { BROKEN, baseline, finish, offlineEnv, openSession, options, rmTree, scanFacts, sleep, writeProjects } from "./lib.mjs";

const opts = options();
const delays = opts.opt("delays", "0,5,10,20,30,40,50,55,60,65,70,75,80,90,100,120,150,200,300").split(",").map(Number);
const reps = Number(opts.opt("reps", "2"));
const modes = opts.opt("modes", "list,call").split(",");
const dirs = writeProjects(path.join(opts.work, "projects"));
const project = "web-npm";
const base = (await baseline(opts.server, opts.work, { [project]: dirs[project] }))[project];

const rows = [];
const violations = [];
let n = 0;
for (let rep = 0; rep < reps; rep++) {
  for (const mode of modes) {
    for (const delay of delays) {
      const home = path.join(opts.work, "homes", `${mode}-${delay}-${rep}-${n++}`);
      const first = await openSession({ server: opts.server, cwd: dirs[project], env: offlineEnv(home) });
      if (mode === "list") {
        await first.tools();
        await sleep(delay);
      } else {
        first.call("vulnerability_scan", {}).catch(() => undefined);
        await sleep(delay);
      }
      await first.killHard();
      const next = await openSession({ server: opts.server, cwd: dirs[project], env: offlineEnv(home) });
      const problems = [];
      try {
        const tools = (await next.tools()).sort().join(",");
        if (tools !== base.tools) problems.push(`lists other tools (${tools.split(",").length}, a fresh folder lists ${base.toolCount})`);
        const scan = await next.call("vulnerability_scan", {});
        const f = scanFacts(scan);
        if (scan.isError) problems.push(`scan answered an error: ${scan.text.slice(0, 160)}`);
        else if (f.deps !== base.scan.deps) problems.push(`scan read ${f.deps} dependencies, a fresh folder ${base.scan.deps}`);
        if (BROKEN.test(scan.text)) problems.push(`scan says: ${scan.text.match(BROKEN)?.[0]}`);
        const subject = `env-kill-${mode}-${delay}-${rep}`;
        const rec = await next.call("decision_memory", { action: "record", decision_type: "pattern", subject, decision: "d", rationale: "r" });
        const list = await next.call("decision_memory", { action: "list", limit: 50 });
        if (rec.isError || !list.text.includes(subject)) problems.push(`a decision was not kept (${rec.text.slice(0, 120)})`);
      } catch (e) {
        problems.push(e instanceof Error ? e.message : String(e));
      } finally {
        await next.close();
      }
      const files = fs.existsSync(path.join(home, "4da-mcp")) ? fs.readdirSync(path.join(home, "4da-mcp")).map((f) => `${f}:${fs.statSync(path.join(home, "4da-mcp", f)).size}`) : [];
      rows.push({ rep, mode, delay, files, problems });
      console.log(`${mode} kill at ${delay} ms (rep ${rep}): [${files.join(" ")}] -> ${problems.length ? `BROKEN: ${problems.join("; ")}` : "next session ok"}`);
      for (const p of problems) violations.push(`${mode} kill at ${delay} ms (rep ${rep}): ${p}`);
      if (!opts.keep) rmTree(home);
    }
  }
}
finish("firstrun-kill", opts, { project, delays, reps, modes, broken: rows.filter((r) => r.problems.length).length, of: rows.length, rows, baseline: base }, violations);
if (!opts.keep) rmTree(opts.work);
