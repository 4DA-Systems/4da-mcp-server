// SPDX-License-Identifier: Apache-2.0
// G7 runner. Each run = a fresh copy of the task template + a fresh headless Claude Code session (claude -p).
//  control:         no MCP servers at all (--strict-mcp-config, no --mcp-config)
//  treatment:       ONLY @4da/mcp-server via `npx -y` (G7_SERVER_SPEC), fresh server data dir + DB per run
//  treatment-local: the same, served by a local build (G7_LOCAL_SERVER=<path>/dist/index.js). The 6.2.5 and 6.2.6
//                   results were measured this way, on the release candidate installed from its packed tarball.
// Same model, same prompt, same tools otherwise (Read/Glob/Grep/Edit/Write; no shell, no web, no subagents).
// Edits are auto-accepted only inside the run's working dir (--permission-mode acceptEdits); anything else is
// denied because -p cannot prompt.
// Usage: node run-g7.mjs <arm: control|treatment|treatment-local|both, or comma-separated> <trials> [concurrency<=3] [task-id regex]
// Environment: G7_CLAUDE (the claude executable; default `claude` on PATH), G7_MODEL, G7_SERVER_SPEC, G7_LOCAL_SERVER.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { HERE } from "./lib-truth.mjs";

const [armArg = "both", trialsArg = "3", concArg = "3", filter = ""] = process.argv.slice(2);
const TRIALS = Number(trialsArg), CONC = Math.min(3, Number(concArg));
export const MODEL = process.env.G7_MODEL || "claude-sonnet-5-5";
// The pre-registered run (2026-10-11) used @4da/mcp-server@6.1.0.
export const SERVER_SPEC = process.env.G7_SERVER_SPEC || "@4da/mcp-server@6.2.6";
const LOCAL_SERVER = process.env.G7_LOCAL_SERVER || "";
const CLAUDE = process.env.G7_CLAUDE || "claude";
const MIN_FREE_GB = 3;
const TIMEOUT_MS = 10 * 60 * 1000;
const tasks = JSON.parse(fs.readFileSync(path.join(HERE, "tasks.json"), "utf8")).filter((t) => !filter || new RegExp(filter).test(t.id));
const arms = armArg === "both" ? ["control", "treatment"] : armArg.split(",");

const jobs = [];
// Interleave arms and tasks so time-of-day / rate-limit drift hits both arms equally.
for (let n = 1; n <= TRIALS; n++) for (const t of tasks) for (const arm of arms) {
  const runDir = path.join(HERE, "runs", arm, t.id, `t${n}`);
  if (fs.existsSync(path.join(runDir, "rec.json"))) continue; // resumable
  jobs.push({ t, n, arm, runDir });
}
console.log(`model ${MODEL} | server ${arms.includes("treatment-local") ? LOCAL_SERVER : SERVER_SPEC} | ${jobs.length} runs to do (${tasks.length} tasks x ${TRIALS} x ${arms.join("+")}) | concurrency ${CONC}`);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitForRam() {
  for (;;) {
    const free = os.freemem() / 2 ** 30;
    if (free >= MIN_FREE_GB) return free;
    console.log(`  free RAM ${free.toFixed(2)} GB < ${MIN_FREE_GB} GB, pausing 30s`);
    await sleep(30000);
  }
}

function runOne({ t, n, arm, runDir }) {
  return new Promise((resolve) => {
    fs.rmSync(runDir, { recursive: true, force: true });
    const work = path.join(runDir, "work");
    fs.cpSync(path.join(HERE, "tasks", t.id), work, { recursive: true });
    const args = ["-p", t.prompt, "--model", MODEL, "--output-format", "stream-json", "--verbose",
      "--setting-sources", "project,local", "--strict-mcp-config", "--no-session-persistence",
      "--max-turns", "25", "--permission-mode", "acceptEdits",
      "--disallowedTools", "Bash", "PowerShell", "WebFetch", "WebSearch", "NotebookEdit", "Agent", "Task", "Skill", "Monitor",
      // host-level tools that could act outside the task dir or the session: off in both arms
      "CronCreate", "CronDelete", "CronList", "RemoteTrigger", "ScheduleWakeup", "PushNotification", "SendMessage", "Workflow",
      "EnterWorktree", "ExitWorktree", "DesignSync", "ListAgents", "TaskStop", "ReportFindings"];
    if (arm === "control-web") {
      // exploratory third arm (not part of G7): no MCP, but live web access (WebFetch/WebSearch) allowed
      for (const tool of ["WebFetch", "WebSearch"]) args.splice(args.indexOf(tool), 1);
      args.push("--allowedTools", "WebFetch", "WebSearch");
    }
    if (arm === "treatment" || arm === "treatment-local") {
      if (arm === "treatment-local" && !LOCAL_SERVER) throw new Error("set G7_LOCAL_SERVER to <worktree>/dist/index.js");
      const srvHome = path.join(runDir, "server-home");
      fs.mkdirSync(srvHome, { recursive: true });
      const cfg = path.join(runDir, "mcp.json");
      fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { "4da": {
        ...(arm === "treatment-local" ? { command: process.execPath, args: [LOCAL_SERVER] } : (process.platform === "win32" ? { command: "cmd", args: ["/c", "npx", "-y", SERVER_SPEC] } : { command: "npx", args: ["-y", SERVER_SPEC] })),
        env: { FOURDA_MCP_HOME: srvHome, FOURDA_DB_PATH: path.join(srvHome, "standalone.db"), FOURDA_PROJECT_DIR: work },
      } } }, null, 2));
      args.push("--mcp-config", cfg, "--allowedTools", "mcp__4da");
    }
    const env = { ...process.env, CLAUDE_CODE_DISABLE_CLAUDE_MDS: "1", CLAUDE_CODE_DISABLE_AUTO_MEMORY: "1" };
    for (const k of Object.keys(env)) if (/^CLAUDECODE$|^CLAUDE_CODE_ENTRYPOINT$|^CLAUDE_CODE_SSE_PORT$/.test(k)) delete env[k];
    const started = Date.now();
    const child = spawn(CLAUDE, args, { cwd: work, env, windowsHide: true, shell: false });
    let stdout = "", stderr = "", timedOut = false;
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, TIMEOUT_MS);
    child.on("close", (code) => {
      clearTimeout(timer);
      const events = stdout.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      const result = events.find((e) => e.type === "result");
      const init = events.find((e) => e.type === "system" && e.subtype === "init");
      const toolCalls = [], toolErrors = [], denials = [];
      for (const e of events) for (const c of e.message?.content ?? []) {
        if (c.type === "tool_use") toolCalls.push({ id: c.id, name: c.name, input: c.input });
        if (c.type === "tool_result" && c.is_error) toolErrors.push({ id: c.tool_use_id, text: String(typeof c.content === "string" ? c.content : JSON.stringify(c.content)).slice(0, 400) });
      }
      for (const d of result?.permission_denials ?? []) denials.push(d);
      const rec = {
        id: t.id, trial: n, arm, model: MODEL, resolved_model: init?.model ?? null, exit: code, timed_out: timedOut, ms: Date.now() - started,
        started_at: new Date(started).toISOString(),
        result: result?.result ?? null, is_error: result?.is_error ?? true, subtype: result?.subtype ?? null, num_turns: result?.num_turns ?? null,
        usage: result?.usage ?? null, cost_usd: result?.total_cost_usd ?? null,
        cwd: init?.cwd ?? null, mcp_servers: init?.mcp_servers ?? null, tools_offered: init?.tools ?? [],
        tool_calls: toolCalls, tool_errors: toolErrors, permission_denials: denials, stderr: stderr.slice(-2000),
      };
      fs.writeFileSync(path.join(runDir, "stream.jsonl"), stdout);
      fs.writeFileSync(path.join(runDir, "rec.json"), JSON.stringify(rec, null, 2));
      // the server's data dir can be large (cache); keep only a size note
      const sh = path.join(runDir, "server-home");
      if (fs.existsSync(sh)) { try { fs.rmSync(sh, { recursive: true, force: true }); } catch {} }
      resolve(rec);
    });
  });
}

let done = 0, i = 0;
const t0 = Date.now();
async function worker(w) {
  await sleep(w * 4000); // stagger first spawns (npx cache)
  while (i < jobs.length) {
    const job = jobs[i++];
    await waitForRam();
    const rec = await runOne(job);
    done++;
    const mcp = rec.tool_calls.filter((c) => c.name.startsWith("mcp__")).map((c) => c.name.replace("mcp__4da__", "")).join(",");
    const doneLine = (rec.result ?? "").split("\n").filter((l) => /^\s*DONE:/i.test(l)).pop() ?? "(no DONE)";
    const srv = rec.mcp_servers ? rec.mcp_servers.map((s) => `${s.name}:${s.status}`).join(",") : "-";
    console.log(`[${done}/${jobs.length} ${Math.round((Date.now() - t0) / 60000)}m] ${rec.arm.padEnd(9)} ${rec.id} t${rec.trial} exit ${rec.exit}${rec.timed_out ? " TIMEOUT" : ""} ${Math.round(rec.ms / 1000)}s turns ${rec.num_turns} $${rec.cost_usd?.toFixed(3)} srv[${srv}] mcp[${mcp}] ${doneLine.trim()}`);
  }
}
await Promise.all(Array.from({ length: CONC }, (_, w) => worker(w)));
console.log(`all runs finished in ${((Date.now() - t0) / 60000).toFixed(1)} min`);
