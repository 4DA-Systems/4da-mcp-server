// SPDX-License-Identifier: Apache-2.0
/**
 * The one child-CPU helper of the briefing's cost tests (a1132-round9 .. a1136-round13). Each call runs the built
 * briefing in a fresh Node.js child and returns the child's own CPU time for each briefing call, in ms.
 *
 * Why a helper (macOS CI, 2026-11): one child in several hundred did not exit within the 120 s wall timeout although its
 * siblings took about a second, and the job failed with `spawnSync node ETIMEDOUT`. So:
 * 1. The parent sets the child's environment: FOURDA_OFFLINE=true and a fresh FOURDA_MCP_HOME of its own, before any
 *    module of the server is imported (the old scripts set FOURDA_OFFLINE after the import).
 * 2. The child prints its figures with `process.stdout.write(line, () => process.exit(0))`: nothing left running after
 *    the measurement (a walk, a timer, a socket) can keep it alive, and a pipe write on POSIX is asynchronous, so it
 *    exits in the write's callback.
 * 3. If the child still hits the wall timeout, what it printed is read: a figure means the measurement finished and is
 *    used; none means the briefing itself did not finish, and the error says so with the last stage the child reached
 *    (one short stage line on STDERR before and after the import, after reading stdin, after each call).
 * 4. The child runs in a fresh empty folder unless the test gives a project_path on purpose: the old P4 children ran in
 *    the repository root.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";

/** The built briefing module the children import. */
export const BRIEFING_DIST = path.resolve(__dirname, "..", "..", "..", "dist", "tools", "what-should-i-know.js");
/** The wall timeout of one child: a backstop, not a measure (the measure is the child's CPU). */
export const CHILD_TIMEOUT_MS = 120_000;
const FIGURES = /^@@cpu (\[[\d.,e+-]*\])$/m;
const STAGE = /@@stage (\S+)/g;

export interface ChildCpuCall {
  /** What the child reads on stdin (the task, or a JSON document the `calls` source parses). */
  input: string;
  /**
   * JavaScript source of a function `(input) => Array<args>`: the arguments of each briefing call the child makes, in
   * order, each measured on its own.
   */
  calls: string;
  /** Wall timeout of the child (default CHILD_TIMEOUT_MS). */
  timeoutMs?: number;
}

/** The child's CPU time for each briefing call, in ms. */
export function childCpu({ input, calls, timeoutMs = CHILD_TIMEOUT_MS }: ChildCpuCall): number[] {
  const home = mkdtempSync(path.join(os.tmpdir(), "4da-childcpu-home-"));
  const cwd = mkdtempSync(path.join(os.tmpdir(), "4da-childcpu-cwd-"));
  const script = `
    import { readFileSync, writeSync } from "node:fs";
    const stage = (s) => { try { writeSync(2, "@@stage " + s + "\\n"); } catch { /* stderr closed */ } };
    stage("before-import");
    const { executeWhatShouldIKnow } = await import(${JSON.stringify(pathToFileURL(BRIEFING_DIST).href)});
    stage("after-import");
    const input = readFileSync(0, "utf8");
    stage("stdin-read");
    const calls = (${calls})(input);
    const figures = [];
    for (let i = 0; i < calls.length; i++) {
      const t0 = process.cpuUsage();
      await executeWhatShouldIKnow(null, calls[i], null);
      const u = process.cpuUsage(t0);
      figures.push((u.user + u.system) / 1000);
      stage("call-" + i + "-done");
    }
    process.stdout.write("@@cpu " + JSON.stringify(figures) + "\\n", () => process.exit(0));`;
  try {
    return runChildScript(script, { input, timeoutMs, cwd, home });
  } finally {
    for (const dir of [home, cwd]) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // Windows: left for the OS temp cleaner.
      }
    }
  }
}

/**
 * One child script run with the helper's environment, read as the helper reads it: the `@@cpu [...]` figures on stdout,
 * from a finished child or from one the wall timeout stopped after it printed; otherwise an error naming the last
 * `@@stage` line the child wrote to stderr.
 */
export function runChildScript(script: string, { input, timeoutMs, cwd, home }: { input: string; timeoutMs: number; cwd: string; home: string }): number[] {
  try {
    const out = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
      cwd,
      env: { ...process.env, FOURDA_OFFLINE: "true", FOURDA_MCP_HOME: home },
      encoding: "utf8",
      input,
      maxBuffer: 1 << 24,
      timeout: timeoutMs,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const figures = FIGURES.exec(out);
    if (!figures) throw new Error(`the child printed no CPU figure: ${out.slice(-300)}`);
    return JSON.parse(figures[1]) as number[];
  } catch (error) {
    const e = error as { stdout?: string | Buffer; stderr?: string | Buffer; code?: string; signal?: string; message?: string };
    const figures = FIGURES.exec(String(e.stdout ?? ""));
    // The measurement finished; only the exit was late: the figure stands.
    if (figures) return JSON.parse(figures[1]) as number[];
    const stages = [...String(e.stderr ?? "").matchAll(STAGE)].map((m) => m[1]);
    throw new Error(`the briefing did not finish in the child within ${timeoutMs} ms (${e.code ?? e.signal ?? e.message}); last stage reached: ${stages.at(-1) ?? "none"}`);
  }
}
