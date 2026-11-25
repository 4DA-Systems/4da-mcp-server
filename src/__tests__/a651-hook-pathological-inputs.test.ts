// SPDX-License-Identifier: Apache-2.0
/**
 * No input makes the guard hook slow, so no held call goes ahead because the hook ran out of time.
 *
 * Claude Code kills a hook at its timeout (hooks.json: 10 s) and, with `onFailure: "continue"`,
 * lets the call through. The 6.5.1 candidate's PEP 440 release pattern backtracked exponentially:
 * `pip install 'foo==1rcrc...rcx'` (26 to 29 "rc") took 16 to 21 s, so one junk requirement beside
 * a held install carried the install through (independent re-check of 0d30b40, B1). A 60 KB
 * `npm pkg set` key of `[` took 2.6 s. Every input here runs the hook as Claude Code runs it, a
 * child process with the payload on stdin, and must answer within 500 ms; a call that also holds
 * an unchecked install (`npm i lodash@4.17.20`) must still be denied.
 */

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");
const LIMIT_MS = 500;
const BIG = 60_000;

// Made when the table is built (the table writes the manifests the Write cases name).
const home = mkdtempSync(join(tmpdir(), "a651-patho-home-"));
const dir = mkdtempSync(join(tmpdir(), "a651-patho-proj-"));
writeFileSync(join(home, "check-ledger.jsonl"), JSON.stringify({ t: new Date().toISOString(), ecosystem: "npm", package: "zz", version: "1.0.0", verdict: "proceed" }) + "\n");
afterAll(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(dir, { recursive: true, force: true });
});

const bash = (command: string) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd: dir, tool_input: { command } });
const pwsh = (command: string) => ({ hook_event_name: "PreToolUse", tool_name: "PowerShell", cwd: dir, tool_input: { command } });
function write(file: string, content: string) {
  const path = join(dir, file);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, "");
  return { hook_event_name: "PreToolUse", tool_name: "Write", cwd: dir, tool_input: { file_path: path, content } };
}

const rc = (n: number, end: string) => `1${"rc".repeat(n)}${end}`;
const HELD = "npm i lodash@4.17.20";

/** [label, payload, the decision it must reach ("deny" when a held install rides along; null: either)]. */
const CASES: Array<[string, unknown, "deny" | null]> = [
  // The re-checker's (B1)
  ["pip install foo==1rc*29x ; npm i (the blocker)", bash(`pip install 'foo==${rc(29, "x")}'; ${HELD}`), "deny"],
  ["Write requirements.txt with foo==1rc*29x", write("requirements.txt", `requests==2.25.0\nfoo==${rc(29, "x")}\n`), "deny"],
  ...["!", "x", " ", "+", "#"].flatMap((end): Array<[string, unknown, "deny" | null]> => [
    [`poetry add requests@1rc*28${end}`, bash(`poetry add 'requests@${rc(28, end)}'; ${HELD}`), "deny"],
    [`pip install requests==1rc*28${end}`, bash(`pip install 'requests==${rc(28, end)}'; ${HELD}`), "deny"],
    [`pip install requests<=1rc*28${end}`, bash(`pip install 'requests<=${rc(28, end)}'; ${HELD}`), "deny"],
    [`pip install requests>=1,<=1rc*28${end}`, bash(`pip install 'requests>=1,<=${rc(28, end)}'; ${HELD}`), "deny"],
    [`uv add requests==1rc*28${end}`, bash(`uv add 'requests==${rc(28, end)}'; ${HELD}`), "deny"],
    [`uv lock -P requests==1rc*28${end}`, bash(`uv lock -P 'requests==${rc(28, end)}'; ${HELD}`), "deny"],
    [`requirements ==1rc*28${end}`, write("requirements.txt", `requests==${rc(28, end)}\nlodash==4.17.20\n`), "deny"],
    [`requirements <=1rc*28${end}`, write("requirements.txt", `requests<=${rc(28, end)}\nlodash==4.17.20\n`), "deny"],
    [`pyproject dependency ==1rc*28${end}`, write("pyproject.toml", `[project]\nname='a'\ndependencies=["requests==${rc(28, end)}", "lodash==4.17.20"]\n`), "deny"],
    [`poetry pyproject value 1rc*28${end}`, write("pyproject.toml", `[tool.poetry.dependencies]\nrequests = "${rc(28, end)}"\nlodash = "4.17.20"\n`), "deny"],
  ]),
  [`poetry add requests@1a-*28!`, bash(`poetry add 'requests@1${"a-".repeat(28)}!'; ${HELD}`), "deny"],
  ["npm pkg set 60 KB key of [", bash(`npm pkg set 'dependencies${"[".repeat(BIG - 40)}=1.0.0'; ${HELD}`), "deny"],
  ["npm pkg set 60 KB key of .a", bash(`npm pkg set dependencies${".a".repeat(BIG / 2 - 30)}=1.0.0; ${HELD}`), "deny"],
  ["bash 60 KB of ' cd' + install", bash(" cd".repeat(BIG / 3 - 20) + ` && ${HELD}`), null],
  ["bash 60 KB of -Cx", bash(`${HELD} ` + " -Cx".repeat(BIG / 4 - 10)), null],
  ["pwsh 60 KB of @a/ words", pwsh("npm i " + "@a/b@1.0.0 ".repeat(BIG / 11 - 5)), null],
  ["pwsh '@' + 60 KB scope word", pwsh("npm i @" + "a".repeat(BIG - 20) + "/b@1.0.0"), null],
  ["npm range 60 KB of '<=1.0.0 '", bash(`npm i 'zz@${"<=1.0.0 ".repeat(BIG / 8 - 10)}'; ${HELD}`), "deny"],
  ["npm range '<= ' x 20000", bash(`npm i 'zz@${"<= ".repeat(20000)}1.0.0'; ${HELD}`), "deny"],
  ["cargo update 60 KB -p list", bash("cargo update --precise 1.0.0" + " -p a".repeat(BIG / 5 - 10)), null],
  ["go mod edit 60 KB -replace list", bash("go mod edit" + " -replace=a.b/c=d.e/f@v1.0.0".repeat(BIG / 30 - 5)), null],
  ["uv lock 60 KB -P list", bash("uv lock" + " -P a==1".repeat(BIG / 8 - 5)), null],
  ["pwsh 60 KB of '<#' without close", pwsh(`${HELD} ` + "<# ".repeat(BIG / 3 - 10)), null],
  ["pwsh 60 KB of '<##>' pairs", pwsh(`${HELD} ` + "<##>".repeat(BIG / 4 - 10)), "deny"],
  // Found by an in-process fuzz of every position that takes the call's text (scratch/redos-fuzz):
  // a run of blanks scanned once per position was quadratic (1.5 s at 30 KB) before tokens were bounded.
  ['pip install "x (1" + 30 KB of blanks + "!"', bash(`pip install "x (1${" ".repeat(30_000)}!"; ${HELD}`), "deny"],
  ["pip install 'x<=1' + 30 KB of newlines", bash(`pip install 'x<=1${"\n".repeat(30_000)}'; ${HELD}`), null],
  ["uv add x==1 + 30 KB of tabs", bash(`uv add 'x==1${"\t".repeat(30_000)}!'; ${HELD}`), "deny"],
  ["pyproject requirement with 30 KB of blanks", write("pyproject.toml", `[project]\ndependencies = ["x==1${" ".repeat(30_000)}!", "lodash==4.17.20"]\n`), "deny"],
  ["pnpm catalog value with 30 KB of blanks", write("pnpm-workspace.yaml", `catalog:\n  x: 1${" ".repeat(30_000)}!\n  lodash: 4.17.20\n`), "deny"],
  ["requirements line of 30 KB of blanks", write("requirements.txt", `x==1${" ".repeat(30_000)}!\nlodash==4.17.20\n`), "deny"],
  ["go.mod line of 30 KB", write("go.mod", `module m\nrequire example.com/x v1${"0".repeat(30_000)}\nrequire golang.org/x/net v0.17.0\n`), "deny"],
  ["npm pkg set 30 KB key of [ quoted", bash(`npm pkg set "1${"[".repeat(30_000)}=1"; ${HELD}`), "deny"],
  // Found by the fuzz in round 3: the PEP 440 spelling comparison (specKey) was quadratic on blanks.
  ["Poetry value with 30 KB of blanks", write("pyproject.toml", `[tool.poetry.dependencies]\nx = "1${" ".repeat(30_000)}!"\nlodash = "4.17.20"\n`), "deny"],
];

/**
 * Loaded into the child before the hook: at exit it writes the process's own CPU time (user and
 * system, every thread) to stderr. The hook is run unchanged.
 */
const CPU_AT_EXIT =
  "data:text/javascript," +
  encodeURIComponent(
    "import { writeSync } from 'node:fs'; process.on('exit', () => { const u = process.cpuUsage(); try { writeSync(2, '\\n@@cpu_ms=' + (u.user + u.system) / 1000 + '@@\\n'); } catch { /* stderr closed */ } });",
  );

interface Run {
  /** Wall-clock time of the child, start to exit. */
  ms: number;
  /** The child's own CPU time; NaN when it wrote none (killed, or stderr lost). */
  cpu: number;
  decision: string;
  status: number | null;
}

function run(payload: unknown, ledgerHome: string = home): Run {
  const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: ledgerHome };
  delete env.FOURDA_GUARD;
  const t0 = performance.now();
  const r = spawnSync(process.execPath, ["--import", CPU_AT_EXIT, HOOK], { input: JSON.stringify(payload), encoding: "utf8", timeout: 15_000, env, maxBuffer: 1 << 26 });
  const ms = performance.now() - t0;
  const cpu = Number(/@@cpu_ms=([0-9.]+)@@/.exec(r.stderr ?? "")?.[1] ?? Number.NaN);
  const decision = r.stdout ? ((JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string } }).hookSpecificOutput?.permissionDecision ?? "other") : "allow";
  return { ms, cpu, decision, status: r.status };
}

/**
 * The best of up to three runs of `payload`: it runs again while the wall clock is over `limit`,
 * and keeps the fastest wall time and the smallest CPU time seen (a pathological input is slow on
 * both, every time: the blocker took 16 to 21 s).
 */
function best(payload: unknown, ledgerHome?: string, limit: number = LIMIT_MS): Run {
  let r = run(payload, ledgerHome);
  for (let tries = 1; tries < 3 && r.ms >= limit; tries++) {
    const again = run(payload, ledgerHome);
    const cpu = Math.min(Number.isNaN(r.cpu) ? Infinity : r.cpu, Number.isNaN(again.cpu) ? Infinity : again.cpu);
    r = { ...(again.ms < r.ms ? again : r), cpu: cpu === Infinity ? Number.NaN : cpu };
  }
  return r;
}

/**
 * The hook answered inside `limit` on the wall clock, or its own work took less than twice `limit`
 * of CPU time. The wall clock is what Claude Code's timeout counts, but on a shared machine it mostly
 * measures the wait for a core, not the hook: with 32 busy processes on 16 cores a trivial call
 * went from 52 ms to 2,000 ms and a 4 MB-ledger row from 390 ms to 4,600 ms, while their CPU time
 * went from 46 to 61 ms and from 450 to 660 ms (measured 2026-11-25). The wall-clock bound failed
 * twice on loaded CI runners with nothing wrong in the hook (1,095 ms and 1,418 ms against 1,000
 * for a 4 MB-ledger row), the second time through a bound scaled by how long a trivial call took at
 * that moment: a trivial call does not slow down the way 8 MB of ledger does. A pathological input
 * is slow in CPU time too (1.5 s, 2.6 s, 3 s, 10 s and 21 s were the rows this file was written
 * for, against 0.14 s here for the slowest 500 ms row and 0.55 s for a ledger row), so the CPU bound
 * catches one on any machine. Twice the bound, not the bound: CPU time is steadier than the wall
 * clock, not constant (a slower runner core, a busy sibling thread: up to 1.5 times here under
 * load). A run that reports no CPU time fails.
 */
function expectWithin(r: Run, limit: number): void {
  if (r.ms < limit) return;
  expect(r.cpu, `the hook's CPU time (wall clock ${r.ms.toFixed(0)} ms against ${limit} ms)`).toBeLessThan(2 * limit);
}

describe("a call that could not be read in time is held, never let through", () => {
  it("over the read budget, an install command or a manifest edit is denied as not read", () => {
    const out = respond(bash("npm i left-pad"), { FOURDA_MCP_HOME: home }, Date.now(), -1);
    expect(out).toContain("could not be read (reading it took over 2 s)");
    const edit = respond(write("package.json", '{"dependencies":{}}'), { FOURDA_MCP_HOME: home }, Date.now(), -1);
    expect(edit).toContain("could not be read (reading it took over 2 s)");
  });

  it("a command that names no package manager is not held for being slow", () => {
    expect(respond(bash("git status"), { FOURDA_MCP_HOME: home }, Date.now(), -1)).toBe("");
  });

  it("within the budget nothing changes", () => {
    expect(respond(bash("npm i left-pad"), { FOURDA_MCP_HOME: home }, Date.now())).toBe("");
  });
});

describe(`every pathological input is answered within ${LIMIT_MS} ms, as a child process`, () => {
  // One run first: the first spawn pays for warming the file cache.
  beforeAll(() => run(bash("npm ci")));

  it.each(CASES)("%s", (_label, payload, mustBe) => {
    const r = best(payload);
    expect(r.status).toBe(0);
    expectWithin(r, LIMIT_MS);
    if (mustBe) expect(r.decision).toBe(mustBe);
  });
});

/**
 * The rows of the round-3 checker's timing table that took over a second (a 4 MB MultiEdit took
 * 21 s and Claude Code let the call through; 25 versions against 4 MB ledgers took 3 s; TOML
 * nested about 7,400 deep threw and the call went ahead), each now a fast deny. The two 4 MB-ledger
 * rows read 8 MB of ledger and are given 1,000 ms; the others 500 ms (expectWithin says of what).
 */
describe("the checker's slow rows are fast denials (round 3 of the hook review)", { timeout: 60_000 }, () => {
  const recent = () => new Date(Date.now() - 60_000).toISOString();
  function bigLedger(name: string, make: (i: number) => unknown): string {
    const h = join(dir, name);
    mkdirSync(h, { recursive: true });
    for (const f of ["check-ledger.jsonl", "check-ledger.1.jsonl"]) {
      const out: string[] = [];
      let size = 0;
      for (let i = 0; size < 4 * 1024 * 1024 - 2000; i++) {
        const v = make(i);
        const l = typeof v === "string" ? v : JSON.stringify(v);
        size += l.length + 1;
        out.push(l);
      }
      writeFileSync(join(h, f), out.join("\n") + "\n");
    }
    return h;
  }
  it("a MultiEdit of a 4 MB requirements.txt with 8,000 edits", () => {
    const lines = 200_000;
    const file = join(dir, "requirements.txt");
    writeFileSync(file, Array.from({ length: lines }, (_, i) => `pkg${i}==1.0.${i}`).join("\n") + "\n");
    const edits = Array.from({ length: 8000 }, (_, i) => ({ old_string: `pkg${i}==1.0.${i}\n`, new_string: `pkg${i}==1.0.${i}\n` }));
    edits.push({ old_string: `pkg${lines - 1}==1.0.${lines - 1}`, new_string: `pkg${lines - 1}==2.0.0` });
    const r = best({ hook_event_name: "PreToolUse", tool_name: "MultiEdit", cwd: dir, tool_input: { file_path: file, edits } });
    expect(r.decision).toBe("deny");
    expectWithin(r, LIMIT_MS);
  });

  it("a Write of a manifest whose payload is over 8 MB", () => {
    const r = best(write("requirements.txt", "requests==2.0.0\n#" + " ".repeat(8 * 1024 * 1024 + 100) + "\n"));
    expect(r.decision).toBe("deny");
    expectWithin(r, LIMIT_MS);
  });

  it("an install command with a 70 KB comment", () => {
    const r = best(bash("npm i lodash@4.17.20 # " + "x".repeat(70 * 1024)));
    expect(r.decision).toBe("deny");
    expectWithin(r, LIMIT_MS);
  });

  it("a Cargo.toml nested 40,000 deep beside a pin", () => {
    const r = best(write("Cargo.toml", `[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0.0"\n\n[package.metadata]\nx = ${"[".repeat(40_000)}${"]".repeat(40_000)}\n`));
    expect(r.decision).toBe("deny");
    expectWithin(r, LIMIT_MS);
  });

  it.each([
    ["PyPI unknown entries whose versions need normalising", (i: number) => ({ t: recent(), ecosystem: "PyPI", package: "Requests", version: `2.0.${i % 50}-rc.${i}.POST-${i}`, verdict: "unknown", reason: "x" })],
    ["lines that do not parse", () => "{".repeat(200)],
  ])("25 versions against 4 MB ledgers of %s", (label, make) => {
    const h = bigLedger(label.replace(/[^a-z]/gi, "").slice(0, 20), make);
    const vers = Array.from({ length: 25 }, (_, i) => `requests==2.0.${i}.post1.dev3`).join(" ");
    const r = best(bash(`pip install ${vers}`), h, 2 * LIMIT_MS);
    expect(r.decision).toBe("deny");
    expectWithin(r, 2 * LIMIT_MS);
  });
});

/**
 * One small Edit with `replace_all` whose old text occurs thousands of times builds a manifest of
 * hundreds of MB: pyproject.toml with 12,000 hits took 10.7 s (Claude Code stops the hook at 10 s
 * and the edit, which adds `urllib3==1.0.0`, goes ahead), 20,000 hits ran V8 out of memory after
 * 38 s, Cargo.toml with 25,000 hits 12.8 s; the same in 6.5.0 (round 4 of the hook review, item 1).
 * The hits are now counted before the edit is applied, and an edit whose result would pass the
 * manifest bound is held; the readers also check the time budget as they go.
 */
describe("a replace_all edit that would build a huge manifest is held fast (round 4)", { timeout: 60_000 }, () => {
  function replaceAll(file: string, disk: string, newString: string) {
    const sub = mkdtempSync(join(dir, "blocker5-"));
    const path = join(sub, file);
    writeFileSync(path, disk);
    return { hook_event_name: "PreToolUse", tool_name: "Edit", cwd: sub, tool_input: { file_path: path, old_string: "Q", new_string: newString, replace_all: true } };
  }
  it.each([
    ["pyproject.toml, 12,000 hits", "pyproject.toml", `[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["requests==2.31.0"${"Q".repeat(12_000)}]\n`, `, "urllib3==1.0.0"` + ", 1".repeat(1500)],
    ["pyproject.toml, 20,000 hits", "pyproject.toml", `[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["requests==2.31.0"${"Q".repeat(20_000)}]\n`, `, "urllib3==1.0.0"` + ", 1".repeat(1500)],
    ["Cargo.toml, 25,000 hits", "Cargo.toml", `[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0.0"\n${"Q".repeat(25_000)}\n`, `\ntime = "0.3.17"` + `\nk = 1`.repeat(300)],
    ["requirements.txt, 20,000 hits", "requirements.txt", `requests==2.31.0\n${"Q".repeat(20_000)}\n`, `\nurllib3==1.0.0` + `\n# x`.repeat(1000)],
    ["package.json array, 20,000 hits", "package.json", `{"name":"x","dependencies":{"lodash":"4.17.21"},"files":["${"Q".repeat(20_000)}"]}`, `","a`.repeat(1000) + `"],"devDependencies":{"left-pad":"1.3.0"},"x":["`],
    ["pnpm-workspace.yaml, 20,000 hits", "pnpm-workspace.yaml", `catalog:\n  react: 18.2.0\n${"Q".repeat(20_000)}\n`, `\n  lodash: 4.17.20` + `\n# x`.repeat(1000)],
    ["go.mod, 20,000 hits", "go.mod", `module m\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.9.1\n${"Q".repeat(20_000)}\n`, `\nrequire golang.org/x/net v0.17.0` + `\n// x`.repeat(1000)],
  ])("%s", (_label, file, disk, newString) => {
    const r = best(replaceAll(file, disk, newString));
    expect(r.status).toBe(0);
    expect(r.decision).toBe("deny");
    expectWithin(r, LIMIT_MS);
  });
});
