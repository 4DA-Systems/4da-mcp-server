// SPDX-License-Identifier: Apache-2.0
/**
 * Round 13, from the eleventh independent check (the header read sentence by sentence): each item
 * with the reviewer's cases.
 */

import { spawn, spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial } from "./helpers/a1125-hook-run.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  // Round 25 (S2): a requirements or constraints file a command names is read at the call: these exist, empty.
  for (const f of ["requirements.txt", "requirements-dev.txt", "constraints.txt", "c.txt", "o.txt", "req.txt"]) s.file(f, "");
  s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash", env: Record<string, string> = {}) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } }, env);

/** The hook on raw stdin text; its stdout and how long it took. */
function raw(text: string, extra: Record<string, string> = {}): { out: string; ms: number } {
  const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: s.home, ...extra };
  delete env.FOURDA_GUARD;
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [HOOK], { input: text, encoding: "utf8", env, timeout: 15_000, maxBuffer: 1 << 26 });
  return { out: r.stdout, ms: Date.now() - t0 };
}

describe("1: a failure or the budget spent holds by tool, not by words; pipes count against the budget", () => {
  const pipes = (head: string, unit: string, kb: number) => head + unit.repeat(Math.floor((kb * 1024) / unit.length));
  it.each([
    ["n\"\"pm i lodash@4.17.20", " | cat", 300, "Bash"],
    ["n''pm i lodash@4.17.20", " | cat", 300, "Bash"],
    ["pi\"\"p install requests==2.5.0", " | cat", 300, "Bash"],
    ["n\"\"pm i lodash@4.17.20", " | cat", 1024, "Bash"],
    ["n''pm i lodash@4.17.20", " | Out-Null", 1024, "PowerShell"],
  ])("%s then %s x %d KB (%s): held, well inside 10 s", (head, unit, kb, tool) => {
    const payload = JSON.stringify({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command: pipes(head, unit, kb) } });
    const r = raw(payload);
    expect(r.out).toContain('"deny"');
    expect(r.ms).toBeLessThan(9000);
  });

  it.each(["\\u006epm i lodash@4.17.20", "n\\u0070m i lodash@4.17.20"])("JSON-escaped %s under a fault: held", (cmd) => {
    const payload = `{"session_id":"s","cwd":".","hook_event_name":"PreToolUse","tool_name":"B\\u0061sh","tool_input":{"command":"${cmd}"}}`;
    expect(raw(payload, { FOURDA_HOOK_FAULT: "respond" }).out).toContain("could not finish reading this command");
  });

  it("a payload that does not parse at all: held", () => {
    expect(raw('{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"n\\"\\"pm i').out).toContain('"deny"');
  });

  it("under a fault an edit of a README gets nothing; one of package.json, or with no path, is held", () => {
    const write = (file_path: unknown) => JSON.stringify({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path, content: "npm install" } });
    expect(raw(write(`${s.project}/README.md`), { FOURDA_HOOK_FAULT: "respond" }).out).toBe("");
    expect(raw(write(`${s.project}/Package.json`), { FOURDA_HOOK_FAULT: "respond" }).out).toContain("could not finish reading this edit");
    expect(raw(write(7), { FOURDA_HOOK_FAULT: "respond" }).out).toContain("could not finish reading this edit");
  });

  it("stdin left open after a whole payload: judged as any other (an ordinary command goes ahead, an install is held)", () => {
    const open = (command: string) =>
      new Promise<string>((done) => {
        const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: s.home };
        delete env.FOURDA_GUARD;
        const p = spawn(process.execPath, [HOOK], { env });
        let o = "";
        p.stdout.on("data", (d: Buffer) => (o += d.toString()));
        p.on("exit", () => done(o));
        p.stdin.write(JSON.stringify({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } }));
        setTimeout(() => p.kill(), 15_000);
      });
    return Promise.all([open("echo let's go home"), open("npm i lodash@4.17.20")]).then(([ordinary, install]) => {
      expect(ordinary).toBe("");
      expect(install).toContain('"deny"');
    });
  }, 20_000);

  it("the plain path is unchanged: an ordinary command goes ahead, an install on its verdict", () => {
    expect(run("ls -la").decision).toBe("allow");
    const r = run("npm i lodash@4.17.21");
    expect(r.decision).toBe("deny");
    answerDenial(s, r, "proceed");
    expect(run("npm i lodash@4.17.21").decision).toBe("allow");
  });
});

describe("2: options that can change which release of a named package is installed", () => {
  it.each([
    "yarn add lodash --cached",
    "yarn workspace b add lodash --cached",
    "yarn add lodash --cached --mode=update-lockfile",
    "yarn add lodash@4.17.20 --mode=update-lockfile",
    "yarn add lodash@4.17.20 --prefer-offline",
    "npm i --offline lodash@4.17.20",
    "npm i --prefer-offline lodash",
    "pnpm add --frozen-lockfile lodash@4.17.20",
    "pnpm add --offline lodash",
    "bun add --frozen-lockfile lodash@4.17.20",
    "pip install --only-binary :all: requests==2.5.0",
    "pip install --upgrade-strategy eager requests==2.5.0",
    "pip install --platform manylinux2014_x86_64 --target out requests==2.5.0",
    "uv pip install --offline requests==2.5.0",
    "uv add --frozen requests==2.5.0",
    "cargo add --locked serde@1.0.0",
    "go get -mod=mod rsc.io/quote@v1.5.0",
  ])("%s: held as not read", (command) => {
    expect(run(command).text, command).toContain("could not be read");
  });

  it.each(["npm ci --offline", "pnpm install --frozen-lockfile", "yarn install --immutable", "bun install --frozen-lockfile", "pip install -r requirements.txt --only-binary :all:", "uv sync --frozen", "uv lock --locked"])("%s: no named package, goes ahead", (command) => {
    expect(run(command).decision, command).toBe("allow");
  });

  it("cargo install --locked builds with the crate's own lockfile: the named release is judged as usual", () => {
    const r = run("cargo install --locked ripgrep@14.1.1");
    expect(r.decision).toBe("deny");
    expect(r.text).not.toContain("could not be read");
  });

  it("pnpm --resolution-mode is no option this hook takes (pnpm 10 rejects it)", () => {
    expect(run("pnpm add --resolution-mode highest lodash@4.17.20").text).toContain("could not be read");
  });
});

describe("3: make leaves the data list; a data program under a setting that is not inert is none", () => {
  it.each([
    ["GH_BROWSER='npm i lodash@4.17.20 --tag' gh pr view 1 --web", "Bash"],
    ["BROWSER='npm i lodash@4.17.20 --tag' gh pr view 1 --web", "Bash"],
    ["$env:GH_BROWSER='npm i lodash@4.17.20 --tag'; gh pr view 1 --web", "PowerShell"],
    ["export GH_BROWSER='npm i lodash@4.17.20 --tag'; gh issue view 1 --web", "Bash"],
    ["make 'X:=$(shell npm i lodash@4.17.20)'", "Bash"],
    ["make 'X!=npm i lodash@4.17.20'", "Bash"],
    ["MAKEFLAGS='--eval=$(shell npm i lodash@4.17.20)' make", "Bash"],
    ["make SHELL='npm i lodash@4.17.20 #'", "Bash"],
    ["make PIP=pip3 install", "Bash"],
    ["PAGER='npm i lodash@4.17.20' git log", "Bash"],
    ["export X=1; echo 'npm install lodash'", "Bash"],
  ])("%s: held", (command, tool) => {
    expect(run(command, tool).decision, command).toBe("deny");
  });

  it("make's remedy says to keep the tool's command off make's line", () => {
    expect(run("make PIP=pip3 install").text).toContain("run the make target without putting the package manager's command on the line");
  });

  it.each([
    'GIT_AUTHOR_DATE="2026-11-26T10:00:00" git commit -m "ci: run npm install"',
    "GIT_COMMITTER_NAME=bot GIT_COMMITTER_EMAIL=bot@example.invalid git commit -m 'docs: pip install -r requirements.txt'",
    "TZ=UTC LANG=C git log --grep 'npm install'",
    "NO_COLOR=1 grep -rn 'npm install' docs",
    "CI=true echo 'run npm install'",
    "make -C docs install",
  ])("%s: an inert setting, or no manager word: goes ahead", (command) => {
    expect(run(command).decision, command).toBe("allow");
  });
});

describe("5: the eleventh check's false holds go ahead; their dangerous neighbours stay held", () => {
  it.each([
    ['GIT_AUTHOR_DATE="2026-11-26T10:00:00" git commit -m "ci: run npm install"', "Bash"],
    ["gh release create v1.0.0 --notes 'Install: npm install lodash'", "Bash"],
    ['gh release create v1.0.0 --title v1 --notes "run pip install -r requirements.txt" --target main', "Bash"],
    ["gh pr review 12 --body 'please npm install first' --comment", "Bash"],
    ["gh pr review 12 --approve --body 'npm install works'", "Bash"],
    ["gh issue comment 5 --body 'try pip install requests'", "Bash"],
    ["echo '- pip install x' >> README.md", "Bash"],
    ["echo -n '- npm install lodash' > notes.txt", "Bash"],
    ["tee docs/setup.md <<'EOF'\nRun npm install lodash\nEOF", "Bash"],
    ["cat <<'EOF' | tee docs/setup.md\nRun npm install lodash\nEOF", "Bash"],
    ["Set-Content -Path README.md -Value 'npm install lodash'", "PowerShell"],
    ["Add-Content README.md 'pip install requests'", "PowerShell"],
    ["Add-Content NOTES.md '- pip install -r requirements.txt'", "PowerShell"],
    ["'npm install lodash' | Out-File -FilePath notes.txt", "PowerShell"],
    ["'npm install lodash' | Set-Content -Path README.md", "PowerShell"],
  ])("%s: goes ahead", (command, tool) => {
    expect(run(command, tool).decision, command).toBe("allow");
  });

  it.each([
    ["Set-Content -Path package.json -Value 'npm install lodash'", "PowerShell"],
    ["'npm install lodash' | Out-File package.json", "PowerShell"],
    ["Set-Content x.txt -Value (npm i lodash@4.17.20)", "PowerShell"],
    ["Set-Content x.txt -Value $(npm i lodash@4.17.20)", "PowerShell"],
    ["Add-Content -Path notes.txt -Stream s 'npm install lodash'", "PowerShell"],
    ["'npm install lodash' | iex", "PowerShell"],
    ['"npm i lodash@4.17.20" | sh', "Bash"],
    ["echo 'npm i lodash@4.17.20' | sh", "Bash"],
    ["echo $(npm i lodash@4.17.20)", "Bash"],
    ["echo 'npm install lodash' >> package.json", "Bash"],
    ["tee package.json <<'EOF'\nnpm install\nEOF", "Bash"],
  ])("%s: held", (command, tool) => {
    expect(run(command, tool).decision, command).toBe("deny");
  });

  it("a write into a manifest names the redirect as written; a substitution holding the install names the command inside it", () => {
    expect(run("echo 'npm install lodash' >> package.json").text).toContain("without `>> package.json`");
    expect(run("echo $(npm i lodash@4.17.20)").text).toContain("with `$(npm i lodash@4.17.20)` written as the command inside it, run as a command of its own");
  });
});

describe("6: a ledger that exists but cannot be read is unreadable, not absent: held", () => {
  it("a ledger file the hook cannot read (a directory in its place): an install is held, an ordinary command goes ahead", () => {
    s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed", reason: "ok" }]);
    expect(run("npm i lodash@4.17.21").decision).toBe("allow");
    mkdirSync(join(s.home, "check-ledger.1.jsonl"));
    const r = run("npm i lodash@4.17.21");
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("exists but could not be read");
    expect(run("ls -la").decision).toBe("allow");
  });

  it("a read that fails (EACCES / EPERM, injected): held", () => {
    s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed", reason: "ok" }]);
    const r = run("npm i lodash@4.17.21", "Bash", { FOURDA_HOOK_FAULT: "ledger-unreadable" });
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("exists but could not be read");
  });
});

describe("proofs: check 11's data rows", () => {
  it("git commit --template is a file of text: goes ahead", () => {
    expect(run("git commit --template=t.txt -m 'npm i lodash@4.17.20'").decision).toBe("allow");
  });

  it.each([
    "cat <<EOF > notes.md\nnpm i lodash@4.17.20\nEOF\nnpm i lodash@4.17.20",
    "tee notes.md <<'EOF'\nx\nEOF\nnpm i lodash@4.17.20",
    "cat <<EOF > package.json\n{}\nEOF\nnpm i lodash@4.17.20",
  ])("an install beside a heredoc is held (the reader does not read a heredoc line): %s", (command) => {
    expect(run(command).decision, command).toBe("deny");
  });
});
