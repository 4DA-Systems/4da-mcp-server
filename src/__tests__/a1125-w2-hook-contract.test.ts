// SPDX-License-Identifier: Apache-2.0
/**
 * Round 21 (T2): THE CONTRACT block of hooks/manifest-edit.mjs, as the independent checks read it.
 * The block is extracted and held to its own rules (each sentence carries a test reference that
 * exists; a bounded length; no banned word without a reference; no list restated; each constant
 * and function it names exists, each constant exported), and the sentences that name this file
 * are pinned here.
 */

import { spawnSync } from "node:child_process";
import { readFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import * as hook from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK_FILE = join(HERE, "..", "..", "hooks", "manifest-edit.mjs");
const SOURCE = readFileSync(HOOK_FILE, "utf8");
const mod = hook as unknown as Record<string, unknown>;

/** THE CONTRACT: the lines between its heading and the notes', comment marks and headings taken out. */
function contractText(): string {
  const start = SOURCE.indexOf(" * THE CONTRACT\n");
  const end = SOURCE.indexOf(" * NOTES ON HOW IT READS\n");
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  return SOURCE.slice(start, end)
    .split("\n")
    .map((l) => l.replace(/^ \*\s?/, ""))
    .filter((l) => !/^[A-Z ]+$/.test(l.trim()))
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}
const TEXT = contractText();
/** Its sentences: each ends with a test reference and a full stop. */
const SENTENCES = TEXT.split(/(?<=\])\.(?:\s+|$)/).map((s) => s.trim()).filter(Boolean);
const REF = /\[test: ([^\]]+)\]$/;
/** The text outside "for example ..." spans (to the next comma-free stop, as written in the block). */
const OUTSIDE_EXAMPLES = SENTENCES.map((s) => s.replace(/for example[^[]*/g, "")).join(" ");

describe("THE CONTRACT is held to its own rules", () => {
  it("each sentence ends with a test reference, and nothing follows the last one", () => {
    expect(SENTENCES.length).toBeGreaterThan(0);
    for (const s of SENTENCES) expect(s, s).toMatch(REF);
    expect(TEXT.endsWith("].")).toBe(true);
  });
  it("is at most 60 sentences (and at least 30: it states the promises)", () => {
    expect(SENTENCES.length).toBeLessThanOrEqual(60);
    expect(SENTENCES.length).toBeGreaterThanOrEqual(30);
  });
  it("each test it names exists", () => {
    const names = new Set(SENTENCES.flatMap((s) => REF.exec(s)![1].split(/,\s*/)));
    for (const n of names) expect(existsSync(join(HERE, `${n}.test.ts`)), n).toBe(true);
  });
  it("each P and L sentence carries a reference", () => {
    const pl = SENTENCES.filter((s) => /^[PL][1-6]\b/.test(s));
    expect(pl.length).toBeGreaterThanOrEqual(20);
    for (const s of pl) expect(s).toMatch(REF);
  });
  it("a banned word (every, always, only, never, exactly, any other) appears only in a sentence with a reference", () => {
    for (const s of SENTENCES) if (/\b(?:every|always|only|never|exactly)\b|\bany other\b/i.test(s)) expect(s, s).toMatch(REF);
  });
  it("restates no list: no manifest file name, no manager name, no option, no host, no run of verbs outside a for-example", () => {
    for (const name of [...(mod.MANIFESTS as Set<string>), ...(mod.UNREAD_MANIFESTS as string[])]) expect(OUTSIDE_EXAMPLES.includes(name), name).toBe(false);
    for (const m of mod.MANAGERS as string[]) expect(new RegExp(`(?<![\\w-])${m}(?![\\w-])`).test(OUTSIDE_EXAMPLES), m).toBe(false);
    expect(OUTSIDE_EXAMPLES).not.toMatch(/(?:^|\s)--?[a-z]/);
    expect(OUTSIDE_EXAMPLES).not.toMatch(/\b[a-z0-9-]+\.(?:com|org|net|io|cn|dev)\b/);
    const verbs = new Set(Object.values(mod.VERBS as Record<string, string[]>).flat());
    const runs = OUTSIDE_EXAMPLES.match(/\b\w+(?:(?:, | \/ )\w+){2,}/g) ?? [];
    for (const r of runs) expect(r.split(/, | \/ /).filter((w) => verbs.has(w)).length, r).toBeLessThan(3);
  });
  it("each constant it names exists and is exported; the windows are the numbers it states", () => {
    const named = new Set(TEXT.match(/\b(?:[A-Z][A-Z0-9]*_[A-Z0-9_]+|MANAGERS|VERBS|MANIFESTS)\b/g) ?? []);
    named.delete("FOURDA_GUARD");
    // An environment setting the text names, not a constant of the hook.
    named.delete("FOURDA_MCP_HOME");
    expect(named.size).toBeGreaterThanOrEqual(15);
    for (const c of named) expect(mod[c], c).toBeDefined();
    expect(mod.LEDGER_WINDOW_MS).toBe(24 * 60 * 60 * 1000);
    expect(mod.LATEST_WINDOW_MS).toBe(60 * 60 * 1000);
    expect(TEXT).toContain("LEDGER_WINDOW_MS (24 hours)");
    expect(TEXT).toContain("LATEST_WINDOW_MS (1 hour)");
  });
  it("each function it names exists in the file", () => {
    for (const f of ["managerWord", "detectsInstall", "manifestKind", "manifestBaseName", "accountCall", "judge", "boundsNothing", "sourceVerdict", "urlDependency", "dataCommand", "ledgerCall", "rawHold", "advisedRun", "dataDir", "readLedger"]) {
      expect(TEXT.includes(f), f).toBe(true);
      expect(new RegExp(`function ${f}\\(`).test(SOURCE), f).toBe(true);
    }
  });
});

describe("WHAT IT IS, pinned", () => {
  it("hooks.json registers it before Bash, PowerShell, Edit, MultiEdit, Write and NotebookEdit, and after Bash, PowerShell, Edit, MultiEdit and Write", () => {
    const json = JSON.parse(readFileSync(join(HERE, "..", "..", "hooks", "hooks.json"), "utf8")) as { hooks: Record<string, Array<{ matcher: string }>> };
    const tools = (event: string) => new Set(json.hooks[event].flatMap((h) => h.matcher.split("|")));
    expect([...tools("PreToolUse")].sort()).toEqual(["Bash", "Edit", "MultiEdit", "NotebookEdit", "PowerShell", "Write"]);
    expect([...tools("PostToolUse")].sort()).toEqual(["Bash", "Edit", "MultiEdit", "PowerShell", "Write"]);
  });
  it("loads no module outside Node's own, and opens no network connection", () => {
    const imports = [...SOURCE.matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const i of imports) expect(i, i).toMatch(/^node:(?:fs|os|path|perf_hooks|worker_threads)$/);
    expect(SOURCE).not.toMatch(/\bfetch\(|\brequire\(|import\(/);
  });
});

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "black", version: "24.1.0", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());
const run = (command: string, tool = "Bash", env: Record<string, string> = {}) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } }, env);

describe("the modes", () => {
  it("off answers nothing; advise denies nothing; any other value blocks", () => {
    expect(run("npm install lodash@4.17.20", "Bash", { FOURDA_GUARD: "off" }).decision).toBe("allow");
    expect(run("npm install lodash@4.17.20", "Bash", { FOURDA_GUARD: "advise" }).decision).not.toBe("deny");
    for (const v of ["block", "on", "yes", ""]) expect(run("npm install lodash@4.17.20", "Bash", { FOURDA_GUARD: v }).decision, v).toBe("deny");
  });
});

describe("P1, generated over MANAGERS, VERBS and the manifest lists", () => {
  const verbs = mod.VERBS as Record<string, string[]>;
  it("each manager on MANAGERS followed by each of its VERBS is detected, as written and with quotes taken out", () => {
    expect(mod.MANAGERS).toEqual(Object.keys(verbs));
    for (const m of mod.MANAGERS as string[]) {
      for (const v of verbs[m]) {
        expect(hook.detectsInstall(`${m} ${v} zzq-pkg`), `${m} ${v}`).toBe(true);
        expect(hook.detectsInstall(`"${m}" '${v}' zzq-pkg`), `quoted ${m} ${v}`).toBe(true);
        expect(hook.detectsInstall(`${m}\n${v} zzq-pkg`), `${m} / ${v} on two lines`).toBe(false);
      }
    }
  });
  it("each name on MANIFESTS, in any letter case, and each MANIFEST_NAME_RULES example, is a manifest", () => {
    const kind = mod.manifestKind as (p: string) => string | null;
    for (const name of mod.MANIFESTS as Set<string>) {
      expect(kind(`/p/${name}`), name).toBe(name);
      expect(kind(`/p/${name.toUpperCase()}`), name).toBe(name);
    }
    expect(kind("/p/go.work")).toBe("go.mod");
    expect(kind("/p/requirements-dev.txt")).toBe("requirements.txt");
    expect(kind("/p/requirements/base.txt")).toBe("requirements.txt");
    expect(kind("/p/notes.txt")).toBeNull();
    expect(kind("/p/README.md")).toBeNull();
  });
  it.each(mod.UNREAD_MANIFESTS as string[])("an edit of %s is examined (denied as not read)", (name) => {
    expect(s.write(`${s.project}/${name}`, "dependencies:\n  lodash: 4.17.20\n").decision).toBe("deny");
  });
  it.each(["ls -la", "git status", "node build.js", "python -m pytest", "echo hello", "cargo fmt", "go test ./..."])("not examined: %s goes ahead with no answer", (command) => {
    expect(run(command).decision).toBe("allow");
  });
  it("an edit of a file that is no manifest goes ahead with no answer", () => {
    expect(s.write(`${s.project}/src/index.ts`, 'import lodash from "lodash"; // npm install lodash@4.17.20\n').decision).toBe("allow");
  });
});

describe("P2: an option the hook does not read, beside a named package, is denied as not read (each manager)", () => {
  it.each(["npm install --zzq-unknown lodash@4.17.21", "pnpm add --zzq-unknown lodash@4.17.21", "yarn add --zzq-unknown lodash@4.17.21", "bun add --zzq-unknown lodash@4.17.21", "pip install --zzq-unknown six==1.17.0", "uv add --zzq-unknown six==1.17.0", "poetry add --zzq-unknown six==1.17.0", "cargo add --zzq-unknown regex@=1.11.0", "go get -zzq golang.org/x/text@v0.21.0"])("%s", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("could not be read");
  });
});

describe("P3: the windows", () => {
  const at = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
  it("an exact answer 23 hours old counts; one 25 hours old does not", () => {
    writeFileSync(join(s.home, "check-ledger.jsonl"), JSON.stringify({ sv: "6.6.0", t: at(23), ecosystem: "npm", package: "ms", version: "2.1.3", verdict: "proceed" }) + "\n");
    expect(run("npm install ms@2.1.3").decision).toBe("allow");
    writeFileSync(join(s.home, "check-ledger.jsonl"), JSON.stringify({ sv: "6.6.0", t: at(25), ecosystem: "npm", package: "ms", version: "2.1.3", verdict: "proceed" }) + "\n");
    expect(run("npm install ms@2.1.3").decision).toBe("deny");
  });
});

describe("P3: which answers count", () => {
  const at = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
  const put = (lines: Array<Record<string, string>>) => writeFileSync(join(s.home, "check-ledger.jsonl"), lines.map((l) => JSON.stringify({ sv: "6.6.0", ...l })).join("\n") + "\n");
  it("an inclusive upper bound with lower bounds only: the release it names counts, where no answer counts for the range itself", () => {
    put([{ t: at(5), ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed" }]);
    expect(run("npm install 'lodash@>=4.17.0 <=4.17.21'").decision).toBe("allow");
    put([
      { t: at(5), ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed" },
      { t: at(4), ecosystem: "npm", package: "lodash", version: "4.17.21", requested: ">=4.17.0 <=4.17.21", verdict: "avoid" },
    ]);
    expect(run("npm install 'lodash@>=4.17.0 <=4.17.21'").decision).toBe("deny");
  });
  it("a Cargo bare version: an avoid for the release counts, and the newest counting answer decides", () => {
    put([
      { t: at(5), ecosystem: "crates.io", package: "regex", version: "1.5.4", requested: "1.5.4", verdict: "proceed" },
      { t: at(4), ecosystem: "crates.io", package: "regex", version: "1.5.4", verdict: "avoid" },
    ]);
    expect(run("cargo add regex@1.5.4").decision).toBe("deny");
    put([
      { t: at(5), ecosystem: "crates.io", package: "regex", version: "1.5.4", verdict: "avoid" },
      { t: at(4), ecosystem: "crates.io", package: "regex", version: "1.5.11", requested: "1.5.4", verdict: "proceed" },
    ]);
    expect(run("cargo add regex@1.5.4").decision).toBe("allow");
    // A proceed for the release does not count for the bare version.
    put([{ t: at(4), ecosystem: "crates.io", package: "regex", version: "1.5.4", verdict: "proceed" }]);
    expect(run("cargo add regex@1.5.4").decision).toBe("deny");
  });
});

describe("P4: a data program's text is not judged; written into a manifest it is", () => {
  it("an inert setting keeps it text; another setting on the line does not", () => {
    expect(run("GIT_AUTHOR_NAME=x git commit -m 'npm install lodash@4.17.20'").decision).toBe("allow");
    expect(run("FOO=1 echo npm install lodash@4.17.20").decision).toBe("deny");
  });
  it.each(["echo npm install lodash@4.17.20", "git commit -m 'npm install lodash@4.17.20'", "grep -r 'npm install lodash@4.17.20' docs"])("%s: goes ahead", (command) => {
    expect(run(command).decision).toBe("allow");
  });
  it("echo ... > package.json: held", () => {
    expect(run('echo "npm install lodash@4.17.20" > package.json').decision).toBe("deny");
  });
});

describe("P5: the bounds", () => {
  it("a command line over MAX_ACCOUNT_CHARS that names an install is denied as not read", () => {
    const pad = "x".repeat((mod.MAX_ACCOUNT_CHARS as number) + 10);
    const r = run(`echo ${pad}; npm install lodash@4.17.21`);
    expect(r.decision).toBe("deny");
  });
  it("an Edit of a manifest over MAX_MANIFEST_BYTES is denied as not read", () => {
    const big = s.file("package.json", `{"dependencies":{"lodash":"4.17.21"},"x":"${"y".repeat((mod.MAX_MANIFEST_BYTES as number) + 10)}"}`);
    const r = s.edit(big, '"lodash":"4.17.21"', '"lodash":"4.17.22"');
    expect(r.decision).toBe("deny");
  });
  it("a ledger file over MAX_LEDGER_BYTES makes an examined call denied as not read", () => {
    const line = JSON.stringify({ sv: "6.6.0", t: new Date().toISOString(), ecosystem: "npm", package: "ms", version: "2.1.3", verdict: "proceed", reason: "r".repeat(200) });
    writeFileSync(join(s.home, "check-ledger.jsonl"), `${line}\n`.repeat(Math.ceil((mod.MAX_LEDGER_BYTES as number) / line.length) + 10));
    const r = run("npm install ms@2.1.3");
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("could not be read");
  });
});

describe("P5: the failure rule", () => {
  it("a payload that does not parse is denied whatever its tool, where a ledger has been started", () => {
    const res = spawnSync(process.execPath, [HOOK_FILE], { input: "{not json", encoding: "utf8", timeout: 20_000, env: { ...process.env, FOURDA_MCP_HOME: s.home, FOURDA_GUARD: "" } });
    expect(res.status).toBe(0);
    expect(res.stdout).toContain("\"permissionDecision\":\"deny\"");
  });
});

describe("P6: a PostToolUse answer carries no permission decision (each kind of call)", () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "a1125-contract-home-"));
    writeFileSync(join(home, "check-ledger.jsonl"), JSON.stringify({ sv: "6.6.0", t: new Date().toISOString(), ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid" }) + "\n");
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));
  const calls: Array<[string, Record<string, unknown>]> = [
    ["Bash", { command: "npm install lodash@4.17.20" }],
    ["Bash", { command: "npm ci" }],
    ["PowerShell", { command: "pnpm install" }],
    ["Bash", { command: "rm -rf check-ledger.jsonl" }],
    ["Edit", { file_path: "/p/package.json", old_string: "a", new_string: "b" }],
    ["Write", { file_path: "/p/package.json", content: '{"dependencies":{"lodash":"4.17.20"}}' }],
  ];
  it.each(calls)("%s %j", (tool, input) => {
    for (const guard of ["", "advise"]) {
      const out = hook.respond({ hook_event_name: "PostToolUse", tool_name: tool, tool_input: input, cwd: tmpdir() }, { FOURDA_MCP_HOME: home, FOURDA_GUARD: guard });
      if (out === "") continue;
      const parsed = JSON.parse(out) as { hookSpecificOutput?: Record<string, unknown> };
      expect(parsed.hookSpecificOutput?.permissionDecision, out).toBeUndefined();
    }
  });
});

describe("L2 and L4: what P1 does not detect goes ahead unchecked", () => {
  it.each(["bash ./install.sh", "make deps", "pipx install black==24.1.0", "docker run node npm install lodash@4.17.20", "echo bnBtIGluc3RhbGwgbG9kYXNoQDQuMTcuMjA= | base64 -d | sh"])("%s: goes ahead", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});
