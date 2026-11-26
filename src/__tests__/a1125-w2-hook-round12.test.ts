// SPDX-License-Identifier: Apache-2.0
/**
 * Round 12, from the tenth independent check (the header read sentence by sentence): each item
 * with the reviewer's cases.
 */

import { spawn, spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash", env: Record<string, string> = {}) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } }, env);

/** Held; answered as the denial says (when it names a call), it goes ahead. */
function releases(command: string, tool = "Bash"): void {
  const r = run(command, tool);
  if (r.decision === "deny") {
    expect(r.text, command).not.toContain("could not be read");
    answerDenial(s, r, "proceed");
    expect(run(command, tool).decision, command).toBe("allow");
  }
}

const I = "npm i lodash@4.17.20";
const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = join(HERE, "..", "..", "hooks", "manifest-edit.mjs");
const STALL = pathToFileURL(join(HERE, "helpers", "a1125-stall-preload.mjs")).href;

/** The hook run on raw stdin text with extra env (and node options); its stdout. */
function spawnHook(raw: string, extra: Record<string, string>, nodeArgs: string[] = []): string {
  const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: s.home, STALL_AFTER: nodeArgs.length > 0 ? "3" : "", ...extra };
  delete env.FOURDA_GUARD;
  const r = spawnSync(process.execPath, [...nodeArgs, HOOK], { input: raw, encoding: "utf8", env, timeout: 15_000, maxBuffer: 1 << 26 });
  return r.stdout;
}

describe("1: sed and awk are never text; git under an editor / pager / GIT_* setting, make with a makefile option, neither", () => {
  it.each([
    [`echo a | sed '/[/p;s]/!e ${I} #]x]'`, "Bash"],
    ["echo a | sed -n --expression='/[/p;s]/!e pip install requests==2.5.0 #]x]'", "Bash"],
    ["cat f | sed '/[/d;s]/!e cargo add serde@1.0.0 #]x]'", "Bash"],
    [`echo a | awk -v x='${I}' '/[/{print "]/;BEGIN{system(x)};#"}'`, "Bash"],
    [`echo a | awk --field-separator '/x/' 'BEGIN{system("${I}")}'`, "Bash"],
    [`echo a | awk --assign 'NR==1' 'BEGIN{system("${I}")}'`, "Bash"],
    [`GIT_EDITOR='${I} #' git commit -a`, "Bash"],
    [`GIT_EXTERNAL_DIFF='${I} #' git diff`, "Bash"],
    [`export GIT_PAGER='${I} #'; git log`, "Bash"],
    [`EDITOR='${I}' git commit`, "Bash"],
    [`$env:GIT_EDITOR='${I} #'; git tag -a v1`, "PowerShell"],
    [`Set-Item env:GIT_PAGER '${I}'; git log`, "PowerShell"],
    [`make -f /dev/stdin <<'EOF'\nall:\n\t${I}\nEOF`, "Bash"],
    [`make --file=Makefile.x ${I}`, "Bash"],
    [`make --eval='all: ; ${I}'`, "Bash"],
  ])("%s: held", (command, tool) => {
    expect(run(command, tool).decision, command).toBe("deny");
    releases(I);
  });

  it("sed and awk get the grep / Write remedy", () => {
    expect(run("sed -n '/npm install/p' README.md").text).toContain("use grep, rg or Select-String");
  });

  it.each(["git commit -m 'docs: npm install lodash'", "git log --grep 'pip install'", "make -C docs install", "grep -rn 'npm install' docs"])("%s: still text", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});

describe("2: a manifest's path is resolved as text before its name is matched", () => {
  const P = () => s.project.replace(/\\/g, "/");
  const write = (path: string, content: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: path, content } });
  const PKG = '{"dependencies":{"lodash":"4.17.20"}}';
  it.each([
    ["x/package.json/.", PKG],
    ["x/package.json\\.", PKG],
    ["x/package.json/x/..", PKG],
    ["x/package.json/", PKG],
    ["x/requirements/./dev.txt", "requests==2.5.0\n"],
    ["x/requirements/x/../dev.txt", "requests==2.5.0\n"],
    ["x/requirements./dev.txt", "requests==2.5.0\n"],
    ["x/Cargo.toml/x/..", '[package]\nname = "p"\nversion = "0.1.0"\n[dependencies]\nserde = "=1.0.0"\n'],
    ["x/Cargo.toml/.", '[package]\nname = "p"\nversion = "0.1.0"\n[dependencies]\nserde = "=1.0.0"\n'],
  ])("Write %s: held on its verdict", (rel, content) => {
    const r = write(`${P()}/${rel}`, content);
    expect(r.decision, r.text).toBe("deny");
    expect(r.items, r.text).not.toBeNull();
  });

  it("another file still goes ahead", () => {
    expect(write(`${P()}/x/package.json/../notes.json`, PKG).decision).toBe("allow");
  });
});

describe("3: no option that installs a name not on the line", () => {
  it.each(["bun add -a ./index.ts", "bun add --analyze src/index.ts", "bun update --interactive", "yarn upgrade --pattern gulp", "yarn upgrade --scope @angular", "yarn install --focus", "yarn add --use-yarnrc ./other.yarnrc lodash@4.17.20", "pnpm update --interactive"])("%s: held as not read", (command) => {
    expect(run(command).text).toContain("could not be read");
  });

  it.each(["bun add lodash@4.17.20", "yarn add lodash@4.17.20", "pnpm update lodash@4.17.20"])("%s: the plain command is read", (command) => {
    releases(command);
  });
});

describe("4: one outermost handler: nothing goes silent", () => {
  const install = (pad = 0) => ({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `${I}${pad ? ` # ${"x".repeat(pad)}` : ""}` } });
  const plain = (pad = 0) => ({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `ls -la${pad ? ` # ${"x".repeat(pad)}` : ""}` } });

  it("a payload over 8 KB with a value nested 4,500 deep: read, and held", () => {
    const deep = "[".repeat(4500) + "]".repeat(4500);
    const raw = `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"${I}","description":${deep}}}`;
    const r = spawnHook(raw, {});
    expect(r).toContain('"deny"');
  });

  it("under 8 KB, the clock jumps 3 s past the budget mid-read (the reviewer's stall): held", () => {
    const r = spawnHook(JSON.stringify(install(6000)), {}, ["--import", STALL]);
    expect(r).toContain('"deny"');
  });

  const POINTS = ["stdin", "parse", "respond", "ledger-guard", "reader", "detector", "account", "ledger-read", "denial", "worker-start", "worker"];
  it.each(POINTS)("a fault injected at %s: an install is held, a plain command is not", (point) => {
    for (const pad of [0, 9000]) {
      const held = spawnHook(JSON.stringify(install(pad)), { FOURDA_HOOK_FAULT: point });
      expect(held, `${point} pad ${pad}`).toContain('"deny"');
      expect(spawnHook(JSON.stringify(plain(pad)), { FOURDA_HOOK_FAULT: point }), `${point} pad ${pad}`).toBe("");
    }
  });

  it("a payload that starts with a BOM is read", () => {
    expect(spawnHook(`﻿${JSON.stringify(install())}`, {})).toContain("lodash");
  });

  it("stdin that is never closed: after 8 s the text that has arrived decides (held here)", async () => {
    const out = await new Promise<string>((done) => {
      const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: s.home };
      delete env.FOURDA_GUARD;
      const p = spawn(process.execPath, [HOOK], { env });
      let o = "";
      p.stdout.on("data", (d: Buffer) => (o += d.toString()));
      p.on("exit", () => done(o));
      p.stdin.write(JSON.stringify(install()).slice(0, -2));
      setTimeout(() => p.kill(), 15_000);
    });
    expect(out).toContain('"deny"');
  }, 20_000);
});

/**
 * 6: for every manager and every verb in the detector, a command held as not read (an option no
 * table knows) prints a remedy command; that command, run as printed (and its dependency_check call
 * answered when it names one), goes ahead.
 */
describe("6: the remedy each denial prints releases", () => {
  const Z = "--zz-not-an-option";
  const HELD: string[] = [
    `npm install ${Z} lodash@4.17.21`,
    `npm install-test ${Z} lodash@4.17.21`,
    `npm it ${Z} lodash@4.17.21`,
    `npm link ${Z} lodash`,
    `npm update ${Z} lodash@4.17.21`,
    `pnpm add ${Z} lodash@4.17.21`,
    `pnpm install ${Z} lodash@4.17.21`,
    `pnpm i ${Z} lodash@4.17.21`,
    `pnpm up ${Z} lodash@4.17.21`,
    `pnpm update ${Z} lodash@4.17.21`,
    `pnpm upgrade ${Z} lodash@4.17.21`,
    `pnpm link ${Z} lodash`,
    `pnpm ln ${Z} lodash`,
    `yarn add ${Z} lodash@4.17.21`,
    `yarn up ${Z} lodash@4.17.21`,
    `yarn upgrade ${Z} lodash@4.17.21`,
    `yarn install ${Z}`,
    `yarn link ${Z} lodash`,
    `bun add ${Z} typescript@5.6.3`,
    `bun a ${Z} typescript@5.6.3`,
    `bun install ${Z} typescript@5.6.3`,
    `bun i ${Z} typescript@5.6.3`,
    `bun update ${Z} typescript@5.6.3`,
    "bun update typescript@5.6.3",
    `bun link ${Z} typescript`,
    `pip install ${Z} requests==2.32.3`,
    `python -m pip install ${Z} requests==2.32.3`,
    `uv add ${Z} requests==2.32.3`,
    `uv sync ${Z}`,
    `uv lock ${Z}`,
    `uv pip install ${Z} requests==2.32.3`,
    `poetry add ${Z} requests==2.32.3`,
    `poetry install ${Z}`,
    `poetry update ${Z}`,
    `poetry lock ${Z}`,
    `cargo add ${Z} serde@1.0.200`,
    `cargo install ${Z} ripgrep@14.1.1`,
    `cargo update ${Z}`,
    `go get ${Z} rsc.io/quote@v1.5.2`,
    `go install ${Z} golang.org/x/tools/gopls@v0.16.2`,
    `go mod edit ${Z} -require=rsc.io/quote@v1.5.2`,
  ];
  it.each(HELD)("%s", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("could not be read");
    const remedy = /plain command of its own: `([^`]+)`/.exec(r.text)?.[1];
    expect(remedy, r.text).toBeDefined();
    expect(remedy).not.toBe(command);
    const first = run(remedy as string);
    if (first.decision === "deny") {
      expect(first.text, remedy).not.toContain("could not be read");
      answerDenial(s, first, "proceed");
      expect(run(remedy as string).decision, remedy).toBe("allow");
    }
  });
});

describe("7: advise mode and no ledger read the file as block mode does", () => {
  it("an Edit of the version alone (no key): advised after it, as block mode denies it before", () => {
    const pkg = s.file("pkg/package.json", '{"dependencies":{"lodash":"4.17.21"}}\n');
    // block mode, before the edit: denied
    expect(s.edit(pkg, '"4.17.21"', '"4.17.20"').decision).toBe("deny");
    // the edit made; advise mode after it: advice naming lodash 4.17.20
    s.file("pkg/package.json", '{"dependencies":{"lodash":"4.17.20"}}\n');
    const advised = s.post(pkg, '"4.17.21"', '"4.17.20"');
    expect(advised.decision).toBe("advise");
    expect(advised.text).toContain("lodash");
    expect(advised.text).toContain("4.17.20");
  });

  it("with no ledger at all (an older server): the same advice", () => {
    const pkg = s.file("pkg/package.json", '{"dependencies":{"lodash":"4.17.20"}}\n');
    const advised = s.post(pkg, '"4.17.21"', '"4.17.20"', { FOURDA_MCP_HOME: `${s.project}/no-ledger-here` });
    expect(advised.decision).toBe("advise");
    expect(advised.text).toContain("4.17.20");
  });

  it("an edit whose new text is not found once falls back to the snippet reading", () => {
    const pkg = s.file("pkg/package.json", '{"dependencies":{"a":"1.0.0","b":"1.0.0"}}\n');
    const advised = s.post(pkg, '"a":"0.9.0"', '"a":"1.0.0"');
    expect(advised.text).toContain("1.0.0");
  });
});

describe("8: option values", () => {
  it.each([
    ["cargo install ripgrep --bin rg", { ecosystem: "crates.io", package: "ripgrep", to: "latest" }],
    ["cargo install --bin rg ripgrep@14.1.1", { ecosystem: "crates.io", package: "ripgrep", to: "14.1.1" }],
    ["cargo install --example demo ripgrep@14.1.1", { ecosystem: "crates.io", package: "ripgrep", to: "14.1.1" }],
    ["pnpm add --trust-policy no-downgrade lodash@4.17.20", { ecosystem: "npm", package: "lodash", to: "4.17.20" }],
  ])("%s: the value is no operand", (command, item) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.items).toEqual([item]);
  });
});

describe("6 (follow-up): the tenth check's three ordinary holds release through the remedy they print", () => {
  it.each([
    ["bun update typescript@5.6.3", "Bash"],
    ["docker run --rm -v $PWD:/app -w /app node:22 pnpm install", "Bash"],
    ["if (Test-Path node_modules) { npm ci } else { npm install }", "PowerShell"],
  ])("%s", (command, tool) => {
    const r = run(command, tool);
    expect(r.decision).toBe("deny");
    const remedy = /plain command of its own: `([^`]+)`/.exec(r.text)?.[1];
    expect(remedy, r.text).toBeDefined();
    releases(remedy as string);
    expect(run(remedy as string).decision).toBe("allow");
  });
});
