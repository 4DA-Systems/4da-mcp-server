// SPDX-License-Identifier: Apache-2.0
/**
 * Round 20, from the eighteenth independent check: the ledger is matched on the reading the server
 * judged (Q1, generated per ecosystem), a `latest` verdict is honoured for 1 hour (Q2), a private
 * record applies in its own project only unless the user listed the name (Q3, with the built-in
 * public mirrors), a UNC or hosted file: location follows the host rule (Q4), and Cargo's build
 * aliases get the advice line (Q5).
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { PrivatePackageRules } from "../live/private-packages.js";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const run = (command: string, cwd = s.project, tool = "Bash") => s.run({ session_id: "s", cwd, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });
const at = (minutesAgo: number) => new Date(Date.now() - minutesAgo * 60_000).toISOString();
/** Ledger lines with their own times (s.ledger stamps them now). */
function lines(entries: Array<Record<string, string>>): void {
  writeFileSync(join(s.home, "check-ledger.jsonl"), entries.map((e) => JSON.stringify({ t: at(1), ...e })).join("\n") + "\n");
}

describe("Q1: a verdict for one reading never releases another", () => {
  // What dependency_check records: an exact `to` as the release (no `requested`); a constraint, and
  // a crates.io bare version (the caret range), with `requested` set to it.
  const EXACT = (eco: string, pkg: string, v: string, verdict: string) => ({ ecosystem: eco, package: pkg, version: v, verdict, reason: "r" });
  const RANGE = (eco: string, pkg: string, req: string, pick: string, verdict: string) => ({ ecosystem: eco, package: pkg, version: pick, requested: req, verdict, reason: "r" });
  const CARGO = (spec: string) => `[package]\nname = "a"\nversion = "0.1.0"\n[dependencies]\nclap = ${spec}\n`;

  it("crates.io: an exact proceed does not release a bare 1.2.3 (^1.2.3), in a command or a manifest", () => {
    lines([EXACT("crates.io", "clap", "4.6.9", "proceed")]);
    expect(run("cargo add clap@4.6.9").decision).toBe("deny");
    expect(run("cargo add clap@4.6.9 -F derive").decision).toBe("deny");
    expect(s.write(`${s.project}/Cargo.toml`, CARGO('"4.6.9"')).decision).toBe("deny");
    expect(s.write(`${s.project}/Cargo.toml`, CARGO('{ version = "4.6.9" }')).decision).toBe("deny");
    // The exact reading is released by it.
    expect(run("cargo add clap@=4.6.9").decision).toBe("allow");
    expect(s.write(`${s.project}/Cargo.toml`, CARGO('"=4.6.9"')).decision).toBe("allow");
  });
  it("crates.io: a caret wait holds the bare form; a later exact proceed does not release it", () => {
    lines([RANGE("crates.io", "clap", "4.6.9", "4.6.9", "wait"), EXACT("crates.io", "clap", "4.6.9", "proceed")]);
    expect(run("cargo add clap@4.6.9").decision).toBe("deny");
    expect(s.write(`${s.project}/Cargo.toml`, CARGO('"4.6.9"')).decision).toBe("deny");
    expect(run("cargo add clap@=4.6.9").decision).toBe("allow");
  });
  it("crates.io: the caret proceed releases the bare form, not the exact one", () => {
    lines([RANGE("crates.io", "clap", "4.6.9", "4.6.10", "proceed")]);
    expect(run("cargo add clap@4.6.9").decision).toBe("allow");
    expect(run("cargo add clap@=4.6.9").decision).toBe("deny");
  });
  it("crates.io: an exact avoid holds the bare form too (a Cargo.lock that holds it keeps it)", () => {
    lines([RANGE("crates.io", "clap", "4.6.9", "4.6.10", "proceed"), EXACT("crates.io", "clap", "4.6.9", "avoid")]);
    expect(run("cargo add clap@4.6.9").decision).toBe("deny");
  });
  it("the newest line for the same reading decides: a wait after a proceed holds", () => {
    lines([RANGE("crates.io", "clap", "4.6.9", "4.6.9", "proceed"), RANGE("crates.io", "clap", "4.6.9", "4.6.10", "wait")]);
    expect(run("cargo add clap@4.6.9").decision).toBe("deny");
  });
  it("cargo install x@1.2.3 is the exact release (cargo help install): released by the exact verdict", () => {
    lines([EXACT("crates.io", "ripgrep", "14.1.1", "proceed")]);
    expect(run("cargo install ripgrep@14.1.1").decision).toBe("allow");
    expect(run("cargo install ripgrep --version 14.1.1").decision).toBe("allow");
  });

  // Generated: for each ecosystem, readings A and B; a verdict for A releases B only when both name the same single release.
  const CASES: Array<{ eco: string; pkg: string; a: Record<string, string>; command: string; releases: boolean }> = [
    { eco: "npm", pkg: "ms", a: EXACT("npm", "ms", "2.1.3", "proceed"), command: "npm install ms@2.1.3", releases: true },
    { eco: "npm", pkg: "ms", a: EXACT("npm", "ms", "2.1.3", "proceed"), command: "npm install ms@2.1", releases: false },
    { eco: "npm", pkg: "ms", a: EXACT("npm", "ms", "2.1.3", "proceed"), command: "npm install ms@2", releases: false },
    { eco: "npm", pkg: "ms", a: RANGE("npm", "ms", "2.1", "2.1.3", "proceed"), command: "npm install ms@2.1.3", releases: false },
    { eco: "npm", pkg: "ms", a: RANGE("npm", "ms", "2.1", "2.1.3", "proceed"), command: "pnpm add ms@2.1", releases: true },
    { eco: "npm", pkg: "ms", a: RANGE("npm", "ms", "2", "2.1.3", "proceed"), command: "yarn add ms@2.1", releases: false },
    { eco: "npm", pkg: "ms", a: RANGE("npm", "ms", "^2.1.0", "2.1.3", "proceed"), command: "npm install ms@^2.1.0", releases: true },
    { eco: "PyPI", pkg: "six", a: EXACT("PyPI", "six", "1.17.0", "proceed"), command: "pip install six==1.17.0", releases: true },
    { eco: "PyPI", pkg: "six", a: EXACT("PyPI", "six", "1.17.0", "proceed"), command: "pip install six==1.17", releases: true },
    { eco: "PyPI", pkg: "six", a: EXACT("PyPI", "six", "1.17.0", "proceed"), command: "pip install 'six~=1.17'", releases: false },
    { eco: "PyPI", pkg: "six", a: RANGE("PyPI", "six", "~=1.17", "1.17.0", "proceed"), command: "pip install six==1.17.0", releases: false },
    { eco: "PyPI", pkg: "six", a: RANGE("PyPI", "six", "~=1.17", "1.17.0", "proceed"), command: "pip install 'six~=1.17'", releases: true },
    { eco: "Go", pkg: "golang.org/x/text", a: EXACT("Go", "golang.org/x/text", "v0.21.0", "proceed"), command: "go get golang.org/x/text@v0.21.0", releases: true },
    { eco: "crates.io", pkg: "regex", a: EXACT("crates.io", "regex", "1.11.0", "proceed"), command: "cargo add regex@1.11.0", releases: false },
    { eco: "crates.io", pkg: "regex", a: EXACT("crates.io", "regex", "1.11.0", "proceed"), command: "cargo add regex@=1.11.0", releases: true },
    { eco: "crates.io", pkg: "regex", a: RANGE("crates.io", "regex", "1.11.0", "1.11.1", "proceed"), command: "cargo add regex@1.11.0", releases: true },
    { eco: "crates.io", pkg: "regex", a: RANGE("crates.io", "regex", "1.11.0", "1.11.1", "proceed"), command: "cargo add regex@=1.11.0", releases: false },
    { eco: "crates.io", pkg: "regex", a: RANGE("crates.io", "regex", "^1.11", "1.11.1", "proceed"), command: "cargo add regex@1.11.0", releases: false },
  ];
  it.each(CASES)("$command with $a.version/$a.requested -> releases: $releases", ({ a, command, releases }) => {
    lines([a]);
    expect(run(command).decision).toBe(releases ? "allow" : "deny");
  });
});

describe("Q2: a verdict for latest is honoured for 1 hour", () => {
  const LATEST = (minutes: number) => ({ t: at(minutes), ecosystem: "npm", package: "ms", version: "2.1.3", requested: "latest", verdict: "proceed", reason: "ok" });
  const write = (e: Record<string, string>) => writeFileSync(join(s.home, "check-ledger.jsonl"), JSON.stringify(e) + "\n");
  it("59 minutes old: a name alone goes ahead", () => {
    write(LATEST(59));
    expect(run("npm install ms").decision).toBe("allow");
  });
  it("61 minutes old: held, and the denial says so", () => {
    write(LATEST(61));
    const r = run("npm install ms");
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("the verdict for latest is older than 1 hour");
  });
  it("an unbounded spec is latest too: held at 61 minutes", () => {
    write(LATEST(61));
    expect(s.write(`${s.project}/package.json`, JSON.stringify({ dependencies: { ms: "*" } })).decision).toBe("deny");
  });
  it("an exact version and a bounded range keep 24 hours", () => {
    writeFileSync(
      join(s.home, "check-ledger.jsonl"),
      [
        { t: at(23 * 60), ecosystem: "npm", package: "ms", version: "2.1.3", verdict: "proceed" },
        { t: at(23 * 60), ecosystem: "npm", package: "ms", version: "2.1.3", requested: "^2.1.0", verdict: "proceed" },
      ]
        .map((e) => JSON.stringify(e))
        .join("\n") + "\n",
    );
    expect(run("npm install ms@2.1.3").decision).toBe("allow");
    expect(run("npm install ms@^2.1.0").decision).toBe("allow");
  });
});

describe("Q3: a private record applies in its own project; a listed name everywhere", () => {
  const priv = (extra: Record<string, string>) => ({ ecosystem: "PyPI", package: "requests", version: "latest", verdict: "unknown", reason: "NOT CHECKED (private)", not_checked: "private", ...extra });
  it("a record made in project A does not release in project B", () => {
    const b = mkdtempSync(join(tmpdir(), "a1125-q3-b-"));
    try {
      lines([priv({ private_rule: "project", project_root: s.project })]);
      expect(run("pip install requests==2.19.0").decision).toBe("allow");
      s.file("sub/.keep", "");
      expect(run("pip install requests==2.19.0", join(s.project, "sub")).decision).toBe("allow");
      expect(run("pip install requests==2.25.0", b).decision).toBe("deny");
      expect(s.run({ session_id: "s", cwd: b, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: join(b, "requirements.txt"), content: "requests==2.19.0\n" } }).decision).toBe("deny");
    } finally {
      rmSync(b, { recursive: true, force: true });
    }
  });
  it("a listed name (FOURDA_PRIVATE_PACKAGES) applies in every project", () => {
    const b = mkdtempSync(join(tmpdir(), "a1125-q3-b-"));
    try {
      lines([priv({ private_rule: "listed" })]);
      expect(run("pip install requests==2.19.0", b).decision).toBe("allow");
    } finally {
      rmSync(b, { recursive: true, force: true });
    }
  });
  it("an older line with no scope applies nowhere; an avoid for the version still holds a scoped one", () => {
    lines([priv({})]);
    expect(run("pip install requests==2.19.0").decision).toBe("deny");
    lines([priv({ private_rule: "project", project_root: s.project }), { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" }]);
    expect(run("pip install requests==2.19.0").decision).toBe("deny");
  });

  describe("the built-in public mirrors make a default index public (server)", () => {
    let dir: string;
    let env: NodeJS.ProcessEnv;
    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "a1125-q3-mirror-"));
      env = { HOME: dir, USERPROFILE: dir, CARGO_HOME: join(dir, ".cargo"), GOENV: "off", PIP_CONFIG_FILE: join(dir, "none.conf") };
    });
    afterEach(() => rmSync(dir, { recursive: true, force: true }));
    it.each(["https://pypi.tuna.tsinghua.edu.cn/simple", "https://mirrors.aliyun.com/pypi/simple/", "https://mirrors.cloud.tencent.com/pypi/simple", "https://repo.huaweicloud.com/repository/pypi/simple", "https://pypi.mirrors.ustc.edu.cn/simple"])(
      "pyproject [[tool.uv.index]] default = true on %s: PyPI is not private",
      (url) => {
        writeFileSync(join(dir, "pyproject.toml"), `[project]\nname = "p"\nversion = "0.1.0"\ndependencies = ["requests==2.19.0"]\n\n[[tool.uv.index]]\nname = "m"\nurl = "${url}"\ndefault = true\n`);
        const rules = new PrivatePackageRules([dir], env);
        expect(rules.registryConfigured("PyPI", dir)).toBe(false);
      },
    );
    it("an index the server does not know stays private", () => {
      writeFileSync(join(dir, "pyproject.toml"), `[project]\nname = "p"\nversion = "0.1.0"\n\n[[tool.uv.index]]\nname = "m"\nurl = "https://pypi.acme.example.org/simple"\ndefault = true\n`);
      expect(new PrivatePackageRules([dir], env).registryConfigured("PyPI", dir)).toBe(true);
    });
    it.each(["sparse+https://mirrors.ustc.edu.cn/crates.io-index/", "sparse+https://rsproxy.cn/index/", "https://mirrors.tuna.tsinghua.edu.cn/git/crates.io-index.git"])("Cargo replace-with %s: crates.io is not private", (url) => {
      mkdirSync(join(dir, ".cargo"), { recursive: true });
      writeFileSync(join(dir, ".cargo", "config.toml"), `[source.crates-io]\nreplace-with = "m"\n\n[source.m]\nregistry = "${url}"\n`);
      writeFileSync(join(dir, "Cargo.toml"), '[package]\nname = "p"\nversion = "0.1.0"\n');
      expect(new PrivatePackageRules([dir], env).registryConfigured("crates.io", dir)).toBe(false);
    });
    it.each(["https://goproxy.cn", "https://goproxy.io,direct", "https://mirrors.aliyun.com/goproxy/"])("GOPROXY=%s: Go is not private", (proxy) => {
      expect(new PrivatePackageRules([dir], { ...env, GOPROXY: proxy }).registryConfigured("Go", dir)).toBe(false);
    });
  });
});

describe("Q4: a UNC path or a hosted file: URL follows the host rule", () => {
  beforeEach(() => s.ledger([{ ecosystem: "PyPI", package: "six", version: "1.17.0", verdict: "proceed" }]));
  it.each(["//evil.com/share", "\\\\evil.com\\share", "file://evil.com/share"])("--no-index --find-links=%s: held", (loc) => {
    expect(run(`pip install six==1.16.0 --no-index --find-links=${loc}`, s.project, loc.startsWith("\\") ? "PowerShell" : "Bash").decision).toBe("deny");
  });
  it.each(["//fileserver/share", "\\\\nas.corp\\wheels", "file://localhost/C:/wheels", "file:///C:/wheels", "./wheels"])("--no-index --find-links=%s: local, goes ahead", (loc) => {
    expect(run(`pip install six==1.16.0 --no-index --find-links=${loc}`, s.project, loc.startsWith("\\") ? "PowerShell" : "Bash").decision).toBe("allow");
  });
});

describe("Q5: Cargo's build aliases get the advice line", () => {
  beforeEach(() => s.ledger([]));
  const post = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command }, tool_response: {} });
  it.each(["cargo b", "cargo build", "cargo r", "cargo run", "cargo t", "cargo test", "cargo fetch"])("%s: advised", (command) => {
    expect(post(command).text).toContain("Run vulnerability_scan");
  });
  it.each(["cargo fmt", "cargo check", "cargo c", "cargo clippy --version", "cargo --version"])("%s: none", (command) => {
    expect(post(command).text).toBe("");
  });
});
