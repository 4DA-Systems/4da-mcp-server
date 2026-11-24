// SPDX-License-Identifier: Apache-2.0
/**
 * A private answer lets a command through only when the command is a plain install, run in the
 * answer's project: an allowlist, not a denylist.
 *
 * Independent re-check of 0d30b40 (S1): the hook let a private answer for project A count unless
 * the command matched a list of folder-changing words, and every list leaks: `c''d ../B && npm i`,
 * `env --chdir ../B npm i`, `sudo -D ../B`, `wsl --cd ../B`, `npm --prefi ../B install` (npm takes
 * unique abbreviations), `npm_config_global=true npm i`, `GOFLAGS=-modfile=../B/go.mod go get`,
 * `PIP_TARGET=../B pip install`, `pip install --user`, `-t../B`, `uv pip install --system`,
 * `../B/.venv/bin/pip install`, `poetry -P ../B add`, PowerShell `cd..; npm i`, `D:; npm i` ...
 * all went ahead from A.
 *
 * Now a private answer covers a command only when: it is the only command on the line (no other
 * command, no redirection); the program is the package manager's bare name (not a path); there is
 * no environment assignment or prefix; and every option is on that tool's list of options that do
 * not choose where it installs (save flags, workspace names inside the project, features). Anything
 * else is held, and the denial gives the plain form. Edits keep the manifest-folder rule. The cwd
 * and the project are compared as real folders (a junction is followed) in Windows form.
 */

import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";

// Made when the tables are built (they name these folders).
const root = mkdtempSync(join(tmpdir(), "a651-plain-"));
const home = join(root, "home");
const A = join(root, "scopeA");
const B = join(root, "scopeB");
const NOW = Date.now();
beforeAll(() => {
  for (const d of [home, A, B, join(A, "packages", "x")]) mkdirSync(d, { recursive: true });
  const entries = [
    ["npm", "lodash", "4.17.20"],
    ["Go", "golang.org/x/net", "v0.17.0"],
    ["PyPI", "requests", "2.25.0"],
    ["crates.io", "serde", "1.0.100"],
  ].map(([ecosystem, pkg, version]) => JSON.stringify({ t: new Date(NOW - 60_000).toISOString(), ecosystem, package: pkg, version, verdict: "unknown", not_checked: "local_source", project: A }));
  writeFileSync(join(home, LEDGER_FILE), entries.join("\n") + "\n");
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

function decide(command: string, cwd: string = A, tool = "Bash"): string {
  const out = respond({ hook_event_name: "PreToolUse", tool_name: tool, cwd, tool_input: { command } }, { FOURDA_MCP_HOME: home }, NOW);
  return out === "" ? "allow" : (JSON.parse(out) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason;
}

describe("held: anything but a plain install (each let through by 0d30b40)", () => {
  it.each([
    "c''d ../scopeB && npm i lodash@4.17.20",
    '"c"d ../scopeB && npm i lodash@4.17.20',
    "builtin cd ../scopeB && npm i lodash@4.17.20",
    "env --chdir ../scopeB npm i lodash@4.17.20",
    "env --chdir=../scopeB npm i lodash@4.17.20",
    "env -C ../scopeB npm i lodash@4.17.20",
    "sudo -D ../scopeB npm i lodash@4.17.20",
    "sudo --chdir=../scopeB npm i lodash@4.17.20",
    "wsl --cd ../scopeB npm i lodash@4.17.20",
    "wsl --cd=../scopeB npm i lodash@4.17.20",
    "npm install lodash@4.17.20 --prefi=../scopeB",
    "npm install lodash@4.17.20 --pref ../scopeB",
    "npm_config_prefix=../scopeB npm i lodash@4.17.20",
    "NPM_CONFIG_PREFIX=../scopeB npm i lodash@4.17.20",
    "npm_config_global=true npm i lodash@4.17.20",
    "env npm_config_prefix=../scopeB npm i lodash@4.17.20",
    "npm i lodash@4.17.20 --location=global",
    "npm i lodash@4.17.20 -g",
    "npm i lodash@4.17.20 --global=true",
    "npm i lodash@4.17.20 --workspace=../scopeB",
    "pnpm -C ../scopeB add lodash@4.17.20",
    "pnpm add lodash@4.17.20 --global",
    "yarn --cwd ../scopeB add lodash@4.17.20",
    "bun add lodash@4.17.20 --cwd=../scopeB",
    "GOFLAGS=-modfile=../scopeB/go.mod go get golang.org/x/net@v0.17.0",
    "go -C ../scopeB get golang.org/x/net@v0.17.0",
    "go get -modfile ../scopeB/go.mod golang.org/x/net@v0.17.0",
    "go mod edit -require=golang.org/x/net@v0.17.0 ../scopeB/go.mod",
    "go mod edit -replace=golang.org/x/net=golang.org/x/net@v0.17.0 ../scopeB/go.mod",
    "PIP_TARGET=../scopeB pip install requests==2.25.0",
    "PIP_PREFIX=../scopeB pip install requests==2.25.0",
    "pip install --root ../scopeB requests==2.25.0",
    "pip install --user requests==2.25.0",
    "pip install --target=../scopeB requests==2.25.0",
    "pip install -t../scopeB requests==2.25.0",
    "pip install --targ ../scopeB requests==2.25.0",
    "pip install --prefix ../scopeB requests==2.25.0",
    "pip install --python ../scopeB/.venv/Scripts/python.exe requests==2.25.0",
    "uv pip install --python ../scopeB/.venv requests==2.25.0",
    "uv pip install -p ../scopeB/.venv requests==2.25.0",
    "uv pip install --system requests==2.25.0",
    "VIRTUAL_ENV=../scopeB/.venv uv pip install requests==2.25.0",
    "UV_PROJECT_ENVIRONMENT=../scopeB/.venv uv add requests==2.25.0",
    "../scopeB/.venv/Scripts/python -m pip install requests==2.25.0",
    "../scopeB/.venv/bin/pip install requests==2.25.0",
    "uv add --project=../scopeB requests==2.25.0",
    "uv --directory ../scopeB add requests==2.25.0",
    "poetry -P ../scopeB add requests==2.25.0",
    "poetry -C ../scopeB add requests==2.25.0",
    "cargo add serde@1.0.100 --manifest-path ../scopeB/Cargo.toml",
    "CARGO_TARGET_DIR=x cargo add serde@1.0.100",
    "(cd ../scopeB; npm i lodash@4.17.20)",
    "bash -c 'cd ../scopeB && npm i lodash@4.17.20'",
    "pushd ../scopeB && npm i lodash@4.17.20",
    "echo prefix=../scopeB > .npmrc && npm i lodash@4.17.20",
    "npm i lodash@4.17.20 > log.txt",
    "npm config set prefix ../scopeB && npm i lodash@4.17.20",
  ])("bash: %s", (command) => {
    expect(decide(command)).not.toBe("allow");
  });

  it.each([
    "cd ../scopeB; npm i lodash@4.17.20",
    "cd..; npm i lodash@4.17.20",
    "cd\\; npm i lodash@4.17.20",
    "D:; npm i lodash@4.17.20",
    "Microsoft.PowerShell.Management\\Set-Location ../scopeB; npm i lodash@4.17.20",
    "Set-Location ../scopeB; npm i lodash@4.17.20",
    "sl ../scopeB; npm i lodash@4.17.20",
    "Push-Location ../scopeB; npm i lodash@4.17.20",
    "chdir ../scopeB; npm i lodash@4.17.20",
    "npm --prefix ../scopeB i lodash@4.17.20",
  ])("PowerShell: %s", (command) => {
    expect(decide(command, A, "PowerShell")).not.toBe("allow");
  });

  it("the denial says what the private answer covers and gives the plain form", () => {
    const reason = decide("npm --prefix ../scopeB install lodash@4.17.20");
    expect(reason).toMatch(/covers a plain install run in/);
    expect(reason).toContain("npm install lodash@4.17.20");
  });
});

describe("allowed: a plain install in the project (or a folder inside it)", () => {
  it.each([
    ["npm i lodash@4.17.20", A],
    ["npm install --save-exact lodash@4.17.20", A],
    ["npm i -D lodash@4.17.20", A],
    ["npm add lodash@4.17.20 --save-dev --legacy-peer-deps", A],
    ["npm i lodash@4.17.20 -w packages/x", A],
    ["pnpm add -D lodash@4.17.20", A],
    ["pnpm --filter web add lodash@4.17.20", A],
    ["yarn add -E lodash@4.17.20", A],
    ["bun add -d lodash@4.17.20", A],
    ["pip install requests==2.25.0", A],
    ["pip3 install -U requests==2.25.0", A],
    ["python -m pip install requests==2.25.0", A],
    ["uv add requests==2.25.0", A],
    ["uv pip install requests==2.25.0", A],
    ["poetry add --group dev requests==2.25.0", A],
    ["cargo add serde@1.0.100 --features derive", A],
    ["go get golang.org/x/net@v0.17.0", A],
    ["npm i lodash@4.17.20", join(A, "packages", "x")],
  ])("%s", (command, cwd) => {
    expect(decide(command, cwd)).toBe("allow");
  });

  it("PowerShell: npm i lodash@4.17.20", () => {
    expect(decide("npm i lodash@4.17.20", A, "PowerShell")).toBe("allow");
  });
});

describe("the folders compared", () => {
  it.runIf(process.platform === "win32")("Git Bash, WSL, long-path and admin-share forms of A's folder are A", () => {
    const m = /^([A-Za-z]):\\(.*)$/.exec(A)!;
    const rest = m[2].replace(/\\/g, "/");
    for (const cwd of [`/${m[1].toLowerCase()}/${rest}`, `/mnt/${m[1].toLowerCase()}/${rest}`, `\\\\?\\${A}`, `\\\\localhost\\${m[1]}$\\${m[2]}`]) {
      expect(decide("npm i lodash@4.17.20", cwd), cwd).toBe("allow");
    }
  });

  it.runIf(process.platform === "win32")("a junction is followed: one inside A to B is B, one outside A to A is A", () => {
    const inside = join(A, "junction-to-B");
    const outside = join(root, "junction-to-A");
    symlinkSync(B, inside, "junction");
    symlinkSync(A, outside, "junction");
    expect(decide("npm i lodash@4.17.20", inside)).not.toBe("allow");
    expect(decide("npm i lodash@4.17.20", outside)).toBe("allow");
  });
});

describe("held under the allowlist, and said so (the re-checker's false holds)", () => {
  it.each(["npm test -- -t smoke && npm i lodash@4.17.20", 'git commit -m "cd into app" && npm i lodash@4.17.20', "npm i lodash@4.17.20 && rg -g '*.ts' lodash", "cargo add serde@1.0.100 --target x86_64-pc-windows-msvc", "git -C . status && npm i lodash@4.17.20", "echo cd && npm i lodash@4.17.20", "docker ps -a && npm i lodash@4.17.20"])(
    "%s",
    (command) => {
      expect(decide(command)).toMatch(/covers a plain install run in/);
    },
  );
});
