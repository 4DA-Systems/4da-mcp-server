// SPDX-License-Identifier: Apache-2.0
/**
 * Round 8 (R8-1, R8-2, R8-3): an install command goes ahead only on positive evidence. A detector
 * over the raw text names every line with a package-manager word followed by one of its verbs;
 * such a line goes ahead only when each simple command holding a hit is read whole (program,
 * prefixes, every option in the manager's table with its arity, every operand a public name the
 * reader judges, a bare name judged at latest, or a form installing nothing new from the public
 * registry). A program that takes the words only as data goes ahead. Anything else is held as not
 * read, with one remedy, and the remedy releases it.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { detectsInstall } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { timedWithin } from "./helpers/a1125-hook-run.js";

const REMEDY = "Run it as a plain command of its own";
const AVOID_LATEST = [
  { ecosystem: "npm", package: "lodash", version: "9.9.9", requested: "latest", verdict: "avoid", reason: "test avoid" },
  { ecosystem: "PyPI", package: "requests", version: "9.9.9", requested: "latest", verdict: "avoid", reason: "test avoid" },
];

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger(AVOID_LATEST);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash", env: Record<string, string> = {}) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } }, env);

describe("R8-1: the detector", () => {
  it.each([
    "npm i lodash",
    "echo x; NPM.CMD Install lodash",
    "python -mpip install requests",
    "python -Im pip install requests",
    "pip3.12 install requests",
    "yarnpkg add lodash",
    "node pnpm.cjs add lodash",
    "uv lock --upgrade",
    "go mod edit -require=rsc.io/quote@v1.5.2",
    "npm pkg set dependencies.lodash=4.17.21",
    `echo ${"x ".repeat(100_000)} && cargo add serde`,
  ])("names %s", (command) => {
    expect(detectsInstall(command)).toBe(true);
  });

  it.each(["npm ci", "npm run build", "bunx tsc", "make install", "brew install node", "apt-get install -y python3-pip", "gem install bundler", "composer require x/y", "dotnet add package X", "npm\ninstall"])(
    "does not name %s",
    (command) => {
      expect(detectsInstall(command)).toBe(false);
    },
  );
});

describe("R8-2: a detected command not read whole is held as not read, with one remedy", () => {
  it.each([
    // spellings the reader did not read
    "python -mpip install requests",
    "pythonw -m pip install requests",
    "python -Im pip install requests",
    "uv run pip install requests",
    "poetry run pip install requests",
    "stdbuf -oL npm i lodash",
    "winpty npm i lodash",
    "cross-env A=1 npm i lodash",
    "flock /tmp/l npm i lodash",
    "find . -maxdepth 0 -exec npm i lodash ';'",
    "watch -n1 npm i lodash",
    "yarnpkg add lodash",
    // options that change what a name resolves to, and settings before the manager
    "npm i --tag next lodash",
    "npm i --before 2020-01-01 lodash",
    "npm_config_tag=next npm i lodash",
    "PIP_INDEX_URL=https://example.invalid/simple pip install requests",
    "UV_PRERELEASE=allow uv add requests",
    "bun add -c x.toml lodash",
    "bun update --latest lodash",
    "pip install --pre requests",
    "uv add --prerelease allow requests",
    "uv lock --upgrade",
    // operands not read as a version
    "npm i lodash@x",
    "pip install 'requests '",
    "go get rsc.io/quote/...",
    // a registry or index this hook cannot classify
    "npm i --registry registry lodash",
    // installs of tools this hook does not read, and managers it detects but does not read
    "cargo install ripgrep",
    "go install golang.org/x/tools/gopls@latest",
    "yarn global add typescript",
    "uv tool install ruff",
    "pipenv install requests",
    "pdm add requests",
    "rye add requests",
    "pixi add requests",
    "hatch add requests",
    // lines this hook cannot take apart
    "npm install $PKG",
    "npm i $(cat pkgs.txt)",
    "bash <<'EOF'\nnpm i lodash\nEOF",
    "cat <<EOF\n$(npm i lodash)\nEOF",
  ])("%s", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("could not be read");
    expect(r.text).toContain(REMEDY);
  });

  it.each(["npm i 'lodash@>=0'", "cargo add 'serde@>=0'", "go get rsc.io/quote@master"])("%s: a range or a tag the reader reads is held on its verdict, not as not read", (command) => {
    const r = run(command);
    expect(r.decision).toBe("deny");
    expect(r.text).not.toContain("could not be read");
  });

  it("PowerShell: a comma command is read in both readings; an install in it is held", () => {
    expect(run("npm i lodash,ms", "PowerShell").decision).toBe("deny");
    expect(run("Write-Output npm, install, lodash@4.17.20", "PowerShell").decision).toBe("allow");
    expect(run("pip install -r requirements.txt --only-binary=:all:,numpy", "PowerShell").decision).toBe("allow");
  });

  it("an over-size line with a hit is held; one past 2 MB is never read", () => {
    const r = run(`npm i lodash@4.17.21 # ${"x".repeat(2 * 1024 * 1024)}`);
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("could not be read");
  });
});

describe("R8-2: what is read whole goes ahead on its verdict, or installs nothing new", () => {
  it.each([
    "npm install",
    "npm ci",
    "pnpm install --frozen-lockfile",
    "yarn install --immutable",
    "bun install",
    "pip install -r requirements.txt",
    "pip install -Ur requirements.txt",
    "pip install -qr requirements-dev.txt",
    "pip install -e .",
    "pip install ./dist/x-1.0-py3-none-any.whl",
    "pip install git+https://github.com/a/b",
    "pip install -i https://pypi.internal.example/simple requests",
    "pip install --no-index --find-links ./wheels requests",
    "uv sync",
    "uv sync --frozen",
    "uv lock",
    "uv pip install -r requirements.txt",
    "poetry install --no-root",
    "poetry lock",
    "cargo build --release",
    "cargo add --path ../x",
    "cargo add x --git https://example.com/x",
    "cargo update",
    "cargo install --path .",
    "go mod tidy",
    "go get ./...",
    "go get -u ./...",
    "go install ./cmd/tool",
    "npm i ./local-pkg",
    "npm i --registry https://npm.internal.example x",
    "npm update lodash",
    "pnpm up react",
    "pnpm --filter web add ./packages/ui",
    "yarn workspace web add ../shared",
  ])("%s", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("allow");
  });

  it.each(["npm i lodash", "pip install requests", "pip install -U requests", "python -m pip install requests", "uv pip install requests", "uv add --dev requests", "npm i -D --save-exact lodash", "pnpm add -w lodash"])(
    "%s: read, and judged on the latest verdict (an avoid on record)",
    (command) => {
      const r = run(command);
      expect(r.decision).toBe("deny");
      expect(r.text).not.toContain("could not be read");
      expect(r.text).toContain("avoid");
    },
  );
});

describe("R8-3: data programs go ahead", () => {
  it.each([
    "docker run --rm node:20 npm install",
    "docker compose run web pip install -r requirements.txt",
    "podman run python:3.12 pip install requests",
    "make install",
    "brew install pnpm",
    "apt-get install -y python3-pip",
    "gem install bundler",
    "composer require monolog/monolog",
    "dotnet add package Newtonsoft.Json",
    "echo 'run npm install lodash first'",
    "printf 'pip install requests\\n'",
    "git commit -m 'npm install lodash in the docs'",
    "git log --grep 'pip install'",
    "grep -rn 'npm install' docs",
    "rg 'cargo add' README.md",
    "cat > INSTALL.md <<'EOF'\nRun npm install lodash, then pip install requests.\nEOF",
    "git commit -F - <<'EOF'\nDocs: pip install -e . first\nEOF",
    "# npm install lodash\nls",
    "gh pr create --title 'Docs' --body 'Run npm install first'",
    "gh issue comment 12 --body 'pip install fails on 3.13'",
    "Get-Content README.md | Select-String 'pip install'",
    "Write-Output 'npm install lodash'",
  ])("%s", (command) => {
    const tool = command.startsWith("Write-Output") || command.startsWith("Get-Content") ? "PowerShell" : "Bash";
    const r = run(command, tool);
    expect(r.decision, r.text).toBe("allow");
  });

  it("a heredoc fed to a shell is not data", () => {
    expect(run("sh <<'EOF'\npip install requests\nEOF").decision).toBe("deny");
  });

  it("a long git commit message that mentions installs is read and goes ahead", () => {
    const r = timedWithin(s.home, { hook_event_name: "PreToolUse", tool_name: "Bash", cwd: s.project, tool_input: { command: `git commit -m "${"We go on; then npm i x and a review. ".repeat(2000)}"` } }, 1500);
    expect(r.decision).toBe("allow");
  });
});

describe("the remedy releases", () => {
  it("python -mpip install requests: held as not read; run as the remedy says, it is judged and goes ahead on a proceed", () => {
    s.ledger([{ ecosystem: "PyPI", package: "requests", version: "2.32.3", requested: "latest", verdict: "proceed" }]);
    expect(run("python -mpip install requests").text).toContain(REMEDY);
    expect(run("pip install requests").decision).toBe("allow");
  });

  it("npm i --tag next lodash: held; npm i lodash@4.17.21 with a proceed goes ahead", () => {
    s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed" }]);
    expect(run("npm i --tag next lodash").text).toContain(REMEDY);
    expect(run("npm i lodash@4.17.21").decision).toBe("allow");
  });

  it("no remedy names a file as a package", () => {
    for (const c of ["pip install -Ur requirements.txt requests==9", "uv pip install -qr requirements.txt"]) expect(run(c).text).not.toMatch(/"requirements/);
  });
});
