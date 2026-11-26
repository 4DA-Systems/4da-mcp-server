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
import { answerDenial, timedWithin } from "./helpers/a1125-hook-run.js";

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
    // bash runs a backquote or $( ) inside double quotes: those are command words
    'git commit -m "docs: `npm install x` step"',
    'echo "$(pip install requests)"',
    "2>/dev/null pip install requests",
    "sudo -E npm i lodash",
    "bash -c 'npm i lodash'",
    "pipenv run pip install requests",
  ])("names %s", (command) => {
    expect(detectsInstall(command)).toBe(true);
  });

  it.each(["npm ci", "npm run build", "bunx tsc", "make install", "brew install node", "apt-get install -y python3-pip", "gem install bundler", "composer require x/y", "dotnet add package X", "npm\ninstall", "pipenv install requests", "pdm install"])(
    "does not name %s",
    (command) => {
      expect(detectsInstall(command)).toBe(false);
    },
  );
});

/**
 * Each command held as not read, beside the command its remedy tells the user to run
 * (`<manager> <verb> <name>@<exact version>`, or the name alone, no other options). NO HOLD WITHOUT
 * A WAY THROUGH: the remedy is run, the dependency_check call its denial names (if any) is answered
 * proceed, and it goes ahead.
 */
const NOT_READ: [string, string][] = [
  // spellings the reader does not read
  ["python -mpip install requests", "pip install requests"],
  ["pythonw -m pip install requests", "pip install requests"],
  ["python -Im pip install requests", "pip install requests"],
  ["stdbuf -oL npm i lodash", "npm i lodash"],
  ["winpty npm i lodash", "npm i lodash"],
  ["cross-env A=1 npm i lodash", "npm i lodash"],
  ["flock /tmp/l npm i lodash", "npm i lodash"],
  ["find . -maxdepth 0 -exec npm i lodash ';'", "npm i lodash"],
  ["watch -n1 npm i lodash", "npm i lodash"],
  ["yarnpkg add lodash", "yarn add lodash"],
  // options that change what a name resolves to, and settings before the manager
  ["npm i --tag next lodash", "npm i lodash@4.17.21"],
  ["npm i --before 2020-01-01 lodash", "npm i lodash@4.17.21"],
  ["npm_config_tag=next npm i lodash", "npm i lodash"],
  ["PIP_INDEX_URL=https://example.invalid/simple pip install requests", "pip install requests"],
  ["UV_PRERELEASE=allow uv add requests", "uv add requests"],
  ["bun add -c x.toml lodash", "bun add lodash"],
  ["bun update --latest lodash", "bun add lodash@4.17.21"],
  ["pip install --pre requests", "pip install requests==2.32.3"],
  ["uv add --prerelease allow requests", "uv add requests==2.32.3"],
  ["uv lock --upgrade", "uv lock --upgrade-package requests==2.32.3"],
  ["npm install --frozen-lockfile", "npm install"],
  // operands not read as a version
  ["npm i lodash@x", "npm i lodash"],
  ["pip install 'requests '", "pip install requests"],
  ["go get rsc.io/quote/...", "go get rsc.io/quote"],
  // a registry this hook cannot classify
  ["npm i --registry registry lodash", "npm i lodash"],
  // lines this hook cannot take apart
  ["npm install $PKG", "npm install lodash"],
  ["npm i $(cat pkgs.txt)", "npm i lodash"],
  ["bash <<'EOF'\nnpm i lodash\nEOF", "npm i lodash"],
  ["cat <<EOF\n$(npm i lodash)\nEOF", "npm i lodash"],
];

/** Runs `command`; when held for a verdict, answers the call its denial names (proceed) and runs it again. */
function releases(command: string): void {
  const first = run(command);
  if (first.decision === "deny") {
    expect(first.text, command).not.toContain("could not be read");
    answerDenial(s, first, "proceed");
    const second = run(command);
    expect(second.decision, second.text).toBe("allow");
  }
}

describe("R8-2: a detected command not read whole is held as not read, with one remedy, and the remedy releases it", () => {
  it.each(NOT_READ)("%s  ->  %s", (command, remedy) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("could not be read");
    expect(r.text).toContain(REMEDY);
    s.ledger([]);
    releases(remedy);
  });
});

describe("a tool installed from the registry is the same question as an add: held on its verdict, released by the call the denial names", () => {
  it.each([
    "cargo install ripgrep",
    "cargo install ripgrep@14.1.1",
    "cargo install ripgrep --version 14.1.1",
    "go install golang.org/x/tools/gopls@latest",
    "go install golang.org/x/tools/gopls@v0.16.2",
    "yarn global add typescript",
    "yarn global add typescript@5.6.3",
    "uv tool install ruff",
    "uv tool install ruff==0.5.0 --with black",
    "uv run pip install requests",
    "poetry run pip install requests",
    "pipenv run pip install requests",
  ])("%s", (command) => {
    s.ledger([]);
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.items, r.text).not.toBeNull();
    releases(command);
  });

  it.each(["cargo install --path .", "cargo install --git https://example.invalid/x.git x", "go install ./cmd/tool", "uv tool install --index-url https://pypi.corp.example/simple ruff"])("goes ahead (no public release named): %s", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});

describe("pipenv, pdm, rye, pixi, hatch and conda installs are not read (a stated limit): they go ahead", () => {
  it.each(["pipenv install requests", "pipenv install", "pdm add requests", "pdm install", "rye add requests", "rye sync", "pixi add requests", "pixi install", "hatch env create", "conda install requests", "pipx inject v requests"])("%s", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});

describe("D5: a manager word in the arguments of a program known to take text as data goes ahead", () => {
  it.each([
    "make PIP=pip3 install",
    "sed 's/npm install/npm ci/' README.md",
    "awk '/pip install/ {print}' docs/setup.md",
    "node -e \"console.log('npm install')\"",
    "python -c \"print('pip install requests')\"",
    "git commit -m 'docs: `npm install x`'",
  ])("%s", (command) => {
    expect(detectsInstall(command)).toBe(true);
    expect(run(command).decision).toBe("allow");
  });

  it("a line this hook cannot take apart is held, with a way through: single quotes", () => {
    expect(run('echo "$HOME: npm install"').decision).toBe("deny");
    expect(run("echo '$HOME: npm install'").decision).toBe("allow");
  });
});

/** D5: unknown wrappers are held (not added one by one): each has the remedy's way through. */
describe("D5: a hit inside a program this hook does not know is held", () => {
  it.each(["start npm -ArgumentList 'i','lodash@4.17.20'", "mise exec -- npm i lodash@4.17.20", "gsudo npm i lodash@4.17.20", "concurrently 'npm i lodash@4.17.20'", "git submodule foreach 'npm i lodash@4.17.20'", "n\\pm i lodash@4.17.20", "np''m i lodash@4.17.20"])("%s", (command) => {
    const r = run(command, command.startsWith("start ") ? "PowerShell" : "Bash");
    expect(r.decision, r.text).toBe("deny");
    s.ledger([]);
    releases("npm i lodash@4.17.20");
  });
});

describe("R8-2: misc", () => {
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

  it("a line of 2 MB with hundreds of thousands of words is read, not ended by an error of the hook's own", () => {
    const command = `pip install ${"-r req.txt ".repeat(190_000)}`;
    const r = timedWithin(s.home, { hook_event_name: "PreToolUse", tool_name: "Bash", cwd: s.project, tool_input: { command } }, 3000);
    expect(r.decision, r.text).toBe("allow");
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

/** D4: a manager subcommand that runs another command is read as that command, then released by the call its denial names. */
describe("D4: what a runner subcommand runs is read", () => {
  it.each([
    "bun run npm i lodash@4.17.20",
    "bun x npm@10 i lodash@4.17.20",
    "pnpm npm i lodash@4.17.20",
    "yarn npm i lodash@4.17.20",
    "yarn run npm i lodash@4.17.20",
    "yarn exec npm i lodash@4.17.20",
    "pnpm exec npm i lodash@4.17.20",
    "npm exec -- npm i lodash@4.17.20",
    "npx -y npm@10.9.2 install lodash@4.17.20",
    "uv tool run uv add requests==2.5.0",
    "uvx uv add requests==2.5.0",
    "python -m uv add requests==2.5.0",
    "python -m poetry add requests==2.5.0",
    "python -X utf8 -m pip install requests==2.5.0",
    "hatch env run -e test -- pip install requests==2.5.0",
    "pdm run pip install requests==2.5.0",
  ])("%s: held, and the call its denial names releases it", (command) => {
    s.ledger([]);
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    releases(command);
  });

  it("python -m <a module this hook does not read> with an install in its words is held", () => {
    expect(run("python -m pipx run uv add requests==2.5.0").text).toContain("could not be read");
  });
});

/** D6: a manager's own setting made earlier in the same call holds the install; any other setting does not. */
describe("D6: a setting made earlier in the call", () => {
  it.each([
    ["export npm_config_before=2020-01-01; npm i lodash", "Bash"],
    ["export npm_config_tag=beta && npm i lodash", "Bash"],
    ["declare -x npm_config_tag=beta; npm i lodash", "Bash"],
    ["npm_config_tag=beta; export npm_config_tag; npm i lodash", "Bash"],
    ["set -a; npm_config_tag=beta; npm i lodash", "Bash"],
    ["export PIP_PRE=1; pip install requests", "Bash"],
    ["export UV_PRERELEASE=allow; uv add requests", "Bash"],
    ["$env:npm_config_tag = 'beta'; npm i lodash", "PowerShell"],
    ["$env:PIP_PRE=1; pip install requests", "PowerShell"],
    ["Set-Item env:npm_config_tag beta; npm i lodash", "PowerShell"],
    ["Set-Item -Path env:UV_PRERELEASE -Value allow; uv add requests", "PowerShell"],
  ])("%s: held as not read; the plain install releases", (command, tool) => {
    const r = run(command, tool);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("made earlier in this call");
    s.ledger([]);
    releases(command.includes("pip") ? "pip install requests" : command.includes("uv add") ? "uv add requests" : "npm i lodash");
  });

  it.each([
    ['$env:CI = "true"; pnpm install --frozen-lockfile', "PowerShell"],
    ["$env:NODE_ENV='production'; npm ci", "PowerShell"],
    ["export CI=true; npm ci", "Bash"],
    ["export NODE_OPTIONS=--max-old-space-size=4096 && npm install", "Bash"],
  ])("%s: another namespace's setting goes ahead", (command, tool) => {
    expect(run(command, tool).decision).toBe("allow");
  });
});

/** D2: a manager at a quoted path with a space, or a manager script node runs, is that manager. */
describe("D2: quoted manager paths and node <manager script>", () => {
  it.each([
    ['"C:/Program Files/nodejs/npm.cmd" install lodash@4.17.20', "Bash"],
    ['& "C:/Program Files/nodejs/npm.cmd" install lodash@4.17.20', "PowerShell"],
    ['node "C:/Program Files/nodejs/node_modules/npm/bin/npm-cli.js" install lodash@4.17.20', "Bash"],
    ['node "C:/Program Files/nodejs/node_modules/npm/bin/npm-cli.js" install lodash@4.17.20', "PowerShell"],
    ["node --max-old-space-size 4096 ./node_modules/pnpm/bin/pnpm.cjs add lodash@4.17.20", "Bash"],
    ["node .yarn/releases/yarn.js add lodash@4.17.20", "Bash"],
  ])("%s (%s): read as the manager, held, released by the call its denial names", (command, tool) => {
    s.ledger([]);
    const r = run(command, tool);
    expect(r.decision, r.text).toBe("deny");
    expect(r.items, r.text).not.toBeNull();
    answerDenial(s, r, "proceed");
    expect(run(command, tool).decision).toBe("allow");
  });

  it("an option the account does not take, after a quoted manager path, is held as not read", () => {
    expect(run('"C:/Program Files/nodejs/npm.cmd" install --@types:registry=https://registry.npmjs.org lodash@4.17.20').text).toContain("could not be read");
  });
});

/** D3: a manager named with its version after a runner is that manager, for the detector as for the reader. */
describe("D3: a runner's manager@version", () => {
  it.each(["npx -y npm@10.9.2 install lodash@4.17.20", "pnpm dlx yarn@1 add lodash@4.17.20", "bunx pnpm@9 add lodash@4.17.20", "corepack pnpm@9.15.0 add lodash@4.17.20"])("%s", (command) => {
    expect(detectsInstall(command)).toBe(true);
    s.ledger([]);
    expect(run(command).decision).toBe("deny");
    releases(command);
  });

  it("with an option the account does not take: held as not read", () => {
    expect(run("npx -y npm@10.9.2 install --@types:registry=https://registry.npmjs.org lodash@4.17.20").text).toContain("could not be read");
  });
});

/** D7: a URL on a public registry host is the public registry: read as name and version, or held. */
describe("D7: a public-registry URL operand", () => {
  it.each([
    ["npm i https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz", { ecosystem: "npm", package: "lodash", to: "4.17.20" }],
    ["npm i https://registry.npmjs.org/@types/node/-/node-20.11.0.tgz", { ecosystem: "npm", package: "@types/node", to: "20.11.0" }],
    ["pip install https://files.pythonhosted.org/packages/aa/bb/requests-2.5.0-py2.py3-none-any.whl", { ecosystem: "PyPI", package: "requests", to: "2.5.0" }],
    ["pip install https://files.pythonhosted.org/packages/aa/bb/requests-2.5.0.tar.gz", { ecosystem: "PyPI", package: "requests", to: "2.5.0" }],
  ])("%s: read, held on its verdict, released by the call", (command, item) => {
    s.ledger([]);
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.items).toEqual([item]);
    answerDenial(s, r, "proceed");
    expect(run(command).decision).toBe("allow");
  });

  it.each(["npm i https://registry.npmjs.org/lodash", "pip install https://pypi.org/simple/requests/", "pip install 'requests @ https://files.pythonhosted.org/x/y'"])("%s: another form on a public host is held as not read", (command) => {
    expect(run(command).text).toContain("could not be read");
  });

  it("a URL on another host is still a source of its own", () => {
    expect(run("npm i https://npm.corp.example/lodash-4.17.20.tgz").decision).toBe("allow");
  });
});

/** D8: a path with extras is a path. */
describe("D8: pip install .[dev]", () => {
  it.each(["pip install .[dev]", 'pip install ".[dev,test]"', "pip install -e .[dev]", "pip install ./pkg[test]", "uv pip install -e '.[dev]'", "python -m pip install '.[all]'"])("%s goes ahead", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});

/** J1-J3 (eighth independent check): a data program's text is text only when its options are known and its output runs nowhere. */
describe("J1: data program options and pipelines", () => {
  it.each([
    ['echo "npm i lodash@4.17.20" | sh', "Bash"],
    ['echo "npm i lodash@4.17.20" | bash -s', "Bash"],
    ['echo "npm i lodash@4.17.20" | pwsh -NoProfile -', "PowerShell"],
    ['echo "npm i lodash@4.17.20" | cmd', "PowerShell"],
    ["printf 'npm i lodash@4.17.20\n' | python", "Bash"],
    ["git grep -O'npm i lodash@4.17.20 #' a", "Bash"],
    ["git -c core.pager='npm i lodash@4.17.20' log", "Bash"],
    ["sed -i 's/x/npm i lodash@4.17.20/' notes.md", "Bash"],
    ["sed 's/x/npm i lodash@4.17.20/e' notes.md", "Bash"],
    ["awk 'BEGIN { system(\"npm i lodash@4.17.20\") }'", "Bash"],
    ["make -f - <<'EOF'\nall:\n\tnpm i lodash@4.17.20\nEOF", "Bash"],
    ["echo 'npm i lodash@4.17.20' > package.json", "Bash"],
  ])("%s: held; the plain command the remedy names releases", (command, tool) => {
    expect(run(command, tool).decision).toBe("deny");
    s.ledger([]);
    releases("npm i lodash@4.17.20");
  });

  it.each([
    ["grep -rn 'npm install' docs | head -5", "Bash"],
    ["git log --oneline --grep 'npm install' | wc -l", "Bash"],
    ["rg 'pip install' -g '*.md' | sort | uniq -c", "Bash"],
    ["echo 'npm install lodash' | tee notes.txt", "Bash"],
    ["Get-Content README.md | Select-String 'pip install' | Select-Object -First 3", "PowerShell"],
    ["echo 'run npm install' > notes.txt", "Bash"],
  ])("%s: goes ahead", (command, tool) => {
    expect(run(command, tool).decision).toBe("allow");
  });
});

describe("J2: operands from somewhere the hook cannot read", () => {
  it.each(["echo lodash@4.17.20 | xargs npm i", "echo requests==2.5.0 | xargs pip install", "cat pkgs.txt | pip install -r -", "pip install -r /dev/stdin", "npm i $(cat pkgs.txt)"])("%s: held as not read; the plain command releases", (command) => {
    expect(run(command).text).toContain("could not be read");
    s.ledger([]);
    releases(command.includes("pip") ? "pip install requests==2.5.0" : "npm i lodash@4.17.20");
  });
});

describe("J3: a PowerShell backtick continuation is one line", () => {
  it("npm `<newline> i lodash@4.17.20: held", () => {
    expect(run("npm `\ni lodash@4.17.20", "PowerShell").decision).toBe("deny");
  });
  it("bash: npm \<newline> i lodash@4.17.20: held", () => {
    expect(run("npm \\\ni lodash@4.17.20").decision).toBe("deny");
  });
});
