// SPDX-License-Identifier: Apache-2.0
/**
 * Round 27 of the hook lane (sentence check 23): one rule for options before the word a reader looks
 * for (E1 runner tables, E4 global options, E5 configuration sources), runner fetches named with a
 * dist-tag or latest (E2) and with an index option (E3), one walk for an expansion (E6), and the
 * manifest faults F1, F7, F9-F12.
 */

import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { CONFIG_SOURCE_OPTIONS, INDEX_TABLE_KEYS, MANAGER_GLOBAL_OPTIONS, RUNNER_OPTIONS, installsIn } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "ruff", version: "0.5.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "npm", package: "cowsay", version: "1.5.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "npm", package: "lodash", version: "4.18.1", verdict: "proceed" },
    { ecosystem: "crates.io", package: "regex", version: "1.5.4", requested: "=1.5.4", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());

const bash = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const post = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command }, tool_response: {} });
const readings = (command: string) => installsIn(command, "bash").map((x: { name: string; spec: string; tag?: boolean }) => `${x.name} ${x.spec}${x.tag ? " tag" : ""}`);

describe("E1: a runner's options before the package are read from its table, with their arity", () => {
  it("each table is exported, and lists the common options", () => {
    expect(RUNNER_OPTIONS.npm.flags).toEqual(expect.arrayContaining(["-y", "--yes", "--no", "-q"]));
    expect(RUNNER_OPTIONS.npm.values).toContain("--loglevel");
    expect(RUNNER_OPTIONS.uvx.values).toEqual(expect.arrayContaining(["--color", "--python"]));
    expect(RUNNER_OPTIONS.gorun.values).toContain("-tags");
  });
  it.each([
    ["npx --loglevel warn --yes cowsay@1.5.0 hi", "cowsay 1.5.0"],
    ["uvx --color never ruff@0.5.0 --version", "ruff ==0.5.0"],
    ["go run -tags foo golang.org/x/text/cmd/gotext@v0.3.0 -h", "golang.org/x/text/cmd/gotext v0.3.0"],
    ["npm create --loglevel warn vite@5.0.0", "create-vite 5.0.0"],
    ["pnpm dlx --cache ./c lodash@4.17.20", "lodash 4.17.20"],
    ["npm --loglevel warn exec cowsay@1.5.0", "cowsay 1.5.0"],
    ["uv --quiet tool run ruff@0.5.0", "ruff ==0.5.0"],
  ])("%s reads %s", (command, reading) => {
    expect(readings(command)).toEqual([reading]);
  });
  it.each(["npx --loglevel warn --yes cowsay@1.5.0 hi", "uvx --color never ruff@0.5.0 --version", "npm create --loglevel warn vite@5.0.0"])("%s: judged (not on the ledger, or avoid)", (command) => {
    expect(bash(command).decision).toBe("deny");
    expect(bash(command).text).not.toContain("could not be read");
  });
  it.each(["npx --frob cowsay@1.5.0", "npx --frob tsc", "uvx --frob x ruff@0.5.0", "pnpm --frob dlx lodash@4.17.20", "uv --frob tool run ruff@0.5.0", "bash -c 'npx --frob cowsay@1.5.0'", "uv run --config-file x.toml pytest"])("%s: an option off the table is not read, whether or not the detector names the line", (command) => {
    const r = bash(command);
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("could not be read");
  });
  it.each(["npx --yes tsc --noEmit", "npx -y prettier --write .", "npx --no-install eslint .", "uv run --frozen pytest -q", "go run -race ./cmd/x", "pnpm -r run build", "pnpm --filter web run build", "npm exec -- eslint .", "uvx --python 3.12 ruff check"])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});

describe("E2: every runner, with a version, a range, a dist-tag and latest", () => {
  const npmRunners = ["npx", "npx --yes", "bunx", "pnpx", "npm exec", "npm x", "pnpm dlx", "yarn dlx", "bun x"];
  for (const r of npmRunners) {
    it(`${r}`, () => {
      expect(readings(`${r} cowsay@1.2.3`)).toEqual(["cowsay 1.2.3"]);
      expect(readings(`${r} "cowsay@^1.2.0"`)).toEqual(["cowsay ^1.2.0"]);
      expect(readings(`${r} cowsay@beta`)).toEqual(["cowsay beta tag"]);
      expect(readings(`${r} cowsay@latest`)).toEqual(["cowsay latest"]);
    });
  }
  for (const r of ["npm init", "npm create", "pnpm create", "yarn create", "bun create"]) {
    it(`${r}`, () => {
      expect(readings(`${r} vite@1.2.3`)).toEqual(["create-vite 1.2.3"]);
      expect(readings(`${r} "vite@^1.2.0"`)).toEqual(["create-vite ^1.2.0"]);
      expect(readings(`${r} vite@next`)).toEqual(["create-vite next tag"]);
      expect(readings(`${r} vite@latest`)).toEqual(["create-vite latest"]);
    });
  }
  for (const r of ["uvx", "uv tool run", "pipx run"]) {
    it(`${r}`, () => {
      expect(readings(`${r} ruff@1.2.3`)).toEqual(["ruff ==1.2.3"]);
      expect(readings(`${r} "ruff>=1.2"`)).toEqual(["ruff >=1.2"]);
      expect(readings(`${r} ruff@latest`)).toEqual(["ruff latest"]);
    });
  }
  it("go run", () => {
    expect(readings("go run golang.org/x/text/cmd/gotext@v0.3.0")).toEqual(["golang.org/x/text/cmd/gotext v0.3.0"]);
    expect(readings("go run golang.org/x/text/cmd/gotext@latest")).toEqual(["golang.org/x/text/cmd/gotext latest"]);
    expect(readings("go run golang.org/x/text/cmd/gotext@master")).toEqual(["golang.org/x/text/cmd/gotext master tag"]);
  });
  it.each(["npx semver@legacy", "npx ms@beta", "npm init vite@next", "uvx ruff@latest", "uvx --from ruff@latest ruff"])("%s: judged, never through", (command) => {
    expect(bash(command).decision).toBe("deny");
  });
});

describe("E3: a Python runner with an index option follows the install's source rule", () => {
  it.each([
    ["uvx --index-url https://pypi.org/simple ruff@0.5.1", ["ruff ==0.5.1"]],
    ["uvx --index-url https://mirror.example.cn/simple ruff@0.5.1", ["ruff ==0.5.1"]],
    ["pipx run --index-url https://pypi.org/simple black==23.1.0", ["black ==23.1.0"]],
    ["uv run --index-url https://pypi.org/simple --with requests==2.19.0 python -c 1", ["requests ==2.19.0"]],
    ["uvx --index-url https://pypi.corp.internal/simple ruff@0.5.1", []],
    ["uvx --no-index -f ./wheels ruff@0.5.1", []],
  ])("%s", (command, expected) => {
    expect(readings(command)).toEqual(expected);
  });
  it("public index: judged on the avoid; --no-index beside a remote location: not read", () => {
    expect(bash("uv run --index-url https://pypi.org/simple --with requests==2.19.0 python -c 1").text).toContain("answered avoid");
    expect(bash("uvx --no-index -f https://files.example.com/w ruff@0.5.1").text).toContain("could not be read");
  });
});

describe("E4: a configuration write behind a global option", () => {
  it("the tables are exported", () => {
    expect(MANAGER_GLOBAL_OPTIONS.pip.values).toEqual(expect.arrayContaining(["--cache-dir", "--proxy"]));
    expect(MANAGER_GLOBAL_OPTIONS.poetry.values).toContain("-C");
  });
  it.each([
    "npm --cache ./c config set registry https://evil-mirror.com/",
    "npm --loglevel warn config set registry https://evil-mirror.com/",
    "npm -C . config set registry https://evil-mirror.com/",
    "pip --cache-dir ./c config set global.index-url https://evil-mirror.com/simple",
    "python -m pip --proxy http://p:1 config set global.index-url https://evil-mirror.com/simple",
    "poetry -C . config repositories.evil https://evil-mirror.com/simple",
    "npm --frobx 1 config set fund false",
    "pnpm --frobx config set registry https://evil-mirror.com/",
  ])("%s: not read", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
  it.each(["npm --loglevel warn config set fund false", "pip --no-cache-dir config set global.no-color true", "npm config list"])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});

describe("E5: a configuration source named on the command", () => {
  beforeEach(() => {
    s.file("evil.npmrc", "registry=https://evil-mirror.com/\n");
  });
  it("the table is exported", () => {
    expect(CONFIG_SOURCE_OPTIONS.uv).toContain("--config-file");
    expect(CONFIG_SOURCE_OPTIONS.cargo).toEqual(expect.arrayContaining(["--config", "-Z"]));
  });
  it.each([
    "npm ci --userc=evil.npmrc",
    "npm ci --globalc evil.npmrc",
    "npm ci --us x",
    "uv lock --config-file evil.toml",
    "uv sync --config-file evil.toml",
    "cargo update --config evilcargo.toml",
    "cargo build -Zunstable-options",
    "pnpm install --config.registry=https://evil-mirror.com/",
    "yarn install --use-yarnrc x.yml",
    "bun install -c x.toml",
    "go get -modfile=x.mod golang.org/x/text@v0.3.0",
    "go build -modfile=x.mod ./...",
    "poetry -C . install",
  ])("%s: not read", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
  it.each(["npm ci", "npm ci --no-audit", "npm test -- --userconfig x", "poetry install", "uv sync", "cargo update", "echo npm --userconfig x"])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
  it("the remedy names the option alone", () => {
    expect(bash("uv lock --config-file evil.toml").text).toContain("without the option `--config-file`");
  });
});

describe("E6: an expansion, found by the reader's own walk", () => {
  it.each([
    "V=install; timeout 60 npm $V lodash@4.17.20 --ignore-scripts",
    "V=install; (npm $V lodash@4.17.20)",
    "{ npm $V x; }",
    "sudo -u root npm $V x",
    'env -u X npm "${a[@]}"',
    "nice -n 5 npm $V x",
    "exec -a x npm $V",
    "ionice -c 3 npm $V x",
    "corepack pnpm $V x",
    "py -3 -m pip $V x",
    "P=ruff@0.5.0; uvx $P --version",
    "P=semver@5.7.1; pnpm dlx $P --help",
    "npm exec $P",
    "npm init $P",
    "uv tool run $P",
    "uv run --with $P python",
    "go run $M",
    "pipx run $P",
    "cat <(npm $V)",
  ])("%s: not read", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
  it.each(["npm run build -- $ARGS", "uv run pytest $ARGS", "go run . $X", "echo $HOME", 'echo "$(date)"; npm run build'])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});

describe("F1: a conditional own source leaves the registry reading judged", () => {
  const P = (rest: string) => `[project]\nname = "a"\nversion = "0.1.0"\ndependencies = ["requests==2.19.0"]\n${rest}`;
  it.each([
    "[tool.uv.sources]\nrequests = { path = \"./r\", marker = \"sys_platform == 'linux'\" }\n",
    '[project.optional-dependencies]\ncpu = []\n[tool.uv.sources]\nrequests = { git = "https://github.com/psf/requests", extra = "cpu" }\n',
    '[tool.uv.sources]\nrequests = { path = "./r", group = "dev" }\n',
    '[tool.uv.sources]\nrequests = { path = "./r", python = ">=3.12" }\n',
    "[tool.uv.sources]\nrequests = [ { path = \"./r\", marker = \"sys_platform == 'linux'\" }, { path = \"./r2\", marker = \"sys_platform == 'darwin'\" } ]\n",
    "[tool.uv.sources.requests]\npath = \"./r\"\nmarker = \"sys_platform == 'linux'\"\n",
    "[tool.uv.sources]\nrequests = { workspace = false }\n",
  ])("%j: judged", (tables) => {
    expect(s.write(join(s.project, "pyproject.toml"), P(tables)).text).toContain("answered avoid");
  });
  it.each(['[tool.uv.sources]\nrequests = { path = "./r" }\n', '[tool.uv.sources]\nrequests = { workspace = true }\n', '[tool.uv.sources.requests]\ngit = "https://github.com/psf/requests"\n'])("%j: the project's own, but an avoid on record still denies (round 31, K1)", (tables) => {
    expect(s.write(join(s.project, "pyproject.toml"), P(tables)).text).toContain("answered avoid");
    // The same source with a requirement no verdict names: the project's own.
    expect(s.write(join(s.project, "pyproject.toml"), P(tables).replace('"requests==2.19.0"', '"requests==2.31.0"')).decision).toBe("allow");
  });
});

describe("F7: an index table is read by its own tool's keys", () => {
  const P = (rest: string) => `[project]\nname = "a"\nversion = "0.1.0"\n${rest}`;
  it("the key lists are exported", () => {
    expect(INDEX_TABLE_KEYS["tool.uv.index"]).toContain("explicit");
    expect(INDEX_TABLE_KEYS["tool.poetry.source"]).toContain("priority");
  });
  it.each([
    '[[tool.uv.index]]\nname = "e"\nurl = "http://127.0.0.1:18765/simple"\npriority = "explicit"\n',
    '[[tool.uv.index]]\nname = "e"\nurl = "https://mirror.example.cn/simple"\nexplicit = true\nfrob = 1\n',
    '[[tool.poetry.source]]\nname = "e"\nurl = "https://mirror.example.cn/simple"\nexplicit = true\n',
  ])("%j: held", (tables) => {
    s.file("pyproject.toml", P(""));
    expect(s.write(join(s.project, "pyproject.toml"), P(tables)).text).toContain("could not be read");
  });
  it.each(['[[tool.uv.index]]\nname = "e"\nurl = "https://mirror.example.cn/simple"\nexplicit = true\n', '[[tool.poetry.source]]\nname = "e"\nurl = "https://mirror.example.cn/simple"\npriority = "explicit"\n'])("%j: goes ahead", (tables) => {
    s.file("pyproject.toml", P(""));
    expect(s.write(join(s.project, "pyproject.toml"), P(tables)).decision).toBe("allow");
  });
});

describe("F9: the packageManager key is the stated L2 limit", () => {
  it.each(['{"name":"t","version":"1.0.0","packageManager":"pnpm@9.15.0"}', '{"name":"t","devEngines":{"packageManager":{"name":"pnpm","version":"9.15.0"}}}'])("%s goes ahead", (text) => {
    expect(s.write(join(s.project, "package.json"), text).decision).toBe("allow");
  });
});

describe("F10, F11: Poetry develop and file, packageExtensions and catalogs", () => {
  const head = '[tool.poetry]\nname = "t"\nversion = "0.1.0"\n[tool.poetry.dependencies]\n';
  it("develop without a path is judged; a file that is not a string is not read", () => {
    expect(s.write(join(s.project, "pyproject.toml"), `${head}requests = { version = "2.19.0", develop = true }\n`).text).toContain("answered avoid");
    expect(s.write(join(s.project, "pyproject.toml"), `${head}requests = { file = 5, version = "2.19.0" }\n`).text).toContain("could not be read");
  });
  it.each([
    '{"name":"t","pnpm":{"packageExtensions":{"foo@1":5}}}',
    '{"name":"t","pnpm":{"packageExtensions":{"foo@1":{"dependencies":5}}}}',
    '{"name":"t","pnpm":{"packageExtensions":5}}',
    '{"name":"t","workspaces":{"packages":[],"catalog":5}}',
    '{"name":"t","workspaces":{"packages":[],"catalogs":{"x":5}}}',
  ])("%s: not read", (text) => {
    expect(s.write(join(s.project, "package.json"), text).text).toContain("could not be read");
  });
});

describe("F12: the updates the manager chooses are advised", () => {
  it.each(["npm audit fix", "pnpm audit --fix", "go mod tidy", "uv lock --upgrade", "poetry lock", "npm dedupe"])("%s", (command) => {
    expect(post(command).decision).toBe("advise");
  });
});

describe("F1: Cargo, each entry its own", () => {
  const C = (dep: string) => `[package]\nname = "a"\nversion = "0.1.0"\n\n${dep}\n`;
  it.each([
    '[dependencies]\nregex = "=1.5.4"\n\n[target.\'cfg(unix)\'.dependencies]\nregex = { path = "../regex" }',
    '[target.\'cfg(unix)\'.dependencies]\nregex = { path = "../regex" }\n\n[target.\'cfg(windows)\'.dependencies]\nregex = "=1.5.4"',
  ])("%j: the version entry is judged", (dep) => {
    expect(s.write(join(s.project, "Cargo.toml"), C(dep)).text).toContain("answered avoid");
  });
});
