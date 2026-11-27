// SPDX-License-Identifier: Apache-2.0
/**
 * Round 21 (T3): every form in which an examined call names a release the hook reads, per manager
 * (operand forms) and per manifest kind (entry forms), with an avoid answer recorded for that
 * reading: each is denied, and the denial names the avoid. This is the table behind THE CONTRACT's
 * P3 (a1125-w2-hook-contract.test.ts names it).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    // Exact readings.
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "regex", version: "1.5.4", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "Go", package: "golang.org/x/text", version: "v0.3.0", verdict: "avoid", reason: "test avoid" },
    // Range readings (the server records the constraint as `requested`).
    { ecosystem: "npm", package: "lodash", version: "4.17.21", requested: "^4.17.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "requests", version: "2.32.3", requested: ">=2", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "regex", version: "1.11.0", requested: "^1", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "regex", version: "1.11.0", requested: "1.5.4", verdict: "avoid", reason: "test avoid" },
    // latest (a name alone, and a spec that bounds nothing).
    { ecosystem: "npm", package: "lodash", version: "4.17.21", requested: "latest", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "requests", version: "2.32.3", requested: "latest", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "regex", version: "1.11.0", requested: "latest", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "Go", package: "golang.org/x/text", version: "v0.21.0", requested: "latest", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

const LT = "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz";
const WH = "https://files.pythonhosted.org/packages/cc/15/abc/requests-2.19.0-py2.py3-none-any.whl";

/** Command operand forms, per manager. */
export const COMMAND_FORMS: Array<[string, string]> = [
  // npm
  ["npm", "npm install lodash@4.17.20"],
  ["npm", "npm i lodash@4.17.20"],
  ["npm", "npm add lodash@4.17.20"],
  ["npm", "npm install -D lodash@4.17.20"],
  ["npm", "npm install -g lodash@4.17.20"],
  ["npm", "npm install lodash@^4.17.0"],
  ["npm", "npm install lodash"],
  ["npm", "npm install lodash@latest"],
  ["npm", "npm install my-lodash@npm:lodash@4.17.20"],
  ["npm", "npm install my-lodash@npm:lodash"],
  ["npm", `npm install ${LT}`],
  ["npm", `npm install lodash@${LT}`],
  ["npm", "npm link lodash"],
  ["npm", "npm pkg set dependencies.lodash=4.17.20"],
  ["npm", "npx npm install lodash@4.17.20"],
  ["npm", "npm exec -- npm install lodash@4.17.20"],
  ["npm", 'bash -c "npm install lodash@4.17.20"'],
  ["npm", "sudo npm install -g lodash@4.17.20"],
  // pnpm
  ["pnpm", "pnpm add lodash@4.17.20"],
  ["pnpm", "pnpm install lodash@4.17.20"],
  ["pnpm", "pnpm add lodash@^4.17.0"],
  ["pnpm", "pnpm add lodash"],
  ["pnpm", "pnpm up -L lodash"],
  ["pnpm", "pnpm up --latest lodash"],
  ["pnpm", "pnpm dlx pnpm add lodash@4.17.20"],
  // yarn
  ["yarn", "yarn add lodash@4.17.20"],
  ["yarn", "yarn add lodash@^4.17.0"],
  ["yarn", "yarn add lodash"],
  ["yarn", "yarn up lodash"],
  ["yarn", "yarn upgrade lodash --latest"],
  ["yarn", "yarn global add lodash@4.17.20"],
  // bun
  ["bun", "bun add lodash@4.17.20"],
  ["bun", "bun install lodash@4.17.20"],
  ["bun", "bun add lodash"],
  ["bun", "bun update lodash"],
  // pip
  ["pip", "pip install requests==2.19.0"],
  ["pip", "pip3 install requests==2.19.0"],
  ["pip", "python -m pip install requests==2.19.0"],
  ["pip", "pip install requests[socks]==2.19.0"],
  ["pip", "pip install 'requests>=2'"],
  ["pip", "pip install requests"],
  ["pip", "pip install -U requests"],
  ["pip", `pip install ${WH}`],
  ["pip", `pip install "requests @ ${WH}"`],
  // uv
  ["uv", "uv add requests==2.19.0"],
  ["uv", "uv add 'requests>=2'"],
  ["uv", "uv add requests"],
  ["uv", `uv add "requests @ ${WH}"`],
  ["uv", "uv pip install requests==2.19.0"],
  ["uv", "uv tool install requests==2.19.0"],
  ["uv", "uv lock --upgrade-package requests==2.19.0"],
  ["uv", "uv sync -P requests==2.19.0"],
  // poetry
  ["poetry", "poetry add requests==2.19.0"],
  ["poetry", "poetry add requests"],
  ["poetry", "poetry self add requests==2.19.0"],
  ["poetry", "poetry add requests@latest"],
  // cargo
  ["cargo", "cargo add regex@=1.5.4"],
  ["cargo", "cargo add --dev regex@=1.5.4"],
  ["cargo", "cargo add regex@1.5.4"],
  ["cargo", "cargo add regex@^1"],
  ["cargo", "cargo add regex"],
  ["cargo", "cargo install regex@1.5.4"],
  ["cargo", "cargo install regex --version 1.5.4"],
  ["cargo", "cargo update -p regex --precise 1.5.4"],
  // go
  ["go", "go get golang.org/x/text@v0.3.0"],
  ["go", "go get golang.org/x/text@latest"],
  ["go", "go get golang.org/x/text"],
  ["go", "go mod edit -require=golang.org/x/text@v0.3.0"],
  ["go", "go mod edit -replace=golang.org/x/text=golang.org/x/text@v0.3.0"],
];

/** Manifest entry forms, per manifest kind: [kind, file, content]. */
const pj = (o: unknown) => JSON.stringify(o);
const CARGO = (deps: string) => `[package]\nname = "a"\nversion = "0.1.0"\n${deps}`;
const PYP = (deps: string) => `[project]\nname = "x"\nversion = "0"\n${deps}`;
export const MANIFEST_FORMS: Array<[string, string, string]> = [
  // package.json
  ["package.json", "package.json", pj({ dependencies: { lodash: "4.17.20" } })],
  ["package.json", "package.json", pj({ devDependencies: { lodash: "4.17.20" } })],
  ["package.json", "package.json", pj({ optionalDependencies: { lodash: "4.17.20" } })],
  ["package.json", "package.json", pj({ peerDependencies: { lodash: "4.17.20" } })],
  ["package.json", "package.json", pj({ dependencies: { lodash: "^4.17.0" } })],
  ["package.json", "package.json", pj({ dependencies: { lodash: "*" } })],
  ["package.json", "package.json", pj({ dependencies: { lodash: "latest" } })],
  ["package.json", "package.json", pj({ dependencies: { "my-lodash": "npm:lodash@4.17.20" } })],
  ["package.json", "package.json", pj({ dependencies: { lodash: LT } })],
  ["package.json", "package.json", pj({ overrides: { lodash: "4.17.20" } })],
  ["package.json", "package.json", pj({ resolutions: { lodash: "4.17.20" } })],
  ["package.json", "package.json", pj({ overrides: { "some-parent": { lodash: "4.17.20" } } })],
  ["package.json", "package.json", pj({ workspaces: { packages: ["a"], catalogs: { old: { lodash: "4.17.20" } } } })],
  ["package.json", "package.json", pj({ workspaces: ["a"], catalog: { lodash: "4.17.20" } })],
  ["package.json", "package.json", pj({ pnpm: { overrides: { lodash: "4.17.20" } } })],
  ["package.json", "package.json", pj({ pnpm: { packageExtensions: { "some-pkg": { dependencies: { lodash: "4.17.20" } } } } })],
  ["package.json", "package.json", pj({ workspaces: { packages: ["a"], catalog: { lodash: "4.17.20" } } })],
  // pnpm-workspace.yaml
  ["pnpm-workspace.yaml", "pnpm-workspace.yaml", "catalog:\n  lodash: 4.17.20\n"],
  ["pnpm-workspace.yaml", "pnpm-workspace.yaml", "catalogs:\n  old:\n    lodash: 4.17.20\n"],
  ["pnpm-workspace.yaml", "pnpm-workspace.yaml", "overrides:\n  lodash: 4.17.20\n"],
  ["pnpm-workspace.yaml", "pnpm-workspace.yaml", "packageExtensions:\n  some-pkg:\n    dependencies:\n      lodash: 4.17.20\n"],
  ["pnpm-workspace.yaml", "pnpm-workspace.yaml", "configDependencies:\n  lodash: 4.17.20\n"],
  // Cargo.toml
  ["Cargo.toml", "Cargo.toml", CARGO('[dependencies]\nregex = "=1.5.4"\n')],
  ["Cargo.toml", "Cargo.toml", CARGO('[dependencies]\nregex = "1.5.4"\n')],
  ["Cargo.toml", "Cargo.toml", CARGO('[dependencies]\nregex = { version = "=1.5.4" }\n')],
  ["Cargo.toml", "Cargo.toml", CARGO('[dependencies.regex]\nversion = "=1.5.4"\n')],
  ["Cargo.toml", "Cargo.toml", CARGO('[dependencies]\nregex.version = "=1.5.4"\n')],
  ["Cargo.toml", "Cargo.toml", CARGO('[dev-dependencies]\nregex = "=1.5.4"\n')],
  ["Cargo.toml", "Cargo.toml", CARGO('[build-dependencies]\nregex = "=1.5.4"\n')],
  ["Cargo.toml", "Cargo.toml", CARGO("[target.'cfg(unix)'.dependencies]\nregex = \"=1.5.4\"\n")],
  ["Cargo.toml", "Cargo.toml", '[workspace]\nmembers = []\n[workspace.dependencies]\nregex = "=1.5.4"\n'],
  ["Cargo.toml", "Cargo.toml", CARGO('[dependencies]\nre = { package = "regex", version = "=1.5.4" }\n')],
  ["Cargo.toml", "Cargo.toml", CARGO('[dependencies]\nregex = "*"\n')],
  // pyproject.toml
  ["pyproject.toml", "pyproject.toml", PYP('dependencies = ["requests==2.19.0"]\n')],
  ["pyproject.toml", "pyproject.toml", PYP('dependencies = ["requests>=2"]\n')],
  ["pyproject.toml", "pyproject.toml", PYP('dependencies = ["requests"]\n')],
  ["pyproject.toml", "pyproject.toml", PYP(`dependencies = ["requests @ ${WH}"]\n`)],
  ["pyproject.toml", "pyproject.toml", PYP('[project.optional-dependencies]\nweb = ["requests==2.19.0"]\n')],
  ["pyproject.toml", "pyproject.toml", '[dependency-groups]\ndev = ["requests==2.19.0"]\n'],
  ["pyproject.toml", "pyproject.toml", '[build-system]\nrequires = ["requests==2.19.0"]\n'],
  ["pyproject.toml", "pyproject.toml", '[tool.uv]\ndev-dependencies = ["requests==2.19.0"]\n'],
  ["pyproject.toml", "pyproject.toml", '[tool.poetry.dependencies]\nrequests = "2.19.0"\n'],
  ["pyproject.toml", "pyproject.toml", '[tool.poetry.dependencies]\nrequests = { version = "2.19.0" }\n'],
  ["pyproject.toml", "pyproject.toml", '[tool.poetry.group.dev.dependencies]\nrequests = "2.19.0"\n'],
  ["pyproject.toml", "pyproject.toml", '[tool.poetry.dependencies]\nrequests = "*"\n'],
  ["pyproject.toml", "pyproject.toml", '[tool.poetry.dependencies]\nrequests = [{ version = "2.19.0", python = "<3.11" }, { version = "2.19.0", python = ">=3.11" }]\n'],
  ["pyproject.toml", "pyproject.toml", `${PYP('dependencies = ["requests"]\n')}\n[tool.uv.sources]\nrequests = { url = ${JSON.stringify(WH)} }\n`],
  // requirements.txt
  ["requirements.txt", "requirements.txt", "requests==2.19.0\n"],
  ["requirements.txt", "requirements.txt", "requests>=2\n"],
  ["requirements.txt", "requirements.txt", "requests\n"],
  ["requirements.txt", "requirements.txt", "requests[socks]==2.19.0 ; python_version >= '3.8'\n"],
  ["requirements.txt", "requirements.txt", "requests==2.19.0 \\\n    --hash=sha256:abc\n"],
  ["requirements.txt", "requirements.txt", `requests @ ${WH}\n`],
  ["requirements.txt", "requirements.txt", `${WH}\n`],
  ["requirements.txt", "requirements-dev.txt", "requests==2.19.0\n"],
  ["requirements.txt", "requirements/base.txt", "requests==2.19.0\n"],
  // go.mod / go.work
  ["go.mod", "go.mod", "module example.com/m\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n"],
  ["go.mod", "go.mod", "module example.com/m\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.3.0\n)\n"],
  ["go.mod", "go.mod", "module example.com/m\n\ngo 1.22\n\nrequire golang.org/x/text latest\n"],
  ["go.mod", "go.mod", "module example.com/m\n\nrequire golang.org/x/text v0.3.0 // indirect\n"],
  ["go.mod", "go.mod", "module example.com/m\n\nreplace golang.org/x/text => golang.org/x/text v0.3.0\n"],
  ["go.mod", "go.work", "go 1.22\n\nreplace golang.org/x/text => golang.org/x/text v0.3.0\n"],
];

describe("P3 forms: an avoid answer for the reading denies each command form", () => {
  it.each(COMMAND_FORMS)("%s: %s", (_manager, command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text, r.text).toContain("answered avoid");
  });
  it.each(COMMAND_FORMS.filter(([, c]) => !c.includes("'") && !c.includes('"')))("%s (PowerShell): %s", (_manager, command) => {
    const r = run(command, "PowerShell");
    expect(r.decision, r.text).toBe("deny");
    expect(r.text, r.text).toContain("answered avoid");
  });
});

describe("P3 forms: an avoid answer for the reading denies each manifest form", () => {
  it.each(MANIFEST_FORMS)("%s (%s): %j", (_kind, file, content) => {
    const r = s.write(`${s.project}/${file}`, content);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text, r.text).toContain("answered avoid");
  });
});

/** Round 23 (V1): each range form with a character cmd.exe treats specially, through each manager's .cmd shim. */
const CMD_RANGES = ["^4.17.0", "^4.17", '">=4.17.0"', '"<5"', '">=4.17.0 <5"', '"4.17.0 || 4.17.21"'];
const CMD_MANAGERS: Array<[string, string]> = [
  ["npm.cmd", "install"],
  ["pnpm.cmd", "add"],
  ["yarn.cmd", "add"],
  ["bun.cmd", "add"],
];
describe("V1 forms: every range form through every .cmd manager is denied as not read", () => {
  const cases = CMD_MANAGERS.flatMap(([m, verb]) => CMD_RANGES.map((r) => [`${m} ${verb} lodash@${r.startsWith('"') ? r.slice(1, -1) : r}`.replace(/lodash@(.*)$/, (_x, v: string) => (/\s/.test(v) || /[<>|]/.test(v) ? `"lodash@${v}"` : `lodash@${v}`))]));
  it.each(cases)("%s", (command) => {
    for (const tool of ["Bash", "PowerShell"]) {
      const r = run(command, tool);
      expect(r.decision, `${tool}: ${r.text}`).toBe("deny");
      expect(r.text).toContain("cmd.exe rewrites");
    }
  });
});
