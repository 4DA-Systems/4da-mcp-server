// SPDX-License-Identifier: Apache-2.0
/**
 * Round 17, from the fifteenth independent check: a name alone goes ahead only where the hook has
 * positively placed the install (L1), a source option keeps its own remedy (L2), one "bounds
 * nothing" for every reader (L3), go.work's replace (L4), one name normaliser (L5), and the advice
 * after any install verb (L6). The reviewer's cases, and generated sweeps of each class.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { realpathSync } from "node:fs";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "lodash", version: "4.17.21", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "npm", package: "zod", version: "3.23.8", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "npm", package: "eslint", version: "9.0.0", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "npm", package: "prettier", version: "3.3.3", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "PyPI", package: "requests", version: "2.32.3", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "crates.io", package: "regex", version: "1.11.0", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "Go", package: "golang.org/x/text", version: "v0.3.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "ryu", version: "1.0.0", verdict: "proceed", reason: "ok" },
  ]);
});
afterEach(() => s.dispose());

const run = (command: string, cwd = s.project, tool = "Bash") => s.run({ session_id: "s", cwd, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });
const FOLLOW = "a directory change this hook does not follow";
const SELECT = "a workspace option: the member's own files are not read";
const INSIDE = "this folder is inside a workspace";

describe("L1 a: the folder is followed only where the hook resolves it", () => {
  beforeEach(() => {
    s.file("packages/app/.keep", "");
  });
  it.each([
    "cd packages/app && npm install zod",
    "cd packages/app; npm install zod",
    "cd packages/app\nnpm install zod",
    "cd ./packages/app/ && pnpm add zod",
    'cd "packages/app" && yarn add zod',
    "pushd packages/app && npm install zod",
    "builtin cd packages/app && npm install zod",
    "command cd packages/app && npm install zod",
    "cd packages/app || exit 1; npm install zod",
    // (Round 18, M1 ii: `cd packages && cd app && bun add zod` is held: a cd after && is not followed.)
    "npm install zod --prefix packages/app",
    "pnpm add zod -C packages/app",
    "pnpm --dir packages/app add zod",
    "yarn --cwd packages/app add zod",
    "bun add zod --cwd=packages/app",
  ])("%s: placed, judged on latest, goes ahead", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("allow");
  });
  it.each([
    ["PS> Set-Location packages/app; npm install zod", "PowerShell"],
    ["Set-Location -Path packages/app; npm install zod", "PowerShell"],
    ["Push-Location -LiteralPath packages/app; npm install zod", "PowerShell"],
    ["sl packages/app; npm install zod", "PowerShell"],
    ["cd packages\\app; npm install zod", "PowerShell"],
  ])("%s: placed (PowerShell)", (command, tool) => {
    const r = run(command.replace(/^PS> /, ""), s.project, tool);
    expect(r.decision, r.text).toBe("allow");
  });
  it.each([
    "cd ~ && npm install zod",
    "cd - && npm install zod",
    "cd && npm install zod",
    "cd nowhere && npm install zod",
    "pushd packages/app && popd && npm install zod",
    "source env.sh && npm install zod",
    "(cd packages/app) && npm install zod",
    "{ cd packages/app; } ; npm install zod",
    "cd packages/app | true; npm install zod",
    "cd packages/app & npm install zod",
    "cd packages/app || npm install zod",
    "env -C packages/app npm install zod",
    "sudo -D packages/app npm install zod",
    "npm install zod --prefix nowhere",
    "pnpm add zod -C ~/x",
    "cargo add regex --manifest-path nowhere/Cargo.toml",
  ])("%s: held, the directory change not followed", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain(FOLLOW);
    expect(r.text).toContain("name the version (`");
  });
  it.each(["cd $DIR && npm install zod", "npm install zod --prefix $P"])("%s: held as not read", (command) => {
    expect(run(command).text).toContain("could not be read");
  });
  it("Pop-Location is not followed", () => {
    const r = run("Push-Location packages/app; Pop-Location; npm install zod", s.project, "PowerShell");
    expect(r.text).toContain(FOLLOW);
  });
  it("a Git Bash /c/... path is the Windows folder it names", () => {
    if (process.platform !== "win32") return;
    // M8: from the fixture folder's own drive (CI runs on D:) and its long name (no 8.3 RUNNER~1 part).
    const real = realpathSync.native(s.project);
    const msys = `/${real[0].toLowerCase()}${real.slice(2).replace(/\\/g, "/")}/packages/app`;
    expect(run(`cd /cygdrive/${real[0].toUpperCase()}${real.slice(2).replace(/\\/g, "/")}/packages/app && npm install zod`).decision).toBe("allow");
    // The 8.3 spelling (a ~ inside a name) is followed too.
    const short = s.project.replace(/\\/g, "/");
    expect(run(`cd /${short[0].toLowerCase()}${short.slice(2)}/packages/app && npm install zod`).decision).toBe("allow");
    expect(run(`cd ${msys} && npm install zod`).decision).toBe("allow");
    expect(run(`cd /cygdrive${msys} && npm install zod`).decision).toBe("allow");
    expect(run(`npm install zod --prefix ${msys}`).decision).toBe("allow");
    expect(run("cd /tmp && npm install zod").text).toContain(FOLLOW);
  });
  it("inside the group the change is followed; past its end it is not", () => {
    s.file("packages/app/package.json", '{"dependencies":{"zod":"3.0.0"}}');
    expect(run("(cd packages/app && npm install zod)").text).toContain("already names zod");
  });
});

describe("L1 b: a workspace selector holds the name alone", () => {
  it.each([
    "npm install lodash -w packages/app",
    "npm install lodash --workspace=app",
    "npm --workspace packages/app install lodash",
    "npm install lodash --workspaces",
    "npm install lodash -ws",
    "npm install lodash --include-workspace-root",
    "pnpm --filter app add lodash",
    "pnpm -F app add lodash",
    "pnpm add lodash --filter ./packages/app",
    "pnpm -r add lodash",
    "pnpm --recursive add lodash",
    "pnpm add -w lodash",
    "pnpm add -Dw lodash",
    "pnpm add -wD lodash",
    "pnpm add lodash --workspace-root",
    "yarn workspace app add lodash",
    "yarn workspaces foreach add lodash",
    "bun add lodash --filter app",
    "cargo add regex -p a",
    "cargo add regex --package a",
    "uv add requests --package a",
  ])("%s: held", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain(SELECT);
  });
  it("a selector beside a named version is judged as before", () => {
    expect(run("pnpm --filter app add lodash@4.17.21").decision).toBe("allow");
  });
});

describe("L1 c: a folder inside a workspace holds the name alone (the sibling case)", () => {
  it.each([
    ["pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n", "pnpm add lodash"],
    ["pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n", "npm install lodash"],
    ["pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n", "yarn add lodash"],
    ["pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n", "bun add lodash"],
    ["package.json", '{"private":true,"workspaces":["packages/*"]}', "npm install lodash"],
    ["pyproject.toml", '[tool.uv.workspace]\nmembers = ["packages/*"]\n', "uv add requests"],
    ["Cargo.toml", '[workspace]\nmembers = ["packages/*"]\n', "cargo add regex"],
    ["go.work", "go 1.22\nuse ./packages/a\n", "npm install lodash"],
  ])("%s at the root; %s in packages/a: held", (file, content, command) => {
    s.file(file, content);
    s.file("packages/b/package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    s.file("packages/a/.keep", "");
    const r = run(command, `${s.project}/packages/a`);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain(INSIDE);
    expect(r.text).toContain("another member");
  });
  it.each([
    ["pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n", "cargo add regex"],
    ["pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n", "uv add requests"],
    ["Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n', "npm install lodash"],
    ["pyproject.toml", '[tool.uv.workspace]\nmembers = ["py/*"]\n', "pnpm add lodash"],
  ])("a %s workspace does not hold another ecosystem's name alone (%s)", (file, content, command) => {
    s.file(file, content);
    const r = run(command);
    expect(r.decision, r.text).toBe("allow");
  });
  it("at the root itself: held too", () => {
    s.file("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n");
    expect(run("pnpm add -D zod").text).toContain(INSIDE);
  });
});

describe("L1 d: a mention in a package.json value that only mentions names does not count", () => {
  it.each(["scripts", "description", "keywords", "name", "bin", "main", "files", "repository", "author", "license", "engines"])("%s naming eslint and prettier: goes ahead", (key) => {
    const value =
      key === "keywords" || key === "files" ? ["eslint", "prettier"] : key === "scripts" || key === "bin" || key === "engines" ? { lint: "eslint . && prettier --check ." } : "eslint prettier";
    s.file("package.json", JSON.stringify({ [key]: value, dependencies: { zod: "3.23.8" } }));
    const r = run("npm install -D eslint prettier");
    expect(r.decision, r.text).toBe("allow");
  });
  it.each(["dependencies", "devDependencies", "overrides", "resolutions", "pnpm", "peerDependencies", "x-anything"])("%s naming eslint: held", (key) => {
    s.file("package.json", JSON.stringify({ [key]: key === "pnpm" ? { overrides: { eslint: "8.0.0" } } : { eslint: "8.0.0" } }));
    expect(run("npm install -D eslint").text).toContain("already names eslint");
  });
  it("a package.json that does not parse counts whole", () => {
    s.file("package.json", '{"scripts":{"lint":"eslint ."},}');
    expect(run("npm install -D eslint").text).toContain("already names eslint");
  });
});

describe("L2: a source option keeps its source remedy, never `without`", () => {
  it("pnpm --registry is read as npm's: a host private by its shape goes ahead", () => {
    expect(run("pnpm add zqx-acme-widget@1.0.0 --registry http://localhost:4873").decision).toBe("allow");
    expect(run("pnpm install --registry http://localhost:4873").decision).toBe("allow");
    expect(run("pnpm add lodash@4.17.20 --registry=http://10.1.2.3/").decision).toBe("allow");
  });
  it("pnpm --registry on another host: the named packages are judged on the ledger", () => {
    const r = run("pnpm add lodash@4.17.20 --registry https://nexus.example.org/");
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("answered avoid");
  });
  const SOURCES: Array<[string, string]> = [];
  const managers: Record<string, string[]> = {
    "npm install x@1.0.0": ["--registry"],
    "pnpm add x@1.0.0": ["--registry"],
    "yarn add x@1.0.0": ["--registry"],
    "bun add x@1.0.0": ["--registry"],
    "pip install x==1.0.0": ["-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--no-index", "--trusted-host"],
    "uv add x==1.0.0": ["--index", "--index-url", "--default-index", "--extra-index-url", "-f", "--find-links", "--no-index"],
    "uv pip install x==1.0.0": ["-i", "--index-url", "--default-index", "--extra-index-url", "--index", "-f", "--find-links", "--no-index"],
    "poetry add x==1.0.0": ["--source"],
    "cargo add x@1.0.0": ["--registry", "--index"],
  };
  const values = ["", "registry", "https://pypi.org/simple", "https://nexus.example.org/x", "http://localhost:4873", "$URL"];
  for (const [command, options] of Object.entries(managers)) {
    for (const option of options) {
      for (const value of values) {
        const takes = option !== "--no-index";
        SOURCES.push([`${command} ${option}${takes && value !== "" ? ` ${value}` : ""}`, option]);
        if (takes && value !== "") SOURCES.push([`${command} ${option}=${value}`, option]);
        if (takes && value !== "") SOURCES.push([`${command} ${option} ${value} ${option} ${value}`, option]);
      }
    }
  }
  it.each(SOURCES)("%s: no denial says to leave the option out", (command, option) => {
    const r = run(command);
    if (r.decision !== "deny") return;
    expect(r.text, r.text).not.toContain(`without the option \`${option}`);
    expect(r.text).not.toMatch(new RegExp(`without \`${option.replace(/[-]/g, "\\-")}`));
  });
});

describe("L3: one `bounds nothing` for every reader", () => {
  const wild = ["*", "x", "X", "x.x", "*.*", "X.x", "x.x.x", "^*", "=*", ">=*", "~*"];
  it.each(wild)("Cargo.toml %j in every form: held for a verdict on latest", (w) => {
    const forms = [
      `[package]\nname = "a"\nversion = "0.1.0"\n[dependencies]\nzzq = "${w}"\n`,
      `[package]\nname = "a"\nversion = "0.1.0"\n[dependencies]\nzzq = { version = "${w}" }\n`,
      `[package]\nname = "a"\nversion = "0.1.0"\n[dependencies.zzq]\nversion = "${w}"\n`,
      `[package]\nname = "a"\nversion = "0.1.0"\n[target.'cfg(unix)'.dependencies]\nzzq = "${w}"\n`,
      `[workspace]\nmembers = []\n[workspace.dependencies]\nzzq = "${w}"\n`,
      `[package]\nname = "a"\nversion = "0.1.0"\n[dev-dependencies]\nzzq = "${w}"\n`,
    ];
    for (const content of forms) {
      const r = s.write(`${s.project}/Cargo.toml`, content);
      expect(r.decision, `${content}\n${r.text}`).toBe("deny");
      expect(r.items, content).toEqual([{ ecosystem: "crates.io", package: "zzq", to: "latest" }]);
    }
  });
  it.each(["*", "x", "X", "x.x", "*.*", ""])("package.json sections, pnpm catalog, Poetry %j: latest", (w) => {
    for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const r = s.write(`${s.project}/package.json`, JSON.stringify({ [section]: { zzq: w } }));
      expect(r.items, section).toEqual([{ ecosystem: "npm", package: "zzq", to: "latest" }]);
    }
    if (w !== "") {
      const c = s.write(`${s.project}/pnpm-workspace.yaml`, `catalog:\n  zzq: '${w}'\n`);
      expect(c.items).toEqual([{ ecosystem: "npm", package: "zzq", to: "latest" }]);
      const p = s.write(`${s.project}/pyproject.toml`, `[tool.poetry.dependencies]\nzzq = "${w}"\n`);
      expect(p.items).toEqual([{ ecosystem: "PyPI", package: "zzq", to: "latest" }]);
      const t = s.write(`${s.project}/pyproject.toml`, `[tool.poetry.dependencies]\nzzq = { version = "${w}" }\n`);
      expect(t.items).toEqual([{ ecosystem: "PyPI", package: "zzq", to: "latest" }]);
    }
  });
  it("a Cargo version this reader does not read is kept and judged, never dropped", () => {
    const r = s.write(`${s.project}/Cargo.toml`, '[package]\nname = "a"\nversion = "0.1.0"\n[dependencies]\nzzq = "latest-ish"\n');
    expect(r.decision).toBe("deny");
  });
});

describe("L4: go.work's replace directives are read with go.mod's reader", () => {
  it.each([
    "go 1.22\nuse ./app\nreplace golang.org/x/text => golang.org/x/text v0.3.0\n",
    "go 1.22\nuse (\n  ./app\n)\nreplace (\n  golang.org/x/text => golang.org/x/text v0.3.0\n)\n",
  ])("%j: held on the avoid", (content) => {
    const r = s.write(`${s.project}/go.work`, content);
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("answered avoid");
  });
  it("use lines declare nothing", () => {
    expect(s.write(`${s.project}/go.work`, "go 1.22\nuse (\n  ./app\n  ./lib\n)\n").decision).toBe("allow");
  });
});

describe("L5: one path normaliser for every manifest name", () => {
  it.each(["package.yaml::$DATA", "package.json5::$DATA", "package.yaml.", "package.json5 ", "PACKAGE.YAML:s"])("%s: held as package.yaml / package.json5", (name) => {
    const r = s.write(`${s.project}/${name}`, "dependencies:\n  lodash: 4.17.20\n");
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("write the project's manifest as package.json");
  });
  it.each(["package.json", "package.yaml", "Cargo.toml", "go.work", "requirements.txt", "package.json::$DATA"])("a NotebookEdit of %s is held, never read", (name) => {
    const r = s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "NotebookEdit", tool_input: { notebook_path: `${s.project}/${name}`, new_source: '{"dependencies":{"lodash":"4.17.20"}}' } });
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("Edit or Write");
  });
  it("a NotebookEdit of a notebook goes ahead", () => {
    expect(s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "NotebookEdit", tool_input: { notebook_path: `${s.project}/a.ipynb`, new_source: "x = 1" } }).decision).toBe("allow");
  });
  it("go.work::$DATA is read as go.work", () => {
    expect(s.write(`${s.project}/go.work::$DATA`, "replace golang.org/x/text => golang.org/x/text v0.3.0\n").text).toContain("answered avoid");
  });
});

describe("L6: the advice line after any install verb, package named or not", () => {
  const post = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PostToolUse", tool_name: tool, tool_input: { command }, tool_response: {} });
  const ADVICE = "The package manager decides the releases actually installed. Run vulnerability_scan to check them.";
  it.each([
    "npm ci",
    "npm clean-install",
    "npm install",
    "pnpm install --frozen-lockfile",
    "yarn install",
    "yarn",
    "bun install",
    "pip install -r requirements.txt",
    "python -m pip install -r requirements.txt",
    "uv sync",
    "uv pip install -r requirements.txt",
    "poetry install",
    "cargo fetch",
    "cargo build",
    "go mod download",
    "cd app && npm ci",
  ])("%s: advised", (command) => {
    const r = post(command);
    expect(r.decision).not.toBe("deny");
    expect(r.text).toBe(ADVICE);
  });
  it.each(["npm test", "npm run build", "yarn --version", "git commit -m 'npm ci'", "echo npm ci", "uv run pytest"])("%s: none", (command) => {
    expect(post(command).text).toBe("");
  });
});
