// SPDX-License-Identifier: Apache-2.0
/**
 * Every command the server's own planner writes with a version in it is read by the guard hook.
 *
 * upgrade_planner and dependency_check's fix paths tell the agent to run `cargo update -p time@0.3.17
 * --precise 0.3.20`, `uv lock --upgrade-package requests==2.25.0`, `npm pkg set
 * "overrides.lodash=4.17.20"`, `go mod edit -replace=...@v0.17.0` and the compile commands with
 * `--upgrade-package "x==v"`; the 6.5.1 candidate read none of them, so each went ahead with no
 * verdict (blind review 2026-11-24, item 3).
 *
 * The last block reads the planner's own sources: each template literal that starts with a package
 * manager and interpolates something must be one this table knows, so a new command shape fails
 * here until the hook is taught to read it (or it is listed as naming no version).
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { installsIn } from "../../hooks/manifest-edit.mjs";

const read = (command: string, dialect: "bash" | "powershell" = "bash") => installsIn(command, dialect).map((r) => `${r.ecosystem} ${r.name} ${r.spec}`);

describe("the planner's commands are read", () => {
  it.each([
    ["cargo update -p time@0.3.17 --precise 0.3.20", ["crates.io time 0.3.20"]],
    ["cargo update -p time --precise 0.3.20", ["crates.io time 0.3.20"]],
    ["cargo update time --precise 0.3.20", ["crates.io time 0.3.20"]],
    ["cargo update --package=time --precise=0.3.20", ["crates.io time 0.3.20"]],
    ["cargo update -p serde -p time && cargo update -p time@0.3.17 --precise 0.3.20", ["crates.io time 0.3.20"]],
    ['cargo add "time@=0.3.20"', ["crates.io time =0.3.20"]],
    ["uv lock --upgrade-package requests==2.25.0", ["PyPI requests ==2.25.0"]],
    ["uv sync --upgrade-package requests==2.25.0", ["PyPI requests ==2.25.0"]],
    ["uv lock -P requests==2.25.0", ["PyPI requests ==2.25.0"]],
    ["uv lock --upgrade-package=requests==2.25.0", ["PyPI requests ==2.25.0"]],
    ['uv pip compile requirements.in -o requirements.txt --upgrade-package "idna==3.15"', ["PyPI idna ==3.15"]],
    ['pip-compile requirements.in --output-file requirements.txt --upgrade-package "idna==3.15" --upgrade-package "urllib3==2.2.2"', ["PyPI idna ==3.15", "PyPI urllib3 ==2.2.2"]],
    ['npm pkg set "overrides.lodash=4.17.20"', ["npm lodash 4.17.20"]],
    ["npm pkg set dependencies.lodash=4.17.20", ["npm lodash 4.17.20"]],
    ['npm pkg set "overrides.express.qs=6.11.0" "devDependencies.@types/node=20.0.0"', ["npm qs 6.11.0", "npm @types/node 20.0.0"]],
    ['npm pkg set "dependencies[lodash.merge]=4.6.2"', ["npm lodash.merge 4.6.2"]],
    ['npm pkg set "resolutions.minimist=1.2.5"', ["npm minimist 1.2.5"]],
    ['npm pkg set "pnpm.overrides.minimist=1.2.5"', ["npm minimist 1.2.5"]],
    ["go mod edit -replace=golang.org/x/net=golang.org/x/net@v0.17.0", ["Go golang.org/x/net v0.17.0"]],
    ["go mod edit -replace golang.org/x/net@v0.20.0=github.com/someone/net@v0.0.1", ["Go github.com/someone/net v0.0.1"]],
    ["go mod edit -require=golang.org/x/net@v0.17.0", ["Go golang.org/x/net v0.17.0"]],
  ])("%s", (command, expected) => {
    expect(read(command)).toEqual(expected);
  });

  it("the same from PowerShell", () => {
    expect(read("uv lock --upgrade-package requests==2.25.0", "powershell")).toEqual(["PyPI requests ==2.25.0"]);
    expect(read("cargo update -p time --precise 0.3.20", "powershell")).toEqual(["crates.io time 0.3.20"]);
  });

  // Round 11: `uv lock --upgrade-package requests` names a package and moves it to its newest release: the request "latest" (a1125-w2-hook-round11.test.ts).
  it("uv lock --upgrade-package <name> is the request latest", () => {
    expect(read("uv lock --upgrade-package requests")).toEqual(["PyPI requests latest"]);
  });

  it("forms that name no version stay unread", () => {
    for (const command of [
      "cargo update",
      "cargo update -p time",
      "npm pkg set name=app",
      "npm pkg set scripts.test=vitest",
      "npm pkg get dependencies.lodash",
      "go mod edit -replace=golang.org/x/net=../net",
      "go mod edit -dropreplace=golang.org/x/net",
    ]) {
      expect(read(command), command).toEqual([]);
    }
  });
});

/**
 * The planner's command templates, by their literal start, with an example as the planner fills
 * it and what the hook reads from it ([] for a template that names no version).
 */
const KNOWN: Record<string, [string, string[]]> = {
  "cargo add ": ['cargo add "time@=0.3.20"', ["crates.io time =0.3.20"]],
  "cargo update -p ": ["cargo update -p time@0.3.17 --precise 0.3.20", ["crates.io time 0.3.20"]],
  "cargo update ": ["cargo update -p serde -p time", []],
  "go get ": ["go get golang.org/x/net@v0.17.0", ["Go golang.org/x/net v0.17.0"]],
  "go mod edit -dropreplace=": ["go mod edit -dropreplace=golang.org/x/net", []],
  "go mod edit -replace=": ["go mod edit -replace=golang.org/x/net=golang.org/x/net@v0.17.0", ["Go golang.org/x/net v0.17.0"]],
  "npm install ": ["npm install lodash@4.17.21 --save-exact", ["npm lodash 4.17.21"]],
  "npm update ": ["npm update lodash", []],
  "npm pkg set ": ['npm pkg set "overrides.lodash=4.17.21"', ["npm lodash 4.17.21"]],
  "pnpm up ": ["pnpm up lodash@4.17.21", ["npm lodash 4.17.21"]],
  "pnpm update ": ["pnpm update lodash --no-save", []],
  "pnpm add ": ['pnpm add -D "lodash@^4.17.21"', ["npm lodash ^4.17.21"]],
  "yarn up ": ["yarn up lodash@4.17.21", ["npm lodash 4.17.21"]],
  "yarn upgrade ": ["yarn upgrade lodash@4.17.21", ["npm lodash 4.17.21"]],
  "yarn workspace ": ["yarn workspace web add lodash@4.17.21", ["npm lodash 4.17.21"]],
  "uv lock --upgrade-package ": ["uv lock --upgrade-package requests==2.25.0", ["PyPI requests ==2.25.0"]],
  "uv pip compile ": ['uv pip compile requirements.in -o requirements.txt --upgrade-package "idna==3.15"', ["PyPI idna ==3.15"]],
  "pip-compile ": ['pip-compile requirements.in --output-file requirements.txt --upgrade-package "idna==3.15"', ["PyPI idna ==3.15"]],
  "pip install --dry-run -r ": ["pip install --dry-run -r requirements.txt", []],
  "poetry update ": ["poetry update requests", []],
};

/** Second words that make a template a sentence about the tool, not a command it runs. */
const PROSE = new Set(["registry", "installs", "took", "would", "answered", "may", "also", "downloads", "replaces"]);

describe("the planner's own command templates", () => {
  const src = join(dirname(fileURLToPath(import.meta.url)), "..");
  const files = [...readdirSync(join(src, "live")).map((f) => join(src, "live", f)), ...readdirSync(join(src, "tools")).map((f) => join(src, "tools", f))].filter((f) => f.endsWith(".ts"));
  const templates = new Set<string>();
  for (const file of files) {
    for (const m of readFileSync(file, "utf8").matchAll(/`((?:npm|pnpm|yarn|bun|cargo|uv|pip|pip-compile|poetry|go) [^`$]*)\$\{/g)) {
      // Sentences that start with a tool's name ("npm installs it from ...") are not commands.
      if (!PROSE.has(m[1].split(" ")[1].replace(/:$/, ""))) templates.add(m[1]);
    }
  }

  it("finds the templates (the reader of the sources still works)", () => {
    expect(templates.size).toBeGreaterThan(10);
  });

  it("each one is a shape this table knows, and the hook reads what the table says", () => {
    const unknown = [...templates].filter((t) => !Object.keys(KNOWN).some((k) => t === k || t.startsWith(k) || k.startsWith(t)));
    expect(unknown).toEqual([]);
    for (const [example, expected] of Object.values(KNOWN)) expect(read(example), example).toEqual(expected);
  });
});
