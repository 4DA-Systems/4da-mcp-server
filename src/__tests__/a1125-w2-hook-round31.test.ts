// SPDX-License-Identifier: Apache-2.0
/**
 * Round 31 of the hook lane (sentence check 27): a requirement a uv source maps to the project's
 * own source is still denied by an avoid or wait verdict on record (K1), one rule for the table and
 * inline spellings of [tool.uv.sources]; an OWN_SOURCE_FORMS value is read before the dist-tag test
 * (K2); the expansion sentence names the verb lists (K3).
 */

import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "six", version: "1.16.0", verdict: "wait", reason: "test wait" },
    { ecosystem: "PyPI", package: "httpx", version: "0.27.2", verdict: "proceed" },
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());

const P = (deps: string, rest: string) => `[project]\nname = "a"\nversion = "0.1.0"\ndependencies = [${deps}]\n${rest}`;
const bash = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("K1: a requirement a uv source maps is denied by an avoid or wait verdict on record", () => {
  const sources: Array<[string, (name: string) => string]> = [
    ["the table form", (n) => `[tool.uv.sources]\n${n} = { path = "../${n}" }\n`],
    ["the dotted table form", (n) => `[tool.uv.sources.${n}]\npath = "../${n}"\n`],
    ["an inline table under [tool.uv]", (n) => `[tool.uv]\nsources = { ${n} = { path = "../${n}" } }\n`],
    ["an inline table under [tool]", (n) => `[tool]\nuv = { sources = { ${n} = { git = "https://github.com/x/${n}" } } }\n`],
    ["workspace = true", (n) => `[tool.uv.sources]\n${n} = { workspace = true }\n`],
  ];
  for (const [label, src] of sources) {
    it(`${label}: avoid denies`, () => {
      expect(s.write(join(s.project, "pyproject.toml"), P('"requests==2.19.0"', src("requests"))).text).toContain("answered avoid");
    });
    it(`${label}: wait denies`, () => {
      expect(s.write(join(s.project, "pyproject.toml"), P('"six==1.16.0"', src("six"))).text).toContain("answered wait");
    });
    it(`${label}: proceed, or no verdict, goes ahead`, () => {
      expect(s.write(join(s.project, "pyproject.toml"), P('"httpx==0.27.2"', src("httpx"))).decision).toBe("allow");
      expect(s.write(join(s.project, "pyproject.toml"), P('"mylib>=0.3.0"', src("mylib"))).decision).toBe("allow");
    });
  }
  it("an optional-dependency and a dependency-group entry the source maps: the same rule", () => {
    const src = '[tool.uv.sources]\nrequests = { path = "../r" }\n';
    expect(s.write(join(s.project, "pyproject.toml"), `[project]\nname = "a"\nversion = "0.1.0"\n[project.optional-dependencies]\nx = ["requests==2.19.0"]\n${src}`).text).toContain("answered avoid");
    expect(s.write(join(s.project, "pyproject.toml"), `[project]\nname = "a"\nversion = "0.1.0"\n[dependency-groups]\ndev = ["requests==2.19.0"]\n${src}`).text).toContain("answered avoid");
  });
  it("without the source the avoid denies too (control)", () => {
    expect(s.write(join(s.project, "pyproject.toml"), P('"requests==2.19.0"', "")).text).toContain("answered avoid");
  });
});

describe("K2: every OWN_SOURCE_FORMS value written without ./ is the project's own", () => {
  it.each(["lodash-4.17.20.tgz", "lodash-4.17.20.tar.gz", "lodash-4.17.20.tar", "lodash/lodash", "lodash/lodash#4.17.20", "file:lodash-4.17.20.tgz", "link:lodash", "workspace:*", "catalog:", "github:lodash/lodash"])("%s goes ahead", (value) => {
    expect(s.write(s.file("package.json", '{"name":"p"}'), JSON.stringify({ name: "p", dependencies: { lodash: value } })).decision).toBe("allow");
  });
  it.each(["https://files.example.com/lodash-4.17.20.tgz", "beta", "4.17.20"])("%s is not: a URL, a tag, an avoided version", (value) => {
    expect(s.write(s.file("package.json", '{"name":"p"}'), JSON.stringify({ name: "p", dependencies: { lodash: value } })).decision).toBe("deny");
  });
});

describe("K3: the expansion sentence follows the verb lists", () => {
  it.each(["pnpm install $X", "yarn install $X", "bun install $X", "uv sync $X", "npm install $X"])("%s: a verb on VERBS: held", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
  it.each(["npm ci $X", "npm rebuild $X", "npm run build -- $X"])("%s: a verb on none of the lists: goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});
