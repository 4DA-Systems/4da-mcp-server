// SPDX-License-Identifier: Apache-2.0
/**
 * Round 33 of the hook lane (sentence check 29): the four sub-command blockers fixed exactly (npm
 * explore, a whole command line given to a runner as one word, yarn global upgrade, bun pm pkg set
 * with an object value), every word under a SUBCOMMAND_PATHS entry reaching a reader, a uv url
 * source at a public registry file read as that release whichever line is new, and the minors.
 */

import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { PATH_NO_PACKAGE, SUBCOMMAND_PATHS } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "six", version: "1.16.0", verdict: "proceed" },
    { ecosystem: "crates.io", package: "regex", version: "1.5.4", requested: "=1.5.4", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "Go", package: "golang.org/x/text", version: "v0.3.0", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());

const bash = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("T1: the four blockers", () => {
  for (const tool of ["Bash", "PowerShell"]) {
    it.each([
      "npm explore ms -- npm install lodash@4.17.20",
      'bun exec "npm install lodash@4.17.20"',
      'pnpm exec "npm install lodash@4.17.20"',
      'pnpm -r exec "npm install lodash@4.17.20"',
      'yarn exec "npm install lodash@4.17.20"',
      'yarn workspace a exec "npm install lodash@4.17.20"',
      'npx "npm install lodash@4.17.20"',
      "yarn global upgrade lodash@4.17.20",
      "yarn global up lodash@4.17.20",
      "bun pm pkg set dependencies.lodash=4.17.20",
    ])(`${tool} %s: denied`, (command) => {
      expect(bash(command, tool).decision).toBe("deny");
    });
  }
  it.each([`bun pm pkg set dependencies='{"lodash":"4.17.20"}' --json`, 'bun pm pkg set "dependencies.lodash = 4.17.20"', `npm pkg set dependencies='{"lodash":"4.17.20"}' --json`, `pnpm pkg set dependencies='{"lodash":"4.17.20"}' --json`])("%s: held, as npm's is", (command) => {
    expect(bash(command).decision).toBe("deny");
  });
  it.each(["npm explore ms", "pnpm exec eslint .", "bun exec echo hi", "yarn exec tsc", "bun pm pkg get name"])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});

describe("T1: every word under a SUBCOMMAND_PATHS entry reaches a reader, or names no release", () => {
  const PKG: Record<string, string> = { npm: "lodash@4.17.20", pnpm: "lodash@4.17.20", yarn: "lodash@4.17.20", bun: "lodash@4.17.20", pip: "requests==2.19.0", uv: "requests==2.19.0", poetry: "requests==2.19.0", cargo: "regex@=1.5.4", go: "golang.org/x/text@v0.3.0" };
  // The form each reader reads its package in, where it is not the bare operand.
  const FORM: Record<string, string> = { "npm pkg set": "dependencies.lodash=4.17.20", "pnpm pkg set": "dependencies.lodash=4.17.20", "bun pm pkg": "set dependencies.lodash=4.17.20", "go mod edit": "-require=golang.org/x/text@v0.3.0", "go work edit": "-require=golang.org/x/text@v0.3.0", "go mod download": "golang.org/x/text@v0.3.0", "pip config set": "global.index-url https://evil.example.cn/simple", "uv tool run": "requests==2.19.0" };
  for (const [manager, paths] of Object.entries(SUBCOMMAND_PATHS as Record<string, Record<string, string[] | "*">>)) {
    for (const [path, words] of Object.entries(paths)) {
      if (words === "*") continue;
      for (const w of words) {
        const key = `${manager} ${path} ${w}`;
        it(key, () => {
          if (PATH_NO_PACKAGE.has(key)) return;
          const command = `${key} ${FORM[key] ?? PKG[manager]}`;
          expect(bash(command).decision, `${command} fell through`).toBe("deny");
        });
      }
    }
  }
});

describe("T3: a uv url source at a public registry file is that release, whichever line is new", () => {
  const URL = "https://files.pythonhosted.org/packages/cc/15/e1c318dbc20032ffbe5628837ca0de2d5b116ffd1b849c699634010f6a5d/requests-2.19.0-py2.py3-none-any.whl";
  const P = (deps: string, source: boolean) => `[project]\nname = "p"\nversion = "0.1.0"\ndependencies = [${deps}]\n${source ? `\n[tool.uv.sources]\nrequests = { url = "${URL}" }\n` : ""}`;
  it("the source on disk first, then an edit adds the requirement", () => {
    const f = s.file("pyproject.toml", P('"six==1.16.0"', true));
    expect(s.edit(f, '"six==1.16.0"', '"six==1.16.0", "requests"').text).toContain("answered avoid");
  });
  it("the requirement on disk first, then an edit adds the source", () => {
    const f = s.file("pyproject.toml", P('"six==1.16.0", "requests"', false));
    expect(s.write(f, P('"six==1.16.0", "requests"', true)).text).toContain("answered avoid");
  });
  it("both in one edit", () => {
    const f = s.file("pyproject.toml", P('"six==1.16.0"', false));
    expect(s.write(f, P('"six==1.16.0", "requests"', true)).text).toContain("answered avoid");
  });
  it("a Poetry url dependency at a registry file is judged; a git one is the project's own", () => {
    const head = '[tool.poetry]\nname = "t"\nversion = "0.1.0"\n[tool.poetry.dependencies]\n';
    expect(s.write(s.file("pyproject.toml", head), `${head}requests = { url = "${URL}" }\n`).text).toContain("answered avoid");
    expect(s.write(s.file("pyproject.toml", head), `${head}requests = { git = "https://github.com/psf/requests" }\n`).decision).toBe("allow");
  });
});

describe("T4: the minors", () => {
  it.each(["poetry -Psub show", "poetry show -Psub", "poetry -Csub run pytest", "poetry run -Csub pytest", "poetry install -Csub", "bun install -cbunfig.toml"])("%s: an attached short value is held", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
  it("uv run --with-requirements reads the file", () => {
    s.file("rq.txt", "requests==2.19.0\n");
    s.file("ok.txt", "six==1.16.0\n");
    expect(bash("uv run --with-requirements rq.txt python -c 1").text).toContain("answered avoid");
    expect(bash("uv run --with-requirements ok.txt python -c 1").decision).toBe("allow");
  });
  it.each(["uv export --format requirements-txt", "uv export -o requirements.txt", "uv export --format requirements-txt -o r.txt --no-hashes --no-header"])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
  it("uv export -P is still judged", () => {
    expect(bash("uv export -P requests==2.19.0").text).toContain("answered avoid");
  });
});

void join;
