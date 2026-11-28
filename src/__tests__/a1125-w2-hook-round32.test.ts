// SPDX-License-Identifier: Apache-2.0
/**
 * Round 32 of the hook lane (sentence check 28): on a command the hook examines, the sub-command
 * path is read only from SUBCOMMAND_PATHS / NO_PACKAGE_SUBCOMMANDS (F1, F5); CONFIG_SOURCE_OPTIONS
 * are held wherever they stand (F2); npm's command words in their written case (F3); uv's
 * --no-sources held (F4); a Poetry path source maps its [project] requirement as uv's does.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ACCOUNT_TABLES, CONFIG_SOURCE_OPTIONS, NAMED_OPTIONS, NO_PACKAGE_SUBCOMMANDS, SUBCOMMAND_PATHS, VERBS, detectsInstall } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const FIXTURE = JSON.parse(readFileSync(join(__dirname, "fixtures", "a1125-subcommands.json"), "utf8")) as Record<string, { version: string; commands: string[] }>;

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "six", version: "1.16.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "regex", version: "1.5.4", requested: "=1.5.4", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "Go", package: "golang.org/x/text", version: "v0.3.0", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());

const bash = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("F1, F5: a sub-command path on no table is not read", () => {
  it.each(["pnpm pkg set dependencies.lodash=4.17.20", "bun pm pkg set dependencies.lodash=4.17.20", "npm pkg set dependencies.lodash=4.17.20", "pnpm store add lodash@4.17.20", "npm cache add lodash@4.17.20"])("%s: judged on the avoid", (command) => {
    expect(bash(command).text).toContain("answered avoid");
  });
  it.each(['uv tool upgrade "django==3.0.0"', "uv export -P $X", "poetry self add requests==2.19.0", "poetry self update", "npm frobnicate lodash@4.17.20 install", "pnpm frob add lodash@4.17.20"])("%s: held", (command) => {
    expect(bash(command).decision).toBe("deny");
  });
  it.each(["npm run x", "pnpm --filter a run build", "uv tool upgrade --all", "poetry self show", "go mod tidy", "bun pm ls", "npm pkg get name", "npm view lodash@4.17.20 version", "npm run add", "cargo build"])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
  // The generated check: every sub-command each tool's help lists, followed by a package with an
  // avoid verdict, and by a variable: each examined command is judged, held, or on a table.
  const PACKAGE: Record<string, string> = { npm: "lodash@4.17.20", pnpm: "lodash@4.17.20", yarn: "lodash@4.17.20", bun: "lodash@4.17.20", pip: "requests==2.19.0", uv: "requests==2.19.0", poetry: "requests==2.19.0", cargo: "regex@=1.5.4", go: "golang.org/x/text@v0.3.0" };
  for (const [manager, { version, commands }] of Object.entries(FIXTURE)) {
    if (manager === "note") continue;
    for (const sub of commands) {
      for (const tail of [PACKAGE[manager], "$X"]) {
        const command = `${manager} ${sub} ${tail}`;
        it(`${manager} ${version}: ${command}`, () => {
          const r = bash(command);
          if (r.decision === "deny") return;
          const tabled = Object.hasOwn(NO_PACKAGE_SUBCOMMANDS[manager] ?? {}, sub) || Object.hasOwn(SUBCOMMAND_PATHS[manager] ?? {}, sub);
          // A verb on VERBS is read by its manager's reader (one that takes no package names none).
          const verb = ((VERBS as Record<string, readonly string[]>)[manager] ?? []).includes(sub);
          // Not denied: the sub-command is on a table, or the hook does not examine the command (P1).
          expect(tabled || verb || !detectsInstall(command), `${command} went ahead by falling through`).toBe(true);
        });
      }
    }
  }
  it("each NO_PACKAGE_SUBCOMMANDS entry carries its help line", () => {
    for (const subs of Object.values(NO_PACKAGE_SUBCOMMANDS)) for (const line of Object.values(subs)) expect(String(line).length).toBeGreaterThan(2);
  });
});

describe("F2: a CONFIG_SOURCE_OPTIONS option is held wherever it stands, and is on no reader table", () => {
  it.each(["poetry add -C ../other six==1.16.0", "poetry install -P ..", "poetry lock -C ..", "poetry lock --directory=..", "poetry add six==1.16.0 --project ../x", "poetry -C .. install"])("%s: held", (command) => {
    expect(bash(command).text).toContain("could not be read");
  });
  it("poetry run's own program keeps its options", () => {
    expect(bash("poetry run pytest -C x").decision).toBe("allow");
  });
  it("no option is on CONFIG_SOURCE_OPTIONS and on an account or named-option table", () => {
    const tables: Record<string, string[]> = { uv: ["uvpip", "uvtool", "uvadd"], cargo: ["cargo"], poetry: ["poetry"], yarn: ["yarn"], bun: ["bun"], go: ["go", "gomodedit"], pnpm: ["pnpm"] };
    const both: string[] = [];
    for (const [manager, options] of Object.entries(CONFIG_SOURCE_OPTIONS as Record<string, readonly string[]>)) {
      for (const t of tables[manager] ?? []) for (const o of options) if ((ACCOUNT_TABLES as Record<string, ReadonlyMap<string, number>>)[t]?.has(o)) both.push(`${t} ${o}`);
      for (const [key, rows] of Object.entries(NAMED_OPTIONS as Record<string, [string, string][]>)) {
        if (!key.startsWith(manager)) continue;
        for (const [spec] of rows) for (const w of spec.split(" ")) if (options.includes(w.replace(/[=?]$/, ""))) both.push(`${key} ${w}`);
      }
    }
    expect(both).toEqual([]);
  });
});

describe("F3: npm's command words are read in the case they are written", () => {
  it.each(["npm installTest $X", "npm installTest lodash@4.17.20", "npm installTest @types/node@$V"])("%s: held or judged", (command) => {
    expect(bash(command).decision).toBe("deny");
  });
  it("PowerShell too", () => {
    expect(bash("npm installTest @X", "PowerShell").decision).toBe("deny");
  });
});

describe("F4: uv's --no-sources is held as a release-picking option", () => {
  it.each(["uv sync --no-sources", "uv lock --no-sources", "uv add --no-sources requests==2.31.0", "uv run --no-sources pytest", "uvx --no-sources ruff"])("%s: held", (command) => {
    expect(bash(command).text).toContain("--no-sources");
  });
  it.each(["uv run pytest --no-sources", "uvx ruff --no-sources", "uv sync"])("%s goes ahead (the option is the program's, or absent)", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});

describe("the Poetry path source maps its [project] requirement as a uv source does", () => {
  const P = (dep: string) => `[project]\nname = "a"\nversion = "0.1.0"\ndependencies = ["${dep}"]\n[tool.poetry.dependencies]\n${dep.split(/[=<>]/)[0]} = { path = "../x" }\n`;
  it("an avoid on record denies; no verdict goes ahead", () => {
    expect(s.write(join(s.project, "pyproject.toml"), P("requests==2.19.0")).text).toContain("answered avoid");
    expect(s.write(join(s.project, "pyproject.toml"), P("mylib==0.3.0")).decision).toBe("allow");
  });
});
