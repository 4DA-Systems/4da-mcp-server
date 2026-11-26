// SPDX-License-Identifier: Apache-2.0
/**
 * The plugin hook as a guard (hooks/manifest-edit.mjs, PreToolUse): before an edit or an install
 * command writes a dependency version, it reads the check ledger dependency_check writes in the
 * data folder, and denies a version that has no recent verdict or whose verdict is avoid, naming
 * the call to make. Run the way Claude Code runs it: a separate Node process, the payload on stdin,
 * the decision as JSON on stdout (https://code.claude.com/docs/en/hooks, PreToolUse decision
 * control). It used to run only after the edit (PostToolUse), could never block, and never saw a
 * Write, a pnpm catalog, a requirements-*.txt or any install command.
 */

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { dataDir, installsIn, poetryToPep440, simpleCommands } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE, recordVerdicts, type LedgerEntry } from "../check-ledger.js";
import { serverDataDir, type FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { runDependencyCheck } from "../tools/dependency-check.js";
import { parseTarget } from "../tools/dependency-check-versions.js";
import { emptyNet, npmDoc, onlineForTests, stubNet } from "./helpers/a1119-check-net.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const HOOK = join(root, "hooks", "manifest-edit.mjs");
const HOUR = 3_600_000;

let home: string;
let project: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "a1123-guard-home-"));
  project = mkdtempSync(join(tmpdir(), "a1123-guard-project-"));
  // A server from 6.5.0 on starts the ledger when it starts, and the hook denies only where one
  // exists (a1123-skew-guard-older-server.test.ts has the folder without one).
  writeFileSync(join(home, LEDGER_FILE), "");
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(project, { recursive: true, force: true });
});

/** Run the hook on `payload` with the data folder `home` (FOURDA_GUARD unset unless given). */
function hook(payload: unknown, extraEnv: Record<string, string> = {}): { status: number | null; stdout: string } {
  const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: home, ...extraEnv };
  if (!("FOURDA_GUARD" in extraEnv)) delete env.FOURDA_GUARD;
  const res = spawnSync(process.execPath, [HOOK], { input: typeof payload === "string" ? payload : JSON.stringify(payload), encoding: "utf8", timeout: 20_000, env });
  return { status: res.status, stdout: res.stdout };
}

const pre = (tool_name: string, tool_input: Record<string, unknown>) => ({
  session_id: "s",
  transcript_path: "/tmp/t.jsonl",
  cwd: project,
  permission_mode: "default",
  hook_event_name: "PreToolUse",
  tool_name,
  tool_input,
  tool_use_id: "toolu_1",
});
const bash = (command: string) => pre("Bash", { command, description: "install" });

/** The hook's decision: null when it let the call go ahead (exit 0, no output). */
function decision(out: { status: number | null; stdout: string }): { permissionDecision: string; permissionDecisionReason: string } | null {
  expect(out.status).toBe(0);
  if (out.stdout === "") return null;
  const parsed = JSON.parse(out.stdout) as { hookSpecificOutput: { hookEventName: string; permissionDecision: string; permissionDecisionReason: string } };
  expect(parsed.hookSpecificOutput.hookEventName).toBe("PreToolUse");
  return parsed.hookSpecificOutput;
}
const denied = (out: { status: number | null; stdout: string }): string => {
  const d = decision(out);
  expect(d?.permissionDecision).toBe("deny");
  return d!.permissionDecisionReason;
};
const allowed = (out: { status: number | null; stdout: string }) => expect(decision(out)).toBeNull();

/** The dependency_check call a denial names. */
function callIn(reason: string): { items: Array<Record<string, string>> } {
  const m = /dependency_check (\{"items":.*?\]\})/.exec(reason);
  expect(m, reason).not.toBeNull();
  return JSON.parse(m![1]) as { items: Array<Record<string, string>> };
}

function ledger(entries: Array<Partial<LedgerEntry> & { package: string; version: string; verdict: string }>, ageMs = 60_000) {
  const t = new Date(Date.now() - ageMs).toISOString();
  writeFileSync(join(home, LEDGER_FILE), entries.map((e) => JSON.stringify({ t, ecosystem: "npm", ...e })).join("\n") + "\n");
}

/** A package.json on disk and an Edit of lodash's version in it. */
function lodashEdit(to: string, from = "4.17.21") {
  const file = join(project, "package.json");
  writeFileSync(file, `{\n  "name": "app",\n  "dependencies": {\n    "lodash": "${from}"\n  }\n}\n`);
  return pre("Edit", { file_path: file, old_string: `"lodash": "${from}"`, new_string: `"lodash": "${to}"`, replace_all: false });
}

describe("registration", () => {
  const hooks = JSON.parse(readFileSync(join(root, "hooks", "hooks.json"), "utf8")) as { hooks: Record<string, Array<{ matcher: string; hooks: Array<Record<string, unknown>> }>> };

  it("runs before Edit, MultiEdit, Write, NotebookEdit, Bash and PowerShell, and a hook that cannot run never blocks", () => {
    const [entry] = hooks.hooks.PreToolUse;
    expect(entry.matcher.split("|").sort()).toEqual(["Bash", "Edit", "MultiEdit", "NotebookEdit", "PowerShell", "Write"]);
    expect(entry.hooks[0]).toMatchObject({ type: "command", onFailure: "continue" });
    expect(String(entry.hooks[0].command)).toContain("${CLAUDE_PLUGIN_ROOT}/hooks/manifest-edit.mjs");
  });

  it("keeps the after-edit advice registration for FOURDA_GUARD=advise", () => {
    const [entry] = hooks.hooks.PostToolUse;
    expect(entry.matcher.split("|").sort()).toEqual(["Edit", "MultiEdit", "Write"]);
    expect(entry.hooks[0]).toMatchObject({ type: "command", onFailure: "continue" });
  });
});

describe("an exact version, by what the ledger holds", () => {
  it("no verdict: denied, naming the exact call, which the edit passes once it answers proceed", () => {
    const reason = denied(hook(lodashEdit("4.17.20")));
    expect(callIn(reason)).toEqual({ items: [{ ecosystem: "npm", package: "lodash", to: "4.17.20", from: "4.17.21" }] });
    expect(reason).toContain("will pass once that call answers proceed");
  });

  it("proceed or review within 24 hours: goes ahead silently", () => {
    ledger([{ package: "lodash", version: "4.17.20", verdict: "proceed" }]);
    allowed(hook(lodashEdit("4.17.20")));
    ledger([{ package: "lodash", version: "4.17.20", verdict: "review", reason: "major upgrade" }]);
    allowed(hook(lodashEdit("4.17.20")));
  });

  it("avoid: denied with the verdict's reason", () => {
    ledger([{ package: "lodash", version: "4.17.20", verdict: "avoid", reason: "GHSA-35jh-r3h4-6jhm (high) affects 4.17.20; safe: 4.18.1." }]);
    const reason = denied(hook(lodashEdit("4.17.20")));
    expect(reason).toContain("dependency_check answered avoid");
    expect(reason).toContain("GHSA-35jh-r3h4-6jhm (high) affects 4.17.20; safe: 4.18.1.");
    expect(reason).not.toContain('{"items"');
  });

  it("wait: denied with the verdict's reason", () => {
    ledger([{ package: "lodash", version: "4.17.20", verdict: "wait", reason: "released 1 day ago" }]);
    expect(denied(hook(lodashEdit("4.17.20")))).toContain("dependency_check answered wait at");
  });

  it("the latest verdict for the version counts", () => {
    const t = (ms: number) => new Date(Date.now() - ms).toISOString();
    writeFileSync(
      join(home, LEDGER_FILE),
      [
        { t: t(2 * HOUR), ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "proceed" },
        { t: t(HOUR), ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "a new advisory" },
      ]
        .map((e) => JSON.stringify(e))
        .join("\n"),
    );
    expect(denied(hook(lodashEdit("4.17.20")))).toContain("a new advisory");
  });

  it("a verdict older than 24 hours does not count", () => {
    ledger([{ package: "lodash", version: "4.17.20", verdict: "proceed" }], 25 * HOUR);
    expect(callIn(denied(hook(lodashEdit("4.17.20")))).items[0]).toMatchObject({ package: "lodash", to: "4.17.20" });
  });

  it("an unknown verdict is not a verdict: denied with the call, and the last answer named", () => {
    ledger([{ package: "lodash", version: "4.17.20", verdict: "unknown", reason: "NOT CHECKED (time budget): ...", not_checked: "time_budget" }]);
    const reason = denied(hook(lodashEdit("4.17.20")));
    expect(reason).toContain("the last dependency_check answer was unknown");
    expect(callIn(reason).items).toHaveLength(1);
  });

  it("a package a private-registry rule covers goes ahead (it is never looked up), as in 6.5.0; one a project takes from elsewhere is held", () => {
    ledger([{ package: "lodash", version: "1.0.0", verdict: "unknown", not_checked: "private" }]);
    allowed(hook(lodashEdit("4.17.20")));
    // A git, path, workspace or alias source does not apply to the registry release (a651-hook-withheld.test.ts).
    ledger([{ package: "lodash", version: "1.0.0", verdict: "unknown", not_checked: "local_source" }]);
    expect(denied(hook(lodashEdit("4.17.20")))).toContain("from the public registry, which was not checked");
  });

  it("another version's verdict does not count for this one", () => {
    ledger([{ package: "lodash", version: "4.18.1", verdict: "proceed" }]);
    expect(callIn(denied(hook(lodashEdit("4.17.20")))).items[0].to).toBe("4.17.20");
  });

  it("an empty ledger says where it looked, and that FOURDA_GUARD is the user's setting, not the agent's", () => {
    const reason = denied(hook(lodashEdit("4.17.20")));
    expect(reason).toContain(home);
    expect(reason).toContain("FOURDA_GUARD (advise, off) is the user's setting: tell the user, and do not change it yourself");
  });
});

describe("a range or constraint", () => {
  it("is denied with the call for that constraint only when the package has no verdict at all", () => {
    const reason = denied(hook(lodashEdit("^4.17.0", "4.17.21")));
    expect(callIn(reason).items[0]).toEqual({ ecosystem: "npm", package: "lodash", to: "^4.17.0", from: "4.17.21" });
  });

  it("goes ahead on a proceed for that same constraint, not on one for another (a651-hook-ranges.test.ts)", () => {
    ledger([{ package: "lodash", version: "4.18.1", verdict: "proceed", requested: "^4.18.0" }]);
    expect(callIn(denied(hook(lodashEdit("^4.17.0")))).items[0].to).toBe("^4.17.0");
    ledger([{ package: "lodash", version: "4.18.1", verdict: "proceed", requested: "^4.17.0" }]);
    allowed(hook(lodashEdit("^4.17.0")));
  });

  it("is denied when that same constraint's last verdict was avoid", () => {
    ledger([{ package: "lodash", version: "4.17.21", verdict: "avoid", requested: "^4.17.0", reason: "no release in ^4.17.0 is free of known advisories" }]);
    expect(denied(hook(lodashEdit("^4.17.0")))).toContain("no release in ^4.17.0 is free of known advisories");
  });
});

describe("modes", () => {
  it("FOURDA_GUARD=advise never denies, and advises after the edit as before", () => {
    const payload = lodashEdit("4.17.20");
    allowed(hook(payload, { FOURDA_GUARD: "advise" }));
    writeFileSync(String(payload.tool_input.file_path), '{\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}\n');
    const after = hook({ ...payload, hook_event_name: "PostToolUse" }, { FOURDA_GUARD: "advise" });
    const out = JSON.parse(after.stdout) as { hookSpecificOutput: { hookEventName: string; additionalContext: string } };
    expect(out.hookSpecificOutput.hookEventName).toBe("PostToolUse");
    expect(out.hookSpecificOutput.additionalContext).toContain("\"lodash\": \"4.17.21\" -> \"4.17.20\"");
  });

  it("FOURDA_GUARD=off does nothing, before or after", () => {
    const payload = lodashEdit("4.17.20");
    expect(hook(payload, { FOURDA_GUARD: "off" })).toEqual({ status: 0, stdout: "" });
    expect(hook({ ...payload, hook_event_name: "PostToolUse" }, { FOURDA_GUARD: "off" })).toEqual({ status: 0, stdout: "" });
    expect(hook(bash("npm install lodash@4.17.20"), { FOURDA_GUARD: "off" })).toEqual({ status: 0, stdout: "" });
  });

  it("by default the after-edit call says nothing (the guard already ran before it)", () => {
    expect(hook({ ...lodashEdit("4.17.20"), hook_event_name: "PostToolUse" })).toEqual({ status: 0, stdout: "" });
  });
});

describe("it fails open", () => {
  it("a data folder that does not exist: the server never ran there, so nothing is held", () => {
    home = join(home, "never-created");
    allowed(hook(lodashEdit("4.17.20")));
    allowed(hook(bash("npm install lodash@4.17.20")));
  });

  it("input it does not understand: exit 0, no output", () => {
    for (const payload of ["", "[]", "null", { hook_event_name: "PreToolUse" }, { hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: "x" }, { tool_name: "Bash", tool_input: { command: "npm i lodash@4.17.20" } }, pre("Read", { file_path: "package.json" }), pre("Bash", { command: 42 }), pre("Edit", { file_path: 7 })]) {
      expect(hook(payload), JSON.stringify(payload)).toEqual({ status: 0, stdout: "" });
    }
  });

  // Round 13: a payload that does not parse at all is held where a ledger exists (eleventh independent check, S31).
  it("a payload that does not parse is held", () => {
    expect(hook("not json").stdout).toContain("could not read it");
  });

  it("garbage and torn lines in the ledger are skipped; the good ones after them still count", () => {
    writeFileSync(join(home, LEDGER_FILE), `not json\n{"t":"x"}\n{"t":"2026\n{"t":"${new Date().toISOString()}","ecosystem":"npm","package":"lodash","version":"4.17.20","verdict":"proceed"}\n`);
    allowed(hook(lodashEdit("4.17.20")));
  });

  // Round 14 (R9, S35): a line cut before its package could have been any package's answer: the
  // lines before it no longer count (a proceed before it does not stand in for it).
  it("a torn line after a proceed, cut before its package: the proceed no longer counts", () => {
    writeFileSync(join(home, LEDGER_FILE), `{"t":"${new Date().toISOString()}","ecosystem":"npm","package":"lodash","version":"4.17.20","verdict":"proceed"}\n{"t":"2026`);
    denied(hook(lodashEdit("4.17.20")));
  });

  it("an edit that changes no dependency version, or a file that is not a manifest, says nothing", () => {
    const file = join(project, "package.json");
    writeFileSync(file, '{\n  "name": "app",\n  "dependencies": {\n    "lodash": "4.17.21"\n  }\n}\n');
    allowed(hook(pre("Edit", { file_path: file, old_string: '"name": "app"', new_string: '"name": "web"' })));
    allowed(hook(pre("Edit", { file_path: join(project, "src", "main.ts"), old_string: "a", new_string: '"lodash": "4.17.20"' })));
  });
});

describe("whole-file Write", () => {
  it("a new manifest: every version it declares is held to the ledger", () => {
    const reason = denied(hook(pre("Write", { file_path: join(project, "package.json"), content: '{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.20"},"devDependencies":{"vite":"^7.0.0"}}' })));
    expect(callIn(reason).items).toEqual([
      { ecosystem: "npm", package: "lodash", to: "4.17.20" },
      { ecosystem: "npm", package: "vite", to: "^7.0.0" },
    ]);
  });

  it("rewriting a manifest: only the versions that change are held", () => {
    const file = join(project, "Cargo.toml");
    writeFileSync(file, '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0.200"\ntokio = { version = "1.40", features = ["full"] }\n');
    allowed(hook(pre("Write", { file_path: file, content: '[package]\nname = "app"\nversion = "0.2.0"\n\n[dependencies]\nserde = "1.0.200"\ntokio = { version = "1.40", features = ["full"] }\n' })));
    const reason = denied(hook(pre("Write", { file_path: file, content: '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0.210"\ntokio = { version = "1.40", features = ["full"] }\n' })));
    expect(callIn(reason).items).toEqual([{ ecosystem: "crates.io", package: "serde", to: "1.0.210", from: "1.0.200" }]);
  });
});

describe("edits are applied to the file as the tool will apply them", () => {
  it("a MultiEdit's edits in order, each version it introduces held", () => {
    const file = join(project, "package.json");
    writeFileSync(file, '{\n  "dependencies": {\n    "vite": "^6.0.0",\n    "@tauri-apps/api": "2.11.1"\n  }\n}\n');
    const items = callIn(
      denied(
        hook(
          pre("MultiEdit", {
            file_path: file,
            edits: [
              { old_string: '"vite": "^6.0.0"', new_string: '"vite": "^7.0.0"' },
              { old_string: '"@tauri-apps/api": "2.11.1"', new_string: '"@tauri-apps/api": "2.12.0"' },
            ],
          }),
        ),
      ),
    ).items;
    expect(items).toEqual([
      { ecosystem: "npm", package: "vite", to: "^7.0.0" },
      { ecosystem: "npm", package: "@tauri-apps/api", to: "2.12.0", from: "2.11.1" },
    ]);
  });

  it("a manifest with CRLF line endings, edited with LF text, and an edit that shows no section", () => {
    const file = join(project, "Cargo.toml");
    writeFileSync(file, '[package]\r\nname = "app"\r\nversion = "0.1.0"\r\n\r\n[dependencies]\r\nserde = "1.0.200"\r\n');
    expect(callIn(denied(hook(pre("Edit", { file_path: file, old_string: 'serde = "1.0.200"\n', new_string: 'serde = "1.0.210"\n' })))).items).toEqual([
      { ecosystem: "crates.io", package: "serde", to: "1.0.210", from: "1.0.200" },
    ]);
    // The package's own version is not a dependency, though the edit does not show its table.
    allowed(hook(pre("Edit", { file_path: file, old_string: 'version = "0.1.0"', new_string: 'version = "0.2.0"' })));
  });
});

describe("a very large manifest is answered, not timed out", () => {
  it("a Write of 40,000 dependencies against a full ledger names the first 25 and counts the rest", () => {
    const t = new Date().toISOString();
    writeFileSync(join(home, LEDGER_FILE), Array.from({ length: 4000 }, (_, i) => JSON.stringify({ t, ecosystem: "npm", package: `other-${i}`, version: "1.0.0", verdict: "proceed" })).join("\n"));
    const deps = Object.fromEntries(Array.from({ length: 40_000 }, (_, i) => [`pkg-${i}`, `1.0.${i}`]));
    const reason = denied(hook(pre("Write", { file_path: join(project, "package.json"), content: JSON.stringify({ name: "app", dependencies: deps }, null, 2) })));
    expect(callIn(reason).items).toHaveLength(25);
    expect(reason).toContain("this edit names 40000, so call again for the rest");
  });
});

describe("manifests the hook did not read before", () => {
  it("pnpm-workspace.yaml: catalog, named catalogs and overrides", () => {
    const file = join(project, "pnpm-workspace.yaml");
    const before = "packages:\n  - apps/*\ncatalog:\n  react: ^18.2.0\n  '@types/node': 20.11.0\ncatalogs:\n  legacy:\n    react: ^17.0.2\noverrides:\n  qs: 6.11.0\n";
    writeFileSync(file, before);
    const after = before.replace("'@types/node': 20.11.0", "'@types/node': 20.12.0").replace("    react: ^17.0.2", "    react: ^17.0.3").replace("qs: 6.11.0", "qs: 6.14.1");
    const items = callIn(denied(hook(pre("Write", { file_path: file, content: after })))).items;
    expect(items).toEqual([
      { ecosystem: "npm", package: "@types/node", to: "20.12.0", from: "20.11.0" },
      { ecosystem: "npm", package: "react", to: "^17.0.3" },
      { ecosystem: "npm", package: "qs", to: "6.14.1", from: "6.11.0" },
    ]);
  });

  it("requirements-dev.txt and requirements/base.txt", () => {
    const dev = join(project, "requirements-dev.txt");
    writeFileSync(dev, "pytest==8.0.0\n");
    expect(callIn(denied(hook(pre("Edit", { file_path: dev, old_string: "pytest==8.0.0", new_string: "pytest==8.3.4" })))).items).toEqual([
      { ecosystem: "PyPI", package: "pytest", to: "8.3.4", from: "8.0.0" },
    ]);
    mkdirSync(join(project, "requirements"));
    const base = join(project, "requirements", "base.txt");
    writeFileSync(base, "# pinned\nrequests==2.31.0  # http\n");
    expect(callIn(denied(hook(pre("Edit", { file_path: base, old_string: "requests==2.31.0", new_string: "requests>=2.32,<3" })))).items).toEqual([
      { ecosystem: "PyPI", package: "requests", to: ">=2.32,<3", from: "2.31.0" },
    ]);
  });
});

describe("Poetry constraints are named as calls the server accepts", () => {
  it("a caret edit in [tool.poetry.dependencies] becomes a PEP 440 range dependency_check reads", () => {
    const file = join(project, "pyproject.toml");
    writeFileSync(file, '[tool.poetry.dependencies]\npython = "^3.10"\nrequests = "^2.31"\n');
    const [item] = callIn(denied(hook(pre("Edit", { file_path: file, old_string: 'requests = "^2.31"', new_string: 'requests = "^2.19"' })))).items;
    expect(item).toEqual({ ecosystem: "PyPI", package: "requests", to: ">=2.19,<3" });
    expect(parseTarget("PyPI", item.to)).toMatchObject({ kind: "range" });
  });

  it.each([
    ["^2.19", ">=2.19,<3"],
    ["^0.2.3", ">=0.2.3,<0.3"],
    ["^0.0.3", ">=0.0.3,<0.0.4"],
    ["^1", ">=1,<2"],
    ["~2.19", ">=2.19,<2.20"],
    ["~2.19.1", ">=2.19.1,<2.20"],
    ["~2", ">=2,<3"],
    [">=2,<3", ">=2,<3"],
  ])("%s -> %s", (poetry, pep440) => {
    expect(poetryToPep440(poetry)).toBe(pep440);
    expect(parseTarget("PyPI", pep440)).not.toBeNull();
  });

  it("a bare Poetry version is that one release", () => {
    const file = join(project, "pyproject.toml");
    writeFileSync(file, '[tool.poetry.dependencies]\nrequests = "2.31.0"\n');
    expect(callIn(denied(hook(pre("Edit", { file_path: file, old_string: '"2.31.0"', new_string: '"2.32.3"' })))).items).toEqual([{ ecosystem: "PyPI", package: "requests", to: "2.32.3", from: "2.31.0" }]);
  });
});

describe("install commands", () => {
  it.each([
    ["npm install lodash@4.17.20", "npm", "lodash", "4.17.20"],
    ["npm i -D @types/node@20.11.0", "npm", "@types/node", "20.11.0"],
    ["npm add lodash@^4.17.0", "npm", "lodash", "^4.17.0"],
    ["pnpm add lodash@4.17.20", "npm", "lodash", "4.17.20"],
    ["pnpm --filter web install lodash@4.17.20", "npm", "lodash", "4.17.20"],
    ["yarn add lodash@4.17.20 --dev", "npm", "lodash", "4.17.20"],
    ["bun add lodash@4.17.20", "npm", "lodash", "4.17.20"],
    ["cargo add serde@1.0.200 --features derive", "crates.io", "serde", "1.0.200"],
    ["cargo add tokio@1.40", "crates.io", "tokio", "1.40"],
    ["uv add 'requests==2.31.0'", "PyPI", "requests", "==2.31.0"],
    ["uv add 'requests>=2.31,<3'", "PyPI", "requests", ">=2.31,<3"],
    ["uv pip install requests==2.31.0", "PyPI", "requests", "==2.31.0"],
    ["pip install requests==2.31.0", "PyPI", "requests", "==2.31.0"],
    ["python3 -m pip install -U 'requests[socks]==2.31.0'", "PyPI", "requests", "==2.31.0"],
    ["poetry add requests@^2.31", "PyPI", "requests", "^2.31"],
    ["poetry add requests==2.31.0", "PyPI", "requests", "==2.31.0"],
    ["go get github.com/spf13/cobra@v1.10.2", "Go", "github.com/spf13/cobra", "v1.10.2"],
    ["cd web && npm install lodash@4.17.20 2>&1 | tail -5", "npm", "lodash", "4.17.20"],
    ["CI=1 sudo npm install -g typescript@5.6.3", "npm", "typescript", "5.6.3"],
  ])("%s", (command, ecosystem, name, spec) => {
    expect(installsIn(command, "bash")).toEqual([{ ecosystem, name, spec }]);
  });

  it("an install command is denied with the call, as the edit is", () => {
    const items = callIn(denied(hook(bash("npm install lodash@4.17.20 && pip install requests==2.31.0 && go get github.com/spf13/cobra@v1.10.2")))).items;
    expect(items).toEqual([
      { ecosystem: "npm", package: "lodash", to: "4.17.20" },
      { ecosystem: "PyPI", package: "requests", to: "2.31.0" },
      { ecosystem: "Go", package: "github.com/spf13/cobra", to: "v1.10.2" },
    ]);
    expect(denied(hook(bash("npm install lodash@4.17.20")))).toContain("this command will pass once that call answers proceed");
  });

  it("the PowerShell tool is read the same way", () => {
    expect(callIn(denied(hook(pre("PowerShell", { command: "npm.cmd install lodash@4.17.20; cargo add serde@1.0.200" })))).items.map((i) => i.package)).toEqual(["lodash", "serde"]);
    // PowerShell passes an unquoted `@scope/pkg@1` as written (only a bare `@name` splats): read
    // (a651-hook-powershell-scoped.test.ts).
    expect(installsIn("npm install @types/node@20.11.0", "powershell")).toEqual([{ ecosystem: "npm", name: "@types/node", spec: "20.11.0" }]);
    expect(installsIn("npm install @splat", "powershell")).toEqual([]);
    expect(installsIn("npm install '@types/node@20.11.0'", "powershell")).toEqual([{ ecosystem: "npm", name: "@types/node", spec: "20.11.0" }]);
  });

  it("a checked version goes ahead", () => {
    ledger([{ package: "lodash", version: "4.17.20", verdict: "proceed" }]);
    allowed(hook(bash("npm install lodash@4.17.20")));
  });

  it.each([
    "npm install",
    "npm ci",
    "pnpm install",
    // A package named without a version, `@latest`, a dist-tag or a version-less alias is read since wave 2
    // (the request "latest", or the tag): a1125-w2-hook-bare-names.test.ts.
    "npm install github:lodash/lodash",
    "npm install ./local-pkg",
    "npm install --registry https://npm.example.com lodash@4.17.20",
    "npm install $PKG",
    "npm install lodash@$(cat version)",
    "npm install `echo lodash@4.17.20`",
    "pip install -r requirements.txt",
    "pip install --index-url https://pypi.example.com/simple requests==2.31.0",
    "uv add --index https://pypi.example.com/simple requests==2.31.0",
    "cargo add mycrate@1.0.0 --registry corp",
    "cargo add mycrate@1.0.0 --git https://example.com/repo",
    "poetry add requests@^2.31 --source corp",
    "go get ./...",
    "cat <<EOF > package.json",
    "echo npm install lodash@4.17.20",
    // A subshell `(npm install lodash@4.17.20)` is read since 6.5.1 (a651-hook-command-prefixes-and-aliases).
    "npm update lodash",
  ])("not read, so allowed without comment: %s", (command) => {
    expect(installsIn(command, "bash")).toEqual([]);
  });

  it("a command that installs nothing new from the public registry goes ahead, run as Claude Code runs the hook", () => {
    for (const command of ["npm ci", "pip install --index-url https://pypi.example.com/simple requests==2.31.0"]) allowed(hook(bash(command)));
  });

  // Round 8 (R8-2): an install the hook cannot read (a variable) is held as not read, no longer let through.
  it("an install it cannot read is held as not read", () => {
    expect(hook(bash("npm install $PKG")).stdout).toContain("could not be read");
  });

  it("the tokenizer reads redirections and separators, and refuses what it cannot read exactly", () => {
    expect(simpleCommands("a b > out.txt; c 2>/dev/null && d >> log || e &", "bash")).toEqual([["a", "b"], ["c"], ["d"], ["e"]]);
    expect(simpleCommands("a 'b c' \"d e\"", "bash")).toEqual([["a", "b c", "d e"]]);
    expect(simpleCommands("a \\\n  b", "bash")).toEqual([["a", "b"]]);
    for (const line of ["a $X", "a \"$X\"", "a `b`", "a $(b)", "a 'open", "a <<EOF", "a \\x"]) expect(simpleCommands(line, "bash"), line).toBeNull();
    expect(simpleCommands("C:\\tools\\npm.cmd install x@1.0.0", "powershell")).toEqual([["C:\\tools\\npm.cmd", "install", "x@1.0.0"]]);
    for (const line of ["npm i `", "npm i $v", "npm i a,b", "npm --% i x"]) expect(simpleCommands(line, "powershell"), line).toBeNull();
  });
});

describe("the ledger the server writes is the one the hook reads", () => {
  it("the hook looks in the server's data folder", () => {
    expect(dataDir(process.env, process.platform, homedir())).toBe(serverDataDir());
    const outer = process.env.FOURDA_MCP_HOME;
    delete process.env.FOURDA_MCP_HOME;
    try {
      expect(dataDir(process.env, process.platform, homedir())).toBe(serverDataDir());
    } finally {
      process.env.FOURDA_MCP_HOME = outer;
    }
    expect(dataDir({}, "linux", "/home/u")).toBe(join("/home/u", ".local", "share", "4da-mcp"));
    expect(dataDir({ XDG_DATA_HOME: "/x" }, "linux", "/home/u")).toBe(join("/x", "4da-mcp"));
    expect(dataDir({}, "darwin", "/Users/u")).toBe(join("/Users/u", "Library", "Application Support", "4da-mcp"));
    expect(dataDir({ LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local" }, "win32", "C:\\Users\\u")).toBe(join("C:\\Users\\u\\AppData\\Local", "4da-mcp"));
    expect(dataDir({ FOURDA_MCP_HOME: " /custom " }, "linux", "/home/u")).toBe("/custom");
  });

  it("entries recorded by the server let the edit through; names and versions are compared as the registries compare them", async () => {
    await recordVerdicts(
      [
        { ecosystem: "npm", package: "lodash", to: "4.18.1", verdict: "proceed" },
        { ecosystem: "PyPI", package: "Django", to: "5.1", verdict: "proceed" },
        { ecosystem: "Go", package: "github.com/spf13/cobra", to: "v1.10.2", verdict: "proceed" },
        { ecosystem: "crates.io", package: "serde_json", to: "1.0.140", verdict: "review" },
      ],
      { dir: home },
    );
    allowed(hook(lodashEdit("4.18.1")));
    const req = join(project, "requirements.txt");
    writeFileSync(req, "django==5.0.0\n");
    allowed(hook(pre("Edit", { file_path: req, old_string: "django==5.0.0", new_string: "django==5.1.0" })));
    const gomod = join(project, "go.mod");
    writeFileSync(gomod, "module example.com/m\n\nrequire github.com/spf13/cobra v1.8.0\n");
    allowed(hook(pre("Edit", { file_path: gomod, old_string: "cobra v1.8.0", new_string: "cobra v1.10.2" })));
    allowed(hook(bash("cargo add serde-json@1.0.140")));
  });

  describe("the call the hook names, made through the real tool, lets the edit through", () => {
    let restore: () => void;
    let outer: string | undefined;
    beforeEach(() => {
      restore = onlineForTests();
      outer = process.env.FOURDA_MCP_HOME;
      process.env.FOURDA_MCP_HOME = home;
      const net = emptyNet();
      const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();
      net.npm["lodash"] = npmDoc("lodash", { "4.17.21": { at: daysAgo(700) }, "4.18.1": { at: daysAgo(60) } });
      stubNet(net);
    });
    afterEach(async () => {
      await recordVerdicts([]);
      vi.unstubAllGlobals();
      process.env.FOURDA_MCP_HOME = outer;
      restore();
    });

    it("denied, the call made, then allowed", async () => {
      const payload = lodashEdit("4.18.1");
      const call = callIn(denied(hook(payload)));
      const answer = (await runDependencyCheck(null as unknown as FourDADatabase, call, new LiveIntelligence(new Database(":memory:")))) as { results: Array<{ verdict: string }> };
      expect(answer.results[0].verdict).toBe("proceed");
      await recordVerdicts([]);
      allowed(hook(payload));
    });
  });
});
