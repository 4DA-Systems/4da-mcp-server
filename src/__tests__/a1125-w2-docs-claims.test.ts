// SPDX-License-Identifier: Apache-2.0
/**
 * The 6.6.0 README and CHANGELOG sentences that carry a number, a level or a quoted wording, each held
 * to the code that keeps it (docs lane of wave 2, 2026-11-26). A row that starts failing means the code
 * or the sentence moved: change both together.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";
import { NODE_SERVER_FLOOR } from "../http-transport-floor.js";
import { MAX_DECLARED, MAX_TO_CONFIRM, SCAN_STILL_READS } from "../tools/briefing-confirm.js";
import { MAX_READ_PACKAGES } from "../tools/briefing-new-packages.js";
import { MAX_TASK_WORD } from "../tools/briefing-task-screen.js";
import { AGE_NOTE_MINUTES } from "../tools/dependency-check-age.js";
import { AFTER_RUN } from "../tools/upgrade-plan-protocol.js";
import { whatShouldIKnowTool } from "../tools/what-should-i-know.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const text = (file: string) => readFileSync(join(root, file), "utf8");
const readme = text("README.md");
const changelog = text("CHANGELOG.md");
const hookSource = text("hooks/manifest-edit.mjs");
/** The changelog's section for the next release, up to the 6.5.1 section. */
const next = changelog.slice(changelog.indexOf("## 6.6.0 "), changelog.indexOf("\n## 6.5.1 "));
/** A `const NAME = <expression>;` of the hook, evaluated (the hook keeps its bounds module-private). */
function hookConst(name: string): number {
  const m = new RegExp(`^const ${name} = ([0-9_ *]+);`, "m").exec(hookSource);
  expect(m, `hooks/manifest-edit.mjs no longer defines ${name}`).not.toBeNull();
  return m![1]!.replace(/_/g, "").split("*").reduce((a, b) => a * Number(b.trim()), 1);
}
const MB = 1024 * 1024;

describe("the changelog's section for 6.6.0", () => {
  it("is the one unreleased section, in the heading form scripts/release.mjs requires", () => {
    expect(changelog).toMatch(/^## 6\.6\.0 — unreleased$/m);
    expect(changelog).not.toMatch(/^## 6\.5\.2 /m);
    expect(next).toMatch(/^### Behaviour changes to know before upgrading$/m);
  });

  it("names no answer field the briefing no longer has, except as folded into task_packages", () => {
    for (const gone of ["unverified_words", "withheld_from_task"]) {
      const uses = next.split("\n").filter((l) => l.includes(gone));
      expect(uses.every((l) => l.includes("task_packages")), `${gone}: ${uses.join("\n")}`).toBe(true);
      expect(readme).not.toContain(gone);
    }
  });
});

describe("what_should_i_know: the caps and levels the docs state", () => {
  it("packages and not_packages: at most 100 each, in the schema and in both documents", () => {
    expect(MAX_DECLARED).toBe(100);
    const props = whatShouldIKnowTool.inputSchema.properties;
    expect(props.packages.maxItems).toBe(MAX_DECLARED);
    expect(props.not_packages.maxItems).toBe(MAX_DECLARED);
    expect(readme).toContain(`\`packages: [{ ecosystem, name, version?, public }]\` (at most ${MAX_DECLARED})`);
    expect(readme).toContain(`reads at most ${MAX_DECLARED} \`packages\` entries and ${MAX_DECLARED} \`not_packages\` words`);
    expect(next).toContain(`(at most ${MAX_DECLARED} entries;`);
  });

  it("to_confirm lists at most 25, the task is read for at most 100 packages, a word over 300 characters is not read", () => {
    expect(readme).toContain(`at most ${MAX_TO_CONFIRM} listed and \`to_confirm_total\` counting all`);
    expect(next).toContain(`at most ${MAX_TO_CONFIRM} entries, with \`to_confirm_total\` counting all`);
    expect(readme).toContain(`a task is read for at most ${MAX_READ_PACKAGES} packages, and a word longer than ${MAX_TASK_WORD} characters is not read`);
    expect(next).toContain(`a word longer than any package name (${MAX_TASK_WORD} characters) is not read, and a task is read for at most ${MAX_READ_PACKAGES} packages`);
  });

  it("the five levels the README names are the type's five", () => {
    const type = /export type DelegationLevel = ([^;]+);/.exec(text("src/tools/what-should-i-know.ts"))![1]!;
    const levels = [...type.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]!).sort();
    expect(levels).toEqual(["confirmation_needed", "human_only", "review_needed", "safe_to_delegate", "unknown"]);
    const row = readme.split("\n").find((l) => l.startsWith("| `what_should_i_know` |"))!;
    for (const level of levels) expect(row, level).toContain(`\`${level}\``);
  });

  it("a declaration keeps the briefing from looking a name up, and the docs never say the scan stops sending it", () => {
    expect(SCAN_STILL_READS).toContain("does not change this project's own vulnerability scan");
    expect(readme).toContain("A declaration does not change the project's own vulnerability scan, which reads the installed dependencies and sends their names unless the project's configuration marks them private");
    expect(next).toContain("A declaration does not change this project's own vulnerability scan");
    for (const doc of [readme, next]) expect(doc).not.toMatch(/`public: false`[^.]{0,80}\bis never sent\b/);
  });

  it("the README's example hint is the wording to_confirm builds", () => {
    expect(text("src/tools/briefing-confirm.ts")).toContain("`one edit from ${near}: if you mean ${near}, confirm ${near} instead`");
    expect(readme).toContain('"hint": "one edit from lodash: if you mean lodash, confirm lodash instead"');
  });
});

describe("the other numbers the docs state", () => {
  it("the HTTP floor and the Node.js floor", () => {
    expect(NODE_SERVER_FLOOR).toBe("2.1.6");
    expect(readme).toContain(`refuses to start when the copy\nit would load is older than ${NODE_SERVER_FLOOR}`);
    expect(next).toContain(`refuses to start when it is below ${NODE_SERVER_FLOOR}`);
    expect(text("src/node-gate.ts")).toMatch(/export const MIN_NODE_MAJOR = 22;/);
    expect(readme).toContain("Requires Node.js 22 or later; below it the server stops at once");
  });

  it("dependency_check's age note starts at 5 minutes, and after_run says to scan again", () => {
    expect(AGE_NOTE_MINUTES).toBe(5);
    expect(readme).toContain(`(the summary says so at ${AGE_NOTE_MINUTES} minutes or more)`);
    expect(next).toContain(`once that age is ${AGE_NOTE_MINUTES} minutes or more`);
    expect(AFTER_RUN).toMatch(/^When the steps have run .* call vulnerability_scan again/);
  });

  it("the hook's bounds, as the README's guard hook section states them", () => {
    const section = readme.slice(readme.indexOf("## The guard hook"), readme.indexOf("## Standalone vs. Full Mode"));
    expect(hookConst("READ_BUDGET_MS")).toBe(2000);
    expect(hookConst("WALL_LIMIT_MS")).toBe(5000);
    expect(hookConst("WORKER_ABOVE_CHARS")).toBe(8 * 1024);
    expect(section).toContain("2 s of reading from its start, and a 5 s wall clock for a payload over 8 KB");
    expect(hookConst("MAX_INPUT_CHARS")).toBe(8 * MB);
    expect(hookConst("MAX_PARSE_CHARS")).toBe(64 * MB);
    expect(section).toContain("A payload over 8 MB that does not parse, or one over 64 MB, is judged from its first 64 KB.");
    expect(hookConst("SELF_LIMIT_MS")).toBe(8000);
    expect(section).toContain("still open after 8 s");
    expect(JSON.parse(text("hooks/hooks.json")).hooks.PreToolUse[0].hooks[0].timeout).toBe(10);
    expect(section).toContain("Claude Code stops a hook after 10 s");
    expect(hookConst("MAX_LINE_CHARS")).toBe(65536);
    expect(hookConst("MAX_VERSION_CHARS")).toBe(80);
    expect(hookConst("MAX_CONSTRAINT_CHARS")).toBe(1000);
    expect(hookConst("MAX_KEY_CHARS")).toBe(600);
    expect(hookConst("MAX_NESTING")).toBe(100);
    expect(hookConst("MAX_MANIFEST_BYTES")).toBe(8 * MB);
    expect(hookConst("MAX_ACCOUNT_CHARS")).toBe(2 * MB);
    expect(hookConst("MAX_LEDGER_BYTES")).toBe(4 * MB);
    expect(hookConst("MAX_ENTRIES_PER_PACKAGE")).toBe(5000);
    expect(section).toContain(
      "a requirement or manifest line over 64 KB, a version over 80 characters, a range or constraint over 1,000, an `npm pkg set` key over 600, TOML nested more than 100 levels, a manifest on disk or after the edit over 8 MB",
    );
    expect(section).toContain("a command over 2 MB that names an install, a ledger file over 4 MB or with more than 5,000 entries for one package");
    expect(hookConst("MAX_WRAPS")).toBe(3);
    expect(section).toContain("(at most three deep)");
    expect(hookConst("LEDGER_WINDOW_MS")).toBe(24 * 60 * 60 * 1000);
    expect(section).toContain("The hook reads the answers of the last 24 hours");
  });
});

describe("the guard hook's wording the docs quote", () => {
  let dir: string;
  let home: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "a1125-docs-"));
    home = join(dir, "home");
    mkdirSync(home);
    writeFileSync(join(home, LEDGER_FILE), "");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const deny = (tool_name: string, tool_input: Record<string, unknown>, env: Record<string, string> = {}): string => {
    const out = respond({ hook_event_name: "PreToolUse", cwd: dir, tool_name, tool_input }, { FOURDA_MCP_HOME: home, ...env }, Date.now());
    return out === "" ? "" : (JSON.parse(out) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason;
  };

  it("an option the hook does not know: \"Run the same command without `<that part>`\"", () => {
    expect(deny("Bash", { command: "npm i ms@2.1.3 --before 2020-01-01" })).toContain("Run the same command without the option `--before`; if that option takes a value, remove its value too");
    expect(readme).toContain("without the option `--before`; if that option takes a value, remove its value too");
    expect(readme).toContain('"Run the same command without `<that part>`"');
  });

  it("a package named without a version needs an answer for latest; public: false releases nothing", () => {
    const reason = deny("Bash", { command: "npm install ky" });
    expect(reason).toContain('{"ecosystem":"npm","package":"ky","to":"latest"}');
    expect(reason).toContain("what_should_i_know's `public: false`) records nothing and releases nothing");
    expect(readme).toContain("Marking a package `public: false` in `what_should_i_know` records nothing and releases nothing.");
  });

  it("text that only mentions an install goes ahead; a call that names the ledger is held, with or without a ledger file", () => {
    expect(deny("Bash", { command: 'git commit -m "npm install lodash@4.17.20"' })).toBe("");
    expect(deny("Bash", { command: "echo 'npm install lodash@4.17.20'" })).toBe("");
    expect(deny("Bash", { command: `echo x >> ${join(home, LEDGER_FILE)}` })).toContain("check ledger");
    rmSync(join(home, LEDGER_FILE));
    expect(deny("Bash", { command: `echo x >> ${join(home, LEDGER_FILE)}` })).toContain("check ledger");
    expect(deny("Bash", { command: "npm install lodash@4.17.20" })).toBe("");
    expect(readme).toContain("the hook denies nothing but a call that names the ledger");
  });

  it("advise mode never denies, the ledger guard included", () => {
    expect(deny("Bash", { command: `echo x >> ${join(home, LEDGER_FILE)}` }, { FOURDA_GUARD: "advise" })).toBe("");
    expect(deny("Bash", { command: "npm install ky" }, { FOURDA_GUARD: "advise" })).toBe("");
    expect(readme).toContain("`FOURDA_GUARD=advise` never denies (the ledger guard included)");
  });
});
