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
import { CREDENTIAL_REFUSAL } from "../argument-screen.js";
import { WORD_SCAN_CAP } from "../call-budget.js";
import { NODE_SERVER_FLOOR } from "../http-transport-floor.js";
import { canonicalCommands, MANAGER_NAMES } from "../tools/briefing-canonical.js";
import { STAYS_REVIEW, RAW_SOURCE, SOURCE_SPELLINGS, unreadableReason } from "../tools/briefing-command-check.js";
import { BEST_EFFORT_READING, BRIEFING_FAILED, SCAN_ALL_PRIVATE, SCAN_LOCKFILE_UNREADABLE, SCAN_NPMRC_UNREADABLE, UNLISTED_FOLDERS, PRIVATE_INSTALLED, SCAN_INCOMPLETE, DISMISSED_KNOWN, NOT_SCANNED_LOCKFILES, INSTALLED_MALWARE, INSTALLED_PLACEHOLDER, NO_DECISION_CONFLICT, OUTSIDE_COVERAGE, PROJECT_FINDINGS_LISTED, TASK_FOLDED, MAX_DECLARED, MAX_TO_CONFIRM, readDeclarations, RESTS_ON_DECLARATION, SCAN_STILL_READS, SOURCE_HELD } from "../tools/briefing-confirm.js";
import { MAX_READ_PACKAGES } from "../tools/briefing-new-packages.js";
import { MAX_TASK_WORD } from "../tools/briefing-task-screen.js";
import { AGE_NOTE_MINUTES } from "../tools/dependency-check-age.js";
import { AFTER_RUN } from "../tools/upgrade-plan-protocol.js";
import { whatShouldIKnowTool } from "../tools/what-should-i-know.js";
// The hook's PATH lookups see a stub for each manager and runner word, whatever the machine (Windows).
import "./helpers/a1125-manager-stubs.js";

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
  it("is the one section for 6.6.0, in the heading form scripts/release.mjs requires: unreleased before the release, dated by it", () => {
    // scripts/release.mjs turns "— unreleased" into "— <date>" in the same change that sets package.json to 6.6.0.
    const released = (JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version: string }).version === "6.6.0";
    expect(changelog).toMatch(released ? /^## 6\.6\.0 — \d{4}-\d{2}-\d{2}$/m : /^## 6\.6\.0 — unreleased$/m);
    expect(changelog.match(/^## 6\.6\.0 /gm)).toHaveLength(1);
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

describe("what_should_i_know after confirmation round 7: the command grammar and the wordings the docs quote", () => {
  const operands = (task: string) => canonicalCommands(task).flatMap((c) => (c.canonical ? c.operands.map((o) => o.name) : []));

  it("a command inside a sentence holds the words after it; its own line, a code span or a parenthesis does not", () => {
    expect(operands("Use npm install msw for tests")).toEqual(["msw", "for", "tests"]);
    expect(operands("Please npm install x and then run the tests")).toEqual(["x", "and", "then", "run", "the", "tests"]);
    expect(operands("Add a test helper.\nnpm install msw")).toEqual(["msw"]);
    expect(operands("Use `npm install msw` for tests")).toEqual(["msw"]);
    expect(operands("Add a helper (npm install msw) for tests")).toEqual(["msw"]);
    for (const doc of [readme, next]) expect(doc).toContain('"Use npm install msw for tests" holds msw, for and tests');
    expect(next).toContain('"Please npm install x and then run the tests" holds x, and, then, run, the and tests');
  });

  it("a command not read whole is said by its manager and verb, with the wordings the CHANGELOG quotes", () => {
    const comma = canonicalCommands("pip install requests, x")[0]!;
    expect(comma.canonical).toBe(false);
    expect(unreadableReason({ ...comma, unreadable: comma.why as never, operands: [] })).toBe(`This task holds a command (pip install) this briefing could not read whole (a comma in its list of packages): check what it installs with dependency_check. ${STAYS_REVIEW}`);
    // Round 9, E3: the remedy is gone; the truth instead (README/CHANGELOG follow from the ROUND 9 block).
    // Round 14, X5: true at every level it is said with (confirmation_needed included).
    expect(STAYS_REVIEW).toBe("This command, as the task writes it, keeps the answer from safe_to_delegate: it is not an error. Check what the command installs with dependency_check before running it.");
    expect(next).toContain("(\"This task holds a command (pip install) this briefing could not read whole (a comma in its list of packages): check what it installs with dependency_check.\")");
    expect(canonicalCommands("npm create vite")[0]!.why).toBe("it fetches and runs a package named create-<name> (or <scope>/create), which this briefing does not check");
    expect(next).toContain('"it fetches and runs a package named create-<name> (or <scope>/create), which this briefing does not check"');
    expect(canonicalCommands("npm install --before 2020-01-01 x")[0]!.why).toBe("an option this briefing does not read");
    expect(next).toContain('("an option this briefing does not read")');
    for (const runner of ["npx x", "pnpm dlx x", "uv tool run x", "go run example.com/x@v1.0.0", "deno run npm:x"]) expect(canonicalCommands(runner)[0]!.canonical, runner).toBe(false);
  });

  it("a package source of the task's own: the not_read wording; source words in their own case and manager", () => {
    expect(SOURCE_HELD).toBe("not looked up: the task names a package source of its own; if it is on the public registry, check it with dependency_check");
    expect(next).toContain(`"${SOURCE_HELD}"`);
    expect(RAW_SOURCE.test("cargo add -F derive serde")).toBe(false);
    expect(RAW_SOURCE.test("pip install -f ./wheels x")).toBe(true);
    expect(RAW_SOURCE.test("cargo add --features derive serde")).toBe(false);
    expect(next).toContain("Cargo's `-F derive` and npm's `-f` are no source");
    expect(next).not.toContain("names a package source of its own and nothing the task adds is looked up; write");
  });

  // Round 13: the docs lane writes the ROUND 13 sentences (docs-w2-confirm.txt) into the CHANGELOG; until then this
  // one fails on purpose, naming the two sentences the CHANGELOG still quotes from round 12.
  it("round 13: the line cap, the requirements-file cap and the private basis, in the code and the CHANGELOG", () => {
    const wsik = text("src/tools/what-should-i-know.ts");
    expect(wsik).toContain("`a line longer than this briefing reads (${MAX_READ_LINE.toLocaleString(\"en-US\")} charac");
    expect(next).toContain('"a line longer than this briefing reads (2,000 characters)"');
    expect(wsik).toContain('"the requirements files it names are more than this briefing reads (');
    expect(next).toContain('"the requirements files it names are more than this briefing reads (8)"');
    expect(text("src/tools/briefing-confirm.ts")).toContain('"your FOURDA_PRIVATE_PACKAGES list"');
    expect(next).toContain('its basis is "your FOURDA_PRIVATE_PACKAGES list" when that list names it');
    expect(next).toContain("is shown as its first four characters and its length");
  });

  // Round 14: the docs lane writes the ROUND 14 sentences; until then this one fails on purpose.
  it("round 14: the CHANGELOG carries the contract's 18 sentences in order (round 15), and the source and masking rules as the code has them", () => {
    const contract = next.slice(next.indexOf("- What `what_should_i_know` promises, and nothing more"), next.indexOf("- The one promise:"));
    const numbers = [...contract.matchAll(/^ {2}(\d+)\. /gm)].map((m) => Number(m[1]));
    expect(numbers).toEqual(Array.from({ length: 18 }, (_, i) => i + 1));
    expect(contract).toContain(`"${OUTSIDE_COVERAGE}"`);
    expect(contract).toContain(`\`task_note\` says "${TASK_FOLDED}"`);
    expect(contract).toContain("6.5.1 sent such a name to the npm registry and OSV.dev and wrote it to the check ledger.");
    expect(contract).toContain("it does not promise to notice each such command");
    expect(readme).toContain("for npm, PyPI, crates.io and Go packages (what a task installs through any other manager or tool is outside its answer");
    expect(contract).toContain("a public entry without `version` never leaves the answer at `safe_to_delegate`");
    expect(contract).toContain("a task that only mentions such a spelling can be safe");
    expect(next).not.toContain("the level is at most `review_needed`, and nothing is written to the check ledger");
    expect(next).toContain("Only known shapes are masked: a long random-looking folder name, a sha512 integrity string or a 64-hex digest is shown as it is");
    expect(text("src/tool-args.ts") + text("src/tools/dependency-check.ts")).toContain("an unknown parameter (");
    expect(readme).not.toContain("this stays `review_needed` for the command");
  });

  it("round 16: the fixed texts the CHANGELOG quotes are the code's", () => {
    expect(INSTALLED_MALWARE(["crossenv@1.0.1"])).toBe("This project has crossenv@1.0.1 installed, which is recorded as malware: a person must deal with that before any task is delegated.");
    expect(next).toContain(`("${INSTALLED_MALWARE(["crossenv@1.0.1 (in packages/web)"])}";`);
    expect(PROJECT_FINDINGS_LISTED(1)).toContain('1 project-wide finding is listed below (advisories, scope "project")');
    expect(next).toContain(`opens "${PROJECT_FINDINGS_LISTED(1)}"`);
    expect(NO_DECISION_CONFLICT).toBe("no recorded-decision conflict for this task");
    expect(next).toContain(`"${NO_DECISION_CONFLICT}" is said only where no decision conflict was found`);
    expect(next).toContain(`"${CREDENTIAL_REFUSAL("package name")}"`);
    expect(CREDENTIAL_REFUSAL("ecosystem")).toContain("not an ecosystem");
    expect(next).not.toContain("an operand of a runner command, an entry of a snippet");
    // Round 18: the narrowed sentences.
    expect(next).toContain(`"${DISMISSED_KNOWN("lodash")}"`);
    expect(next).toContain(`("${NOT_SCANNED_LOCKFILES(1)}";`);
    expect(next).toContain(`"${NOT_SCANNED_LOCKFILES({ ignored: 0, depth: 1, projectLimit: 0, outside: 0, unreadable: 0 })}"`);
    expect(next).toContain(`"${SCAN_INCOMPLETE}"`);
    // Round 20.
    expect(next).toContain(`("${UNLISTED_FOLDERS(1)}")`);
    expect(next).toContain(`"${SCAN_ALL_PRIVATE(1)}"`);
    expect(next).toContain(`"${SCAN_LOCKFILE_UNREADABLE(["package-lock.json"])}"`);
    expect(SCAN_NPMRC_UNREADABLE(2)).toContain("checked none of the 2 installed dependencies");
    expect(next).toContain("checked none of the N installed dependencies");
    expect(text("src/project-tree.ts")).toContain("export const MAX_DEPTH = 8;");
    expect(readme).toContain("20,000 directories, 8 levels and 256 projects");
    expect(next).toContain(`("${PRIVATE_INSTALLED(1)}")`);
    expect(next).toContain(`"${BRIEFING_FAILED}"`);
    expect(next).toContain("it does not promise to see every copy on disk");
    expect(next).toContain(`the answer says so: "${SCAN_STILL_READS}"`);
    for (const doc of [readme, next]) {
      expect(doc).not.toContain("percent-escapes decoded");
      expect(doc).not.toContain("anywhere in the full scan");
    }
    // Round 17: the id refusal and the installed-copy text the CHANGELOG quotes.
    expect(text("src/stdio-gate.ts")).toContain('"Invalid Request: the request id has a credential\'s shape, so it is not echoed and the request was not run; send it again with another id."');
    expect(next).toContain(`"Invalid Request: the request id has a credential's shape, so it is not echoed and the request was not run; send it again with another id."`);
    expect(text("src/tools/what-should-i-know.ts")).toContain("the installed copy is the vulnerable one, so make sure the task replaces it");
    expect(next).toContain("the installed copy is the vulnerable one, so make sure the task replaces it");
    // Rounds 16b / 16c: the placeholder text, and no sentence left saying a glued token is not matched.
    expect(next).toContain(`"${INSTALLED_PLACEHOLDER(["lodahs@0.0.1-security"])}"`);
    for (const doc of [readme, next]) expect(doc).not.toMatch(/glued to the letters before it[^.]*is not matched/);
  });

  it("docs lane, round 14: the CHANGELOG quotes the reworded STAYS_REVIEW", () => {
    expect(next).toContain(`the reason adds "${STAYS_REVIEW}" No remedy is offered.`);
  });

  it("docs lane, round 13: the CHANGELOG quotes the new last sentence and no longer the raw-text dismissal rule", () => {
    expect(next).toContain(`"${RESTS_ON_DECLARATION}"`);
    expect(next).not.toContain("it stands after a package manager's name in the task: make sure nothing installs it");
  });

  it("the safe_to_delegate reason's last sentence, and the task length limit", () => {
    // Round 13 (#34, U1): the code's sentence; the CHANGELOG half is checked apart below (docs lane).
    expect(RESTS_ON_DECLARATION).toBe("This rests on your declaration of what the task adds and on your statement of which words are not packages: a package you did not declare may not have been checked.");
    expect(/^const MAX_TEXT_ARG_LENGTH = 200_000;$/m.test(text("src/tool-args.ts"))).toBe(true);
    expect(next).toContain("the error for a `task` over 200,000 characters repeats nothing of the task");
  });

  it("build metadata: the wording dependency_check gives, quoted without the label", () => {
    expect(text("src/tools/dependency-check.ts")).toContain('"Build metadata in %s was ignored, as npm ignores it when it orders versions"');
    expect(next).toContain('("Build metadata in "4.17.20+..." was ignored ... and the metadata was not sent")');
  });

  it("a Go path in the proxy's `!`-escaped form is refused in a declaration (round 7c)", () => {
    const { entries, refused } = readDeclarations([{ ecosystem: "Go", name: "github.com/!sirupsen/logrus", version: "v1.9.3", public: true }]);
    expect(entries).toEqual([]);
    expect(refused[0]!.reason).toContain("`name` is no Go package name");
    expect(next).toContain("is refused in a declaration, as `dependency_check` refuses the same item: neither tool looks it up or writes a ledger line for it");
    expect(next).not.toContain("passes the entry check");
  });

  it("to_confirm entries carry no version, and the docs say so", () => {
    expect(text("src/tools/what-should-i-know.ts")).toContain("for (const w of gated.unverified) delete w.version;");
    expect(readme).not.toContain("the `version` the task writes");
    expect(next).not.toContain("the `version` the task writes");
    expect(readme).toContain("a `hint` or `caution` for the agent, never a version");
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
    expect(section).toContain("A payload over 8 MB that does not parse, or one over 64 MB, is not read whole and is held like a failure of the hook:");
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

describe("what_should_i_know after confirmation round 8: the wordings and the list the docs quote", () => {
  const wsik = text("src/tools/what-should-i-know.ts");

  // Round 9, E1: the leftover-version rule is gone; a public entry without `version` is confirmation_needed.
  it("a public entry without `version`: the fixed next_step", () => {
    expect(wsik).toContain("State \\`version\\` for each package you declared public: the version or range you will write, or \"latest\" for the newest release (checked so far:");
    expect(wsik).not.toContain("VERSION_UNTIED");
    expect(next).toContain('`next_step` says "State `version` for each package you declared public: the version or range you will write, or "latest" for the newest release (checked so far: <name> at <version>, ...)."');
    for (const doc of [readme, next]) {
      expect(doc).not.toContain("cannot tie to a package");
      expect(doc).not.toContain("For a clean answer");
      expect(doc).not.toContain("on a line with a package manager's name");
    }
    // Round 14: the CHANGELOG half of STAYS_REVIEW is checked in the docs-lane test below.
    // Round 13, U1: the raw-text dismissed-word rule and its text are gone from the code (the CHANGELOG half below).
    expect(wsik).not.toContain("it stands after a package manager's name in the task");
    expect(readme).toContain('"name": "lodahs", "version": "latest", "public": true');
  });

  it("more than 100 names: the sentence the CHANGELOG quotes", () => {
    expect(wsik).toContain("const TOO_MANY = `The task holds more than ${MAX_DECLARED} names that may be packages, more than one call can declare: split the task into smaller ones.`;");
    expect(next).toContain(`"The task holds more than ${MAX_DECLARED} names that may be packages, more than one call can declare: split the task into smaller ones."`);
  });

  it("the source check is a list, and the CHANGELOG names every spelling of it", () => {
    for (const spelling of SOURCE_SPELLINGS) {
      if (/^pip -[if] /.test(spelling)) continue;
      // Round 9: the go.mod entry covers the block form too; the docs lane renames it from the ROUND 9 block.
      if (spelling.startsWith("a go.mod replace directive")) {
        expect(next).toContain("a go.mod replace directive with `=>`, single-line or block");
        continue;
      }
      const shown = `\`${spelling.replace(/ \(.*\)$/, "")}\``;
      expect(next, spelling).toContain(shown);
    }
    expect(next).toContain("pip's `-i` and `-f` inside a pip command");
    expect(next).toContain("A courtesy check on a list of spellings, not a promise about sources.");
    expect(readme).toContain('a source named any other way ("from our Artifactory") is not noticed');
  });

  it("the tool says first that a public name is sent and what to declare private", () => {
    expect(whatShouldIKnowTool.description).toContain("Declare public: false for anything the task or the project takes from a private registry, an index of its own, git or a path");
    expect(whatShouldIKnowTool.description).toContain("a name declared public: true is sent to the public registry and checked in this call");
    const items = (whatShouldIKnowTool.inputSchema.properties.packages as unknown as { items: { properties: { public: { description: string } } } }).items;
    expect(items.properties.public.description).toBe("false for anything from a private registry, an own index, git or a path; true sends the name to the public registry.");
    expect(next).toContain("sends every name you declare `public: true` to its public registry");
  });
});

describe("what_should_i_know after confirmation round 10: the list, the bounds and the wordings the docs quote", () => {
  const wsik = text("src/tools/what-should-i-know.ts");

  it("the CHANGELOG gives MANAGER_NAMES as the code holds it", () => {
    const shown = MANAGER_NAMES.map((n) => (n === "pip3" ? "pip3 (and pipX.Y)" : n)).join(", ");
    expect(next).toContain(`is one of this list (MANAGER_NAMES): ${shown}.`);
  });

  it("a command the briefing does not read: the wording", () => {
    expect(wsik).toContain("`This task holds a command this briefing does not read (${foreignLines.slice(0, 5).join(\", \")}): check what it installs with dependency_check.`");
    expect(next).toContain('"This task holds a command this briefing does not read (brew): check what it installs with dependency_check."');
  });

  it("the CPU bound: 4000 distinct words (a safeguard, not quoted as user-visible), the deadline and snippet sentences", () => {
    expect(WORD_SCAN_CAP).toBe(4000);
    expect(next).toContain(`on at most ${WORD_SCAN_CAP} distinct words a call has not seen`);
    expect(next).not.toContain("more distinct words than one call reads in full");
    expect(wsik).toContain('"This briefing did not finish reading the task within its time budget: split the task and ask for each part."');
    expect(next).toContain('"This briefing did not finish reading the task within its time budget: split the task and ask for each part."');
    expect(wsik).toContain("`This task holds more manifest snippets than one call reads (${MAX_SNIPPETS}): split the task and ask for each part.`");
    expect(next).toContain('"This task holds more manifest snippets than one call reads (100): split the task and ask for each part."');
  });
});

describe("what_should_i_know after confirmation round 11: one promise, the rest best effort", () => {
  const promise = "The level rests on your declaration and on your statement of which words are not packages: each package you declare public is checked at the `version` you state. Declare the version the task writes.";
  it("the promise comes first, and the best-effort sentence is the one the code gives", () => {
    expect(next).toContain(`makes one promise. ${promise}`);
    expect(next).toContain(`- The one promise: ${promise}`);
    expect(readme).toContain(`| \`what_should_i_know\` |`);
    expect(readme).toContain(`${promise} Pass the request in the user's words`);
    expect(readme).toContain("The briefing makes one promise, resting on your declaration and on your statement of which words are not packages: each package you declare public is checked at the `version` you state");
    expect(BEST_EFFORT_READING).toBe("The versions this briefing read in the task's commands and snippets are best effort: a version written in a spelling it does not read was not checked, so declare the version the task writes.");
    for (const doc of [readme, next]) expect(doc).toContain(`"${BEST_EFFORT_READING}"`);
  });

  it("no sentence about the briefing promises a complete reading of the task text", () => {
    for (const doc of [readme, next]) {
      for (const phrase of ["no line is dropped in silence", "is read in its ecosystem's grammar or makes the snippet not read whole", "bare or spaced", "The forms that tie a version to a package name, exactly", "a small exact grammar", "exactly these forms"]) expect(doc, phrase).not.toContain(phrase);
    }
  });
});

describe("what_should_i_know after confirmation round 12: the wordings the docs quote", () => {
  const wsik = text("src/tools/what-should-i-know.ts");
  it("a requirements file the task names: the three wordings", () => {
    for (const said of ["a requirements file outside the project is not read", "the requirements file it names could not be read"]) {
      expect(wsik).toContain(`unreadable: "${said}"`);
      expect(next).toContain(`"${said}"`);
    }
    expect(text("src/tools/briefing-confirm.ts")).toContain('file: "a line of the requirements file the task names"');
    expect(next).toContain('seen as "a line of the requirements file the task names"');
  });
  it("the not_packages rule has no lines or fences, and the best-effort sentence is unconditional", () => {
    for (const doc of [readme, next]) {
      expect(doc).not.toContain("on its line, a continued line or in the same fenced block");
      expect(doc).not.toContain("Where the task holds a fenced block, a manifest file name or a command");
      expect(doc).not.toContain("Where the task holds a command, a fenced block or a manifest file name");
    }
    // Round 13: the anywhere-earlier rule is gone.
    for (const doc of [readme, next]) expect(doc).not.toContain("stands anywhere earlier in the task (");
    expect(next).toContain("is the caller's statement and holds nothing by itself, wherever it stands");
    expect(next).toContain("In a call that declared at least one package, every `safe_to_delegate` reason says");
    expect(readme).toContain("In a call that declared at least one package, every `safe_to_delegate` reason says so");
  });
  it("a public entry without version is never safe_to_delegate", () => {
    expect(next).toContain("the answer is never `safe_to_delegate`");
    expect(readme).toContain("the answer is never `safe_to_delegate`");
  });
  it("round 12b: a refused entry holds review_needed; a requirements file not read whole offers nothing; include-group is no entry", () => {
    expect(next).toContain("a refused entry holds the level at `review_needed` at least");
    expect(next).toContain("A requirements file the briefing says it did not read whole offers none of its entries");
    expect(next).toContain('or a PEP 735 `{include-group = "cli"}` entry');
    expect(next).toContain("`not_packages` is your statement of which words of the task are not packages");
  });
  it("the near-miss cap wording in the code (a safeguard; not quoted in the docs)", () => {
    expect(wsik).toContain("than one call checks for near-miss names (${WORD_SCAN_CAP})");
  });
});
