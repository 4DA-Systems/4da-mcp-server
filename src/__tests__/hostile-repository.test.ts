// SPDX-License-Identifier: Apache-2.0
/**
 * A scanned repository is hostile input (audit 2026-11-11, M4 and M15).
 *
 * The server walks the project synchronously, at startup and on the first tool
 * call, and reads what it finds: .gitignore files, manifests, lockfiles. Two
 * lines of .gitignore (`a*a*...*b`, 20 stars) beside a 40-character directory
 * name hung published 6.2.7: `dependency_check` and then `tools/list` timed
 * out, so cloning a repository could silently remove the pre-write safety
 * check. Each case below is one way a tree could hold the event loop, pinned:
 * it must finish quickly, and where the server gives up it must say so (an
 * incomplete walk, an unread lockfile), never report a clean result.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { IgnoreRules, MAX_PATTERN_LENGTH, MAX_RULES_PER_FILE, MAX_WILDCARD_PIECE } from "../gitignore.js";
import { discoveryNote, lockfileProblemNotes, scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { cargoPackageName } from "../project-scanner.js";
import { startWalkBudget } from "../walk-budget.js";
import { LiveIntelligence } from "../live/index.js";
import { resolveGroup } from "../live/resolution.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { resultText, serverEntry, stdioSession } from "./helpers/stdio-session.js";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-hostile-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
  delete process.env.FOURDA_WALK_BUDGET_MS;
  delete process.env.FOURDA_MAX_LOCKFILE_BYTES;
});
const write = (rel: string, content: string) => {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
};
const timed = <T>(fn: () => T): { ms: number; value: T } => {
  const started = performance.now();
  const value = fn();
  return { ms: performance.now() - started, value };
};
const caseless = process.platform === "win32" || process.platform === "darwin";

/** The audit's two lines: twenty stars, ending in a character the name does not end with. */
const STARS = `${"a*".repeat(20)}b\n${"a*".repeat(20)}c/\n`;
const LONG_NAME = "a".repeat(40);

describe(".gitignore matching: no pattern can make it backtrack", () => {
  it("the audit's pattern against a 40-character name answers at once (it took longer than the server lived)", () => {
    write(".gitignore", STARS);
    const rules = new IgnoreRules(dir);
    const run = timed(() => [rules.ignores(LONG_NAME, true), rules.ignores(`${LONG_NAME}/package-lock.json`, false), rules.ignores(`${LONG_NAME}b`, true)]);
    expect(run.value).toEqual([false, false, true]);
    expect(run.ms).toBeLessThan(50);
  });

  it("many stars, many `?`, long names, every shape that made a backtracking matcher explode", () => {
    const name = "a".repeat(250);
    const patterns = [
      `${"a*".repeat(400)}b`,
      `${"*a".repeat(400)}b`,
      `${"a?".repeat(30)}*${"?a".repeat(30)}*b`,
      `${"*".repeat(900)}b`,
      `**/${"a*".repeat(200)}b/**/${"a*".repeat(200)}c`,
      `${"a*a*a*/".repeat(100)}b`,
      `${"**/".repeat(300)}b`,
    ];
    write(".gitignore", `${patterns.join("\n")}\n`);
    const rules = new IgnoreRules(dir);
    const deep = Array.from({ length: 30 }, () => name).join("/");
    const run = timed(() => [rules.ignores(name, true), rules.ignores(deep, true), rules.ignores(`${deep}/Cargo.lock`, false)]);
    expect(run.value).toEqual([false, false, false]);
    expect(run.ms).toBeLessThan(250);
  });

  it("a line of 200,000 spaces before one character is trimmed in one pass", () => {
    write(".gitignore", `build/\n${" ".repeat(200_000)}x\nout${" ".repeat(200_000)}\n`);
    const run = timed(() => new IgnoreRules(dir));
    expect(run.ms).toBeLessThan(250);
    expect(run.value.ignores("build", true)).toBe(true);
    expect(run.value.ignores("out", true)).toBe(true);
  });

  it("cost grows with the input, not with a power of it: 4x the name and the stars, well under 16x the time", () => {
    const cost = (n: number) => {
      write(".gitignore", `${"ab*".repeat(n)}c\n`);
      const rules = new IgnoreRules(dir);
      const name = "ab".repeat(n * 4);
      // Enough repetitions to measure, the same number for both sizes.
      return timed(() => {
        for (let i = 0; i < 300; i++) rules.ignores(`${name}${i}`, true);
      }).ms;
    };
    cost(50); // warm-up
    const small = cost(50);
    const large = cost(200);
    expect(large).toBeLessThan(Math.max(small, 1) * 12);
  });
});

describe(".gitignore matching: what a pattern means is unchanged", () => {
  const rulesOf = (content: string, nested: Record<string, string> = {}) => {
    write(".gitignore", content);
    for (const [rel, text] of Object.entries(nested)) write(`${rel}/.gitignore`, text);
    const rules = new IgnoreRules(dir);
    for (const rel of Object.keys(nested)) rules.load(rel);
    return rules;
  };

  it("names, directory-only rules, anchoring and nesting", () => {
    const r = rulesOf("# comment\n\nnode_modules\ntarget/\n/dist\ndocs/api/*/\n*.tmp\nfoo?bar\n", { tools: "scratch/\n/only-here\n" });
    // A bare name matches at any depth, files and directories alike; everything below a match is ignored.
    expect(r.ignores("node_modules", true)).toBe(true);
    expect(r.ignores("packages/a/node_modules", true)).toBe(true);
    expect(r.ignores("packages/a/node_modules/x/package-lock.json", false)).toBe(true);
    // `target/` is a directory: a file named target is not ignored, a file below one is.
    expect(r.ignores("target", true)).toBe(true);
    expect(r.ignores("target", false)).toBe(false);
    expect(r.ignores("crates/x/target/Cargo.lock", false)).toBe(true);
    // A leading slash anchors to the file's directory.
    expect(r.ignores("dist", true)).toBe(true);
    expect(r.ignores("packages/a/dist", true)).toBe(false);
    // `dir/*/` ignores the subdirectories, not the files beside them (langchain's docs requirements).
    expect(r.ignores("docs/api/core", true)).toBe(true);
    expect(r.ignores("docs/api/requirements.txt", false)).toBe(false);
    expect(r.ignores("docs/api/core/requirements.txt", false)).toBe(true);
    // `*` and `?` stay inside one path segment.
    expect(r.ignores("a/b/c.tmp", false)).toBe(true);
    expect(r.ignores("fooxbar", true)).toBe(true);
    expect(r.ignores("foo/bar", true)).toBe(false);
    expect(r.ignores("fooxxbar", true)).toBe(false);
    // A nested file's rules apply below its own directory only.
    expect(r.ignores("tools/scratch", true)).toBe(true);
    expect(r.ignores("tools/deep/scratch/x", true)).toBe(true);
    expect(r.ignores("scratch", true)).toBe(false);
    expect(r.ignores("tools/only-here", true)).toBe(true);
    expect(r.ignores("tools/deep/only-here", true)).toBe(false);
    expect(r.ignores("src", true)).toBe(false);
  });

  it("`**` as git reads it: any depth before, between and after", () => {
    const r = rulesOf("**/gen\nsrc/**/fixtures\nvendor/**\nlogs/**/*.log\nx**y\n");
    expect(r.ignores("gen", true)).toBe(true);
    expect(r.ignores("a/b/gen", true)).toBe(true);
    expect(r.ignores("a/b/gen/Cargo.lock", false)).toBe(true);
    expect(r.ignores("src/fixtures", true)).toBe(true);
    expect(r.ignores("src/a/b/fixtures", true)).toBe(true);
    // The regular-expression translation matched this one: `src/**/fixtures` became `src/.*fixtures`.
    expect(r.ignores("src/notfixtures", true)).toBe(false);
    expect(r.ignores("lib/src/fixtures", true)).toBe(false);
    // `vendor/**` is everything inside, not the directory itself.
    expect(r.ignores("vendor", true)).toBe(false);
    expect(r.ignores("vendor/x", true)).toBe(true);
    expect(r.ignores("vendor/x/y/go.mod", false)).toBe(true);
    expect(r.ignores("logs/app.log", false)).toBe(true);
    expect(r.ignores("logs/2026/11/app.log", false)).toBe(true);
    expect(r.ignores("logs/app.txt", false)).toBe(false);
    // Stars that are not a whole segment are one star.
    expect(r.ignores("x-anything-y", true)).toBe(true);
    expect(r.ignores("x/y", true)).toBe(false);
  });

  it("a negation is conservative: nothing it could re-include is skipped", () => {
    const r = rulesOf("*.lock\n!Cargo.lock\nbuild/\n!build/keep/\n");
    expect(r.ignores("yarn.lock", false)).toBe(true);
    expect(r.ignores("Cargo.lock", false)).toBe(false);
    expect(r.ignores("build", true)).toBe(true);
    expect(r.ignores("build/keep", true)).toBe(false);
    expect(r.ignores("build/keep/Cargo.lock", false)).toBe(false);
  });

  it.runIf(caseless)("names compare without case where the filesystem does", () => {
    const r = rulesOf("Build/\n*.TMP\n");
    expect(r.ignores("build", true)).toBe(true);
    expect(r.ignores("a/x.tmp", false)).toBe(true);
  });

  it("agrees with the old regular-expression translation on every pattern it read correctly", () => {
    // The translation this module replaced, kept here as the reference for patterns without `**`
    // (its `**` reading was wrong, see above). Small inputs only: it is the one that backtracks.
    const reference = (glob: string, anchored: boolean) => {
      let re = "";
      for (const ch of glob) re += ch === "*" ? "[^/]*" : ch === "?" ? "[^/]" : ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      return new RegExp(`^${anchored ? "" : "(?:.*/)?"}${re}(?:/.*)?$`, caseless ? "i" : "");
    };
    let seed = 20261111;
    const random = (n: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    const pick = (alphabet: string, max: number) => Array.from({ length: 1 + random(max) }, () => alphabet[random(alphabet.length)]).join("");
    let compared = 0;
    for (let round = 0; round < 400; round++) {
      const segments = Array.from({ length: 1 + random(3) }, () => pick("ab*?.", 5));
      const lead = random(3) === 0 ? "/" : "";
      const dirOnly = random(3) === 0;
      const glob = segments.join("/");
      if (glob.includes("**")) continue;
      const line = `${lead}${glob}${dirOnly ? "/" : ""}`;
      fs.rmSync(path.join(dir, ".gitignore"), { force: true });
      const rules = rulesOf(`${line}\n`);
      const regex = reference(glob, lead === "/" || glob.includes("/"));
      for (let p = 0; p < 25; p++) {
        const names = Array.from({ length: 1 + random(4) }, () => pick("ab.", 4));
        const rel = names.join("/");
        const isDir = random(2) === 0;
        const parent = names.length > 1 ? names.slice(0, -1).join("/") : null;
        const expected = dirOnly && !isDir ? parent !== null && regex.test(parent) : regex.test(rel);
        expect(rules.ignores(rel, isDir), `${JSON.stringify(line)} against ${rel}${isDir ? "/" : ""}`).toBe(expected);
        compared++;
      }
    }
    expect(compared).toBeGreaterThan(5_000);
  });
});

describe(".gitignore limits: over a cap means scan more, never hide a lockfile", () => {
  it("a pattern over the length cap is not applied; one within it is", () => {
    const long = `${"x".repeat(MAX_PATTERN_LENGTH + 1)}`;
    write(".gitignore", `${long}\nvendor/\n`);
    const rules = new IgnoreRules(dir);
    expect(rules.ignores(long, true)).toBe(false);
    expect(rules.ignores("vendor", true)).toBe(true);
  });

  it("a NEGATION that cannot be applied re-includes everything below its file", () => {
    write(".gitignore", "vendor/\n");
    write("sub/.gitignore", `gen/\n!${"y".repeat(MAX_PATTERN_LENGTH + 1)}\n`);
    const rules = new IgnoreRules(dir);
    rules.load("sub");
    expect(rules.ignores("vendor", true)).toBe(true);
    expect(rules.ignores("sub/gen", true)).toBe(false);
    expect(rules.ignores("sub/vendor", true)).toBe(false);
  });

  it("a `?` piece longer than the cap is not applied", () => {
    write(".gitignore", `${"?".repeat(MAX_WILDCARD_PIECE + 1)}\n${"?".repeat(4)}\n`);
    const rules = new IgnoreRules(dir);
    expect(rules.ignores("z".repeat(MAX_WILDCARD_PIECE + 1), true)).toBe(false);
    expect(rules.ignores("zzzz", true)).toBe(true);
  });

  it("rules past the per-file count are not read, and then nothing below that file is skipped", () => {
    write(".gitignore", `${Array.from({ length: MAX_RULES_PER_FILE }, (_, i) => `n${i}/`).join("\n")}\nlast/\n`);
    const run = timed(() => new IgnoreRules(dir));
    expect(run.ms).toBeLessThan(500);
    expect(run.value.ignores("n1", true)).toBe(false);
    expect(run.value.ignores("last", true)).toBe(false);
    // Exactly at the cap every rule applies.
    write(".gitignore", `${Array.from({ length: MAX_RULES_PER_FILE }, (_, i) => `n${i}/`).join("\n")}\n`);
    expect(new IgnoreRules(dir).ignores("n1", true)).toBe(true);
  });

  it("a .gitignore over the size cap is not read at all", () => {
    write(".gitignore", `vendor/\n${"# padding\n".repeat(120_000)}`);
    expect(fs.statSync(path.join(dir, ".gitignore")).size).toBeGreaterThan(1_048_576);
    expect(new IgnoreRules(dir).ignores("vendor", true)).toBe(false);
  });

  it("out of its matching budget, the rule set stops answering and says so", () => {
    write(".gitignore", "vendor/\n");
    const rules = new IgnoreRules(dir, { budgetMs: -1 });
    expect(rules.ignores("vendor", true)).toBe(false);
    expect(rules.exhausted).toBe(true);
  });
});

describe("the project-tree walk has a time budget", () => {
  const project = (rel: string) => {
    write(`${rel}/package.json`, JSON.stringify({ name: rel.replace(/\W/g, "-"), dependencies: { lodash: "4.17.21" } }));
    write(`${rel}/package-lock.json`, JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.21" } } }));
  };

  it("within the budget the walk is complete and says nothing", () => {
    for (let i = 0; i < 5; i++) project(`apps/p${i}`);
    const { entries, discovery } = scanProjectTree(dir);
    expect(entries).toHaveLength(6);
    expect(discovery.walkTruncated).toBe(false);
    expect(discovery.walkStopped).toBeUndefined();
    expect(discoveryNote(discovery)).toBeNull();
  });

  it("past the budget it stops, and every tool is told the scan is partial", async () => {
    for (let i = 0; i < 40; i++) project(`apps/p${i}`);
    process.env.FOURDA_WALK_BUDGET_MS = "0.001";
    const { entries, discovery } = scanProjectTree(dir);
    expect(discovery.walkTruncated).toBe(true);
    expect(discovery.walkStopped).toBe("time_budget");
    expect(entries.length).toBeLessThan(41);
    const note = discoveryNote(discovery);
    expect(note).toMatch(/^Partial scan: the directory walk stopped at its 0 s time budget, so the directories it had not reached were not read/);

    // The same walk, as vulnerability_scan reports it: coverage is not complete.
    const live = new LiveIntelligence(null);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    live.scanVulnerabilities = async () => ({
      scannedAt: new Date().toISOString(), projectPath: dir, ecosystemsScanned: ["npm"], totalScanned: 1, totalVulnerable: 0, platformInactiveVulnerable: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities: [], cleanCount: 1, scanDurationMs: 0, cached: false, offline: false, unchecked: 0, uncheckedReason: null, staleAnswers: 0,
    });
    const answer = (await executeVulnerabilityScan(null, { response_format: "detailed" }, live)) as { coverage?: { complete: boolean; note: string } };
    expect(answer.coverage?.complete).toBe(false);
    expect(answer.coverage?.note).toContain("time budget");
  });

  it("a rule set that ran out of its budget ends the walk the same way", () => {
    const budget = startWalkBudget({ exhausted: true });
    expect(budget.spent()).toBe(true);
    expect(budget.stopped).toBe(true);
    expect(startWalkBudget({ exhausted: false }).spent()).toBe(false);
  });

  it("5,000 of the most expensive rules the matcher accepts cannot hold the walk past its budget", () => {
    for (let i = 0; i < 4; i++) project(`apps/p${i}`);
    write(".gitignore", `${Array.from({ length: MAX_RULES_PER_FILE }, (_, i) => `${"a?".repeat(30)}*${"?a".repeat(30)}*z${i}`).join("\n")}\n`);
    for (let i = 0; i < 80; i++) write(`big/${"a".repeat(240)}${i}/keep.txt`, "");
    // A budget that is certainly spent before the walk ends, on any machine: what is under test is
    // that the walk STOPS promptly once it is spent, with 5,000 of the costliest rules to match at
    // every directory. (A 150 ms budget made this depend on runner speed: CI walked the tree in 119 ms.)
    process.env.FOURDA_WALK_BUDGET_MS = "1";
    const run = timed(() => scanProjectTree(dir));
    // Stopped, and said so: never a silent drop, never a hang.
    expect(run.value.discovery.walkTruncated).toBe(true);
    expect(run.value.discovery.walkStopped).toBe("time_budget");
    expect(discoveryNote(run.value.discovery)).toMatch(/stopped at its [\d.]+ s time budget/);
    expect(run.ms).toBeLessThan(5_000);
  });
});

describe("a lockfile over the size cap is not read, and is reported", () => {
  it("the group resolves to nothing with a problem that names the file and the size", () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.21" } }));
    write("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.21" } }, padding: "x".repeat(4_096) }));
    const group = { dir, language: "npm", deps: ["lodash"], devDeps: [], targets: {} };
    expect(resolveGroup(group).audit.map((d) => `${d.name}@${d.version}`)).toEqual(["lodash@4.17.21"]);

    process.env.FOURDA_MAX_LOCKFILE_BYTES = "2048";
    const refused = resolveGroup(group);
    expect(refused.audit).toEqual([]);
    expect(refused.resolved).toEqual([]);
    expect(refused.problems).toHaveLength(1);
    expect(refused.problems[0].file).toBe(path.join(dir, "package-lock.json"));
    expect(refused.problems[0].error).toMatch(/^is 4 KB, over the 2 KB this server reads in one lockfile or manifest, so it was not read$/);
    // Worded for the agent as every unread lockfile is: its dependencies were not checked.
    expect(lockfileProblemNotes(refused.problems).join(" ")).toMatch(/^UNREADABLE: 1 lockfile could not be read, so its dependencies were not checked: .*package-lock\.json \(is 4 KB, over the 2 KB/);
    // Its signature is kept: once the file shrinks, the group is read again.
    expect(refused.signatures.has(path.join(dir, "package-lock.json"))).toBe(true);
  });
});

describe("Cargo.toml: the crate name is read in one pass", () => {
  it("reads the [package] table's name and nothing else", () => {
    expect(cargoPackageName('[package]\nname = "fourda"\nversion = "1.0.0"\n')).toBe("fourda");
    expect(cargoPackageName('[workspace]\nmembers = []\n\n[package]\nedition = "2021"\nname="a-b"\n[lib]\nname = "other"\n')).toBe("a-b");
    expect(cargoPackageName('[package]\nversion = "1"\n[lib]\nname = "not-the-package"\n')).toBeNull();
    expect(cargoPackageName('[workspace]\nmembers = []\n')).toBeNull();
    expect(cargoPackageName('[package]\r\nname = "crlf"\r\n')).toBe("crlf");
    expect(cargoPackageName('[package]\nnamespace = "x"\nname = ""\n')).toBeNull();
  });

  it("2 MB of [package] headers (minutes for the regular expression it replaced)", () => {
    const run = timed(() => cargoPackageName("[package]\n".repeat(200_000)));
    expect(run.value).toBeNull();
    expect(run.ms).toBeLessThan(250);
  });
});

/**
 * Published 6.2.7 never answers the first tool call here, so any bound proves the fix. This one is
 * generous on purpose: on a machine busy with other work the first tool call of a session (which
 * creates the standalone database) has been seen to take over 15 s.
 */
const REQUEST_BOUND_MS = 45_000;

// The built server is needed: skipped where only the source is checked out (the 4DA repo's
// MCP schema contract job runs this suite without building it). MCP CI builds first, so it runs there.
describe.skipIf(!fs.existsSync(serverEntry))("the built server, started inside a hostile repository, answers every request", () => {
  it("two lines of .gitignore and a 40-character directory: tool calls and tools/list all answer", async () => {
    write(".gitignore", STARS);
    write(`${LONG_NAME}/README.md`, "x");
    write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { lodash: "4.17.21" } }));
    write("package-lock.json", JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", dependencies: { lodash: "4.17.21" } }, "node_modules/lodash": { version: "4.17.21" } } }));
    const constraint = `>=${"1 ".repeat(4_000)}x`;
    const { results, timings, tools } = await stdioSession(
      dir,
      [
        ["dependency_check", { items: [{ ecosystem: "npm", package: "lodash", to: "4.17.21" }] }],
        ["vulnerability_scan", {}],
        ["dependency_check", { items: [{ ecosystem: "npm", package: "lodash", to: constraint }] }],
        ["dependency_health", {}],
      ],
      {},
      { requestTimeoutMs: REQUEST_BOUND_MS, listAfterCalls: true },
    );
    expect(tools).toContain("dependency_check");
    expect(timings.map((t) => t.method)).toEqual([
      "initialize",
      "tools/list",
      "resources/list",
      "tools/call dependency_check",
      "tools/call vulnerability_scan",
      "tools/call dependency_check",
      "tools/call dependency_health",
      "tools/list (after the calls)",
    ]);
    // Every request answered, each within the bound (the session rejects one that is not).
    for (const t of timings) expect(t.ms, t.method).toBeLessThan(REQUEST_BOUND_MS);
    // The network is blocked in this session, so nothing is clean: each answer says it was not checked.
    expect(resultText(results[0])).toContain('"verdict":"unknown"');
    expect(resultText(results[1])).toMatch(/NOT CHECKED/);
    // The 8 KB constraint is refused by its length, immediately, with what was too long.
    expect(results[2].isError).toBe(true);
    expect(resultText(results[2])).toMatch(/items\[0\]\.to is 8,003 characters long; the limit is 256\. It starts /);
    expect(resultText(results[2]).length).toBeLessThan(400);
    expect(timings[5].ms).toBeLessThan(5_000);
  }, 240_000);
});
