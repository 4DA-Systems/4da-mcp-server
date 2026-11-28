// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25 B-B1: a directory name comes from the scanned repository, and it reached
 * `run_order[].dir`, the rows' `commands[].dir`, `upgradeCommands[].dir` and the "run X in <dir>"
 * prose unfiltered (`a$(PWN1)`, `c;PWN3;`, backticks, `%VAR%`, a leading `--`). A step in a
 * directory whose name is not a plain path gets no command and no `dir` an agent could paste:
 * only words saying the name is not safe in a command, with the name shown escaped, and the row
 * is not counted as fixed or put in run_order.
 *
 * The network is the harness's stubbed fetch: nothing leaves the process.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { escapeUnsafeDirs, isShellSafeDir, unsafeDirLabel } from "../live/shell-safe.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
// Every request goes to the harness's stubbed global fetch, which answers in-process: no socket is
// opened. (A dead HTTPS_PROXY would route the lookups through undici's proxy agent instead, around
// the stub; the proxy variables are cleared so that cannot happen.)
const PROXY_VARS = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of PROXY_VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  h = createHarness();
});
afterEach(() => {
  h.dispose();
  for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
});

describe("isShellSafeDir: a plain path on bash, cmd and PowerShell", () => {
  it.each([
    ".",
    "packages/web",
    "apps/my app",
    "packages/@scope/ui",
    "node_modules/@types/node",
    "dir.with.dots/v1.2",
    "pkgs/under_score-dash",
    "Ünïcödé/日本語/данные",
    "c++",
    "../sibling",
    "C:/work/project",
    "/home/dev/project",
    // Real repository names, inert quoted and unquoted (audit 2026-11-25 blind check).
    "@scope/pkg2",
    "c#lib",
    "v1,2",
    "a=b",
    "x  y",
    "a~b",
    "a+b",
    "a@b",
    "packages/-x",
    "i‐x",
  ])("%j is a plain path", (dir) => {
    expect(isShellSafeDir(dir)).toBe(true);
    expect(unsafeDirLabel(dir)).toBe(dir);
  });

  it.each([
    ["a$(PWN1)", "bash/PowerShell command substitution"],
    ["b`PWN2`", "backticks"],
    ["c;PWN3;", "a command separator"],
    ["d&PWN4&", "cmd and bash &"],
    ["e %PWN5% x", "a cmd variable"],
    ["f$HOME$PWN6", "a variable"],
    ["--registry=PWN7", "a leading dash"],
    ["g'PWN8'", "a quote"],
    ["h{PWN9}", "a PowerShell script block"],
    ["\u2013x", "a leading en dash PowerShell reads as a parameter dash"],
    ["~tmp", "a leading tilde (bash: the home of user tmp)"],
    ["#x", "a leading # (a comment unquoted)"],
    ["a:b", "a PowerShell drive"],
    ["a?b", "a wildcard"],
    ["a\u201cb", "a curly quote PowerShell ends a string on"],
    ["a\u00a0b", "a no-break space"],
    ["j @(PWN11)", "a PowerShell array subexpression"],
    ["k!PWN12!", "cmd delayed expansion"],
    ["Program Files (x86)/app", "parentheses: PowerShell runs (x86) as a subexpression when unquoted"],
    ["x\u200by", "a zero-width space"],
    ["x\u202ey", "a bidi override"],
    ["x\u3164y", "a Hangul filler that renders blank"],
    ["x\ny", "a newline"],
    ["@scope", "a bare leading @ (PowerShell splats @scope unquoted)"],
    ["a|b", "a pipe"],
    ["a>b", "a redirect"],
    ["a*b", "a glob"],
    ["web[1]", "a PowerShell wildcard even quoted, a bash glob unquoted: cd lands in web1"],
    ["[legacy]", "a bracket wildcard"],
    ["c^d", "cmd's escape: unquoted cd c^d lands in cd"],
    ["a\\b", "a backslash"],
    ["", "an empty name"],
    ["a//b", "an empty segment"],
    ["x".repeat(1100), "an overlong path"],
  ])("%j is not (%s)", (dir) => {
    expect(isShellSafeDir(dir)).toBe(false);
  });

  it("the label shows an unsafe name escaped, with no shell metacharacter left in it", () => {
    const label = unsafeDirLabel("a$(PWN1)");
    expect(label).toBe("[unsafe directory name, escaped: a\\u0024\\u0028PWN1\\u0029]");
    for (const dir of ["b`PWN2`", "c;PWN3;", "e %PWN5% x", "--registry=PWN7", "k!PWN12!", "x\u202ey", "j @(PWN11)"]) {
      const inner = unsafeDirLabel(dir).replace(/^\[unsafe directory name, escaped: /, "").replace(/\]$/, "");
      expect(inner).not.toMatch(/[$`;&%!'"(){}|<>\u202e@]|^-/);
    }
  });

  it("escapeUnsafeDirs rewrites prose, never a command field or a backtick span", () => {
    const value = {
      reasons: ["run `npm ci` in a$(PWN1)", "a$(PWN1)/package.json declares it", "see packages/a$(PWN1) too"],
      upgradeCommands: [{ dir: "ok", command: "npm install a$(PWN1)" }],
      run: "keep a$(PWN1)",
    };
    const out = escapeUnsafeDirs(value, ["a$(PWN1)", "packages/a$(PWN1)"]) as typeof value;
    expect(out.reasons[0]).toBe(`run \`npm ci\` in ${unsafeDirLabel("a$(PWN1)")}`);
    expect(out.reasons[1]).toBe(`${unsafeDirLabel("a$(PWN1)")}/package.json declares it`);
    expect(out.reasons[2]).toBe(`see ${unsafeDirLabel("packages/a$(PWN1)")} too`);
    expect(out.upgradeCommands[0].command).toBe("npm install a$(PWN1)");
    expect(out.run).toBe("keep a$(PWN1)");
  });

  it("a name inside another word is not rewritten; one that starts a word in prose is", () => {
    const out = escapeUnsafeDirs({ reasons: ["pip-a$(x) stays", "in a$(x)."] }, ["a$(x)"]) as { reasons: string[] };
    expect(out.reasons[0]).toBe("pip-a$(x) stays");
    expect(out.reasons[1]).toBe(`in ${unsafeDirLabel("a$(x)")}.`);
  });

  it("hundreds of unsafe directories over a large answer are rewritten quickly", () => {
    const dirs = Array.from({ length: 400 }, (_, i) => `packages/d${i}$(x)`);
    const reasons = Array.from({ length: 2000 }, (_, i) => `run \`npm ci\` in packages/d${i % 400}$(x); ${"plain words ".repeat(15)}`);
    const start = process.hrtime.bigint();
    const out = escapeUnsafeDirs({ reasons }, dirs) as { reasons: string[] };
    expect(Number(process.hrtime.bigint() - start) / 1e6).toBeLessThan(2000);
    expect(out.reasons.some((r) => r.includes("$(x)"))).toBe(false);
    expect(escapeUnsafeDirs({ projectPath: "C:/w/d1$(x)" }, ["d1$(x)"])).toEqual({ projectPath: "C:/w/d1$(x)" });
  });

  it("a bare @scope is escaped on its own, never inside @scope/pkg; a plain dir field is kept exactly", () => {
    const out = escapeUnsafeDirs({ reasons: ["in @scope and in @scope/pkg2 and packages/@scope/pkg"], dir: "@scope/pkg2" }, ["@scope"]) as { reasons: string[]; dir: string };
    expect(out.reasons[0]).toBe(`in ${unsafeDirLabel("@scope")} and in @scope/pkg2 and packages/@scope/pkg`);
    expect(out.dir).toBe("@scope/pkg2");
  });

  it("a Windows spelling of a nested unsafe directory is rewritten too", () => {
    const out = escapeUnsafeDirs({ note: "C:\\p\\packages\\z$(PWN13)\\package-lock.json" }, ["packages/z$(PWN13)"]) as { note: string };
    expect(out.note).not.toContain("$(PWN13)");
  });
});

describe("upgrade_planner: a step in a directory whose name is not a plain path", () => {
  const LOCK = (name: string) => JSON.stringify({ name, version: "1.0.0", lockfileVersion: 3, packages: { "": { name, version: "1.0.0", dependencies: { lodash: "4.17.20" } }, "node_modules/lodash": { version: "4.17.20" } } });
  function project(dirs: string[]) {
    h.ADVISORIES.lodash = [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21"))];
    h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } } };
    for (const [i, d] of dirs.entries()) {
      h.write(`${d}/package.json`, JSON.stringify({ name: `p${i}`, version: "1.0.0", dependencies: { lodash: "4.17.20" } }));
      h.write(`${d}/package-lock.json`, LOCK(`p${i}`));
    }
  }
  const DIR_FIELDS = (result: Record<string, any>): string[] => {
    const dirs: string[] = [];
    for (const s of result.run_order ?? []) dirs.push(s.dir);
    for (const r of result.recommendations ?? []) {
      for (const c of r.commands ?? []) dirs.push(c.dir);
      for (const c of r.upgradeCommands ?? []) dirs.push(c.dir);
      for (const c of r.refreshCommands ?? []) dirs.push(c.dir);
      for (const c of r.upgradeInstructions ?? []) dirs.push(c.dir);
      for (const u of r.parentUpgrades ?? []) {
        for (const c of u.refreshCommands ?? []) dirs.push(c.dir);
        for (const l of u.levers ?? []) for (const c of [...(l.commands ?? []), ...(l.instructions ?? [])]) dirs.push(c.dir);
      }
    }
    return dirs;
  };

  it("names no command and no dir there, says why in words, and counts the row as not runnable", async () => {
    project(["a$(PWN1)"]);
    const { result, step } = await h.plan();
    const row = step("lodash");
    expect(row).toBeDefined();
    expect(DIR_FIELDS(result).filter((d) => !isShellSafeDir(d))).toEqual([]);
    expect(result.run_order).toEqual([]);
    expect(result.quickWins).toBe(0);
    expect(row.reasons.join("\n")).toMatch(/not safe to put in a command/);
    expect(row.reasons.join("\n")).toContain(unsafeDirLabel("a$(PWN1)"));
    // The raw name is nowhere in the answer.
    expect(JSON.stringify(result)).not.toContain("$(PWN1)");
    expect(result.summary).toMatch(/not safe to put in a command/);
    expect(result.run_order_note).toMatch(/not safe to put in a command/);
  });

  it.each(["c;PWN3;", "b`PWN2`", "e %PWN5% x", "--registry=PWN7", "k!PWN12!"])("the same for %j", async (d) => {
    project([d]);
    const { result } = await h.plan();
    expect(DIR_FIELDS(result).filter((x) => !isShellSafeDir(x))).toEqual([]);
    expect(result.run_order).toEqual([]);
    const marker = /PWN\d+/.exec(d)![0];
    // The marker may appear escaped; the raw directory name may not.
    expect(JSON.stringify(result)).not.toContain(JSON.stringify(d).slice(1, -1));
    expect(JSON.stringify(result)).toContain(marker);
  });

  it("a safe directory beside an unsafe one keeps its step in run_order; only the unsafe one is withheld, and said", async () => {
    project(["ok", "a$(PWN1)", "zz"]);
    const { result, step } = await h.plan();
    const row = step("lodash");
    expect(DIR_FIELDS(result).filter((d) => !isShellSafeDir(d))).toEqual([]);
    expect(row.commands.some((c: { dir: string }) => c.dir === "ok")).toBe(true);
    // Every step in a safe directory stays, in order (the blind check: one odd directory emptied run_order).
    expect(result.run_order.map((s: { dir: string }) => s.dir)).toEqual(["ok", "zz"]);
    expect(result.quickWins).toBe(0);
    expect(result.run_order_note).toMatch(/^run_order is 2 steps/);
    expect(result.run_order_note).toMatch(/1 step was withheld because it would run in a directory whose name is not safe to put in a command/);
    expect(result.summary).toMatch(/1 with 1 step withheld/);
    expect(JSON.stringify(result)).not.toContain("$(PWN1)");
  });

  it("ordinary directory names keep their commands (spaces, unicode, dots, @scope)", async () => {
    project(["apps/my app", "packages/@scope/ui", "Ünïcödé.v2"]);
    const { result, step } = await h.plan();
    const row = step("lodash");
    // NFC on both sides: a filesystem may hand the name back decomposed (both forms are plain paths).
    const nfc = (dirs: string[]) => dirs.map((d) => d.normalize("NFC")).sort();
    expect(nfc(row.commands.map((c: { dir: string }) => c.dir))).toEqual(nfc(["Ünïcödé.v2", "apps/my app", "packages/@scope/ui"]));
    expect(result.run_order.length).toBeGreaterThan(0);
    expect(row.reasons.join("\n")).not.toMatch(/not safe to put in a command/);
  });
});
