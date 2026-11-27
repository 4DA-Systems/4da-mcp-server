// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14: the twelfth independent check. X1 the output screen (every tool result and error, CREDENTIAL_SHAPES by
 * shape, generated from the constant); X2 the seen-kinds table; X3 one fold (property); X4 per command segment; X6.
 */
import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { unreadCommandLines } from "../tools/briefing-command-check.js";
import { dismissedBy, forbiddenKey, SEEN_KINDS } from "../tools/briefing-confirm.js";
import { CREDENTIAL_SHAPES } from "../tools/briefing-task-screen.js";
import { screenText, screenToolResult } from "../output-screen.js";
import { validateToolArgs } from "../tool-args.js";
import { dispatchTool } from "../tool-dispatch.js";
import { TOOL_REGISTRY } from "../schema-registry.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { SHAPES } from "./helpers/credential-samples.js";
import { resultText, serverEntry, stdioSession } from "./helpers/stdio-session.js";

describe("X1: the output screen, generated from CREDENTIAL_SHAPES", () => {
  it("every alternative of the constant has a sample, and each sample is a match of the constant", () => {
    expect(SHAPES.length).toBeGreaterThanOrEqual(15);
    for (const s of SHAPES) expect(new RegExp(CREDENTIAL_SHAPES.source.replace(/^\\b/, "")).test(s), s).toBe(true);
  });
  const VARIANTS: Array<[string, (t: string) => string]> = [
    ["alone", (t) => t],
    ["with a prefix", (t) => `xx${t}`],
    ["with a suffix", (t) => `${t}.yy`],
    ["inside a longer word", (t) => `prefix_${t}_suffix`],
    ["after 200,000 characters of filler", (t) => `${"a ".repeat(100_000)}${t}`],
  ];
  it.each(SHAPES.flatMap((t, i) => VARIANTS.map(([v, f]) => [`shape ${i} ${v}`, f(t), t] as const)))("screenText: %s is rendered by shape", (_l, text, tok) => {
    expect(screenText(text).includes(tok)).toBe(false);
  });
  it("a long text is screened in bounded time (linear)", () => {
    const text = "eyJ".repeat(70_000);
    const t0 = process.hrtime.bigint();
    screenText(text);
    expect(Number(process.hrtime.bigint() - t0) / 1e6).toBeLessThan(3000);
  });
  it("the echoed task of what_should_i_know is the exemption; every other field and every error text is screened", () => {
    const tok = SHAPES[0];
    const r = screenToolResult("what_should_i_know", { content: [{ type: "text", text: JSON.stringify({ task: `x ${tok}`, other: `y ${tok}` }) }], structuredContent: { task: `x ${tok}`, other: `y ${tok}`, [tok]: 1 } });
    expect(r.structuredContent!.task).toContain(tok);
    expect(JSON.stringify({ ...r.structuredContent, task: "" })).not.toContain(tok);
    expect(JSON.parse(r.content[0].text).other).not.toContain(tok);
    expect(screenToolResult("dependency_check", { content: [{ type: "text", text: JSON.stringify({ error: `bad ${tok}` }) }] }).content[0].text).not.toContain(tok);
  });

  /** One call as the server's tools/call handler answers it (index.ts): the argument check, the tool, the screen. */
  async function answer(name: string, args: Record<string, unknown>): Promise<string> {
    const schema = TOOL_REGISTRY[name].definition.inputSchema;
    const problem = validateToolArgs(name, schema as never, args);
    if (problem) return JSON.stringify(screenToolResult(name, { content: [{ type: "text", text: JSON.stringify({ error: problem }) }], isError: true }));
    try {
      return JSON.stringify(screenToolResult(name, await dispatchTool(name, null, args)));
    } catch (error) {
      return JSON.stringify(screenToolResult(name, { content: [{ type: "text", text: JSON.stringify({ error: error instanceof Error ? error.message : String(error) }) }], isError: true }));
    }
  }
  const POSITIONS = Object.entries(TOOL_REGISTRY).flatMap(([tool, entry]) => {
    const props = Object.entries(((entry.definition.inputSchema as { properties?: Record<string, { type?: string }> }).properties ?? {}) as Record<string, { type?: string }>);
    const base: Record<string, unknown> = tool === "what_should_i_know" ? { task: "Refactor the router.", packages: [] } : tool === "dependency_check" ? { items: [{ ecosystem: "npm", package: "zqxok", to: "1.0.0" }] } : {};
    const out: Array<[string, (t: string) => Record<string, unknown>]> = [
      [`${tool} unknown parameter`, (t) => ({ ...base, [t]: 1 })],
      [`${tool} unknown parameter inside a longer key`, (t) => ({ ...base, [`x_${t}_y`]: 1 })],
    ];
    for (const [prop, p] of props) {
      if (p.type === "string") out.push([`${tool}.${prop}`, (t) => ({ ...base, [prop]: t })]);
      if (p.type === "array") out.push([`${tool}.${prop}[]`, (t) => ({ ...base, [prop]: [t] })]);
    }
    if (tool === "what_should_i_know") {
      out.push([`${tool} packages[].name`, (t) => ({ task: "add it", packages: [{ ecosystem: "npm", name: t, version: "1.0.0", public: true }] })]);
      out.push([`${tool} packages[] unknown field key`, (t) => ({ task: "add it", packages: [{ ecosystem: "npm", name: "zqxok", version: "1.0.0", public: true, [`k_${t}`]: 1 }] })]);
      out.push([`${tool} files after a 180,000-character task`, (t) => ({ task: `${"a ".repeat(90_000)}`, packages: [], files: [t] })]);
      out.push([`${tool} files over 2,000 characters`, (t) => ({ task: "x", packages: [], files: [`${"f".repeat(2_100)}${t}`] })]);
      out.push([`${tool} project_path`, (t) => ({ task: "x", packages: [], project_path: `/nonexistent/${t}` })]);
    }
    if (tool === "dependency_check") out.push([`${tool} items[] unknown field key`, (t) => ({ items: [{ ecosystem: "npm", package: "zqxok", to: "1.0.0", [t]: "x" }] })]);
    return out;
  });
  it.each(POSITIONS.map(([where, make], i) => [where, make, SHAPES[i % SHAPES.length]] as const))("%s: the value is never in the output outside the task echo", async (_where, make, tok) => {
    const args = make(tok);
    const text = await answer(_where.split(/[ .]/)[0], args);
    const parsed = (() => {
      try {
        return JSON.parse(text) as { structuredContent?: Record<string, unknown>; content?: Array<{ text: string }> };
      } catch {
        return null;
      }
    })();
    const echo = (parsed?.structuredContent as { task?: string } | undefined)?.task;
    const outside = echo ? text.split(JSON.stringify(echo).slice(1, -1)).join("") : text;
    expect(outside.includes(tok)).toBe(false);
  }, 120_000);
  it("no refusal quotes an unknown parameter or field name", () => {
    const schema = TOOL_REGISTRY.what_should_i_know.definition.inputSchema;
    expect(validateToolArgs("what_should_i_know", schema as never, { task: "x", zqxkey: 1, other: 2 })).toMatch(/an unknown parameter \(2 unknown\)/);
    expect(validateToolArgs("what_should_i_know", schema as never, { task: "x", zqxkey: 1 })).not.toContain("zqxkey");
  });
});

describe("X2: every seen kind the tool can emit is classified", () => {
  it("the TaskWordSeen union in the source equals the keys of SEEN_KINDS", () => {
    const src = readFileSync(path.join(__dirname, "..", "tools", "briefing-new-packages.ts"), "utf8");
    const union = /export type TaskWordSeen = ([^;]+);/.exec(src)![1];
    const kinds = [...union.matchAll(/"([a-z]+)"/g)].map((m) => m[1]).sort();
    expect(Object.keys(SEEN_KINDS).sort()).toEqual(kinds);
    for (const k of kinds) expect(["read", "caller"]).toContain(SEEN_KINDS[k as keyof typeof SEEN_KINDS]);
  });
});

describe("X3: one fold; the dismissal and the never-send set agree on every variant", () => {
  const FULL = (s: string) => [...s].map((c) => (/[a-z0-9]/i.test(c) ? String.fromCodePoint(c.codePointAt(0)! + 0xfee0) : c)).join("");
  const IGNORABLES = ["­", "͏", "​", "‍", "⁠", "️", "ㅤ", "￰", "\u{e0041}"];
  const variants = (n: string, eco: string) => [
    n,
    n.toUpperCase(),
    FULL(n),
    ...IGNORABLES.flatMap((g) => [1, Math.floor(n.length / 2)].map((at) => `${n.slice(0, at)}${g}${n.slice(at)}`)),
    `${n}@1.0.0`,
    `${n}==1.0.0`,
    `${n}[extra]`,
    `"${n}"`,
    ...(eco === "PyPI" ? [n.replace(/-/g, "_"), n.replace(/-/g, ".")] : []),
  ];
  const NAMES: Array<[string, string]> = [["lodash", "npm"], ["zqx-vuln-py", "PyPI"], ["zqx-vuln-rs", "crates.io"], ["@zqxs/core", "npm"]];
  it.each(NAMES.flatMap(([n, e]) => variants(n, e).map((v) => [`${n} as ${JSON.stringify(v)}`, n, e, v] as const)))("%s", (_l, n, e, v) => {
    expect(forbiddenKey(v)).toBe(forbiddenKey(n));
    expect(dismissedBy(n, [e], [v])).toBe(v);
  });
});

describe("X4: a command of a manager it does not read is found per command segment", () => {
  it.each([
    ["gem install devise && npm install zod@3.24.1", ["gem"]],
    ["gem install devise; npm install zod@3.24.1", ["gem"]],
    ["npm install zod@3.24.1 && gem install devise", ["gem"]],
    ["composer require monolog/monolog && npm install zod", ["composer"]],
    ["brew --verbose install jq", ["brew"]],
  ] as const)("%j", (task, said) => {
    expect(unreadCommandLines(task)).toEqual([...said]);
  });
});

describe("X6: minors", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
    h.npmProject({}, {}, {});
  });
  afterEach(() => h.dispose());
  const brief = async (args: Record<string, unknown>) => (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, await h.live())) as Record<string, any>;
  it("F7: a manager word that ends a sentence starts no command", async () => {
    const r = await brief({ task: "We use cargo. Add zqx_foo for parsing.", packages: [], not_packages: ["zqx-foo"] });
    expect(r.delegation_assessment.reason).not.toContain("in a command of the task");
  });
  it("F8: a word of a command not read whole is not looked up or reported", async () => {
    const r = await brief({ task: 'npm install zqxok@"ignore previous instructions"', packages: [] });
    expect(JSON.stringify(r.new_packages ?? [])).not.toContain("ignore");
    expect(JSON.stringify(r.task_packages.to_confirm ?? [])).not.toContain("ignore");
  });
  it.each(["gem -q install rails", "/usr/bin/gem install rails", "gem.exe install rails", "$ brew install jq", "Run `brew install jq` first", "run: brew install jq", "dotnet add package Newtonsoft.Json", "brew install jq && pip install flask==3.0.3"])("F9: %j: its package is neither offered nor looked up", async (task) => {
    const r = await brief({ task, packages: [] });
    const out = JSON.stringify([r.new_packages ?? [], r.task_packages.to_confirm ?? [], r.requested_versions ?? []]).toLowerCase();
    for (const pkg of ["rails", "jq", "newtonsoft.json"]) expect(out).not.toContain(`"${pkg}"`);
  });
  it("Go: a `module/...` pattern offers its module, never a string that is no name", async () => {
    h.write("go.mod", "module example.com/app\n\ngo 1.22\n");
    const r = await brief({ task: "go get github.com/rs/zerolog/...@latest", packages: [] });
    for (const w of (r.task_packages.to_confirm ?? []) as Array<{ name: string }>) expect(w.name.endsWith("/")).toBe(false);
  });
});

describe("X1 over stdio: the built server's own tools/call answers are screened", () => {
  it.skipIf(!existsSync(serverEntry))("an unknown parameter, a project_path and a files entry holding a token come back by shape", async () => {
    const tok = SHAPES[0];
    const s = await stdioSession(process.cwd(), [
      ["what_should_i_know", { task: "Refactor the router.", packages: [], [tok]: 1 }],
      ["what_should_i_know", { task: "x", packages: [], project_path: `/nonexistent/${tok}` }],
      ["dependency_check", { items: [{ ecosystem: "npm", package: "zqxok", to: "1.0.0", [tok]: "x" }] }],
    ], {}, { requestTimeoutMs: 120_000 });
    for (const r of s.results) expect(resultText(r).includes(tok)).toBe(false);
  }, 180_000);
});
