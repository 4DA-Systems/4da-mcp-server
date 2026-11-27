// SPDX-License-Identifier: Apache-2.0
/**
 * Round 15: the thirteenth independent check. A1 the call's never-send set at the request choke point (every lookup
 * path, Go prefixes); A2 every JSON-RPC response screened at the transport, whole tokens; A4 command positions;
 * A5 the folded task is said; the near-miss word cap counts a call's own words.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { unreadCommandLines } from "../tools/briefing-command-check.js";
import { forbiddenKey, OUTSIDE_COVERAGE, TASK_FOLDED } from "../tools/briefing-confirm.js";
import { refusePrivateRequest, VETOED, withRequestVeto } from "../live/private-guard.js";
import { screenJsonRpc, screenText, screenWireText } from "../output-screen.js";
import { mayScanWord, runWithCallBudget, WORD_SCAN_CAP } from "../call-budget.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { serverEntry } from "./helpers/stdio-session.js";
import { SHAPES } from "./helpers/credential-samples.js";

describe("A1: the call's never-send set at the request choke point", () => {
  const veto = (forbidden: string[]) => {
    const keys = new Set(forbidden.map(forbiddenKey));
    return {
      forbids: (_eco: string | null, name: string) => {
        if (keys.has(forbiddenKey(name))) return true;
        const parts = name.split("/");
        for (let k = parts.length - 1; k >= 1; k--) if (keys.has(forbiddenKey(parts.slice(0, k).join("/")))) return true;
        return false;
      },
    };
  };
  const refused = (forbidden: string[], url: string, body?: unknown) =>
    withRequestVeto(veto(forbidden), () => {
      try {
        refusePrivateRequest(url, body === undefined ? undefined : { body: JSON.stringify(body) });
        return false;
      } catch (e) {
        expect(String((e as Error).message)).toContain(VETOED);
        return true;
      }
    });
  const FOLDS = (n: string) => [n, n.toUpperCase(), [...n].map((c) => (/[a-z]/.test(c) ? String.fromCodePoint(c.codePointAt(0)! + 0xfee0) : c)).join(""), `${n.slice(0, 2)}​${n.slice(2)}`];
  // Every lookup path of the engine, by its request shape.
  const PATHS: Array<[string, string, (n: string) => [string, unknown?]]> = [
    ["npm document", "zqxpriv", (n) => [`https://registry.npmjs.org/${n}`]],
    ["npm release", "zqxpriv", (n) => [`https://registry.npmjs.org/${n}/1.0.0`]],
    ["npm scoped", "@zqxs/core", (n) => [`https://registry.npmjs.org/${n.replace("/", "%2f")}`]],
    ["PyPI document", "zqx-priv", (n) => [`https://pypi.org/pypi/${n}/json`]],
    ["PyPI release", "zqx-priv", (n) => [`https://pypi.org/pypi/${n}/1.0.0/json`]],
    ["crates index", "zqx-priv", (n) => [`https://index.crates.io/zq/x-/${n}`]],
    ["crates API", "zqx-priv", (n) => [`https://crates.io/api/v1/crates/${n}`]],
    ["OSV query", "zqxpriv", (n) => ["https://api.osv.dev/v1/query", { package: { name: n, ecosystem: "npm" } }]],
    ["OSV batch", "zqxpriv", (n) => ["https://api.osv.dev/v1/querybatch", { queries: [{ package: { name: "lodash", ecosystem: "npm" } }, { package: { name: n, ecosystem: "npm" } }] }]],
    ["Go list", "github.com/zqxpriv/mod", (n) => [`https://proxy.golang.org/${n.toLowerCase()}/@v/list`]],
    ["Go latest", "github.com/zqxpriv/mod", (n) => [`https://proxy.golang.org/${n.toLowerCase()}/@latest`]],
    ["Go walk: a public sub-path's parent", "github.com/zqxpriv/mod", () => ["https://proxy.golang.org/github.com/zqxpriv/mod/@latest"]],
    ["Go sub-path under it", "github.com/zqxpriv/mod", () => ["https://proxy.golang.org/github.com/zqxpriv/mod/sub/@v/v1.2.0.info"]],
    ["GitHub repository", "github.com/zqxpriv/mod", () => ["https://api.github.com/repos/zqxpriv/mod/releases"]],
  ];
  it.each(PATHS.flatMap(([label, name, make]) => FOLDS(name).map((v) => [`${label}, forbidden as ${JSON.stringify(v)}`, v, make(name)] as const)))("%s: refused", (_l, forbidden, [url, body]) => {
    expect(refused([forbidden], url, body)).toBe(true);
  });
  it("a request for another name passes", () => {
    expect(refused(["zqxpriv"], "https://registry.npmjs.org/lodash")).toBe(false);
    expect(refused(["github.com/zqxpriv/mod"], "https://proxy.golang.org/github.com/zqxpub/mod/@latest")).toBe(false);
  });
});

describe("A2: every JSON-RPC response is screened, whole tokens", () => {
  it.each(SHAPES.map((t, i) => [i, t] as const))("shape %i in a resources/read or prompts/get error and in a prompt's text", (_i, tok) => {
    const err = screenJsonRpc({ jsonrpc: "2.0", id: 1, error: { code: -32002, message: `Resource not found: ${tok}`, data: { uri: tok } } });
    expect(JSON.stringify(err).includes(tok)).toBe(false);
    const prompt = screenJsonRpc({ jsonrpc: "2.0", id: 2, result: { messages: [{ role: "user", content: { type: "text", text: `scope ${tok}` } }] } });
    expect(JSON.stringify(prompt).includes(tok)).toBe(false);
    expect(screenWireText(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: 3, error: { code: 1, message: tok } })}\n\n`).includes(tok)).toBe(false);
  });
  it("a token longer than 1,024 characters is consumed whole, and the scan stays linear", () => {
    const jwt = `eyJ${"a".repeat(5000)}.${"b".repeat(3000)}.${"c".repeat(100)}`;
    expect(screenText(`x ${jwt} y`)).toBe(`x ${jwt.slice(0, 4)}... (${jwt.length} characters) y`);
    const t0 = Date.now();
    screenText("eyJ".repeat(70_000));
    screenText(`ghp_${"a".repeat(200_000)}`);
    expect(Date.now() - t0).toBeLessThan(3000);
  });
  it.skipIf(!fs.existsSync(serverEntry))("over stdio: resources/read with a token URI and prompts/get with a token name echo nothing of it", async () => {
    const tok = SHAPES[0];
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "a1138-"));
    const child = spawn(process.execPath, [serverEntry], { cwd: process.cwd(), env: { ...process.env, FOURDA_MCP_HOME: home, FOURDA_DATA_DIR: path.join(home, "none"), FOURDA_OFFLINE: "true" }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    const send = (m: unknown) => child.stdin.write(`${JSON.stringify(m)}\n`);
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
    await new Promise((r) => setTimeout(r, 1500));
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "resources/read", params: { uri: `4da://${tok}` } });
    send({ jsonrpc: "2.0", id: 3, method: "prompts/get", params: { name: tok } });
    send({ jsonrpc: "2.0", id: 4, method: "prompts/get", params: { name: "deps", arguments: { scope: tok } } });
    await new Promise((r) => setTimeout(r, 4000));
    child.stdin.end();
    await new Promise((r) => child.once("exit", r));
    expect(out).toMatch(/"id":2/);
    expect(out.includes(tok)).toBe(false);
  }, 60_000);
});

describe("A4: command positions of managers the briefing does not read", () => {
  it.each(["cd app&&gem install x", "cd app;gem install x", "sudo gem install x", "FOO=1 gem install x", "echo y|gem install x", "true||gem install x", "- gem install x", "* gem install x", "1. gem install x", "> gem install x", "PS> gem install x", "(gem install x)", "$(gem install x)", '"gem" install x'])("%j", (task) => {
    expect(unreadCommandLines(task)).toEqual(["gem"]);
  });
  it.each(["For the docs bundle, add hono", "a hidden gem: install dayjs", "Let it brew; install ky later"])("%j names no command", (task) => {
    expect(unreadCommandLines(task)).toEqual([]);
  });
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
    h.npmProject({}, {}, {});
  });
  afterEach(() => h.dispose());
  it.each(["sudo brew install jq", "cd x&&apt-get install curl", "- dotnet add package Newtonsoft.Json"])("%j: its package is neither offered nor looked up, and the answer is not safe", async (task) => {
    const r = (await executeWhatShouldIKnow(null, { task, packages: [], project_path: h.dir } as never, await h.live())) as Record<string, any>;
    const out = JSON.stringify([r.new_packages ?? [], r.task_packages.to_confirm ?? []]).toLowerCase();
    for (const p of ['"jq"', '"curl"', '"newtonsoft.json"']) expect(out).not.toContain(p);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(r.delegation_assessment.reason).toContain("a command this briefing does not read");
  });
  it("the coverage limit is one constant, said in the description", async () => {
    const { whatShouldIKnowTool } = await import("../tools/what-should-i-know.js");
    expect(whatShouldIKnowTool.description).toContain("for npm, PyPI, crates.io and Go packages");
    expect(OUTSIDE_COVERAGE).toContain("outside what this answer covers");
  });
  it("A5: a task with folded or removed characters says so", async () => {
    const r = (await executeWhatShouldIKnow(null, { task: "ｕｐｇｒａｄｅ zod", packages: [], project_path: h.dir } as never, await h.live())) as Record<string, any>;
    expect(r.task).toBe("upgrade zod");
    expect(r.task_note).toBe(TASK_FOLDED);
    const plain = (await executeWhatShouldIKnow(null, { task: "upgrade   zod", packages: [], project_path: h.dir } as never, await h.live())) as Record<string, any>;
    expect(plain.task_note).toBeUndefined();
  });
});

describe("the near-miss word cap counts the call's own distinct words", () => {
  it("a word seen in an earlier call still counts in this one; a repeat does not", async () => {
    await runWithCallBudget(Date.now(), async () => {
      for (let i = 0; i < 10; i++) mayScanWord(`w${i}`);
    });
    const counted = await runWithCallBudget(Date.now(), async () => {
      let ok = 0;
      for (let i = 0; i < WORD_SCAN_CAP + 10; i++) if (mayScanWord(`w${i % (WORD_SCAN_CAP + 5)}`)) ok++;
      for (let i = 0; i < 5; i++) mayScanWord("w1");
      return ok;
    });
    expect(counted).toBe(WORD_SCAN_CAP);
  });
});
