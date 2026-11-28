// SPDX-License-Identifier: Apache-2.0
/**
 * Round 16: the fourteenth independent check (review-confirm14). C1 installed malware holds every briefing of the
 * project at human_only, other project-wide findings are listed and said; C2 every HTTP chunk and echoed header
 * screened whole; C3 decision conflicts over the declared, read and installed names; C4 every string argument of
 * what_should_i_know but `task` screened; C5 the reading copy by the Unicode property, each step named; C7 both screens
 * match exactly CREDENTIAL_SHAPES; C8 TEXT_RULES' dismissal patterns read the capitalised sentence.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FourDADatabase } from "../db.js";
import { executeWhatShouldIKnow, readingCopy } from "../tools/what-should-i-know.js";
import { executeDecisionMemory } from "../tools/decision-memory.js";
import { INSTALLED_MALWARE, NO_DECISION_CONFLICT, PROJECT_FINDINGS_LISTED, TASK_FOLDED } from "../tools/briefing-confirm.js";
import { CREDENTIAL_SHAPES } from "../tools/briefing-task-screen.js";
import { credentialSpans, hasCredentialShape, screenText } from "../output-screen.js";
import { CREDENTIAL_REFUSAL, screenArguments } from "../argument-screen.js";
import { validateItem } from "../tools/dependency-check.js";
import { DEFAULT_IGNORABLE, readableText } from "../live/private-guard.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import { screenResponse } from "../http-transport.js";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { serverEntry } from "./helpers/stdio-session.js";
import { SHAPES } from "./helpers/credential-samples.js";
import { brokenTextRules } from "./helpers/a1137-text-rules.js";

/** A seeded generator: the property tests are the same on every run. */
function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

describe("C7: both screens match exactly what CREDENTIAL_SHAPES matches", () => {
  const exact = (x: string) => new RegExp(CREDENTIAL_SHAPES.source).test(x);
  it("over generated strings, hyphenated names with token prefixes mid-word among them: screen(x) differs from x iff a shape matches (property)", () => {
    const r = rng(16);
    const pieces = ["sk-", "ghp_", "gho_", "npm_", "AKIA", "xoxb-", "SG.", "eyJ", "hf_", "pypi-", "glpat-", "github_pat_", "dop_v1_", "shpat_", "AIza", "whsec_", "sk_live_", "risk-", "desk-", "-", "_", ".", "/", " ", "@", "a", "Z", "0", "q9", "report", "ing", "toolkit", "abcdef0123456789", "ABCDEFGHIJKLMNOP"];
    let differ = 0;
    for (let n = 0; n < 30_000; n++) {
      const len = 1 + Math.floor(r() * 14);
      let x = "";
      for (let k = 0; k < len; k++) x += pieces[Math.floor(r() * pieces.length)];
      const m = exact(x);
      expect(screenText(x) !== x, x).toBe(m);
      expect(hasCredentialShape(x), x).toBe(m);
      if (m) differ++;
    }
    expect(differ).toBeGreaterThan(1000);
  });
  it("each sample shape is matched alone and after a non-word character, and not after a word character", () => {
    for (const tok of SHAPES) {
      expect(hasCredentialShape(tok), tok.slice(0, 6)).toBe(true);
      expect(hasCredentialShape(`-${tok}`), tok.slice(0, 6)).toBe(exact(`-${tok}`));
      expect(hasCredentialShape(`ab${tok}`), tok.slice(0, 6)).toBe(exact(`ab${tok}`));
      const m = new RegExp(CREDENTIAL_SHAPES.source).exec(`x ${tok} y`)!;
      expect(credentialSpans(`x ${tok} y`)).toEqual([[m.index, m.index + m[0].length]]);
    }
  });
  it("risk-reportingtoolkitforteams and the reviewer's other over-matches are names, not credentials", () => {
    for (const name of ["risk-reportingtoolkitforteams", "@acme/flask-abcdefghijklmnopqrstuv", ["abc", "ghp", "_abcdefghijklmnop"].join("")]) {
      expect(hasCredentialShape(name), name).toBe(false);
      expect(screenText(name)).toBe(name);
      expect(screenArguments("upgrade_impact", { package: name })).toEqual({ args: { package: name }, masked: 0 });
    }
  });
  it("no name of the bundled popular npm list (the 1,000 most-depended among them) nor of the bench's world is refused by dependency_check's validator", () => {
    const world = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "bench", "g7c", "world.json"), "utf8")) as Record<string, Record<string, unknown> | string>;
    const items: Array<[string, string]> = [...POPULAR_NPM.map((n) => ["npm", n] as [string, string])];
    for (const [eco, pkgs] of Object.entries(world)) if (typeof pkgs === "object") for (const n of Object.keys(pkgs)) items.push([eco, n]);
    const refused: string[] = [];
    for (const [ecosystem, name] of items) {
      try {
        validateItem({ ecosystem, package: name, to: "1.0.0" }, 0);
      } catch (e) {
        if (/credential/.test((e as Error).message)) refused.push(`${ecosystem}:${name}`);
      }
    }
    expect(items.length).toBeGreaterThan(1500);
    expect(refused).toEqual([]);
  });
});

describe("C2: HTTP mode screens every chunk type and every echoed header, across chunk boundaries", () => {
  const tok = SHAPES.find((s) => s.startsWith("gh"))!;
  const get = (port: number, p = "/") =>
    new Promise<{ headers: Record<string, unknown>; body: string }>((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port, path: p, method: "GET" }, (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (d) => (body += d));
        res.on("end", () => resolve({ headers: res.headers, body }));
      });
      req.on("error", reject);
      req.end();
    });
  const serve = async (handler: (res: import("node:http").ServerResponse) => void) => {
    const server = createServer((_req, res) => {
      screenResponse(res);
      handler(res);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    return server;
  };
  const cases: Array<[string, (res: import("node:http").ServerResponse) => void]> = [
    ["a JSON body as one Uint8Array", (res) => {
      res.writeHead(200, { "content-type": "application/json", "content-length": "999" });
      res.end(new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id: tok, error: { code: -32602, message: `unknown ${tok}` } })));
    }],
    ["a token split over two Uint8Array writes", (res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      const line = `event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { x: tok } })}\n\n`;
      const bytes = new TextEncoder().encode(line);
      const cut = line.indexOf(tok) + 7;
      res.write(bytes.subarray(0, cut));
      res.end(bytes.subarray(cut));
    }],
    ["a DataView, a Buffer and a string with an encoding", (res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      const a = Buffer.from(`data: {"a":"${tok.slice(0, 5)}`);
      res.write(new DataView(a.buffer, a.byteOffset, a.byteLength));
      res.write(Buffer.from(tok.slice(5, 9)));
      res.end(Buffer.from(`${tok.slice(9)}"}\n\n`).toString("hex"), "hex");
    }],
    ["a multi-byte character split across chunks", (res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      const b = Buffer.from(`data: {"a":"é ${tok}"}\n\n`);
      const at = b.indexOf(0xc3) + 1;
      res.write(b.subarray(0, at));
      res.end(b.subarray(at));
    }],
    ["an echoed header value", (res) => {
      res.setHeader("mcp-session-id", tok);
      res.writeHead(400, { "x-echo": `bad ${tok}` });
      res.end(`{"error":"Unsupported protocol version: ${tok}"}`);
    }],
  ];
  it.each(cases)("%s", async (_l, handler) => {
    const server = await serve(handler);
    try {
      const { headers, body } = await get((server.address() as AddressInfo).port);
      const all = `${JSON.stringify(headers)}\n${body}`;
      expect(all.includes(tok)).toBe(false);
      expect(all).toContain(`${tok.slice(0, 4)}...`);
      expect(headers["content-length"]).toBeUndefined();
    } finally {
      server.close();
    }
  });
  it.skipIf(!fs.existsSync(serverEntry))("the built server over --http on loopback: each method's results and errors, SSE lines, the header echo, a token id (generated)", async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "a1139h-"));
    const port = await new Promise<number>((r) => {
      const s = createServer();
      s.listen(0, "127.0.0.1", () => {
        const p = (s.address() as AddressInfo).port;
        s.close(() => r(p));
      });
    });
    const child = spawn(process.execPath, [serverEntry, "--http", "--port", String(port)], { cwd: process.cwd(), env: { ...process.env, FOURDA_MCP_HOME: home, FOURDA_DATA_DIR: path.join(home, "none"), FOURDA_OFFLINE: "true" }, stdio: ["ignore", "pipe", "pipe"] });
    const T = SHAPES.slice(0, 12);
    let text = "";
    try {
      const send = (p: string, body: string, headers: Record<string, string>) =>
        new Promise<{ status: number; headers: Record<string, unknown>; body: string }>((resolve, reject) => {
          const req = httpRequest({ host: "127.0.0.1", port, path: p, method: "POST", headers: { "content-length": String(Buffer.byteLength(body)), ...headers } }, (res) => {
            let b = "";
            res.setEncoding("utf8");
            res.on("data", (d) => (b += d));
            res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: b }));
          });
          req.on("error", reject);
          req.end(body);
        });
      for (let k = 0; k < 60; k++) {
        try {
          await send("/", "", {});
          break;
        } catch {
          await new Promise((r) => setTimeout(r, 250));
        }
      }
      const post = async (body: unknown, headers: Record<string, string> = {}) => {
        const res = await send("/mcp", typeof body === "string" ? body : JSON.stringify(body), { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers });
        text += `\n#${res.status} ${JSON.stringify(res.headers)}\n${res.body}`;
        return res;
      };
      const init = await post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: T[0], version: "1" } } });
      const sid = init.headers["mcp-session-id"] as string | undefined;
      const H: Record<string, string> = sid ? { "mcp-session-id": sid, "mcp-protocol-version": "2025-06-18" } : {};
      await post({ jsonrpc: "2.0", method: "notifications/initialized" }, H);
      await post({ jsonrpc: "2.0", id: 2, method: T[1] }, H);
      await post({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "upgrade_impact", arguments: { package: T[2] } } }, H);
      await post({ jsonrpc: "2.0", id: 4, method: "resources/read", params: { uri: T[3] } }, H);
      await post({ jsonrpc: "2.0", id: T[4], method: "tools/list" }, H);
      await post(`{"jsonrpc":"2.0","id":6,"method":"${T[5]}"`, H);
      await post({ jsonrpc: "2.0", id: 7, method: "tools/list" }, { ...H, "mcp-session-id": T[6] });
      await post({ jsonrpc: "2.0", id: 8, method: "tools/list" }, { ...H, "mcp-protocol-version": T[7] });
      await post({ jsonrpc: "2.0", id: 9, method: "prompts/get", params: { name: "deps", arguments: { scope: T[8] } } }, H);
      await post({ jsonrpc: "2.0", id: 10, method: "prompts/get", params: { name: T[9] } }, H);
      await post({ jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: "what_should_i_know", arguments: { task: "refactor", packages: [{ ecosystem: T[10], name: "zod", version: "1", public: true }] } } }, H);
      const g = await send(`/${T[11]}`, "{}", {});
      text += `\n#PATH ${g.status}\n${g.body}`;
    } finally {
      child.kill();
    }
    expect(text).toMatch(/"id":4/);
    for (const t of T) expect(text.includes(t), t.slice(0, 6)).toBe(false);
  }, 90_000);
});

describe("C4: what_should_i_know's every string argument but task is screened", () => {
  const tok = SHAPES[0];
  it.each([
    ["files", { task: "Refactor this file.", files: [`src/${tok}.js`], packages: [] }, "file path"],
    ["project_path", { task: "Refactor.", project_path: `C:/work/p-${tok}`, packages: [] }, "path"],
  ] as const)("%s holding a token is refused before anything runs", (_l, args, field) => {
    expect(screenArguments("what_should_i_know", args as never)).toEqual({ refused: CREDENTIAL_REFUSAL(field) });
  });
  it("the task is the documented exception; packages are refused entry by entry by the tool, and not_packages (a dismissed task word, a withheld token among them) is compared, never sent", () => {
    expect("refused" in screenArguments("what_should_i_know", { task: `npm install x ${tok}`, packages: [], not_packages: [tok] })).toBe(false);
    expect("refused" in screenArguments("what_should_i_know", { task: `npm install ${tok}` })).toBe(false);
    expect("refused" in screenArguments("what_should_i_know", { task: "x", packages: [{ ecosystem: "npm", name: tok, public: true }] })).toBe(false);
  });
});

describe("C5: the reading copy (readingCopy), each step", () => {
  it("removes each default-ignorable code point, generated from the property at test time (generated)", () => {
    const di = /^\p{Default_Ignorable_Code_Point}$/u;
    let n = 0;
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const ch = String.fromCodePoint(cp);
      if (!di.test(ch)) continue;
      n++;
      expect(readingCopy(`ab${ch}cd`), cp.toString(16)).toBe("abcd");
      expect(readableText(`lo${ch}dash`), cp.toString(16)).toBe("lodash");
      expect(new RegExp(DEFAULT_IGNORABLE.source, "u").test(ch)).toBe(true);
    }
    expect(n).toBeGreaterThan(4000);
  });
  it.each([
    ["control characters removed", "a\u0007b", "ab"],
    ["U+2028 as a space", "a\u2028b", "a b"],
    ["percent-escapes decoded", "npm i %40acme%2Fui", "npm i @acme/ui"],
    ["twice-escaped decoded", "npm i %2540acme", "npm i @acme"],
    ["default-ignorable removed", "insta\u200bll", "install"],
    ["NFKC-folded", "\uff4e\uff50\uff4d", "npm"],
    ["a dash look-alike as -", "a\u2010b", "a-b"],
    ["a slash look-alike as /", "a\u2215b", "a/b"],
    ["markup dropped", "**npm i x**", "npm i x"],
    ["a line continuation joined", "npm i a \\\n  b", "npm i a b"],
    ["each run of blanks one space", "a \t  b", "a b"],
    ["a line over MAX_READ_LINE left out", `a\n${"x".repeat(5000)}\nb`, "a\n\nb"],
  ])("%s", (_l, input, out) => {
    expect(readingCopy(input)).toBe(out);
  });
  describe("TASK_FOLDED compares after removing blanks only", () => {
    let h: Harness;
    beforeEach(() => {
      h = createHarness();
      h.NPM.hono = { latest: "4.6.14", versions: { "4.6.14": {} } };
      h.npmProject({ hono: "4.6.14" }, {}, { hono: { version: "4.6.14" } });
    });
    afterEach(() => h.dispose());
    const brief = async (task: string) => (await executeWhatShouldIKnow(null, { task, packages: [{ ecosystem: "npm", name: "hono", version: "4.6.14", public: true }], project_path: h.dir } as never, await h.live())) as Record<string, any>;
    it("U+FEFF inside a word is said", async () => {
      expect((await brief("npm insta\ufeffll hono@4.6.14")).task_note).toBe(TASK_FOLDED);
    });
    it.each(["npm insta\u{1BCA0}ll hono@4.6.14", "npm insta\u{1D173}ll hono@4.6.14", "npm insta\u{E01F0}ll hono@4.6.14"])("%j: removed and said", async (task) => {
      const r = await brief(task);
      expect(r.task).toBe("npm install hono@4.6.14");
      expect(r.task_note).toBe(TASK_FOLDED);
    });
    it("blanks alone are not said", async () => {
      expect((await brief("npm  install \t hono@4.6.14")).task_note).toBeUndefined();
    });
  });
});

describe("C1 / C3: the level, the project's findings and decisions", () => {
  let h: Harness;
  let db: FourDADatabase;
  let prof: string;
  beforeEach(() => {
    h = createHarness();
    prof = fs.mkdtempSync(path.join(os.tmpdir(), "a1139db-"));
    db = new FourDADatabase(path.join(prof, "standalone.db"));
    for (const n of ["zod", "ky", "fastifyy", "lodash", "axios"]) h.NPM[n] = { latest: "4.17.21", versions: { "1.0.1": {}, "1.7.4": {}, "1.7.9": {}, "3.24.1": {}, "4.17.20": {}, "4.17.21": {} } };
    h.ADVISORIES.fastifyy = [adv("MAL-2026-90001", "fastifyy", [{ introduced: "0" }], "npm", "CRITICAL")];
    h.ADVISORIES.lodash = [adv("GHSA-g7c0-hhhh-0005", "lodash", [{ introduced: "0" }, { fixed: "4.17.21" }], "npm", "HIGH")];
  });
  afterEach(() => {
    db.close();
    h.dispose();
    try {
      fs.rmSync(prof, { recursive: true, force: true });
    } catch {
      // Windows: left for the OS temp cleaner.
    }
  });
  const brief = async (args: Record<string, unknown>, withDb = false) => (await executeWhatShouldIKnow(withDb ? db : null, { ...args, project_path: h.dir } as never, await h.live())) as Record<string, any>;

  it.each([
    ["Refactor the config module.", []],
    ["Add ky for the HTTP calls.", [{ ecosystem: "npm", name: "ky", version: "1.7.4", public: true }]],
    ["Refactor the config module.", undefined],
  ] as const)("installed malware: %j is human_only with INSTALLED_MALWARE, whatever the task", async (task, packages) => {
    h.npmProject({ zod: "3.24.1", fastifyy: "1.0.1" }, {}, { zod: { version: "3.24.1" }, fastifyy: { version: "1.0.1" } });
    const r = await brief({ task, ...(packages ? { packages } : {}) });
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason.startsWith(INSTALLED_MALWARE(["fastifyy@1.0.1 (in .)"]))).toBe(true);
    expect(INSTALLED_MALWARE(["fastifyy@1.0.1"])).toBe("This project has fastifyy@1.0.1 installed, which is recorded as malware: a person must deal with that before any task is delegated.");
    expect(brokenTextRules(r, { task, packages })).toEqual([]);
  });
  it("a high advisory on an installed dependency the task does not touch: listed, the level untouched, and the safe reason says so", async () => {
    h.npmProject({ zod: "3.24.1", lodash: "4.17.20" }, {}, { zod: { version: "3.24.1" }, lodash: { version: "4.17.20" } });
    const r = await brief({ task: "Refactor the config module.", packages: [] });
    expect(r.delegation_assessment.level).toBe("safe_to_delegate");
    expect(r.delegation_assessment.reason.startsWith(PROJECT_FINDINGS_LISTED(1))).toBe(true);
    expect(r.delegation_assessment.reason).not.toMatch(/nothing version-confirmed, no major/);
    expect(r.advisories.some((a: any) => a.scope === "project" && a.version_confirmed)).toBe(true);
    expect(brokenTextRules(r, { packages: [] })).toEqual([]);
  });
  it("the same advisory on a dependency the task touches raises the level", async () => {
    h.npmProject({ zod: "3.24.1", lodash: "4.17.20" }, {}, { zod: { version: "3.24.1" }, lodash: { version: "4.17.20" } });
    const r = await brief({ task: "Refactor how we use lodash in the config module.", packages: [] });
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
  it.each([
    ["declared", "Add axios for the HTTP calls.", { packages: [{ ecosystem: "npm", name: "axios", version: "1.7.9", public: true }] }],
    ["read in the task", "npm install axios@1.7.9", { packages: [{ ecosystem: "npm", name: "axios", version: "1.7.9", public: true }] }],
    ["waiting in to_confirm", "Use axios for the HTTP calls.", {}],
    ["installed and touched", "Refactor how we use axios.", { packages: [] }],
  ] as const)("a decision that rejects axios, %s: a conflict, human_only, and no 'no recorded-decision conflict'", async (_l, task, extra) => {
    h.npmProject({ zod: "3.24.1", axios: "1.7.9" }, {}, { zod: { version: "3.24.1" }, axios: { version: "1.7.9" } });
    await executeDecisionMemory(db, { action: "record", decision_type: "dependency", subject: "http", decision: "Use ky for HTTP; axios is rejected", rationale: "team rule", alternatives_rejected: ["axios"], context_tags: ["http"] } as never);
    const r = await brief({ task, ...extra }, true);
    expect(r.decision_conflicts.map((c: any) => c.technology)).toContain("axios");
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason).not.toContain(NO_DECISION_CONFLICT);
  });
  it("a dismissed name is not asked", async () => {
    h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
    await executeDecisionMemory(db, { action: "record", decision_type: "dependency", subject: "http", decision: "axios is rejected", rationale: "team rule", alternatives_rejected: ["axios"], context_tags: ["http"] } as never);
    const r = await brief({ task: "Write the axios migration notes.", packages: [], not_packages: ["axios"] }, true);
    expect(r.decision_conflicts).toEqual([]);
  });
});

describe("C8: TEXT_RULES reads the capitalised first sentence", () => {
  it("a capitalised DISMISSED_READ / DISMISSED_INSTEAD at safe_to_delegate is a broken rule", () => {
    const at = (reason: string) => brokenTextRules({ delegation_assessment: { level: "safe_to_delegate", reason } }, {});
    expect(at("You said zqx is not a package; it stands where a package name stands in a command of the task: make sure nothing installs it.").some((b) => b.startsWith("DISMISSED_READ"))).toBe(true);
    expect(at("You said zqx is not a package and declared zqy instead: the task names zqx.").some((b) => b.startsWith("DISMISSED_INSTEAD"))).toBe(true);
  });
});
