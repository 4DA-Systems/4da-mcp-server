// SPDX-License-Identifier: Apache-2.0
/**
 * Regression: the fifth independent check (review-confirm5, round 7's sentences), its own sets vendored under
 * fixtures/a1130-confirm/ with the canned world they ran against (px2) and its project templates: a2 (bad installs
 * with secrets), blk (its blockers), c2, cap, create, dep, e (172 ordinary tasks with the truth declared), flags,
 * g, inj, misc, n1, priv-rep, smoke, stop (205 stop-word forms) and xeco. The f sets (types, sizes, prototype-named
 * keys: 7 MB of generated strings) are regenerated here as its gen-f.mjs built them, and pass through the server's
 * own argument check first, as they did on the reviewer's harness. Token-shaped literals are assembled at run time.
 *
 * Held for every case and step, as in the fourth check's regression: a watched word is never in any request; a name
 * marked private or not a package is never looked up in that step; nothing reaches an embedding provider; a task a
 * bare call finds human_only is never safe after any declaration. And per set: blk, create and stop tasks are never
 * safe; no answer or refusal repeats a secret the task holds; an e task declared truthfully is held by nothing the
 * round-7 contract does not name (C10).
 */
import { readFileSync } from "node:fs";
import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FourDADatabase } from "../../db.js";
import { executeWhatShouldIKnow } from "../../tools/what-should-i-know.js";
import { executeDecisionMemory } from "../../tools/decision-memory.js";
import { forbiddenKey } from "../../tools/briefing-confirm.js";
import type { OsvVulnerability } from "../../live/types.js";
import { createHarness, type Harness } from "./a1119-planner-harness.js";
import { userConfigFile } from "./a1129-user-config.js";
import { validateToolArgs } from "../../tool-args.js";
import { TOOL_REGISTRY } from "../../schema-registry.js";

const DIR = path.join(__dirname, "..", "fixtures", "a1130-confirm");
const HOLES: Record<string, string> = {
  "{{SK}}": ["sk", "test-not-real-0000"].join("-"),
  "{{HEX}}": ["9f8e7d6c", "5b4a3f2e", "1d0c"].join(""),
  "{{HEX12}}": ["9f8e7d6c", "5b4a"].join(""),
  "{{PW}}": ["Tr0ub", "4dor&3zqx"].join(""),
  "{{PW9}}": ["Tr0ub", "4dor"].join(""),
  "{{TOK}}": ["token", "0123456789abcd"].join(""),
};
const RAW_HOLES = (JSON.parse(readFileSync(path.join(DIR, "review5-cases.json"), "utf8")) as { holes: Record<string, [string, string]> }).holes;
const load = (file: string) =>
  JSON.parse(
    Object.entries({ ...HOLES, ...Object.fromEntries(Object.entries(RAW_HOLES).map(([k, [a, b]]) => [k, `${a}${b}`])) }).reduce(
      (s, [k, v]) => s.replaceAll(k, JSON.stringify(v).slice(1, -1)),
      readFileSync(path.join(DIR, file), "utf8"),
    ),
  );

type Step = { args?: Record<string, any>; tool?: string; agent?: boolean; agentLeft?: number; not?: string[]; private?: string[]; truth?: string[] };
type Case = { set: string; id: string; template?: string; note?: string; env?: Record<string, string>; files?: Record<string, string>; homeFiles?: Record<string, string>; watch?: string[]; steps: Step[] };
const big = (n: number, ch = "a") => ch.repeat(n);
const deep = (d: number) => {
  let o: Record<string, unknown> = { x: 1 };
  for (let i = 0; i < d; i++) o = { a: o };
  return o;
};
const NPM_TOKEN = ["npm", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"].join("_");
/** The f sets, as review-confirm5/gen-f.mjs and its f3 list built them. */
function fCases(): Case[] {
  const c: Case[] = [];
  const A = (id: string, args: Record<string, unknown>) => c.push({ set: "f", id, template: "npm", steps: [{ args }] });
  A("types-task-num", { task: 12345 });
  A("types-task-null", { task: null });
  A("types-task-obj", { task: { a: 1 } });
  A("types-pk-str", { task: "npm install zqxok", packages: "zqxok" });
  A("types-pk-obj", { task: "npm install zqxok", packages: { ecosystem: "npm", name: "zqxok", public: true } });
  A("types-np-str", { task: "npm install zqxok", not_packages: "zqxok" });
  A("types-entry-mixed", { task: "npm install zqxok zqxok2", packages: [null, 1, "x", [], { ecosystem: "npm", name: "zqxok", public: true }, { ecosystem: "npm", name: "zqxok2", public: 1 }, { ecosystem: "NPM ", name: " zqxok3 ", public: true }, { ecosystem: "npm", name: "zqxok4", public: true, registry: "https://zqxsecretreg.corp" }] });
  A("refused-name-repeat", { task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "Zqx Secret Name!", public: true }, { ecosystem: "npm", name: "zqxok", version: "zqxsecretversion!!", public: true }, { ecosystem: "PyPI", name: "zqx..bad", public: true }] });
  A("np-many", { task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "zqxok", public: true }], not_packages: Array.from({ length: 10000 }, (_, i) => `w${i}`) });
  A("pk-many", { task: "npm install zqxok", packages: Array.from({ length: 10000 }, () => ({ ecosystem: "npm", name: "zqxok", public: true })) });
  A("pk-many-distinct", { task: "npm install zqxok", packages: Array.from({ length: 10000 }, (_, i) => ({ ecosystem: "npm", name: `zqxm${i}`, public: false })) });
  A("pk-100-public", { task: "npm install zqxok", packages: Array.from({ length: 100 }, (_, i) => ({ ecosystem: "npm", name: `zqxp${i}`, public: true })) });
  A("name-200k", { task: "npm install zqxok", packages: [{ ecosystem: "npm", name: big(200000), public: true }] });
  A("np-200k", { task: "npm install zqxok", not_packages: [big(200000)] });
  A("task-200k", { task: `npm install ${big(200000, "z")}` });
  A("task-200k-words", { task: Array(40000).fill("npm i zqxok").join(" ") });
  A("task-200k-dots", { task: `npm install zqxok${big(200000, ".")}` });
  A("task-200k-spaces", { task: `npm install${big(200000, " ")}zqxok` });
  A("task-200k-quotes", { task: `npm install "${big(100000, '"')}` });
  A("task-200k-brace", { task: `"dependencies": {${big(100000, "{")}` });
  A("task-200k-backtick", { task: `npm i ${big(150000, "`")}` });
  A("task-200k-dollar", { task: `npm i ${"$(".repeat(60000)}` });
  A("task-200k-newlines", { task: `npm install zqxok${"\\n".repeat(80000)}` });
  A("task-200k-req", { task: `requirements.txt\n${Array(20000).fill("zqxok==1.0.0").join("\n")}` });
  A("task-5000-fenced", { task: `\`\`\`json\n"dependencies": {\n${Array.from({ length: 5000 }, (_, i) => `"zqxf${i}": "1.0.${i}"`).join(",\n")}\n}\n\`\`\`` });
  A("task-5000-toml", { task: `\`\`\`toml\n[dependencies]\n${Array.from({ length: 5000 }, (_, i) => `zqxt${i} = "1.0.${i}"`).join("\n")}\n\`\`\`` });
  A("task-5000-gomod", { task: `require (\n${Array.from({ length: 5000 }, (_, i) => `  github.com/zqxg/m${i} v1.0.${i}`).join("\n")}\n)` });
  A("task-5000-pyproj", { task: `dependencies = [${Array.from({ length: 5000 }, (_, i) => `"zqxp${i}>=1.${i}"`).join(", ")}]` });
  A("task-16000-cmds", { task: Array.from({ length: 16000 }, (_, i) => `npm i zqxc${i}`).join("\n") });
  A("task-many-options", { task: `npm install ${Array.from({ length: 20000 }, (_, i) => `--opt${i} v${i}`).join(" ")}` });
  A("deep-obj", { task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "zqxok", public: true, version: deep(800) }] });
  A("deep-obj2", { task: "npm install zqxok", packages: [deep(700)] });
  A("proto", { task: "npm install zqxok", packages: [JSON.parse('{"__proto__":{"public":true},"ecosystem":"npm","name":"zqxprotoleak"}'), { ecosystem: "npm", name: "constructor", public: true }, { ecosystem: "npm", name: "__proto__", public: true }, { ecosystem: "npm", name: "hasOwnProperty", public: false }], not_packages: ["__proto__", "constructor", "toString"] });
  A("proto-task", { task: "npm install __proto__ constructor prototype toString hasOwnProperty" });
  A("nul", { task: "npm install zqxok\u0000zqxnulleak", packages: [{ ecosystem: "npm", name: "zqxok\u0000zqxnul2", public: true }], not_packages: ["a\u0000b"] });
  A("surrogate", { task: "npm install zqx\ud800ok \udc00zqxsur", packages: [{ ecosystem: "npm", name: "zqx\ud800sur2", public: true }], not_packages: ["\udfff"] });
  A("files-many", { task: "npm install zqxok", packages: [], files: Array.from({ length: 10000 }, (_, i) => `src/f${i}.ts`) });
  for (const w of ["__proto__", "constructor", "prototype", "toString", "hasOwnProperty", "valueOf", "__defineGetter__", "isPrototypeOf"]) A(`pt-${w}`, { task: `npm install ${w}` });
  A("pt-prose-ctor", { task: "Fix the constructor of the User class" });
  A("pt-prose-proto", { task: "Avoid __proto__ access in src/merge.ts", packages: [] });
  A("pt-pip", { task: "pip install constructor" });
  A("pt-cargo", { task: 'Add toString to Cargo.toml [dependencies]\ntoString = "1"' });
  A("long-secret", { task: `NPM_TOKEN=${NPM_TOKEN} ${big(200000, "x")}` });
  A("long-secret2", { task: `password hunter2zqx please ${big(200000, "y")}` });
  A("entry-1", { task: "npm install zqxok", packages: [1, { ecosystem: "npm", name: "zqxok", public: true }] });
  A("entry-arr", { task: "npm install zqxok", packages: [[], { ecosystem: "npm", name: "zqxok", public: true }] });
  A("entry-pub1", { task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "zqxok2", public: 1 }, { ecosystem: "npm", name: "zqxok", public: true }] });
  A("entry-np-num", { task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "zqxok", public: true }], not_packages: [5, "x"] });
  A("entry-np-null", { task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "zqxok", public: true }], not_packages: [null] });
  A("entry-name-num", { task: "npm install zqxok", packages: [{ ecosystem: "npm", name: 5, public: true }, { ecosystem: "npm", name: "zqxok", public: true }] });
  // What no request may carry: a source URL, a prototype-carried name, text after a NUL, a refused value.
  for (const x of c) x.watch = ["zqxsecretreg", "zqxprotoleak", "zqxnulleak", "zqxnul2", "hunter2zqx", NPM_TOKEN.toLowerCase(), "zqxsecretversion"];
  return c;
}

const SCHEMA = TOOL_REGISTRY.what_should_i_know.definition.inputSchema;
type WorldPkg = { versions: string[]; vulns?: Array<{ id: string; severity?: string; fixed?: string; introduced?: string; malware?: boolean; summary?: string }> };
const WORLD = load("review5-world.json") as Record<string, Record<string, WorldPkg> | string>;
const TEMPLATES = Object.fromEntries(["npm", "py", "go", "rs"].map((t) => [t, load(`template-${t}.json`) as Record<string, string>]));

/** Numeric release order, enough for the world's plain versions. */
const cmp = (a: string, b: string) => {
  const x = a.replace(/^v/, "").split(/[.+-]/).map(Number);
  const y = b.replace(/^v/, "").split(/[.+-]/).map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
  return 0;
};
const worldOf = (ecosystem: string): Record<string, WorldPkg> => (WORLD[ecosystem] as Record<string, WorldPkg>) ?? {};
const keyOf = (ecosystem: string, name: string) => (ecosystem === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : ecosystem === "Go" ? name : name.toLowerCase());
const findPkg = (ecosystem: string, name: string) => Object.entries(worldOf(ecosystem)).find(([n]) => keyOf(ecosystem, n) === keyOf(ecosystem, name));
function osv(ecosystem: string, name: string, v: NonNullable<WorldPkg["vulns"]>[number]): OsvVulnerability {
  const events = [{ introduced: v.introduced ?? "0" }, ...(v.fixed ? [{ fixed: v.fixed }] : [])];
  return {
    id: v.id,
    aliases: [],
    summary: v.summary ?? `${name} ${v.id}`,
    database_specific: { severity: v.severity ?? "CRITICAL" },
    affected: [{ package: { name, ecosystem }, ranges: [{ type: ecosystem === "PyPI" ? "ECOSYSTEM" : "SEMVER", events }] }],
  } as OsvVulnerability;
}
const affects = (v: NonNullable<WorldPkg["vulns"]>[number], version: string) =>
  v.malware === true || (cmp(version, v.introduced ?? "0") >= 0 && (!v.fixed || cmp(version, v.fixed) < 0));

/** Hosted Windows runners are slow: room for each hook and case, the global timeout untouched (round 8, m12). */
const HOOK_MS = 60_000;
const CASE_MS = 120_000;

/**
 * Registers the regression for one half of the fifth check's cases: "vendored" (its JSON sets) or "generated" (the f
 * sets, built here from its gen-f.mjs). Two files, so neither run carries the other's load.
 */
export function runReview5(which: "vendored" | "generated"): void {
const CASES = which === "vendored" ? (load("review5-cases.json") as { cases: Case[] }).cases : fCases();
let h: Harness;
let db: FourDADatabase;
let sent: Array<{ url: string; body: string }>;
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};

beforeEach(() => {
  h = createHarness();
  sent = [];
  for (const [ecosystem, pkgs] of Object.entries(WORLD)) {
    if (typeof pkgs === "string") continue;
    for (const [name, p] of Object.entries(pkgs)) {
      const sorted = [...p.versions].sort(cmp);
      if (ecosystem === "npm") h.NPM[name] = { latest: sorted[sorted.length - 1], versions: Object.fromEntries(sorted.map((v) => [v, {}])) };
      if (ecosystem === "PyPI") h.PYPI[keyOf("PyPI", name)] = Object.fromEntries(sorted.map((v) => [v, {}]));
      if (ecosystem === "crates.io") h.CRATES[name] = sorted.map((vers) => ({ vers }));
      if (ecosystem === "Go") {
        h.GO[name] = sorted;
        for (const v of sorted) h.GOMOD[`${name}@${v}`] = "1.21";
      }
      for (const v of p.vulns ?? []) h.ADVISORIES[`${ecosystem}:${name}:${v.id}`] = [osv(ecosystem, name, v)];
    }
  }
  const inner = globalThis.fetch;
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? String(init.body) : "";
    sent.push({ url: (() => { try { return decodeURIComponent(url); } catch { return url; } })(), body });
    // OSV.dev by ecosystem: the world holds one name in two ecosystems with different answers (colorsx).
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(body) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return json({ results: queries.map((q) => ({ vulns: (findPkg(q.package.ecosystem, q.package.name)?.[1].vulns ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(body) as { package: { name: string; ecosystem: string } };
      const found = findPkg(q.package.ecosystem, q.package.name);
      return json({ vulns: found ? (found[1].vulns ?? []).map((v) => osv(q.package.ecosystem, found[0], v)) : [] });
    }
    if (/api\.openai\.com|\/api\/embeddings/.test(url)) return json({ data: [{ embedding: [1, 0, 0, 0] }], embedding: [1, 0, 0, 0] });
    return inner(input, init);
  });
  for (const key of ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOFLAGS", "FOURDA_PRIVATE_PACKAGES", "FOURDA_EMBED_PROVIDER", "OPENAI_API_KEY", "OLLAMA_URL", "FOURDA_EMBED_MODEL", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "NPM_CONFIG_REGISTRY", "npm_config_registry"]) setEnv(key, undefined);
  const prof = path.join(h.dir, "..", `${path.basename(h.dir)}-u`);
  fs.mkdirSync(path.join(prof, "Roaming"), { recursive: true });
  fs.mkdirSync(path.join(prof, "Local"), { recursive: true });
  for (const [k, v] of Object.entries({ HOME: prof, USERPROFILE: prof, APPDATA: path.join(prof, "Roaming"), LOCALAPPDATA: path.join(prof, "Local"), FOURDA_MCP_HOME: path.join(prof, "mcp-home"), XDG_CONFIG_HOME: path.join(prof, ".config") })) setEnv(k, v);
  // The user's own configuration files are read from this temp profile (the suite's setup turns them off): the
  // machine-wide ones point there too, so nothing outside the test's own folders is read.
  for (const k of ["GOENV", "PIP_CONFIG_FILE", "UV_NO_CONFIG", "NPM_CONFIG_USERCONFIG"]) setEnv(k, undefined);
  for (const k of ["ProgramData", "PROGRAMDATA", "ALLUSERSPROFILE", "XDG_CONFIG_DIRS"]) setEnv(k, path.join(prof, "machine"));
  setEnv("NPM_CONFIG_USERCONFIG", path.join(prof, ".npmrc"));
  db = new FourDADatabase(path.join(prof, "standalone.db"));
}, HOOK_MS);
afterEach(() => {
  db.close();
  const prof = process.env.HOME;
  h.dispose();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  try {
    if (prof) fs.rmSync(prof, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
}, HOOK_MS);

// blk: the check's blockers; create: scaffold commands (round 7, C1); stop: a stop word before the bad name.
const NEVER_SAFE = (c: Case) => c.set === "blk" || c.set === "stop" || (c.set === "create" && c.id.startsWith("create"));

describe(`review-confirm5 cases hold the invariants (${which})`, () => {
  it.each(CASES.map((c) => [`${c.set}/${c.id}: ${c.note ?? ""}`, c] as const))("%s", async (_label, c) => {
    for (const [k, v] of Object.entries(c.env ?? {})) setEnv(k, v);
    for (const [rel, body] of Object.entries(TEMPLATES[c.template ?? "npm"] ?? {})) h.write(rel, body);
    for (const [rel, body] of Object.entries(c.files ?? {})) h.write(rel, body);
    for (const [rel, body] of Object.entries(c.homeFiles ?? {})) {
      // Written where the running platform's tool reads it (round 6, CI: nP/p27's go env file was Windows-only).
      const f = userConfigFile(rel, process.env);
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, body);
    }
    const live = await h.live();
    const steps = [...c.steps];
    const answers: Array<{ args: Record<string, any>; r: Record<string, any> }> = [];
    let bareHumanOnly = false;
    // Round 6, item 4a: the project's own scan sends its installed dependencies whatever a call declares; for such a
    // watched word the answer must say so instead (SCAN_STILL_READS), and no sentence may claim it was not sent.
    const files = JSON.stringify({ ...(TEMPLATES[c.template ?? "npm"] ?? {}), ...(c.files ?? {}) }).toLowerCase();
    // A dependency key of a package.json (`"zod":`, escaped quotes in the stringified files) or a requirements line.
    const installed = (w: string) => [`\\"${w}\\":`, `\\n${w}==`, `\\n${w}>=`, `"${w}==`].some((form) => files.includes(form));
    // A watched registry URL of an installed dependency (dep: `registry.npmjs.org/zod`) is the scan's own request.
    const scanned = (c.watch ?? []).map((w) => w.toLowerCase()).filter((w) => installed(w.split("/").pop()!));
    const watch = (c.watch ?? []).map((w) => w.toLowerCase()).filter((w) => !scanned.includes(w));
    for (let k = 0; k < steps.length; k++) {
      let st = steps[k];
      if (st.tool === "decision_memory") {
        await executeDecisionMemory(db, st.args as never);
        continue;
      }
      // Another tool's step (dependency_check in g): not what this regression replays.
      if (st.tool && st.tool !== "what_should_i_know") continue;
      if (st.agent) {
        const prev = answers.at(-1);
        const tp = prev?.r.task_packages;
        if (!tp || (tp.status === "complete" && prev!.args.packages !== undefined)) break;
        const packages = [...(prev!.args.packages ?? [])];
        const notPackages = [...(prev!.args.not_packages ?? [])];
        for (const e of tp.to_confirm ?? []) {
          if ((st.not ?? []).includes(e.name) || (st.truth && !st.truth.includes(e.name.toLowerCase()))) notPackages.push(e.name);
          // Round 9, E1: the agent states the version it will write ("latest" where none is shown).
          else packages.push({ ecosystem: e.ecosystems[0], name: e.name, version: e.version ?? "latest", public: !(st.private ?? []).includes(e.name) });
        }
        const left = st.agentLeft ?? 3;
        if (left > 0 && k === steps.length - 1) steps.push({ agent: true, agentLeft: left - 1, not: st.not, private: st.private, truth: st.truth });
        st = { args: { task: c.steps.find((s) => s.args?.task !== undefined)?.args?.task, packages, ...(notPackages.length > 0 ? { not_packages: notPackages } : {}) } };
      }
      const args = st.args ?? {};
      sent.length = 0;
      // The server's own argument check comes first (the f sets: wrong types, over-long values).
      const problem = validateToolArgs("what_should_i_know", SCHEMA, args);
      if (problem !== null) {
        for (const w of [...watch, ...scanned]) expect(problem.toLowerCase(), `step ${k} repeated a watched word`).not.toContain(w);
        expect(problem).not.toContain(NPM_TOKEN);
        break;
      }
      const r = (await executeWhatShouldIKnow(db, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
      // The answer gives the caller's own task back in its task field; nothing else of it repeats a secret.
      const { task: _task, ...rest } = r;
      expect(JSON.stringify(rest)).not.toContain(NPM_TOKEN);
      expect(JSON.stringify(rest)).not.toContain("hunter2zqx");
      answers.push({ args, r });
      const level = r.delegation_assessment.level as string;
      if (answers.length === 1 && args.packages === undefined) bareHumanOnly = level === "human_only";
      const hay = sent.map((s) => `${s.url} ${s.body}`.toLowerCase()).join("\n");
      // A name the step itself declares public is the caller's to send (K1), with the spec the task writes on it (C4):
      // the literal agent declares every waiting entry (a2-76's corp module path). Any other watched word is never sent.
      const publicNames = (args.packages ?? []).filter((p: { public?: unknown } | null) => p?.public === true).map((p: { name: unknown }) => String(p.name).toLowerCase());
      const tokens = String(args.task ?? "").toLowerCase().split(/\s+/);
      const declared = (w: string) => publicNames.some((n: string) => n.includes(w) || tokens.some((t) => t.includes(n) && t.includes(w)));
      expect(watch.filter((w) => hay.includes(w) && !declared(w)), `step ${k} sent a watched word`).toEqual([]);
      for (const w of scanned) expect(JSON.stringify(r)).not.toMatch(new RegExp(`${w} was not sent`, "i"));
      const forbidden = [...(args.packages ?? []).filter((p: { public?: unknown } | null) => p?.public === false).map((p: { name: string }) => p.name), ...(args.not_packages ?? [])].filter((x: unknown): x is string => typeof x === "string").map(forbiddenKey);
      const names = sent.flatMap((s) => [...s.url.matchAll(/registry\.npmjs\.org\/((?:@[^/]+\/)?[^/?#]+)|pypi\.org\/pypi\/([^/]+)|index\.crates\.io\/(?:[^/]+\/)*([^/?#]+)|proxy\.golang\.org\/(.+?)\/@v/g)].map((m) => m[1] ?? m[2] ?? m[3] ?? m[4]));
      expect(names.filter((n) => forbidden.includes(forbiddenKey(n))), `step ${k} looked up a forbidden name`).toEqual([]);
      expect(sent.filter((s) => /api\.openai\.com|\/api\/embeddings/.test(s.url)), `step ${k} reached an embedding provider`).toEqual([]);
      if (bareHumanOnly && answers.length > 1) expect(level, `step ${k}`).not.toBe("safe_to_delegate");
      if (NEVER_SAFE(c)) expect(level, `step ${k}`).not.toBe("safe_to_delegate");
    }
    // e: the check's 172 ordinary tasks, declared truthfully (round 7, C10): a version in prose or a word such as
    // python, proxy or derive holds nothing. What may still hold one is named in the reason: a command the grammar
    // does not read whole, a word of a command that waits, or what the declared packages' own checks found.
    if (c.set === "e") {
      const reason = answers.at(-1)?.r.delegation_assessment.reason ?? "";
      expect(reason).not.toMatch(/could not tie to a package|which this briefing could not tie/);
    }
  }, CASE_MS);
});
}
