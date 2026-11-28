// SPDX-License-Identifier: Apache-2.0
/**
 * Regression: the twelfth independent check (review-confirm12, round 14), its own sets vendored under
 * fixtures/a1137-confirm/ with its canned world and templates (its tool-level and over-long cases left out). One-call
 * sets: nothing named zqxpriv* or zqxs3cr* is in a request unless that call declares it public, and (round 9, E1) no
 * call is safe while a public entry has no `version`. Agent sets (none) are replayed with his literal agent,
 * now declaring `version` ("latest" where the truth names none): no case ends waiting.
 */
import { readFileSync } from "node:fs";
import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FourDADatabase } from "../../db.js";
import { executeWhatShouldIKnow } from "../../tools/what-should-i-know.js";
import type { OsvVulnerability } from "../../live/types.js";
import { createHarness, type Harness } from "./a1119-planner-harness.js";
import { validateToolArgs } from "../../tool-args.js";
import { screenToolResult, screenValue } from "../../output-screen.js";
import { CREDENTIAL_SHAPES } from "../../tools/briefing-task-screen.js";
import { forbiddenKey } from "../../tools/briefing-confirm.js";
import { brokenTextRules } from "./a1137-text-rules.js";
import { BEST_EFFORT_READING, RESTS_ON_DECLARATION } from "../../tools/briefing-confirm.js";
/** How many one-call answers were safe (the P1 check above must have something to check). */
const safeSeen = { n: 0 };
import { TOOL_REGISTRY } from "../../schema-registry.js";

const DIR = path.join(__dirname, "..", "fixtures", "a1137-confirm");
const HOLES: Record<string, string> = {
  "{{SK}}": ["sk", "test-not-real-0000"].join("-"),
  "{{HEX}}": ["9f8e7d6c", "5b4a3f2e", "1d0c"].join(""),
  "{{HEX12}}": ["9f8e7d6c", "5b4a"].join(""),
  "{{PW}}": ["Tr0ub", "4dor&3zqx"].join(""),
  "{{PW9}}": ["Tr0ub", "4dor"].join(""),
  "{{TOK}}": ["token", "0123456789abcd"].join(""),
};
const RAW_HOLES_ = (JSON.parse(readFileSync(path.join(DIR, "review12-cases.json"), "utf8")) as { holes: Record<string, [string, string]> }).holes;
const RAW_HOLES = RAW_HOLES_;
/** Every token-shaped value of the vendored cases, joined at run time. */
/** The vendored token values of a credential shape this server knows (CREDENTIAL_SHAPES): the promise's scope. */
const TOKEN_VALUES = [...Object.values(HOLES), ...Object.values(RAW_HOLES).map(([a, b]) => `${a}${b}`)].filter((v) => v.length >= 12 && new RegExp(CREDENTIAL_SHAPES.source.replace(/^\\b/, "")).test(v));
const load = (file: string) =>
  JSON.parse(
    Object.entries({ ...HOLES, ...Object.fromEntries(Object.entries(RAW_HOLES).map(([k, [a, b]]) => [k, `${a}${b}`])) }).reduce(
      (s, [k, v]) => s.replaceAll(k, JSON.stringify(v).slice(1, -1)),
      readFileSync(path.join(DIR, file), "utf8"),
    ),
  );

type Step = { args?: Record<string, any>; tool?: string; agent?: boolean; agentLeft?: number; not?: string[]; private?: string[]; truth?: string[] };
type Case = { set: string; id: string; template?: string; note?: string; env?: Record<string, string>; files?: Record<string, string>; homeFiles?: Record<string, string>; watch?: string[]; steps: Step[] };
const SCHEMA = TOOL_REGISTRY.what_should_i_know.definition.inputSchema;
type WorldPkg = { versions: string[]; vulns?: Array<{ id: string; severity?: string; fixed?: string; introduced?: string; malware?: boolean; summary?: string }> };
const WORLD = load("review12-world.json") as Record<string, Record<string, WorldPkg> | string>;
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
type Task = Case & { task?: string; truth?: Array<{ ecosystem: string; name: string; version?: string; public?: boolean }>; expect?: string; dismiss?: string[] };
const WATCH = /zqxpriv[\w-]*|zqxs3cr[\w-]*/gi;

const ALL = (load("review12-cases.json") as { cases: Task[] }).cases;

/** Registers the regression for some of the sixth check's sets: three files share the 761 cases (round 8, m12). */
export function runReview12(sets: readonly string[]): void {
// Round 8, m12: the agent-loop replay of his ordinary-task sets (f: 298, run5: 151) is a fixed sample in the default
// run (every 6th f case, every 3rd run5 case: the rest is measured on his own harness, agent.mjs), so the suite's
// load on a hosted runner stays near the fifth check's; FOURDA_FULL_REVIEW=1 replays every case.
const SAMPLE: Record<string, number> = process.env.FOURDA_FULL_REVIEW === "1" ? {} : { s12: 4, u12: 2 };
const CASES = ALL.filter((c) => sets.includes(c.set)).filter((c, i, all) => !SAMPLE[c.set] || all.filter((x) => x.set === c.set).indexOf(c) % SAMPLE[c.set] === 0);
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

const key = (x: string) => x.toLowerCase().replace(/[-_.]+/g, "-");
let live: Awaited<ReturnType<Harness["live"]>> | null = null;

/** The package names in the requests of the call (registry documents and OSV single queries, not the scan's batch). */
function namesRequested(): string[] {
  const out: string[] = [];
  for (const x of sent) {
    const npm = /registry\.npmjs\.org\/((?:@[^/]+\/)?[^/?]+)/.exec(x.url);
    if (npm) out.push(npm[1]);
    const pypi = /pypi\.org\/pypi\/([^/]+)\//.exec(x.url);
    if (pypi) out.push(pypi[1]);
    const go = /proxy\.golang\.org\/(.+?)\/@(?:v|latest)/.exec(x.url);
    if (go) out.push(go[1]);
    if (x.url.endsWith("/v1/query")) for (const m of x.body.matchAll(/"name"\s*:\s*"([^"]+)"/g)) out.push(m[1]);
  }
  return out;
}
/** Requested names the call's arguments forbid (not_packages, public: false), folded as the never-send set folds. */
function sentForbidden(args: Record<string, any>, projectText = ""): string[] {
  const forbidden = new Set<string>([
    ...(Array.isArray(args.not_packages) ? args.not_packages.filter((w: unknown) => typeof w === "string") : []),
    ...(Array.isArray(args.packages) ? args.packages.filter((d: any) => d?.public === false && typeof d.name === "string").map((d: any) => d.name) : []),
  ].map(forbiddenKey));
  // A name in the project's own files is the project scan's, which reads installed dependencies whatever a call says
  // (THE CONTRACT, privacy): only the task's lookups are held to this.
  return forbidden.size === 0 ? [] : namesRequested().filter((n) => forbidden.has(forbiddenKey(n)) && !projectText.toLowerCase().includes(n.toLowerCase())).map((n) => `${n} in ${sent.filter((x) => x.url.includes(n) || x.body.includes(n)).map((x) => x.url.slice(0, 80)).join(" , ")}`);
}
/**
 * One call as the server answers it: the argument check, the tool, and the output screen the server applies to every
 * result and error (output-screen.ts), with his own project_path where the case gives one.
 */
async function call(args: Record<string, any>): Promise<{ r: Record<string, any> | null; problem: string | null; text: string }> {
  const problem = validateToolArgs("what_should_i_know", SCHEMA, args);
  if (problem !== null) {
    const screened = screenToolResult("what_should_i_know", { content: [{ type: "text", text: JSON.stringify({ error: problem }) }], isError: true });
    return { r: null, problem, text: screened.content[0].text };
  }
  live ??= await h.live();
  try {
    const answer = (await executeWhatShouldIKnow(db, { ...args, project_path: args.project_path ?? h.dir } as never, live)) as Record<string, any>;
    const r = screenValue(answer, "task") as Record<string, any>;
    return { r, problem: null, text: JSON.stringify(r) };
  } catch (error) {
    const screened = screenToolResult("what_should_i_know", { content: [{ type: "text", text: JSON.stringify({ error: error instanceof Error ? error.message : String(error) }) }], isError: true });
    return { r: null, problem: "error", text: screened.content[0].text };
  }
}

describe(`review-confirm12 cases hold the invariants (${sets.join(", ")})`, () => {
  it.each(CASES.map((c) => [`${c.set}/${c.id}`, c] as const))("%s", async (_label, c) => {
    live = null;
    for (const [rel, body] of Object.entries(TEMPLATES[c.template ?? "npm"] ?? {})) h.write(rel, body);
    for (const [rel, body] of Object.entries(c.files ?? {})) h.write(rel, body);
    if (c.task !== undefined) {
      const truth = c.truth ?? [];
      const pk: Array<Record<string, any>> = truth.map((p) => ({ public: true, ...p, ...(p.public === false || p.version ? {} : { version: "latest" }) }));
      const not: string[] = [];
      let r: Record<string, any> | null = null;
      for (let k = 0; k < 5; k++) {
        ({ r } = await call({ task: c.task, packages: [...pk], ...(not.length ? { not_packages: [...not] } : {}) }));
        const waiting = (r?.task_packages?.to_confirm ?? []) as Array<{ name: string; ecosystems: string[] }>;
        if (!r || waiting.length === 0) break;
        for (const w of waiting) {
          const t = truth.find((p) => key(p.name) === key(w.name));
          if (t && !(c.dismiss ?? []).includes(w.name)) {
            if (!pk.some((p) => p.name === w.name && p.ecosystem === w.ecosystems[0])) pk.push({ ...t, name: w.name, ecosystem: w.ecosystems[0], public: t.public ?? true });
          } else if (!not.includes(w.name)) not.push(w.name);
        }
      }
      const level = r?.delegation_assessment?.level as string;
      // b: his blockers. The literal agent declares no version, so a prose pin now holds review_needed (round 8,
      // D1(b)) where he expected human_only: never safe either way.
      if (c.expect) expect(level, c.task).not.toBe("safe_to_delegate");
      expect(level, c.task).not.toBe("confirmation_needed");
      return;
    }
    for (const st of c.steps) {
      const args = st.args ?? {};
      sent.length = 0;
      const { r, problem, text } = await call(args);
      expect(r !== null || problem !== null).toBe(true);
      const publicNames = (Array.isArray(args.packages) ? args.packages : []).filter((p: any) => p?.public === true && typeof p.name === "string").map((p: any) => String(p.name).toLowerCase());
      const hay = sent.map((x) => `${x.url} ${x.body}`).join("\n");
      const watched = [...new Set([...hay.matchAll(WATCH)].map((m) => m[0].toLowerCase()))].filter((w) => !publicNames.some((n: string) => n.includes(w) || w.includes(n)));
      expect(watched, `${c.id} sent a private-looking name`).toEqual([]);
      // Round 9, E1: a public entry without `version` never leaves the call safe.
      const versionless = (Array.isArray(args.packages) ? args.packages : []).some((p: any) => p?.public === true && (p.version === undefined || p.version === ""));
      if (r && versionless) expect(r.delegation_assessment.level, c.id).not.toBe("safe_to_delegate");
      // Round 11: his blockers. Every task of rep9, rep9b and rfile writes a bad release in an everyday spelling, or
      // a dismissed word after a manager name (P2, P3): never safe. k3rep: a dismissed word of a command this briefing
      // does not read is not repeated in the answer (P6).
      if (r && typeof args.task === "string" && /^(?:rep9|rep9b|rfile)$/.test(c.set)) expect(r.delegation_assessment.level, `${c.id}: ${args.task}`).not.toBe("safe_to_delegate");
      // Round 12, R3: a safe reason ends resting on the declaration, and carries the best-effort sentence exactly when the
      // call declared at least one package.
      if (r && r.delegation_assessment.level === "safe_to_delegate") {
        expect(r.delegation_assessment.reason.endsWith(RESTS_ON_DECLARATION), c.id).toBe(true);
        if (Array.isArray(args.packages) && args.packages.length > 0) expect(r.delegation_assessment.reason, c.id).toContain(BEST_EFFORT_READING);
        else expect(r.delegation_assessment.reason, c.id).not.toContain(BEST_EFFORT_READING);
        safeSeen.n++;
      }
      // Round 14, X1: a value of a credential shape this server knows is never in the output (answer or error),
      // outside the echoed `task` (the reading copy of the caller's own task).
      {
        const caseText = JSON.stringify(c);
        const out = r ? JSON.stringify({ ...r, task: undefined }) : text;
        for (const tok of TOKEN_VALUES.filter((t) => caseText.includes(t))) expect(out.includes(tok), `${c.id} repeated a credential-shaped word`).toBe(false);
      }
      // Round 14, X5: every text constant said is true at the level it is said with (helpers/a1137-text-rules.ts).
      if (r) expect(brokenTextRules(r, args), c.id).toEqual([]);
      // Round 14, X3: nothing the call dismissed or declared private is in a request the task's lookups made.
      if (r) expect(sentForbidden(args, JSON.stringify([c.files ?? {}, TEMPLATES[c.template ?? "npm"] ?? {}])), c.id).toEqual([]);
      if (r && c.set === "k3rep") {
        expect(r.summary, c.id).not.toMatch(/NOT CHECKED[^.]*zqxk9z/);
        expect(r.delegation_assessment.reason, c.id).not.toMatch(/NOT CHECKED[^.]*zqxk9z|zqxk9z \(\w+: not read by this server\)/);
        expect(r.delegation_assessment.level, c.id).toBe("review_needed");
      }
    }
  }, CASE_MS);

  // Round 14, X2: each kind the briefing READS (SEEN_KINDS "read") x each spelling of the dismissal: never safe.
  if (sets.includes("u12")) {
    const KINDS: Array<{ kind: string; template: string; task: string; files?: Record<string, string>; name: string; version: string; ecosystem: string }> = [
      { kind: "command", template: "npm", task: "npm install node-forge@0.10.0", name: "node-forge", version: "0.10.0", ecosystem: "npm" },
      { kind: "runner", template: "npm", task: "npx node-forge@0.10.0", name: "node-forge", version: "0.10.0", ecosystem: "npm" },
      { kind: "manifest", template: "npm", task: 'package.json:\n```json\n{ "dependencies": { "node-forge": "0.10.0" } }\n```', name: "node-forge", version: "0.10.0", ecosystem: "npm" },
      { kind: "form", template: "py", task: "Pin zqx-vuln-py==1.0.0 in the service.", name: "zqx-vuln-py", version: "1.0.0", ecosystem: "PyPI" },
      { kind: "file", template: "py", task: "pip install -r deps.list", files: { "deps.list": "zqx-vuln-py==1.0.0\n" }, name: "zqx-vuln-py", version: "1.0.0", ecosystem: "PyPI" },
    ];
    const spellings = (k: (typeof KINDS)[number]) => [k.name, k.name.toUpperCase(), `${k.name}${k.ecosystem === "PyPI" ? "==" : "@"}${k.version}`, k.ecosystem === "PyPI" ? k.name.replace(/-/g, "_").replace("_vuln", ".vuln") : `${k.name}\u00ad`, `${k.name.slice(0, 3)}\u200b${k.name.slice(3)}`];
    it.each(KINDS.flatMap((k) => spellings(k).map((sp) => [`${k.kind} dismissed as ${JSON.stringify(sp)}`, k, sp] as const)))("%s: never safe", async (_l, k, sp) => {
      live = null;
      for (const [rel, body] of Object.entries(TEMPLATES[k.template] ?? {})) h.write(rel, body);
      for (const [rel, body] of Object.entries(k.files ?? {})) h.write(rel, body);
      const { r } = await call({ task: k.task, packages: [], not_packages: [sp] });
      expect(r?.delegation_assessment.level).not.toBe("safe_to_delegate");
    }, CASE_MS);
    // Round 14, X3: each folding variant of a name dismissed, or declared private: no request carries the name.
    const VARIANTS = ["\uff4c\uff4f\uff44\uff41\uff53\uff48", "lo\u034Fdash", "lo\u3164dash", "lo\uFFF0dash", "lodash@4.17.21", "LoDash", "lo\u00addash", "lo\u200bdash"];
    it.each(VARIANTS.map((v) => [JSON.stringify(v), v] as const))("npm install lodash@4.17.21 with lodash dismissed as %s: lodash is not looked up for the task", async (_l, v) => {
      live = null;
      for (const [rel, body] of Object.entries(TEMPLATES.npm ?? {})) h.write(rel, body);
      sent.length = 0;
      await call({ task: "npm install lodash@4.17.21", packages: [], not_packages: [v] });
      expect(namesRequested().filter((n) => n.toLowerCase() === "lodash")).toEqual([]);
      sent.length = 0;
      await call({ task: "npm install lodash@4.17.21", packages: [{ ecosystem: "npm", name: v, public: false }] });
      expect(namesRequested().filter((n) => n.toLowerCase() === "lodash")).toEqual([]);
    }, CASE_MS);
    it.each(VARIANTS.filter((v) => !v.includes("@")).map((v) => [JSON.stringify(v), v] as const))("a name declared public and dismissed as %s is refused and not sent", async (_l, v) => {
      live = null;
      for (const [rel, body] of Object.entries(TEMPLATES.npm ?? {})) h.write(rel, body);
      sent.length = 0;
      const { r } = await call({ task: "add lodash", packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.21", public: true }], not_packages: [v] });
      expect(namesRequested().filter((n) => n.toLowerCase() === "lodash")).toEqual([]);
      expect(r?.delegation_assessment.level).not.toBe("safe_to_delegate");
    }, CASE_MS);
  }

  // Round 15, A1: the Go walk never asks the proxy about a forbidden module or a path under it.
  if (sets.includes("t12")) {
    const GO: Array<[string, Record<string, unknown>]> = [
      ["go get github.com/zqxevil/mod/sub@latest", { not_packages: ["github.com/zqxevil/mod"] }],
      ["go get github.com/zqxevil/mod/sub@latest", { packages: [{ ecosystem: "Go", name: "github.com/zqxevil/mod", public: false }, { ecosystem: "Go", name: "github.com/zqxevil/mod/sub", version: "latest", public: true }] }],
      ["go install github.com/zqxevil/mod/cmd/tool@v1.2.0", { not_packages: ["github.com/zqxevil/mod"] }],
      ["go get github.com/zqxevil/mod/...@latest", { not_packages: ["GitHub.com/ZqxEvil/Mod"] }],
    ];
    it.each(GO.map(([task, extra]) => [`${task} with ${JSON.stringify(extra).slice(0, 70)}`, task, extra] as const))("%s: no proxy request under the forbidden module, never safe", async (_l, task, extra) => {
      live = null;
      for (const [rel, body] of Object.entries(TEMPLATES.go ?? {})) h.write(rel, body);
      sent.length = 0;
      const { r } = await call({ task, packages: [], ...extra });
      const under = namesRequested().filter((n) => n.toLowerCase().startsWith("github.com/zqxevil/mod"));
      expect(under).toEqual([]);
      expect(r?.delegation_assessment.level).not.toBe("safe_to_delegate");
    }, CASE_MS);
  }

  // Round 12b, item 3: in his world (scan ready), a declaration safe on its own; the same call with one refused entry
  // holds review_needed by that entry alone; without `version` it is confirmation_needed.
  if (sets.includes("t12"))
    it("a refused entry alone holds review_needed; a versionless public entry beside it, confirmation_needed", async () => {
      live = null;
      // PyPI: the harness gives PyPI releases a publish time (its npm documents carry none, so npm is "unknown").
      for (const [rel, body] of Object.entries(TEMPLATES.py ?? {})) h.write(rel, body);
      const good = { ecosystem: "PyPI", name: "litestar", version: "2.13.0", public: true };
      const bad = { ecosystem: "PyPI", name: "zqxbad", public: "yes" };
      const alone = (await call({ task: "Add litestar for the API.", packages: [good] })).r!;
      expect(alone.delegation_assessment.level, JSON.stringify(alone.requested_versions ?? alone.new_packages)).toBe("safe_to_delegate");
      const withBad = (await call({ task: "Add litestar for the API.", packages: [good, bad] })).r!;
      expect(withBad.delegation_assessment.level).toBe("review_needed");
      expect(withBad.delegation_assessment.reason).toContain("was refused");
      const versionless = (await call({ task: "Add litestar for the API.", packages: [{ ...good, version: undefined }, bad] })).r!;
      expect(versionless.delegation_assessment.level).toBe("confirmation_needed");
    }, CASE_MS);
});
}
