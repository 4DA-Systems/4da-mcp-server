// SPDX-License-Identifier: Apache-2.0
/**
 * Regression: the ninth independent check (review-confirm9, round 11), its own sets vendored under
 * fixtures/a1134-confirm/ with its canned world and templates (its tool-level and over-long cases left out). One-call
 * sets: nothing named zqxpriv* or zqxs3cr* is in a request unless that call declares it public, and (round 9, E1) no
 * call is safe while a public entry has no `version`. Agent sets (b9-agent, f9g) are replayed with his literal agent,
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
import { BEST_EFFORT_READING, RESTS_ON_DECLARATION } from "../../tools/briefing-confirm.js";
/** How many one-call answers were safe (the P1 check above must have something to check). */
const safeSeen = { n: 0 };
import { TOOL_REGISTRY } from "../../schema-registry.js";

const DIR = path.join(__dirname, "..", "fixtures", "a1134-confirm");
const HOLES: Record<string, string> = {
  "{{SK}}": ["sk", "test-not-real-0000"].join("-"),
  "{{HEX}}": ["9f8e7d6c", "5b4a3f2e", "1d0c"].join(""),
  "{{HEX12}}": ["9f8e7d6c", "5b4a"].join(""),
  "{{PW}}": ["Tr0ub", "4dor&3zqx"].join(""),
  "{{PW9}}": ["Tr0ub", "4dor"].join(""),
  "{{TOK}}": ["token", "0123456789abcd"].join(""),
};
const RAW_HOLES = (JSON.parse(readFileSync(path.join(DIR, "review9-cases.json"), "utf8")) as { holes: Record<string, [string, string]> }).holes;
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
const WORLD = load("review9-world.json") as Record<string, Record<string, WorldPkg> | string>;
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

const ALL = (load("review9-cases.json") as { cases: Task[] }).cases;

/** Registers the regression for some of the sixth check's sets: three files share the 761 cases (round 8, m12). */
export function runReview9(sets: readonly string[]): void {
// Round 8, m12: the agent-loop replay of his ordinary-task sets (f: 298, run5: 151) is a fixed sample in the default
// run (every 6th f case, every 3rd run5 case: the rest is measured on his own harness, agent.mjs), so the suite's
// load on a hosted runner stays near the fifth check's; FOURDA_FULL_REVIEW=1 replays every case.
const SAMPLE: Record<string, number> = process.env.FOURDA_FULL_REVIEW === "1" ? {} : { "b9-agent": 3, b9: 3 };
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
async function call(args: Record<string, any>): Promise<{ r: Record<string, any> | null; problem: string | null }> {
  const problem = validateToolArgs("what_should_i_know", SCHEMA, args);
  if (problem !== null) return { r: null, problem };
  live ??= await h.live();
  return { r: (await executeWhatShouldIKnow(db, { ...args, project_path: h.dir } as never, live)) as Record<string, any>, problem: null };
}

describe(`review-confirm9 cases hold the invariants (${sets.join(", ")})`, () => {
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
      const { r, problem } = await call(args);
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
      // Round 11, P1: a safe reason ends resting on the declaration, and says the reading is best effort where the task
      // holds a fenced block, a manifest file name or a command.
      if (r && r.delegation_assessment.level === "safe_to_delegate") {
        expect(r.delegation_assessment.reason.endsWith(RESTS_ON_DECLARATION), c.id).toBe(true);
        if (typeof args.task === "string" && (/^\s*(?:```|~~~)/m.test(args.task) || /\b(?:requirements[\w.-]*\.(?:txt|in)|pyproject\.toml|Cargo\.toml|package\.json|go\.mod)\b/i.test(args.task) || /\b(?:npm|pnpm|yarn|bun|pip3?|uv|poetry|cargo|go)\s+(?:install|i|add|get)\b/.test(args.task))) expect(r.delegation_assessment.reason, c.id).toContain(BEST_EFFORT_READING);
        safeSeen.n++;
      }
      if (r && c.set === "k3rep") {
        expect(r.summary, c.id).not.toMatch(/NOT CHECKED[^.]*zqxk9z/);
        expect(r.delegation_assessment.reason, c.id).not.toMatch(/NOT CHECKED[^.]*zqxk9z|zqxk9z \(\w+: not read by this server\)/);
        expect(r.delegation_assessment.level, c.id).toBe("review_needed");
      }
    }
  }, CASE_MS);

});
}
