// SPDX-License-Identifier: Apache-2.0
/**
 * Regression: the fourth independent check (review-confirm4, the sentence method on the level contract), its
 * own sets a (bad installs), d (dual ecosystems), g, k, k3, o (80 ordinary tasks), p (privacy) and q vendored
 * under fixtures/a1129-confirm/ with the canned world they ran against and its project templates.
 * Token- and password-shaped literals are assembled at run time. The registries and OSV.dev are a stubbed
 * fetch answering from the world (a name not in it is a 404), every request is recorded, and the literal
 * agent of the check is replayed: it settles each to_confirm entry public in its first ecosystem.
 *
 * Held for every case and step:
 * - a watched word (a private name, a secret, a label) is never in any request;
 * - a name a step marks private or not a package is never sent in that step (I5);
 * - no what_should_i_know step sends anything to an embedding provider (C1);
 * - a task a bare call finds human_only is never safe after any declaration (I1).
 * And per set: an nR task (an install the reader missed) is never safe (C3); an nK task ends human_only, its
 * bundled or registry malware found past the 25th entry (C4); a t / v / s task of nT is never safe (C2).
 */
import { readFileSync } from "node:fs";
import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FourDADatabase } from "../db.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { executeDecisionMemory } from "../tools/decision-memory.js";
import { forbiddenKey } from "../tools/briefing-confirm.js";
import type { OsvVulnerability } from "../live/types.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { userConfigFile } from "./helpers/a1129-user-config.js";

const DIR = path.join(__dirname, "fixtures", "a1129-confirm");
const HOLES: Record<string, string> = {
  "{{SK}}": ["sk", "test-not-real-0000"].join("-"),
  "{{HEX}}": ["9f8e7d6c", "5b4a3f2e", "1d0c"].join(""),
  "{{HEX12}}": ["9f8e7d6c", "5b4a"].join(""),
  "{{PW}}": ["Tr0ub", "4dor&3zqx"].join(""),
  "{{PW9}}": ["Tr0ub", "4dor"].join(""),
  "{{TOK}}": ["token", "0123456789abcd"].join(""),
};
const RAW_HOLES = (JSON.parse(readFileSync(path.join(DIR, "review4-cases.json"), "utf8")) as { holes: Record<string, [string, string]> }).holes;
const load = (file: string) =>
  JSON.parse(
    Object.entries({ ...HOLES, ...Object.fromEntries(Object.entries(RAW_HOLES).map(([k, [a, b]]) => [k, `${a}${b}`])) }).reduce(
      (s, [k, v]) => s.replaceAll(k, JSON.stringify(v).slice(1, -1)),
      readFileSync(path.join(DIR, file), "utf8"),
    ),
  );

type Step = { args?: Record<string, any>; tool?: string; agent?: boolean; agentLeft?: number; not?: string[]; private?: string[]; truth?: string[] };
type Case = { set: string; id: string; template: string; note?: string; env?: Record<string, string>; files?: Record<string, string>; homeFiles?: Record<string, string>; watch?: string[]; steps: Step[] };
const CASES = (load("review4-cases.json") as { cases: Case[] }).cases;
type WorldPkg = { versions: string[]; vulns?: Array<{ id: string; severity?: string; fixed?: string; introduced?: string; malware?: boolean; summary?: string }> };
const WORLD = load("review4-world.json") as Record<string, Record<string, WorldPkg> | string>;
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
});
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
});

// a: every case installs a bad package (malware, a critical or high release, a typosquat); q: the notes say so.
const NEVER_SAFE = (c: Case) => c.set === "a" || (c.set === "q" && /human_only|not safe/.test(c.note ?? ""));

describe("review-confirm4 cases hold the invariants", () => {
  it.each(CASES.map((c) => [`${c.set}/${c.id}: ${c.note ?? ""}`, c] as const))("%s", async (_label, c) => {
    for (const [k, v] of Object.entries(c.env ?? {})) setEnv(k, v);
    for (const [rel, body] of Object.entries(TEMPLATES[c.template] ?? {})) h.write(rel, body);
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
    const files = JSON.stringify({ ...(TEMPLATES[c.template] ?? {}), ...(c.files ?? {}) }).toLowerCase();
    // A dependency key of a package.json (`"zod":`, escaped quotes in the stringified files) or a requirements line.
    const installed = (w: string) => [`\\"${w}\\":`, `\\n${w}==`, `\\n${w}>=`, `"${w}==`].some((form) => files.includes(form));
    const scanned = (c.watch ?? []).map((w) => w.toLowerCase()).filter(installed);
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
          else packages.push({ ecosystem: e.ecosystems[0], name: e.name, ...(e.version ? { version: e.version } : {}), public: !(st.private ?? []).includes(e.name) });
        }
        const left = st.agentLeft ?? 3;
        if (left > 0 && k === steps.length - 1) steps.push({ agent: true, agentLeft: left - 1, not: st.not, private: st.private, truth: st.truth });
        st = { args: { task: c.steps.find((s) => s.args?.task !== undefined)?.args?.task, packages, ...(notPackages.length > 0 ? { not_packages: notPackages } : {}) } };
      }
      const args = st.args ?? {};
      sent.length = 0;
      const r = (await executeWhatShouldIKnow(db, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
      answers.push({ args, r });
      const level = r.delegation_assessment.level as string;
      if (answers.length === 1 && args.packages === undefined) bareHumanOnly = level === "human_only";
      const hay = sent.map((s) => `${s.url} ${s.body}`.toLowerCase()).join("\n");
      expect(watch.filter((w) => hay.includes(w)), `step ${k} sent a watched word`).toEqual([]);
      for (const w of scanned) expect(JSON.stringify(r)).not.toMatch(new RegExp(`${w} was not sent`, "i"));
      const forbidden = [...(args.packages ?? []).filter((p: { public?: unknown }) => p.public === false).map((p: { name: string }) => p.name), ...(args.not_packages ?? [])].map(forbiddenKey);
      const names = sent.flatMap((s) => [...s.url.matchAll(/registry\.npmjs\.org\/((?:@[^/]+\/)?[^/?#]+)|pypi\.org\/pypi\/([^/]+)|index\.crates\.io\/(?:[^/]+\/)*([^/?#]+)|proxy\.golang\.org\/(.+?)\/@v/g)].map((m) => m[1] ?? m[2] ?? m[3] ?? m[4]));
      expect(names.filter((n) => forbidden.includes(forbiddenKey(n))), `step ${k} looked up a forbidden name`).toEqual([]);
      expect(sent.filter((s) => /api\.openai\.com|\/api\/embeddings/.test(s.url)), `step ${k} reached an embedding provider`).toEqual([]);
      if (bareHumanOnly && answers.length > 1) expect(level, `step ${k}`).not.toBe("safe_to_delegate");
      if (NEVER_SAFE(c)) expect(level, `step ${k}`).not.toBe("safe_to_delegate");
    }
    // o: the reviewer's 80 ordinary tasks, declared exactly: nothing but the round-7 grammar holds them. A command
    // written into a sentence ("npm i bullmq ioredis, then add a worker file") is not read whole (C1, review_needed);
    // no prose version, withheld option value or unlooked-up name does (C10). How many end safe is measured on the
    // reviewer's harness, whose registries carry full release data.
    if (c.set === "o") expect(answers.at(-1)?.r.delegation_assessment.reason ?? "").not.toMatch(/was not looked up|not looked up \(|the word after|could not tie/);
  });
});
